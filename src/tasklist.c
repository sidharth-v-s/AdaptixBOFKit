/*
 * tasklist [filter] - process list with full command lines.
 *
 * Reads the command line with NtQueryInformationProcess(ProcessCommandLine-
 * Information) and falls back to walking the target PEB when that class is
 * not available (pre-Windows 8.1).  32-bit processes show "-" for the
 * command line on a 64-bit agent because their PEB layout differs.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#ifndef PROCESS_COMMAND_LINE_INFORMATION
#define PROCESS_COMMAND_LINE_INFORMATION 60
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct _BOF_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} BOF_UNICODE_STRING;

typedef struct _BOF_PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} BOF_PROCESS_BASIC_INFORMATION;

/* PEB and RTL_USER_PROCESS_PARAMETERS offsets for x64. */
#define BOF_PEB_PROCESS_PARAMETERS 0x20
#define BOF_PARAMS_COMMAND_LINE    0x70

static void copy_remote_string(HANDLE hp, const wchar_t *remote, int bytes,
                               char *out, int outsz)
{
    wchar_t buf[1024];
    SIZE_T got = 0;

    out[0] = 0;
    if (!remote || bytes <= 0 || bytes > (int)(sizeof(buf) - 2)) return;
    if (!KERNEL32$ReadProcessMemory(hp, remote, buf, (SIZE_T)bytes, &got)) return;
    if (got < 2) return;
    buf[got / 2] = 0;
    bof_w2a(buf, out, outsz);
}

static int cmdline_via_class(HANDLE hp, char *out, int outsz)
{
    ULONG need = 0, got = 0;
    NTSTATUS st;
    BYTE *buf;
    BOF_UNICODE_STRING *us;

    out[0] = 0;
    st = NTDLL$NtQueryInformationProcess(hp, PROCESS_COMMAND_LINE_INFORMATION,
                                         NULL, 0, &need);
    if (st != STATUS_INFO_LENGTH_MISMATCH || need < sizeof(BOF_UNICODE_STRING))
        return -1;

    buf = (BYTE *)KERNEL32$VirtualAlloc(NULL, need, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!buf) return -1;

    st = NTDLL$NtQueryInformationProcess(hp, PROCESS_COMMAND_LINE_INFORMATION,
                                         buf, need, &got);
    if (st < 0) {
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return -1;
    }

    us = (BOF_UNICODE_STRING *)buf;
    if (us->Length && us->Buffer) {
        ULONG_PTR start = (ULONG_PTR)buf;
        ULONG_PTR p = (ULONG_PTR)us->Buffer;
        if (p >= start && p < start + need) {
            wchar_t tmp[1024];
            int chars = us->Length / 2;
            if (chars > (int)(sizeof(tmp) / sizeof(tmp[0])) - 1)
                chars = (int)(sizeof(tmp) / sizeof(tmp[0])) - 1;
            bof_memcpy(tmp, us->Buffer, (unsigned int)chars * 2);
            tmp[chars] = 0;
            bof_w2a(tmp, out, outsz);
        } else {
            copy_remote_string(hp, us->Buffer, us->Length, out, outsz);
        }
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    return out[0] ? 0 : -1;
}

static int cmdline_via_peb(HANDLE hp, char *out, int outsz)
{
    BOF_PROCESS_BASIC_INFORMATION pbi;
    ULONG got = 0;
    PVOID params = NULL;
    BOF_UNICODE_STRING cl;
    SIZE_T rd = 0;

    out[0] = 0;
    bof_memzero(&pbi, sizeof(pbi));
    if (NTDLL$NtQueryInformationProcess(hp, 0, &pbi, sizeof(pbi), &got) < 0)
        return -1;
    if (!pbi.PebBaseAddress) return -1;

    if (!KERNEL32$ReadProcessMemory(hp,
            (BYTE *)pbi.PebBaseAddress + BOF_PEB_PROCESS_PARAMETERS,
            &params, sizeof(params), &rd) || !params)
        return -1;

    if (!KERNEL32$ReadProcessMemory(hp,
            (BYTE *)params + BOF_PARAMS_COMMAND_LINE,
            &cl, sizeof(cl), &rd) || !cl.Buffer || !cl.Length)
        return -1;

    copy_remote_string(hp, cl.Buffer, cl.Length, out, outsz);
    return out[0] ? 0 : -1;
}

void go(char *args, int alen)
{
    datap parser;
    char *filter = "";
    int flen = 0;
    HANDLE snap;
    PROCESSENTRY32 pe;
    int count = 0;

    BeaconDataParse(&parser, args, alen);
    filter = BeaconDataExtract(&parser, &flen);
    if (!filter) filter = "";

    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memzero(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    BeaconPrintf(CALLBACK_OUTPUT, "  %-6s %-6s %-28s %s\n",
                 "PID", "PPID", "Image", "Command line");

    if (KERNEL32$Process32First(snap, &pe)) {
        do {
            char cmd[2048];
            HANDLE hp;
            const char *image = pe.szExeFile;

            cmd[0] = 0;
            hp = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                      PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!hp)
                hp = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                          FALSE, pe.th32ProcessID);
            if (hp) {
                if (cmdline_via_class(hp, cmd, sizeof(cmd)) != 0)
                    cmdline_via_peb(hp, cmd, sizeof(cmd));
                KERNEL32$CloseHandle(hp);
            }

            if (filter[0] && !bof_strstr(image, filter) &&
                !(cmd[0] && bof_strstr(cmd, filter)))
                continue;

            BeaconPrintf(CALLBACK_OUTPUT, "  %-6lu %-6lu %-28.28s %s\n",
                         (unsigned long)pe.th32ProcessID,
                         (unsigned long)pe.th32ParentProcessID,
                         image,
                         cmd[0] ? cmd : "-");
            count++;
        } while (KERNEL32$Process32Next(snap, &pe));
    }

    KERNEL32$CloseHandle(snap);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d process(es)\n", count);
}
