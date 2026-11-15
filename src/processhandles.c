/*
 * processhandles <pid> - handles held by a process (type index + access).
 *
 * Uses NtQuerySystemInformation(SystemHandleInformation). Object type names
 * are not resolved (that needs a second NT call that can block on some
 * object types), so the kernel type index is reported instead.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    int pid;
    ULONG size = 1 << 20, needed = 0;
    PVOID buf;
    NTSTATUS st;
    PSYSTEM_HANDLE_INFORMATION info;
    ULONG i, count = 0;

    BeaconDataParse(&parser, args, alen);
    pid = BeaconDataInt(&parser);
    if (pid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: processhandles <pid>\n");
        return;
    }

    buf = KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return;

    for (;;) {
        st = NTDLL$NtQuerySystemInformation(SystemHandleInformation, buf, size, &needed);
        if (st == (NTSTATUS)0xC0000004L) {          /* STATUS_INFO_LENGTH_MISMATCH */
            KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
            size = needed ? needed + (1 << 20) : size * 2;
            if (size > (256u << 20)) return;
            buf = KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buf) return;
            continue;
        }
        break;
    }
    if (st != 0) {
        BeaconPrintf(CALLBACK_ERROR, "NtQuerySystemInformation failed: 0x%08lx\n",
                     (unsigned long)st);
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }

    info = (PSYSTEM_HANDLE_INFORMATION)buf;
    BeaconPrintf(CALLBACK_OUTPUT, "Handles for PID %d\n", pid);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-8s %-6s %-6s %s\n",
                 "Handle", "Type", "Attr", "Access");
    for (i = 0; i < info->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO h = &info->Handles[i];
        if (h->UniqueProcessId != (ULONG)pid) continue;
        BeaconPrintf(CALLBACK_OUTPUT, "  0x%04x   %-6u %-6u 0x%08lx\n",
                     h->HandleValue, (unsigned)h->ObjectTypeIndex,
                     (unsigned)h->HandleAttributes, (unsigned long)h->GrantedAccess);
        count++;
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %lu handle(s)\n", (unsigned long)count);
}
