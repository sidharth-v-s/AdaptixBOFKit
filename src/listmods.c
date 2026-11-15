/*
 * listmods <pid> - list modules loaded in a process (pid 0 = current).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    int pid = 0;
    DWORD target;
    HANDLE snap;
    MODULEENTRY32 me;
    int count = 0;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        pid = BeaconDataInt(&parser);
    }
    target = pid ? (DWORD)pid : KERNEL32$GetCurrentProcessId();

    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed for PID %lu: %lu\n",
                     (unsigned long)target, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memzero(&me, sizeof(me));
    me.dwSize = sizeof(me);

    BeaconPrintf(CALLBACK_OUTPUT, "Modules for PID %lu\n", (unsigned long)target);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %-10s %s\n", "Base", "Size", "Path");

    if (KERNEL32$Module32First(snap, &me)) {
        do {
            BeaconPrintf(CALLBACK_OUTPUT, "  %p %-10lu %s\n",
                         me.modBaseAddr,
                         (unsigned long)me.modBaseSize,
                         me.szExePath);
            count++;
        } while (KERNEL32$Module32Next(snap, &me));
    }

    KERNEL32$CloseHandle(snap);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d module(s)\n", count);
}
