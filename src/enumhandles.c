/*
 * enumhandles - per-process handle counts (lightweight system handle view).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    unsigned long long total = 0;
    int shown = 0;

    (void)args; (void)alen;

    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "process snapshot failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%-8s %-40s %s\n", "PID", "Image", "Handles");
    bof_memzero(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (KERNEL32$Process32First(snap, &pe)) {
        do {
            HANDLE p;
            DWORD count = 0;

            p = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                     pe.th32ProcessID);
            if (!p) continue;
            if (KERNEL32$GetProcessHandleCount(p, &count)) {
                BeaconPrintf(CALLBACK_OUTPUT, "%-8lu %-40s %lu\n",
                             (unsigned long)pe.th32ProcessID,
                             pe.szExeFile, (unsigned long)count);
                total += count;
                shown++;
            }
            KERNEL32$CloseHandle(p);
        } while (KERNEL32$Process32Next(snap, &pe));
    }
    KERNEL32$CloseHandle(snap);

    BeaconPrintf(CALLBACK_OUTPUT, "\nProcesses: %d  Handles: %llu\n",
                 shown, total);
}
