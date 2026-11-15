/*
 * proclist - list processes with PID, PPID, thread count and image path.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    int count = 0;
    (void)args; (void)alen;

    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memzero(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    BeaconPrintf(CALLBACK_OUTPUT, "  %-6s %-6s %-4s %s\n", "PID", "PPID", "Thr", "Image / Path");

    if (KERNEL32$Process32First(snap, &pe)) {
        do {
            char path[MAX_PATH];
            DWORD pathlen = sizeof(path);
            HANDLE hp;
            path[0] = 0;

            hp = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hp) {
                if (!KERNEL32$QueryFullProcessImageNameA(hp, 0, path, &pathlen))
                    path[0] = 0;
                KERNEL32$CloseHandle(hp);
            }

            BeaconPrintf(CALLBACK_OUTPUT, "  %-6lu %-6lu %-4lu %s\n",
                         (unsigned long)pe.th32ProcessID,
                         (unsigned long)pe.th32ParentProcessID,
                         (unsigned long)pe.cntThreads,
                         path[0] ? path : pe.szExeFile);
            count++;
        } while (KERNEL32$Process32Next(snap, &pe));
    }

    KERNEL32$CloseHandle(snap);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d process(es)\n", count);
}
