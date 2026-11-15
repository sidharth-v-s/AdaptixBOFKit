/*
 * killprocess <pid> - terminate a process.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    int pid;
    HANDLE p;

    BeaconDataParse(&parser, args, alen);
    pid = BeaconDataInt(&parser);
    if (pid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: killprocess <pid>\n");
        return;
    }

    p = KERNEL32$OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!p) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %lu\n",
                     pid, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (KERNEL32$TerminateProcess(p, 1))
        BeaconPrintf(CALLBACK_OUTPUT, "Terminated PID %d\n", pid);
    else
        BeaconPrintf(CALLBACK_ERROR, "TerminateProcess(%d) failed: %lu\n",
                     pid, (unsigned long)KERNEL32$GetLastError());

    KERNEL32$CloseHandle(p);
}
