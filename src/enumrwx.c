/*
 * enumrwx <pid> - enumerate RWX memory regions in a process.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    int pid;
    DWORD target;
    HANDLE p;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *addr = NULL;
    int count = 0;

    BeaconDataParse(&parser, args, alen);
    pid = BeaconDataInt(&parser);
    target = pid ? (DWORD)pid : KERNEL32$GetCurrentProcessId();

    p = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target);
    if (!p) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%lu) failed: %lu\n",
                     (unsigned long)target, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "RWX regions in PID %lu\n", (unsigned long)target);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %-10s %-10s %s\n", "Base", "Size", "Type", "Protect");

    while (KERNEL32$VirtualQueryEx(p, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_EXECUTE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  %p %-10llu %-10lu 0x%lx\n",
                         mbi.BaseAddress,
                         (unsigned long long)mbi.RegionSize,
                         (unsigned long)mbi.Type,
                         (unsigned long)mbi.Protect);
            count++;
        }
        addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if (!addr) break;
    }

    KERNEL32$CloseHandle(p);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d region(s)\n", count);
}
