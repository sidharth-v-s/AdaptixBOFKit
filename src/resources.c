/*
 * resources - memory, disk and CPU information.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    MEMORYSTATUSEX ms;
    SYSTEM_INFO si;
    ULARGE_INTEGER avail, total, freeb;
    (void)args; (void)alen;

    ms.dwLength = sizeof(ms);
    if (KERNEL32$GlobalMemoryStatusEx(&ms)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[Memory]\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  Load        : %lu%%\n", (unsigned long)ms.dwMemoryLoad);
        BeaconPrintf(CALLBACK_OUTPUT, "  Total RAM   : %llu MB\n", ms.ullTotalPhys / (1024ULL * 1024ULL));
        BeaconPrintf(CALLBACK_OUTPUT, "  Available   : %llu MB\n", ms.ullAvailPhys / (1024ULL * 1024ULL));
        BeaconPrintf(CALLBACK_OUTPUT, "  Total page  : %llu MB\n", ms.ullTotalPageFile / (1024ULL * 1024ULL));
        BeaconPrintf(CALLBACK_OUTPUT, "  Avail page  : %llu MB\n", ms.ullAvailPageFile / (1024ULL * 1024ULL));
    }

    KERNEL32$GetSystemInfo(&si);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[CPU]\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  Architecture: %u\n", (unsigned)si.wProcessorArchitecture);
    BeaconPrintf(CALLBACK_OUTPUT, "  Processors  : %lu\n", (unsigned long)si.dwNumberOfProcessors);
    BeaconPrintf(CALLBACK_OUTPUT, "  Page size   : %lu\n", (unsigned long)si.dwPageSize);

    avail.QuadPart = total.QuadPart = freeb.QuadPart = 0;
    if (KERNEL32$GetDiskFreeSpaceExA("C:\\", &avail, &total, &freeb)) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[Disk C:]\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  Total       : %llu MB\n", total.QuadPart / (1024ULL * 1024ULL));
        BeaconPrintf(CALLBACK_OUTPUT, "  Free        : %llu MB\n", freeb.QuadPart / (1024ULL * 1024ULL));
    }
}
