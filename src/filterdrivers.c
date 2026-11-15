/*
 * filterdrivers - list filesystem minifilter drivers.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    HANDLE find = NULL;
    DWORD got = 0, count = 0;
    BYTE buf[2048];

    (void)args; (void)alen;

    if (FLTLIB$FilterFindFirst(FilterFullInformation, buf, sizeof(buf), &got, &find) != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "FilterFindFirst failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Filesystem minifilters\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-32s %-10s %s\n", "Filter", "Instances", "Frame");

    for (;;) {
        PFILTER_FULL_INFORMATION fi = (PFILTER_FULL_INFORMATION)buf;
        char name[512];
        int n = fi->FilterNameLength / sizeof(WCHAR);
        int i;
        if (n > 255) n = 255;
        for (i = 0; i < n; i++) name[i] = (char)fi->FilterNameBuffer[i];
        name[n] = 0;

        BeaconPrintf(CALLBACK_OUTPUT, "  %-32s %-10lu %lu\n",
                     name, (unsigned long)fi->NumberOfInstances, (unsigned long)fi->FrameID);
        count++;

        if (FLTLIB$FilterFindNext(find, FilterFullInformation, buf, sizeof(buf), &got) != S_OK)
            break;
    }

    FLTLIB$FilterFindClose(find);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %lu minifilter(s)\n", (unsigned long)count);
}
