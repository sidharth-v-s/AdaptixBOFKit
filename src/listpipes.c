/*
 * listpipes - enumerate named pipes on the local system.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    int count = 0;
    (void)args; (void)alen;

    h = KERNEL32$FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "FindFirstFile failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    do {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", fd.cFileName);
        count++;
    } while (KERNEL32$FindNextFileA(h, &fd));

    KERNEL32$FindClose(h);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d pipe(s)\n", count);
}
