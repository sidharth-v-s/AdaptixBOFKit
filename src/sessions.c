/*
 * sessions - enumerate local/RDP Windows sessions.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *wts_state(WTS_CONNECTSTATE_CLASS s)
{
    switch (s) {
    case WTSActive:       return "Active";
    case WTSConnected:    return "Connected";
    case WTSConnectQuery: return "ConnectQuery";
    case WTSShadow:       return "Shadow";
    case WTSDisconnected: return "Disconnected";
    case WTSIdle:         return "Idle";
    case WTSListen:       return "Listen";
    case WTSReset:        return "Reset";
    case WTSDown:         return "Down";
    case WTSInit:         return "Init";
    }
    return "?";
}

static void query_str(DWORD session, WTS_INFO_CLASS cls, const char *label)
{
    LPSTR buf = NULL;
    DWORD len = 0;
    if (WTSAPI32$WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, session, cls, &buf, &len) && buf) {
        BeaconPrintf(CALLBACK_OUTPUT, "    %-8s %s\n", label, buf);
        WTSAPI32$WTSFreeMemory(buf);
    }
}

void go(char *args, int alen)
{
    PWTS_SESSION_INFOA info = NULL;
    DWORD count = 0, i;
    (void)args; (void)alen;

    if (!WTSAPI32$WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count)) {
        BeaconPrintf(CALLBACK_ERROR, "WTSEnumerateSessionsA failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    for (i = 0; i < count; i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "[Session %lu] %s (%s)\n",
                     (unsigned long)info[i].SessionId,
                     info[i].pWinStationName ? info[i].pWinStationName : "?",
                     wts_state(info[i].State));
        query_str(info[i].SessionId, WTSUserName, "User");
        query_str(info[i].SessionId, WTSDomainName, "Domain");
        query_str(info[i].SessionId, WTSClientName, "Client");
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    WTSAPI32$WTSFreeMemory(info);
}
