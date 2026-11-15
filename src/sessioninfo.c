/*
 * sessioninfo - details of the current logon session (LSA).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *logon_type_name(ULONG t)
{
    switch (t) {
    case 2:  return "Interactive";
    case 3:  return "Network";
    case 4:  return "Batch";
    case 5:  return "Service";
    case 7:  return "Unlock";
    case 8:  return "NetworkCleartext";
    case 9:  return "NewCredentials";
    case 10: return "RemoteInteractive";
    case 11: return "CachedInteractive";
    case 12: return "CachedRemoteInteractive";
    case 13: return "CachedUnlock";
    }
    return "Unknown";
}

static void print_us(const LSA_UNICODE_STRING *us)
{
    char tmp[512];
    int i, n = us->Length / sizeof(WCHAR);
    if (!us->Buffer || n <= 0) { BeaconPrintf(CALLBACK_OUTPUT, "-"); return; }
    if (n > 255) n = 255;
    for (i = 0; i < n; i++) tmp[i] = (char)us->Buffer[i];
    tmp[n] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "%s", tmp);
}

void go(char *args, int alen)
{
    HANDLE tok = NULL;
    TOKEN_STATISTICS ts;
    DWORD len = 0;
    PSECURITY_LOGON_SESSION_DATA sd = NULL;
    NTSTATUS st;
    char sid[256];
    LPSTR sidstr = NULL;
    SYSTEMTIME stime;

    (void)args; (void)alen;
    bof_memzero(&ts, sizeof(ts));

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tok) ||
        !ADVAPI32$GetTokenInformation(tok, TokenStatistics, &ts, sizeof(ts), &len)) {
        BeaconPrintf(CALLBACK_ERROR, "token query failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        if (tok) KERNEL32$CloseHandle(tok);
        return;
    }
    KERNEL32$CloseHandle(tok);

    st = SECUR32$LsaGetLogonSessionData(&ts.AuthenticationId, &sd);
    if (st != 0 || !sd) {
        BeaconPrintf(CALLBACK_ERROR, "LsaGetLogonSessionData failed: 0x%08lx\n",
                     (unsigned long)st);
        return;
    }

    if (ADVAPI32$ConvertSidToStringSidA(sd->Sid, &sidstr) && sidstr) {
        bof_strncpy(sid, sidstr, sizeof(sid));
        KERNEL32$LocalFree(sidstr);
    } else {
        bof_strcpy(sid, "-");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Logon session\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  User            : ");
    print_us(&sd->UserName);
    BeaconPrintf(CALLBACK_OUTPUT, "\n  Domain          : ");
    print_us(&sd->LogonDomain);
    BeaconPrintf(CALLBACK_OUTPUT, "\n  Auth package    : ");
    print_us(&sd->AuthenticationPackage);
    BeaconPrintf(CALLBACK_OUTPUT, "\n  Logon server    : ");
    print_us(&sd->LogonServer);
    BeaconPrintf(CALLBACK_OUTPUT, "\n  SID             : %s\n", sid);
    BeaconPrintf(CALLBACK_OUTPUT, "  Logon type      : %lu (%s)\n",
                 (unsigned long)sd->LogonType, logon_type_name(sd->LogonType));
    BeaconPrintf(CALLBACK_OUTPUT, "  Session         : %lu\n", (unsigned long)sd->Session);
    BeaconPrintf(CALLBACK_OUTPUT, "  LUID            : 0x%lx:0x%lx\n",
                 (unsigned long)sd->LogonId.HighPart, (unsigned long)sd->LogonId.LowPart);

    bof_memzero(&stime, sizeof(stime));
    if (KERNEL32$FileTimeToSystemTime((FILETIME *)&sd->LogonTime, &stime)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  Logon time      : %04u-%02u-%02u %02u:%02u:%02u UTC\n",
                     stime.wYear, stime.wMonth, stime.wDay,
                     stime.wHour, stime.wMinute, stime.wSecond);
    }

    SECUR32$LsaFreeReturnBuffer(sd);
}
