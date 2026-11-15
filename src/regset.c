/*
 * regset <hive> <path> <value> <data>
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *hive, *path, *value, *data;
    int hlen = 0, plen = 0, vlen = 0, dlen = 0;
    HKEY root, h;
    LONG rc;
    DWORD disp = 0;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: regset <hive> <path> <value> <data>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    hive = BeaconDataExtract(&parser, &hlen);
    path = BeaconDataExtract(&parser, &plen);
    value = BeaconDataExtract(&parser, &vlen);
    data = BeaconDataExtract(&parser, &dlen);
    if (!value || !data) return;
    root = bof_hive(hive);

    rc = ADVAPI32$RegCreateKeyExA(root, path, 0, NULL, 0, KEY_SET_VALUE,
                                  NULL, &h, &disp);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegCreateKeyEx failed: %ld\n", (long)rc);
        return;
    }

    rc = ADVAPI32$RegSetValueExA(h, value, 0, REG_SZ, (const BYTE *)data, dlen + 1);
    if (rc == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "Set %s\\%s\\%s = %s\n", hive, path, value, data);
    else
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueEx failed: %ld\n", (long)rc);

    ADVAPI32$RegCloseKey(h);
}
