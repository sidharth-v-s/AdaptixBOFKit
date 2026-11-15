/*
 * regdelete <hive> <path> [value]
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *hive, *path, *value = "";
    int hlen = 0, plen = 0, vlen = 0;
    HKEY root, h;
    LONG rc;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: regdelete <hive> <path> [value]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    hive = BeaconDataExtract(&parser, &hlen);
    path = BeaconDataExtract(&parser, &plen);
    value = BeaconDataExtract(&parser, &vlen);
    if (!value) value = "";
    root = bof_hive(hive);

    if (value[0]) {
        rc = ADVAPI32$RegOpenKeyExA(root, path, 0, KEY_SET_VALUE, &h);
        if (rc != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyEx failed: %ld\n", (long)rc);
            return;
        }
        rc = ADVAPI32$RegDeleteValueA(h, value);
        if (rc == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "Deleted %s\\%s\\%s\n", hive, path, value);
        else
            BeaconPrintf(CALLBACK_ERROR, "RegDeleteValue failed: %ld\n", (long)rc);
        ADVAPI32$RegCloseKey(h);
    } else {
        rc = ADVAPI32$RegDeleteKeyA(root, path);
        if (rc == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "Deleted key %s\\%s\n", hive, path);
        else
            BeaconPrintf(CALLBACK_ERROR, "RegDeleteKey failed: %ld (key must be empty)\n", (long)rc);
    }
}
