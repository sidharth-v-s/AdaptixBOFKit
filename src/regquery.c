/*
 * regquery <hive> <path> [value]
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_data(DWORD type, BYTE *data, DWORD len)
{
    DWORD i;
    char hex[3];

    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        if (len) data[len - 1] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", (char *)data);
    } else if (type == REG_DWORD && len >= 4) {
        BeaconPrintf(CALLBACK_OUTPUT, "0x%08lx (%lu)\n",
                     (unsigned long)*(DWORD *)data, (unsigned long)*(DWORD *)data);
    } else if (type == REG_QWORD && len >= 8) {
        BeaconPrintf(CALLBACK_OUTPUT, "0x%016llx\n", *(unsigned long long *)data);
    } else {
        for (i = 0; i < len && i < 128; i++) {
            bof_hex(data[i], 2, hex);
            BeaconPrintf(CALLBACK_OUTPUT, "%s", hex);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", len > 128 ? "..." : "");
    }
}

void go(char *args, int alen)
{
    datap parser;
    char *hive, *path, *value = "";
    int hlen = 0, plen = 0, vlen = 0;
    HKEY root, h;
    LONG rc;
    BYTE data[4096];
    DWORD type, size, index;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: regquery <hive> <path> [value]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    hive = BeaconDataExtract(&parser, &hlen);
    path = BeaconDataExtract(&parser, &plen);
    value = BeaconDataExtract(&parser, &vlen);
    if (!value) value = "";
    root = bof_hive(hive);

    rc = ADVAPI32$RegOpenKeyExA(root, path, 0, KEY_READ, &h);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyEx failed: %ld\n", (long)rc);
        return;
    }

    if (value[0]) {
        size = sizeof(data);
        rc = ADVAPI32$RegQueryValueExA(h, value, NULL, &type, data, &size);
        if (rc == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s\\%s [%s]\n", hive, path, value, bof_regtype(type));
            print_data(type, data, size);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "RegQueryValueEx failed: %ld\n", (long)rc);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s\n", hive, path);
        for (index = 0; ; index++) {
            char name[512];
            DWORD nameLen = sizeof(name);
            size = sizeof(data);
            rc = ADVAPI32$RegEnumValueA(h, index, name, &nameLen, NULL, &type, data, &size);
            if (rc != ERROR_SUCCESS) break;
            BeaconPrintf(CALLBACK_OUTPUT, "  %-32s [%s] ", name, bof_regtype(type));
            print_data(type, data, size);
        }
    }

    ADVAPI32$RegCloseKey(h);
}
