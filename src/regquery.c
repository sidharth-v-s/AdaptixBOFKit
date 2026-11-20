/*
 * regquery <hive> <path> [value]
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_data(DWORD type, BYTE *data, DWORD len)
{
    static const char hd[] = "0123456789abcdef";
    DWORD i;
    char out[2 * 128 + 8];
    int o = 0;

    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        if (len) data[len - 1] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", (char *)data);
    } else if (type == REG_DWORD && len >= 4) {
        BeaconPrintf(CALLBACK_OUTPUT, "0x%08lx (%lu)\n",
                     (unsigned long)*(DWORD *)data, (unsigned long)*(DWORD *)data);
    } else if (type == REG_QWORD && len >= 8) {
        BeaconPrintf(CALLBACK_OUTPUT, "0x%016llx\n", *(unsigned long long *)data);
    } else {
        DWORD n = len < 128 ? len : 128;
        for (i = 0; i < n; i++) {
            out[o++] = hd[(data[i] >> 4) & 0xf];
            out[o++] = hd[data[i] & 0xf];
        }
        out[o] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "%s%s\n", out, len > 128 ? "..." : "");
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
        bof_error_win32("RegOpenKeyEx", (DWORD)rc,
                        rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND
                            ? "the key does not exist"
                            : rc == ERROR_ACCESS_DENIED
                                ? "the current token cannot read this key"
                                : "could not open the registry key");
        bof_error_context("key", path ? path : "(null)");
        bof_error_context("hive", hive ? hive : "(default HKCU)");
        return;
    }

    if (value[0]) {
        size = sizeof(data);
        rc = ADVAPI32$RegQueryValueExA(h, value, NULL, &type, data, &size);
        if (rc == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s\\%s [%s]\n", hive, path, value, bof_regtype(type));
            print_data(type, data, size);
        } else if (rc == ERROR_MORE_DATA) {
            bof_error_win32("RegQueryValueEx", (DWORD)rc,
                            "value is larger than the 4096-byte buffer");
            bof_error_num("needed", (unsigned long long)size);
            bof_error_context("value", value);
        } else {
            bof_error_win32("RegQueryValueEx", (DWORD)rc,
                            rc == ERROR_FILE_NOT_FOUND
                                ? "the value does not exist under this key"
                                : "could not read the value");
            bof_error_context("value", value);
            bof_error_context("key", path ? path : "(null)");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s\n", hive, path);
        for (index = 0; ; index++) {
            char name[512];
            DWORD nameLen = sizeof(name);
            size = sizeof(data);
            rc = ADVAPI32$RegEnumValueA(h, index, name, &nameLen, NULL, &type, data, &size);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) {
                bof_error_win32("RegEnumValue", (DWORD)rc,
                                "enumeration stopped early");
                bof_error_num("index", (unsigned long long)index);
                bof_error_context("key", path ? path : "(null)");
                break;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "  %-32s [%s] ", name, bof_regtype(type));
            print_data(type, data, size);
        }
    }

    ADVAPI32$RegCloseKey(h);
}
