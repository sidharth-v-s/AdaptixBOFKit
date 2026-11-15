/*
 * regqueryrec <hive> <path> [depth] - recursive registry dump.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_value(HKEY h, const char *full, const char *name)
{
    BYTE data[2048];
    DWORD size = sizeof(data), type = 0;
    LONG rc = ADVAPI32$RegQueryValueExA(h, name, NULL, &type, data, &size);
    DWORD i;
    if (rc != ERROR_SUCCESS) return;

    BeaconPrintf(CALLBACK_OUTPUT, "  %s\\%s [%s] ", full, name, bof_regtype(type));
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        if (size) data[size - 1] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", (char *)data);
    } else if (type == REG_DWORD && size >= 4) {
        BeaconPrintf(CALLBACK_OUTPUT, "0x%08lx (%lu)\n",
                     (unsigned long)*(DWORD *)data, (unsigned long)*(DWORD *)data);
    } else if (type == REG_QWORD && size >= 8) {
        BeaconPrintf(CALLBACK_OUTPUT, "0x%016llx\n", *(unsigned long long *)data);
    } else {
        for (i = 0; i < size && i < 64; i++)
            BeaconPrintf(CALLBACK_OUTPUT, "%02x", data[i]);
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", size > 64 ? "..." : "");
    }
}

static void walk(HKEY h, const char *path, int depth, int maxdepth)
{
    DWORD index;
    char name[512];
    char full[1024];

    for (index = 0; ; index++) {
        DWORD nameLen = sizeof(name);
        LONG rc = ADVAPI32$RegEnumValueA(h, index, name, &nameLen, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;
        bof_strncpy(full, path, sizeof(full));
        if (full[0] && bof_strlen(full) + 1 < (int)sizeof(full))
            bof_strcat(full, "\\");
        bof_strncat(full, name, sizeof(full) - bof_strlen(full) - 1);
        print_value(h, path, name);
    }

    if (depth >= maxdepth) return;

    for (index = 0; ; index++) {
        DWORD nameLen = sizeof(name);
        HKEY sub = NULL;
        LONG rc = ADVAPI32$RegEnumKeyExA(h, index, name, &nameLen, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;

        bof_strncpy(full, path, sizeof(full));
        if (full[0] && bof_strlen(full) + 1 < (int)sizeof(full))
            bof_strcat(full, "\\");
        bof_strncat(full, name, sizeof(full) - bof_strlen(full) - 1);

        rc = ADVAPI32$RegOpenKeyExA(h, name, 0, KEY_READ, &sub);
        if (rc == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", full);
            walk(sub, full, depth + 1, maxdepth);
            ADVAPI32$RegCloseKey(sub);
        }
    }
}

void go(char *args, int alen)
{
    datap parser;
    char *hive, *path;
    int hlen, plen, maxdepth = 3;
    HKEY root, h;
    LONG rc;
    char display[1024];

    BeaconDataParse(&parser, args, alen);
    hive = BeaconDataExtract(&parser, &hlen);
    path = BeaconDataExtract(&parser, &plen);
    maxdepth = BeaconDataInt(&parser);
    if (maxdepth <= 0) maxdepth = 3;
    if (maxdepth > 16) maxdepth = 16;

    root = bof_hive(hive);
    rc = ADVAPI32$RegOpenKeyExA(root, path, 0, KEY_READ, &h);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyEx failed: %ld\n", (long)rc);
        return;
    }

    bof_strncpy(display, path, sizeof(display));
    BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s\n", hive, display);
    walk(h, display, 0, maxdepth);
    ADVAPI32$RegCloseKey(h);
}
