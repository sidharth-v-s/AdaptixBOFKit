/*
 * msi-search [keyword] - installed MSI products and their install paths.
 *
 * Uses the Windows Installer API (msi.dll) to enumerate registered products.
 * The optional keyword is matched case-insensitively against product name,
 * publisher and install location.  Useful for finding vulnerable or outdated
 * software by version.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int ci_contains(const char *hay, const char *needle)
{
    int n = bof_strlen(needle);
    int i;

    if (!n) return 1;
    while (*hay) {
        int ok = 1;
        for (i = 0; i < n; i++) {
            char a = hay[i], b = needle[i];
            if (!a) { ok = 0; break; }
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { ok = 0; break; }
        }
        if (ok) return 1;
        hay++;
    }
    return 0;
}

static int get_info(const char *code, const char *attr, char *out, int outsz)
{
    DWORD sz = (DWORD)outsz;
    UINT rc;

    out[0] = 0;
    rc = MSI$MsiGetProductInfoA(code, attr, out, &sz);
    if (rc != ERROR_SUCCESS) {
        out[0] = 0;
        return -1;
    }
    return 0;
}

void go(char *args, int alen)
{
    datap parser;
    char *keyword = "";
    int klen = 0;
    DWORD index;
    int total = 0, shown = 0;

    BeaconDataParse(&parser, args, alen);
    keyword = BeaconDataExtract(&parser, &klen);
    if (!keyword) keyword = "";

    BeaconPrintf(CALLBACK_OUTPUT, "  %-40s %-12s %-28s %s\n",
                 "Product", "Version", "Publisher", "Name / install location");

    for (index = 0; ; index++) {
        char code[64];
        char name[512], version[64], publisher[256], location[512];
        UINT rc = MSI$MsiEnumProductsA(index, code);

        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) {
            if (rc == ERROR_BAD_CONFIGURATION) continue;
            break;
        }

        total++;
        get_info(code, "ProductName", name, sizeof(name));
        get_info(code, "VersionString", version, sizeof(version));
        get_info(code, "Publisher", publisher, sizeof(publisher));
        get_info(code, "InstallLocation", location, sizeof(location));

        if (!name[0]) continue;
        if (keyword[0] &&
            !ci_contains(name, keyword) &&
            !ci_contains(publisher, keyword) &&
            !ci_contains(location, keyword))
            continue;

        BeaconPrintf(CALLBACK_OUTPUT, "  %-40s %-12s %-28.28s %s\n",
                     code,
                     version[0] ? version : "-",
                     publisher[0] ? publisher : "-",
                     name);
        if (location[0])
            BeaconPrintf(CALLBACK_OUTPUT, "      install: %s\n", location);
        shown++;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\nProducts: %d total, %d shown\n", total, shown);
}
