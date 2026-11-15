/*
 * cacls <path> - print owner and DACL entries for a file or directory.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void sid_name(PSID sid, char *out, int outsz)
{
    char domain[256];
    DWORD dlen = sizeof(domain), ulen = outsz;
    SID_NAME_USE use;

    out[0] = 0;
    if (!sid) { bof_strcpy(out, "-"); return; }
    if (!ADVAPI32$LookupAccountSidA(NULL, sid, out, &ulen,
                                    domain, &dlen, &use)) {
        LPSTR s = NULL;
        if (ADVAPI32$ConvertSidToStringSidA(sid, &s) && s) {
            bof_strncpy(out, s, outsz);
            KERNEL32$LocalFree(s);
        } else {
            bof_strcpy(out, "?");
        }
        return;
    }
    if (domain[0]) {
        char tmp[384];
        bof_strncpy(tmp, domain, sizeof(tmp));
        bof_strncat(tmp, "\\", sizeof(tmp) - bof_strlen(tmp) - 1);
        bof_strncat(tmp, out, sizeof(tmp) - bof_strlen(tmp) - 1);
        bof_strncpy(out, tmp, outsz);
    }
}

static void mask_str(DWORD mask, char *out)
{
    static const struct { DWORD bit; char c; } bits[] = {
        { 0x00000001, 'R' }, { 0x00000002, 'W' }, { 0x00000004, 'A' },
        { 0x00000008, 'r' }, { 0x00000010, 'w' }, { 0x00000020, 'X' },
        { 0x00000040, 'd' }, { 0x00000080, 'a' }, { 0x00000100, 'e' },
        { 0x00010000, 'D' }, { 0x00020000, 'C' }, { 0x00040000, 'W' },
        { 0x00080000, 'O' }, { 0x00100000, 'S' }
    };
    int i, n = 0;

    if ((mask & 0x001F01FF) == 0x001F01FF) {
        bof_strcpy(out, "F");
        return;
    }
    for (i = 0; i < (int)(sizeof(bits) / sizeof(bits[0])); i++)
        if (mask & bits[i].bit) out[n++] = bits[i].c;
    if (!n) out[n++] = '-';
    out[n] = 0;
}

void go(char *args, int alen)
{
    datap parser;
    char *path;
    int plen;
    PSID owner = NULL, group = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD rc, i;
    BOOL present = FALSE, defaulted = FALSE;
    char name[384];

    BeaconDataParse(&parser, args, alen);
    path = BeaconDataExtract(&parser, &plen);
    if (!path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: cacls <path>\n");
        return;
    }

    rc = ADVAPI32$GetNamedSecurityInfoA(path, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, &group, &dacl, NULL, &sd);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "GetNamedSecurityInfo(%s) failed: %lu\n",
                     path, (unsigned long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", path);
    sid_name(owner, name, sizeof(name));
    BeaconPrintf(CALLBACK_OUTPUT, "  Owner: %s\n", name);

    if (!ADVAPI32$GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present || !dacl) {
        BeaconPrintf(CALLBACK_OUTPUT, "  DACL: <none>\n");
        KERNEL32$LocalFree(sd);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-4s %-32s %s\n", "Type", "Principal", "Rights");
    for (i = 0; i < dacl->AceCount; i++) {
        LPVOID ace = NULL;
        ACE_HEADER *hdr;
        PSID sid = NULL;
        DWORD mask = 0;
        const char *type;
        char rights[24];

        if (!ADVAPI32$GetAce(dacl, i, &ace) || !ace) continue;
        hdr = (ACE_HEADER *)ace;
        if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)ace;
            type = "ALLOW";
            mask = a->Mask;
            sid = (PSID)&a->SidStart;
        } else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE *a = (ACCESS_DENIED_ACE *)ace;
            type = "DENY";
            mask = a->Mask;
            sid = (PSID)&a->SidStart;
        } else {
            continue;
        }
        sid_name(sid, name, sizeof(name));
        mask_str(mask, rights);
        BeaconPrintf(CALLBACK_OUTPUT, "  %-4s %-32s %s (0x%08lx)\n",
                     type, name, rights, (unsigned long)mask);
    }

    KERNEL32$LocalFree(sd);
}
