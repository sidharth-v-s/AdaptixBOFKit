/*
 * AdaptixBOFKit - Active Directory security-descriptor helpers.
 *
 * These helpers edit the binary nTSecurityDescriptor and
 * msDS-AllowedToActOnBehalfOfOtherIdentity attributes directly over LDAP.
 * All returned buffers are VirtualAlloc based so callers can free them with
 * VirtualFree(..., 0, MEM_RELEASE).
 */
#ifndef ADAPTIX_ADSD_H
#define ADAPTIX_ADSD_H

#include <windows.h>
#include <aclapi.h>
#include <winldap.h>
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

/* Escape a value for an LDAP filter. */
static inline void bof_ldap_escape(const char *in, char *out, int outsz)
{
    int o = 0;
    while (in && *in && o < outsz - 4) {
        switch (*in) {
        case '\\': out[o++] = '\\'; out[o++] = '5'; out[o++] = 'c'; break;
        case '*':  out[o++] = '\\'; out[o++] = '2'; out[o++] = 'a'; break;
        case '(':  out[o++] = '\\'; out[o++] = '2'; out[o++] = '8'; break;
        case ')':  out[o++] = '\\'; out[o++] = '2'; out[o++] = '9'; break;
        default:   out[o++] = *in; break;
        }
        in++;
    }
    out[o] = 0;
}

/* Turn a DN or sAMAccountName into a DN.  Returns 0 on success. */
static inline int bof_ldap_resolve_dn(LDAP *ld, const char *base,
                                      const char *target, char *out, int outsz)
{
    char esc[512], filter[1100];
    PCHAR attrs[2];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    ULONG rc;
    int ok = -1;

    if (!target || !target[0]) return -1;
    if (bof_strchr(target, ',') && bof_strchr(target, '=')) {
        bof_strncpy(out, target, outsz);
        return 0;
    }

    bof_ldap_escape(target, esc, sizeof(esc));
    filter[0] = 0;
    bof_strncat(filter, "(|(sAMAccountName=", sizeof(filter) - 1);
    bof_strncat(filter, esc, sizeof(filter) - bof_strlen(filter) - 1);
    bof_strncat(filter, ")(cn=", sizeof(filter) - bof_strlen(filter) - 1);
    bof_strncat(filter, esc, sizeof(filter) - bof_strlen(filter) - 1);
    bof_strncat(filter, "))", sizeof(filter) - bof_strlen(filter) - 1);

    attrs[0] = "distinguishedName";
    attrs[1] = NULL;
    rc = WLDAP32$ldap_search_ext_sA(ld, (PCHAR)base, LDAP_SCOPE_SUBTREE,
                                    filter, attrs, 0, NULL, NULL, NULL, 1, &res);
    if (rc == LDAP_SUCCESS && res) {
        e = WLDAP32$ldap_first_entry(ld, res);
        if (e && bof_ldap_get_str(ld, e, "distinguishedName", out, outsz) == 0)
            ok = 0;
        WLDAP32$ldap_msgfree(res);
    }
    return ok;
}

/* Read a binary attribute of a DN.  Returns 0 and fills out/len. */
static inline int bof_ldap_read_bin(LDAP *ld, const char *dn, const char *attr,
                                    unsigned char **out, unsigned int *outlen)
{
    PCHAR attrs[2];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    struct berval **vals;
    unsigned char *buf;
    ULONG rc;
    int ok = -1;

    *out = NULL;
    *outlen = 0;
    attrs[0] = (PCHAR)attr;
    attrs[1] = NULL;
    rc = WLDAP32$ldap_search_ext_sA(ld, (PCHAR)dn, LDAP_SCOPE_BASE,
                                    "(objectClass=*)", attrs, 0, NULL, NULL,
                                    NULL, 1, &res);
    if (rc != LDAP_SUCCESS || !res) return -1;

    e = WLDAP32$ldap_first_entry(ld, res);
    if (e) {
        vals = WLDAP32$ldap_get_values_lenA(ld, e, (PCHAR)attr);
        if (vals && vals[0] && vals[0]->bv_len) {
            buf = (unsigned char *)KERNEL32$VirtualAlloc(NULL,
                        vals[0]->bv_len, MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE);
            if (buf) {
                bof_memcpy(buf, vals[0]->bv_val, vals[0]->bv_len);
                *out = buf;
                *outlen = vals[0]->bv_len;
                ok = 0;
            }
        }
        if (vals) WLDAP32$ldap_value_free_len(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return ok;
}

/* Replace (or add) a binary attribute.  Returns the LDAP result. */
static inline ULONG bof_ldap_write_bin(LDAP *ld, const char *dn,
                                       const char *attr,
                                       const unsigned char *data,
                                       unsigned int len)
{
    struct berval bv;
    struct berval *bvals[2];
    LDAPModA mod;
    LDAPModA *mods[2];

    bv.bv_len = len;
    bv.bv_val = (char *)data;
    bvals[0] = &bv;
    bvals[1] = NULL;
    bof_memzero(&mod, sizeof(mod));
    mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = (char *)attr;
    mod.mod_vals.modv_bvals = bvals;
    mods[0] = &mod;
    mods[1] = NULL;
    return WLDAP32$ldap_modify_ext_sA(ld, (PCHAR)dn, mods, NULL, NULL);
}

/* Write nTSecurityDescriptor with the SD_FLAGS control (DACL only). */
static inline ULONG bof_ldap_write_sd(LDAP *ld, const char *dn,
                                      const unsigned char *data,
                                      unsigned int len)
{
    struct berval bv;
    struct berval *bvals[2];
    LDAPModA mod;
    LDAPModA *mods[2];
    LDAPControlA ctrl;
    LDAPControlA *ctrls[2];
    unsigned char flags[3];

    bv.bv_len = len;
    bv.bv_val = (char *)data;
    bvals[0] = &bv;
    bvals[1] = NULL;
    bof_memzero(&mod, sizeof(mod));
    mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = "nTSecurityDescriptor";
    mod.mod_vals.modv_bvals = bvals;
    mods[0] = &mod;
    mods[1] = NULL;

    flags[0] = 0x02; flags[1] = 0x01; flags[2] = 0x07; /* INTEGER 7 */
    bof_memzero(&ctrl, sizeof(ctrl));
    ctrl.ldctl_oid = "1.2.840.113556.1.4.801";
    ctrl.ldctl_value.bv_len = sizeof(flags);
    ctrl.ldctl_value.bv_val = (char *)flags;
    ctrl.ldctl_iscritical = TRUE;
    ctrls[0] = &ctrl;
    ctrls[1] = NULL;

    return WLDAP32$ldap_modify_ext_sA(ld, (PCHAR)dn, mods, ctrls, NULL);
}

/* Remove a binary attribute entirely. */
static inline ULONG bof_ldap_delete_attr(LDAP *ld, const char *dn,
                                         const char *attr)
{
    LDAPModA mod;
    LDAPModA *mods[2];

    bof_memzero(&mod, sizeof(mod));
    mod.mod_op = LDAP_MOD_DELETE;
    mod.mod_type = (char *)attr;
    mod.mod_vals.modv_strvals = NULL;
    mods[0] = &mod;
    mods[1] = NULL;
    return WLDAP32$ldap_modify_ext_sA(ld, (PCHAR)dn, mods, NULL, NULL);
}

/* Accept S-1-5-... or DOMAIN\name / name.  Caller frees with LocalFree. */
static inline PSID bof_resolve_sid(const char *name)
{
    PSID sid = NULL;

    if (!name || !name[0]) return NULL;
    if ((name[0] == 'S' || name[0] == 's') && name[1] == '-') {
        if (ADVAPI32$ConvertStringSidToSidA(name, &sid)) return sid;
        return NULL;
    }
    {
        DWORD size = 0, dsize = 0;
        char dom[256];
        SID_NAME_USE use;
        dsize = sizeof(dom);
        if (!ADVAPI32$LookupAccountNameA(NULL, name, NULL, &size, dom,
                                         &dsize, &use))
            return NULL;
        sid = (PSID)KERNEL32$LocalAlloc(0, size);
        if (!sid) return NULL;
        dsize = sizeof(dom);
        if (!ADVAPI32$LookupAccountNameA(NULL, name, sid, &size, dom,
                                         &dsize, &use)) {
            KERNEL32$LocalFree(sid);
            return NULL;
        }
    }
    return sid;
}

/* Build a self-relative SD from an absolute SD.  Caller frees. */
static inline unsigned char *bof_sd_make_relative(PSECURITY_DESCRIPTOR absd,
                                                   unsigned int *outlen)
{
    unsigned char *out;
    DWORD need = 0;

    *outlen = 0;
    ADVAPI32$MakeSelfRelativeSD(absd, NULL, &need);
    if (need == 0 || need > 0x100000) return NULL;
    out = (unsigned char *)KERNEL32$VirtualAlloc(NULL, need,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!out) return NULL;
    if (!ADVAPI32$MakeSelfRelativeSD(absd, (PSECURITY_DESCRIPTOR)out, &need)) {
        KERNEL32$VirtualFree(out, 0, MEM_RELEASE);
        return NULL;
    }
    *outlen = need;
    return out;
}

/* Compose a self-relative SD carrying one ACCESS_ALLOWED ACE for sid. */
static inline unsigned char *bof_sd_new_for_sid(PSID sid, DWORD mask,
                                                 int include_owner,
                                                 unsigned int *outlen)
{
    SECURITY_DESCRIPTOR absd;
    unsigned char *aclmem;
    unsigned char *ace;
    unsigned int sidlen, acesize;
    ACL *acl;
    unsigned char *out;

    *outlen = 0;
    if (!sid) return NULL;
    sidlen = ADVAPI32$GetLengthSid(sid);
    if (!sidlen) return NULL;
    acesize = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sidlen;
    aclmem = (unsigned char *)KERNEL32$VirtualAlloc(NULL,
                sizeof(ACL) + acesize + 8, MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);
    if (!aclmem) return NULL;

    acl = (ACL *)aclmem;
    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = (WORD)(sizeof(ACL) + acesize);
    acl->AceCount = 1;
    acl->Sbz2 = 0;

    ace = aclmem + sizeof(ACL);
    ace[0] = ACCESS_ALLOWED_ACE_TYPE;
    ace[1] = 0;
    *(WORD *)(ace + 2) = (WORD)acesize;
    *(DWORD *)(ace + 4) = mask;
    bof_memcpy(ace + 8, sid, sidlen);

    if (!ADVAPI32$InitializeSecurityDescriptor(&absd,
                                               SECURITY_DESCRIPTOR_REVISION)) {
        KERNEL32$VirtualFree(aclmem, 0, MEM_RELEASE);
        return NULL;
    }
    if (include_owner)
        ADVAPI32$SetSecurityDescriptorOwner(&absd, sid, FALSE);
    ADVAPI32$SetSecurityDescriptorDacl(&absd, TRUE, (PACL)acl, FALSE);
    out = bof_sd_make_relative(&absd, outlen);
    KERNEL32$VirtualFree(aclmem, 0, MEM_RELEASE);
    return out;
}

/* Append an allow ACE (optionally object-specific) to a self-relative SD.
 * Returns a newly allocated self-relative SD, or NULL. */
static inline unsigned char *bof_sd_append_ace(const unsigned char *sd,
                                               unsigned int sdlen,
                                               PSID sid, DWORD mask,
                                               const GUID *object_guid,
                                               unsigned int *outlen)
{
    SECURITY_DESCRIPTOR absd;
    PACL oldacl = NULL;
    PSID owner = NULL, group = NULL;
    BOOL od = FALSE, gd = FALSE;
    DWORD aclsize, acesize, revision;
    unsigned char *aclmem;
    unsigned char *ace;
    unsigned int sidlen;
    unsigned char *out;

    *outlen = 0;
    if (!sd || sdlen < 20 || !sid) return NULL;
    sidlen = ADVAPI32$GetLengthSid(sid);
    if (!sidlen) return NULL;

    if (object_guid)
        acesize = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sizeof(DWORD) +
                  sizeof(GUID) + sidlen;
    else
        acesize = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sidlen;

    if (!ADVAPI32$GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)sd, &od,
                                            &oldacl, &gd))
        return NULL;
    if (!od) oldacl = NULL;
    revision = oldacl ? oldacl->AclRevision : ACL_REVISION;
    aclsize = oldacl ? oldacl->AclSize : sizeof(ACL);

    aclmem = (unsigned char *)KERNEL32$VirtualAlloc(NULL,
                aclsize + acesize + 8, MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);
    if (!aclmem) return NULL;

    if (oldacl) {
        bof_memcpy(aclmem, oldacl, aclsize);
    } else {
        ACL *a = (ACL *)aclmem;
        a->AclRevision = ACL_REVISION;
        a->Sbz1 = 0;
        a->AclSize = (WORD)sizeof(ACL);
        a->AceCount = 0;
        a->Sbz2 = 0;
    }

    ace = aclmem + aclsize;
    if (object_guid) {
        ace[0] = ACCESS_ALLOWED_OBJECT_ACE_TYPE;
        ace[1] = 0;
        *(WORD *)(ace + 2) = (WORD)acesize;
        *(DWORD *)(ace + 4) = mask;
        *(DWORD *)(ace + 8) = ACE_OBJECT_TYPE_PRESENT;
        bof_memcpy(ace + 12, object_guid, sizeof(GUID));
        bof_memcpy(ace + 28, sid, sidlen);
    } else {
        ace[0] = ACCESS_ALLOWED_ACE_TYPE;
        ace[1] = 0;
        *(WORD *)(ace + 2) = (WORD)acesize;
        *(DWORD *)(ace + 4) = mask;
        bof_memcpy(ace + 8, sid, sidlen);
    }

    ((ACL *)aclmem)->AclRevision = (BYTE)revision;
    ((ACL *)aclmem)->AclSize = (WORD)(aclsize + acesize);
    ((ACL *)aclmem)->AceCount = (WORD)((oldacl ? oldacl->AceCount : 0) + 1);

    if (!ADVAPI32$InitializeSecurityDescriptor(&absd,
                                               SECURITY_DESCRIPTOR_REVISION)) {
        KERNEL32$VirtualFree(aclmem, 0, MEM_RELEASE);
        return NULL;
    }
    if (ADVAPI32$GetSecurityDescriptorOwner((PSECURITY_DESCRIPTOR)sd, &owner,
                                            &od) && owner)
        ADVAPI32$SetSecurityDescriptorOwner(&absd, owner, od);
    if (ADVAPI32$GetSecurityDescriptorGroup((PSECURITY_DESCRIPTOR)sd, &group,
                                            &gd) && group)
        ADVAPI32$SetSecurityDescriptorGroup(&absd, group, gd);
    ADVAPI32$SetSecurityDescriptorDacl(&absd, TRUE, (PACL)aclmem, FALSE);

    out = bof_sd_make_relative(&absd, outlen);
    KERNEL32$VirtualFree(aclmem, 0, MEM_RELEASE);
    return out;
}

/* Remove every allow ACE for sid from a self-relative SD. */
static inline unsigned char *bof_sd_remove_ace_for_sid(const unsigned char *sd,
                                                       unsigned int sdlen,
                                                       PSID sid,
                                                       unsigned int *outlen)
{
    SECURITY_DESCRIPTOR absd;
    PACL oldacl = NULL;
    PSID owner = NULL, group = NULL;
    BOOL od = FALSE, gd = FALSE;
    DWORD i, keep = 0, totalsz;
    unsigned char *aclmem;
    unsigned int sidlen;
    unsigned char *out;

    *outlen = 0;
    if (!sd || !sid) return NULL;
    sidlen = ADVAPI32$GetLengthSid(sid);
    if (!ADVAPI32$GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)sd, &od,
                                            &oldacl, &gd) || !od || !oldacl)
        return NULL;

    totalsz = sizeof(ACL);
    for (i = 0; i < oldacl->AceCount; i++) {
        LPVOID ace = NULL;
        PACE_HEADER h;
        if (!ADVAPI32$GetAce(oldacl, i, &ace) || !ace) continue;
        h = (PACE_HEADER)ace;
        if (h->AceSize < sizeof(ACE_HEADER)) continue;
        if (h->AceType == ACCESS_ALLOWED_ACE_TYPE ||
            h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
            unsigned int off = (h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE)
                               ? 28 : 8;
            if (h->AceSize >= off + sidlen &&
                bof_memcmp((unsigned char *)ace + off, sid, sidlen) == 0)
                continue;
        }
        totalsz += h->AceSize;
        keep++;
    }

    aclmem = (unsigned char *)KERNEL32$VirtualAlloc(NULL, totalsz + 8,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!aclmem) return NULL;
    ((ACL *)aclmem)->AclRevision = ACL_REVISION;
    ((ACL *)aclmem)->Sbz1 = 0;
    ((ACL *)aclmem)->AclSize = (WORD)totalsz;
    ((ACL *)aclmem)->AceCount = (WORD)keep;
    ((ACL *)aclmem)->Sbz2 = 0;

    totalsz = sizeof(ACL);
    for (i = 0; i < oldacl->AceCount; i++) {
        LPVOID ace = NULL;
        PACE_HEADER h;
        unsigned int off;
        if (!ADVAPI32$GetAce(oldacl, i, &ace) || !ace) continue;
        h = (PACE_HEADER)ace;
        if (h->AceSize < sizeof(ACE_HEADER)) continue;
        off = 0xffffffff;
        if (h->AceType == ACCESS_ALLOWED_ACE_TYPE)
            off = 8;
        else if (h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE)
            off = 28;
        if (off != 0xffffffff && h->AceSize >= off + sidlen &&
            bof_memcmp((unsigned char *)ace + off, sid, sidlen) == 0)
            continue;
        bof_memcpy(aclmem + totalsz, ace, h->AceSize);
        totalsz += h->AceSize;
    }

    if (!ADVAPI32$InitializeSecurityDescriptor(&absd,
                                               SECURITY_DESCRIPTOR_REVISION)) {
        KERNEL32$VirtualFree(aclmem, 0, MEM_RELEASE);
        return NULL;
    }
    if (ADVAPI32$GetSecurityDescriptorOwner((PSECURITY_DESCRIPTOR)sd, &owner,
                                            &od) && owner)
        ADVAPI32$SetSecurityDescriptorOwner(&absd, owner, od);
    if (ADVAPI32$GetSecurityDescriptorGroup((PSECURITY_DESCRIPTOR)sd, &group,
                                            &gd) && group)
        ADVAPI32$SetSecurityDescriptorGroup(&absd, group, gd);
    ADVAPI32$SetSecurityDescriptorDacl(&absd, TRUE, (PACL)aclmem, FALSE);
    out = bof_sd_make_relative(&absd, outlen);
    KERNEL32$VirtualFree(aclmem, 0, MEM_RELEASE);
    return out;
}

#endif /* ADAPTIX_ADSD_H */
