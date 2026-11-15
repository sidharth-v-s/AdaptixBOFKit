/*
 * adcs_enum [all|templates|services|ca]
 *
 * Enumerate ADCS without COM:
 *   ca        - local Certification Authority configuration (CertSvc registry)
 *   templates - certificate templates from the Configuration NC
 *   services  - enrollment services (CAs published in AD)
 *
 * Template output flags likely ESC1 conditions (enrollee supplies subject,
 * no manager approval, no RA signatures, client-auth EKU).  This is a
 * heuristic for triage; confirm with certipy/ESC techniques before use.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "ldaphelpers.h"

static DWORD ldap_dword(LDAP *ld, LDAPMessage *e, const char *attr, DWORD def)
{
    char buf[32];
    if (bof_ldap_get_str(ld, e, attr, buf, sizeof(buf)) != 0)
        return def;
    return (DWORD)bof_atoi(buf);
}

static int eku_has_client_auth(LDAP *ld, LDAPMessage *e, int *count)
{
    struct berval **vals = WLDAP32$ldap_get_values_lenA(ld, e, "pKIExtendedKeyUsage");
    int has = 0;
    ULONG i;

    *count = 0;
    if (!vals) return 0;
    for (i = 0; vals[i]; i++) {
        (*count)++;
        if (vals[i]->bv_len >= 19 &&
            bof_strncmp(vals[i]->bv_val, "1.3.6.1.5.5.7.3.2", 19) == 0)
            has = 1;
        if (vals[i]->bv_len >= 11 &&
            bof_strncmp(vals[i]->bv_val, "2.5.29.37.0", 11) == 0)
            has = 1;
    }
    WLDAP32$ldap_value_free_len(vals);
    return has;
}

static void enum_templates(LDAP *ld, const char *config)
{
    char base[1024];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    PCHAR attrs[8];
    ULONG rc;
    int count = 0;

    bof_strcpy(base, "CN=Certificate Templates,CN=Public Key Services,CN=Services,");
    bof_strncat(base, config, sizeof(base) - bof_strlen(base) - 1);
    attrs[0] = "cn";
    attrs[1] = "displayName";
    attrs[2] = "msPKI-Certificate-Name-Flag";
    attrs[3] = "msPKI-Enrollment-Flag";
    attrs[4] = "msPKI-RA-Signature";
    attrs[5] = "msPKI-Template-Schema-Version";
    attrs[6] = "pKIExtendedKeyUsage";
    attrs[7] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE,
                                    "(objectClass=pKICertificateTemplate)",
                                    attrs, 0, NULL, NULL, NULL, 500, &res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "template search failed: %lu (%s)\n",
                     (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Certificate templates\n");
    for (e = WLDAP32$ldap_first_entry(ld, res); e;
         e = WLDAP32$ldap_next_entry(ld, e)) {
        char cn[256], disp[256];
        DWORD nameflag, enrollflag, rasig, schema;
        int ekus = 0, client = 0;
        int esc1;

        if (bof_ldap_get_str(ld, e, "cn", cn, sizeof(cn)) != 0) continue;
        if (bof_ldap_get_str(ld, e, "displayName", disp, sizeof(disp)) != 0)
            disp[0] = 0;

        nameflag   = ldap_dword(ld, e, "msPKI-Certificate-Name-Flag", 0);
        enrollflag = ldap_dword(ld, e, "msPKI-Enrollment-Flag", 0);
        rasig      = ldap_dword(ld, e, "msPKI-RA-Signature", 0);
        schema     = ldap_dword(ld, e, "msPKI-Template-Schema-Version", 1);
        client     = eku_has_client_auth(ld, e, &ekus);

        esc1 = (schema >= 2) && (nameflag & 0x00000001) && rasig == 0 &&
               !(enrollflag & 0x00000002) && (client || ekus == 0);

        BeaconPrintf(CALLBACK_OUTPUT, "  %-40s schema=%lu\n", cn,
                     (unsigned long)schema);
        if (disp[0] && bof_strcmp(disp, cn) != 0)
            BeaconPrintf(CALLBACK_OUTPUT, "    displayName       : %s\n", disp);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "    nameFlags=0x%08lx enrollFlags=0x%08lx raSigs=%lu eku=%d%s\n",
                     (unsigned long)nameflag, (unsigned long)enrollflag,
                     (unsigned long)rasig, ekus,
                     client ? " (client-auth)" : (ekus ? "" : " (any)"));
        if (esc1)
            BeaconPrintf(CALLBACK_OUTPUT,
                         "    [ESC1 candidate: enrollee supplies subject]\n");
        count++;
    }

    WLDAP32$ldap_msgfree(res);
    BeaconPrintf(CALLBACK_OUTPUT, "  %d template(s)\n\n", count);
}

static void enum_services(LDAP *ld, const char *config)
{
    char base[1024];
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    PCHAR attrs[4];
    ULONG rc;
    int count = 0;

    bof_strcpy(base, "CN=Enrollment Services,CN=Public Key Services,CN=Services,");
    bof_strncat(base, config, sizeof(base) - bof_strlen(base) - 1);
    attrs[0] = "cn";
    attrs[1] = "dNSHostName";
    attrs[2] = "certificateTemplates";
    attrs[3] = NULL;

    rc = WLDAP32$ldap_search_ext_sA(ld, base, LDAP_SCOPE_SUBTREE,
                                    "(objectClass=pKIEnrollmentService)",
                                    attrs, 0, NULL, NULL, NULL, 100, &res);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "enrollment service search failed: %lu (%s)\n",
                     (unsigned long)rc, WLDAP32$ldap_err2stringA(rc));
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Enrollment services\n");
    for (e = WLDAP32$ldap_first_entry(ld, res); e;
         e = WLDAP32$ldap_next_entry(ld, e)) {
        char cn[256], host[256];
        struct berval **vals;
        ULONG i;

        if (bof_ldap_get_str(ld, e, "cn", cn, sizeof(cn)) != 0) continue;
        if (bof_ldap_get_str(ld, e, "dNSHostName", host, sizeof(host)) != 0)
            host[0] = 0;

        BeaconPrintf(CALLBACK_OUTPUT, "  %s  host=%s\n", cn,
                     host[0] ? host : "-");
        vals = WLDAP32$ldap_get_values_lenA(ld, e, "certificateTemplates");
        if (vals) {
            BeaconPrintf(CALLBACK_OUTPUT, "    templates:");
            for (i = 0; vals[i]; i++) {
                char tpl[128];
                ULONG n = vals[i]->bv_len < sizeof(tpl) - 1
                              ? vals[i]->bv_len : sizeof(tpl) - 1;
                bof_memcpy(tpl, vals[i]->bv_val, n);
                tpl[n] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, " %s", tpl);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
            WLDAP32$ldap_value_free_len(vals);
        }
        count++;
    }

    WLDAP32$ldap_msgfree(res);
    BeaconPrintf(CALLBACK_OUTPUT, "  %d service(s)\n\n", count);
}

static void enum_ca_registry(void)
{
    HKEY root;
    DWORD index;
    int count = 0;

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration",
            0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | 0x0100, &root)
            != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Local CA: not configured\n\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Local Certification Authorities\n");
    for (index = 0; ; index++) {
        char name[256], common[256], server[256];
        DWORD glen = sizeof(name), active = 0, size, type;
        HKEY sub;

        if (ADVAPI32$RegEnumKeyExA(root, index, name, &glen, NULL, NULL,
                                   NULL, NULL) != ERROR_SUCCESS)
            break;
        if (ADVAPI32$RegOpenKeyExA(root, name, 0, KEY_READ, &sub)
                != ERROR_SUCCESS)
            continue;

        common[0] = server[0] = 0;
        size = sizeof(common);
        ADVAPI32$RegQueryValueExA(sub, "CACommonName", NULL, &type,
                                  (LPBYTE)common, &size);
        size = sizeof(server);
        ADVAPI32$RegQueryValueExA(sub, "CAServerName", NULL, &type,
                                  (LPBYTE)server, &size);
        size = sizeof(active);
        ADVAPI32$RegQueryValueExA(sub, "Active", NULL, &type,
                                  (LPBYTE)&active, &size);

        BeaconPrintf(CALLBACK_OUTPUT, "  %-24s common=%s server=%s active=%lu\n",
                     name, common[0] ? common : "-",
                     server[0] ? server : "-", (unsigned long)active);
        ADVAPI32$RegCloseKey(sub);
        count++;
    }
    ADVAPI32$RegCloseKey(root);
    BeaconPrintf(CALLBACK_OUTPUT, "  %d CA(s)\n\n", count);
}

void go(char *args, int alen)
{
    datap parser;
    char *op = "", opbuf[32];
    int len;
    int want_templates = 1, want_services = 1, want_ca = 1;
    LDAP *ld;
    char config[1024];

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        op = BeaconDataExtract(&parser, &len);
        if (op) bof_strncpy(opbuf, op, sizeof(opbuf)); else opbuf[0] = 0;
        op = opbuf;
    }

    if (op[0]) {
        want_templates = bof_stricmp(op, "templates") == 0;
        want_services  = bof_stricmp(op, "services") == 0 ||
                         bof_stricmp(op, "enrollment") == 0;
        want_ca        = bof_stricmp(op, "ca") == 0 ||
                         bof_stricmp(op, "local") == 0;
        if (bof_stricmp(op, "all") == 0)
            want_templates = want_services = want_ca = 1;
        if (!want_templates && !want_services && !want_ca) {
            BeaconPrintf(CALLBACK_ERROR,
                         "usage: adcs_enum [all|templates|services|ca]\n");
            return;
        }
    }

    if (want_ca) enum_ca_registry();

    if (want_templates || want_services) {
        ld = bof_ldap_open();
        if (!ld) {
            BeaconPrintf(CALLBACK_ERROR, "LDAP connect/bind failed\n");
            return;
        }
        if (bof_ldap_config_nc(ld, config, sizeof(config)) != 0) {
            BeaconPrintf(CALLBACK_ERROR, "could not read configurationNamingContext\n");
            WLDAP32$ldap_unbind(ld);
            return;
        }
        if (want_templates) enum_templates(ld, config);
        if (want_services)  enum_services(ld, config);
        WLDAP32$ldap_unbind(ld);
    }
}
