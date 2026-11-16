/*
 * driversigs [filter] - kernel drivers with Authenticode signature status.
 *
 * Enumerates SERVICE_DRIVER entries, resolves each ImagePath to a file,
 * checks it with WinVerifyTrust and reports the signer name.  Useful to spot
 * unsigned or third-party drivers in a BYOVD review.  `filter` matches the
 * service name or image path as a case-sensitive substring.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int contains(const char *hay, const char *needle)
{
    return needle[0] ? (bof_strstr(hay, needle) != NULL) : 1;
}

static int starts_ci(const char *s, const char *pfx)
{
    while (*pfx) {
        char a = *s++, b = *pfx++;
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

static void resolve_image(const char *in, char *out, int outsz)
{
    char raw[1024];
    char *p;
    char *q;

    out[0] = 0;
    bof_strncpy(raw, in, sizeof(raw));
    bof_trim(raw);
    if (!raw[0]) return;

    p = raw;
    if (*p == '"') {
        p++;
        q = raw;
        while (*p && *p != '"') *q++ = *p++;
        *q = 0;
        p = raw;
    }

    if (bof_strncmp(p, "\\??\\", 4) == 0) p += 4;

    if (bof_strncmp(p, "\\SystemRoot\\", 12) == 0) {
        bof_strcpy(out, "C:\\Windows\\");
        bof_strncat(out, p + 12, outsz - bof_strlen(out) - 1);
    } else if (starts_ci(p, "System32\\")) {
        bof_strcpy(out, "C:\\Windows\\");
        bof_strncat(out, p, outsz - bof_strlen(out) - 1);
    } else if (p[0] != '\\' && p[0] != '%' && !bof_strstr(p, ":")) {
        bof_strcpy(out, "C:\\Windows\\");
        bof_strncat(out, p, outsz - bof_strlen(out) - 1);
    } else {
        bof_strncpy(out, p, outsz);
    }

    {
        char expanded[1024];
        DWORD n = KERNEL32$ExpandEnvironmentStringsA(out, expanded, sizeof(expanded));
        if (n > 0 && n <= sizeof(expanded))
            bof_strncpy(out, expanded, outsz);
    }
}

static const char *trust_name(LONG status)
{
    switch ((DWORD)status) {
    case 0:                            return "valid";
    case TRUST_E_NOSIGNATURE:          return "unsigned";
    case TRUST_E_EXPLICIT_DISTRUST:    return "distrusted";
    case TRUST_E_SUBJECT_NOT_TRUSTED:  return "not-trusted";
    case TRUST_E_BAD_DIGEST:           return "bad-digest";
    case CERT_E_UNTRUSTEDROOT:         return "untrusted-root";
    case CERT_E_CHAINING:              return "chaining";
    case CERT_E_EXPIRED:               return "expired";
    case CERT_E_REVOKED:               return "revoked";
    case CERT_E_WRONG_USAGE:           return "wrong-usage";
    case CRYPT_E_SECURITY_SETTINGS:    return "security-settings";
    }
    return NULL;
}

static void signer_name(const wchar_t *path, char *out, int outsz)
{
    HCERTSTORE store = NULL;
    HCRYPTMSG msg = NULL;
    DWORD enc = 0, content = 0, format = 0;

    out[0] = 0;
    if (!CRYPT32$CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0, &enc, &content, &format,
            &store, &msg, NULL))
        return;

    if (msg) {
        DWORD cb = 0;
        if (CRYPT32$CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb) && cb) {
            CMSG_SIGNER_INFO *si = (CMSG_SIGNER_INFO *)KERNEL32$VirtualAlloc(
                NULL, cb, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (si && CRYPT32$CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, si, &cb)) {
                CERT_INFO ci;
                PCCERT_CONTEXT cert;
                bof_memzero(&ci, sizeof(ci));
                ci.Issuer = si->Issuer;
                ci.SerialNumber = si->SerialNumber;
                cert = CRYPT32$CertFindCertificateInStore(store,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                        CERT_FIND_SUBJECT_CERT, &ci, NULL);
                if (cert) {
                    CRYPT32$CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                               0, NULL, out, outsz);
                    CRYPT32$CertFreeCertificateContext(cert);
                }
            }
            if (si) KERNEL32$VirtualFree(si, 0, MEM_RELEASE);
        }
        CRYPT32$CryptMsgClose(msg);
    }
    if (store) CRYPT32$CertCloseStore(store, 0);
}

static int verify_file(const char *path, char *publisher, int pubsz)
{
    wchar_t wpath[1024];
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fi;
    WINTRUST_DATA wd;
    LONG status;
    DWORD attr;

    publisher[0] = 0;
    attr = KERNEL32$GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return -1;

    bof_a2w(path, wpath, sizeof(wpath) / sizeof(wpath[0]));
    bof_memzero(&fi, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = wpath;

    bof_memzero(&wd, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    status = WINTRUST$WinVerifyTrust(NULL, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WINTRUST$WinVerifyTrust(NULL, &action, &wd);

    if (status == 0) signer_name(wpath, publisher, pubsz);
    return status;
}

void go(char *args, int alen)
{
    datap parser;
    char *filter = "";
    int flen = 0;
    SC_HANDLE scm;
    LPBYTE list = NULL;
    DWORD need = 0, returned = 0, resume = 0;
    BYTE *cfg = NULL;
    int scanned = 0, flagged = 0, missing = 0;

    BeaconDataParse(&parser, args, alen);
    filter = BeaconDataExtract(&parser, &flen);
    if (!filter) filter = "";

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                   SERVICE_STATE_ALL, NULL, 0, &need, &returned,
                                   &resume, NULL);
    if (!need) {
        BeaconPrintf(CALLBACK_ERROR, "driver enumeration failed\n");
        ADVAPI32$CloseServiceHandle(scm);
        return;
    }

    list = (LPBYTE)KERNEL32$VirtualAlloc(NULL, need, MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    cfg = (BYTE *)KERNEL32$VirtualAlloc(NULL, 16384, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!list || !cfg) goto done;

    BeaconPrintf(CALLBACK_OUTPUT, "  %-28s %-16s %-30s %s\n",
                 "Driver", "Signature", "Signer", "Image");

    resume = 0;
    do {
        DWORD i;
        returned = 0;
        if (!ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                            SERVICE_STATE_ALL, list, need, &need,
                                            &returned, &resume, NULL)) {
            if (KERNEL32$GetLastError() != ERROR_MORE_DATA) break;
        }
        {
            ENUM_SERVICE_STATUS_PROCESSA *svc = (ENUM_SERVICE_STATUS_PROCESSA *)list;
            for (i = 0; i < returned; i++) {
                SC_HANDLE sh;
                DWORD cfgneed = 0;
                QUERY_SERVICE_CONFIGA *qcfg = (QUERY_SERVICE_CONFIGA *)cfg;
                char path[1024];
                char pub[256];
                const char *state;
                LONG status;

                path[0] = 0;
                sh = ADVAPI32$OpenServiceA(scm, svc[i].lpServiceName,
                                           SERVICE_QUERY_CONFIG);
                if (sh) {
                    bof_memzero(cfg, 16384);
                    if (ADVAPI32$QueryServiceConfigA(sh, qcfg, 16384, &cfgneed) &&
                        qcfg->lpBinaryPathName)
                        resolve_image(qcfg->lpBinaryPathName, path, sizeof(path));
                    ADVAPI32$CloseServiceHandle(sh);
                }

                if (!contains(svc[i].lpServiceName, filter) && !contains(path, filter))
                    continue;
                scanned++;

                if (!path[0]) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  %-28s %-16s %-30s %s\n",
                                 svc[i].lpServiceName, "no-image", "-", "-");
                    missing++;
                    continue;
                }

                status = verify_file(path, pub, sizeof(pub));
                if (status == -1) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  %-28s %-16s %-30s %s\n",
                                 svc[i].lpServiceName, "missing", "-", path);
                    missing++;
                    continue;
                }

                state = trust_name(status);
                if (!state) {
                    char hex[16];
                    bof_hex((unsigned long)status, 8, hex);
                    BeaconPrintf(CALLBACK_OUTPUT, "  %-28s 0x%-14s %-30s %s\n",
                                 svc[i].lpServiceName, hex,
                                 pub[0] ? pub : "-", path);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "  %-28s %-16s %-30.30s %s\n",
                                 svc[i].lpServiceName, state,
                                 pub[0] ? pub : "-", path);
                }
                if (status != 0) flagged++;
            }
        }
    } while (returned > 0 && resume != 0);

    BeaconPrintf(CALLBACK_OUTPUT,
                 "\nScanned: %d driver(s), unsigned/untrusted: %d, missing: %d\n",
                 scanned, flagged, missing);

done:
    if (cfg) KERNEL32$VirtualFree(cfg, 0, MEM_RELEASE);
    if (list) KERNEL32$VirtualFree(list, 0, MEM_RELEASE);
    ADVAPI32$CloseServiceHandle(scm);
}
