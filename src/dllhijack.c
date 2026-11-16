/*
 * dllhijack [services|appinit|all]
 *
 * Find service DLL/binary search-order hijack candidates:
 *   services - unquoted service ImagePaths and service directories that the
 *              current user can write to
 *   appinit  - AppInit_DLLs / AppCertDlls entries and their directory rights
 *
 * Writability is tested by creating a temporary file in the directory, so
 * results are real checks rather than ACL guesses.  This is a triage tool:
 * a writable directory is a candidate, not proof of exploitability.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int dir_writable(const char *dir)
{
    char test[1024];
    HANDLE h;

    if (!dir[0]) return 0;
    bof_strncpy(test, dir, sizeof(test));
    bof_trim(test);
    {
        int n = bof_strlen(test);
        while (n > 0 && (test[n - 1] == '\\' || test[n - 1] == '/')) test[--n] = 0;
    }
    if (!test[0]) return 0;

    bof_strncat(test, "\\__bofwtest.tmp", sizeof(test) - bof_strlen(test) - 1);
    h = KERNEL32$CreateFileA(test, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                             NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    KERNEL32$CloseHandle(h);
    return 1;
}

static int split_dir(const char *path, char *dir, int dirsz)
{
    char tmp[1024];
    int n;

    bof_strncpy(tmp, path, sizeof(tmp));
    bof_trim(tmp);
    n = bof_strlen(tmp);
    while (n > 0 && tmp[n - 1] != '\\' && tmp[n - 1] != '/') n--;
    if (n <= 0) { dir[0] = 0; return -1; }
    tmp[n] = 0;
    bof_strncpy(dir, tmp, dirsz);
    return 0;
}

static int has_space(const char *s)
{
    while (*s) { if (*s == ' ') return 1; s++; }
    return 0;
}

static int path_quoted(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return *s == '"';
}

static void expand(char *s, int sz)
{
    char tmp[1024];
    DWORD n = KERNEL32$ExpandEnvironmentStringsA(s, tmp, sizeof(tmp));
    if (n > 0 && n <= sizeof(tmp)) bof_strncpy(s, tmp, sz);
}

static int reg_sz(HKEY root, const char *sub, const char *val, char *out, int outsz)
{
    HKEY h;
    DWORD sz = outsz, type = 0;
    LONG rc;

    out[0] = 0;
    rc = ADVAPI32$RegOpenKeyExA(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &h);
    if (rc != ERROR_SUCCESS) return -1;
    rc = ADVAPI32$RegQueryValueExA(h, val, NULL, &type, (LPBYTE)out, &sz);
    ADVAPI32$RegCloseKey(h);
    if (rc != ERROR_SUCCESS) { out[0] = 0; return -1; }
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        if (sz) out[sz - 1] = 0;
    } else {
        out[0] = 0;
        return -1;
    }
    return 0;
}

static DWORD reg_dword(HKEY root, const char *sub, const char *val, DWORD def)
{
    HKEY h;
    DWORD data = def, sz = sizeof(data), type = 0;
    LONG rc = ADVAPI32$RegOpenKeyExA(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &h);
    if (rc != ERROR_SUCCESS) return def;
    rc = ADVAPI32$RegQueryValueExA(h, val, NULL, &type, (LPBYTE)&data, &sz);
    ADVAPI32$RegCloseKey(h);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return def;
    return data;
}

static int scan_services(void)
{
    SC_HANDLE scm;
    LPBYTE list = NULL, cfg = NULL;
    DWORD need = 0, returned = 0, resume = 0;
    int findings = 0, scanned = 0;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return 0;
    }

    ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                   SERVICE_STATE_ALL, NULL, 0, &need, &returned,
                                   &resume, NULL);
    if (!need) goto done;

    list = (LPBYTE)KERNEL32$VirtualAlloc(NULL, need, MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    cfg = (BYTE *)KERNEL32$VirtualAlloc(NULL, 16384, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!list || !cfg) goto done;

    resume = 0;
    do {
        DWORD i;
        returned = 0;
        if (!ADVAPI32$EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                            SERVICE_STATE_ALL, list, need, &need,
                                            &returned, &resume, NULL)) {
            if (KERNEL32$GetLastError() != ERROR_MORE_DATA) break;
        }
        {
            ENUM_SERVICE_STATUS_PROCESSA *svc = (ENUM_SERVICE_STATUS_PROCESSA *)list;
            for (i = 0; i < returned; i++) {
                SC_HANDLE sh;
                QUERY_SERVICE_CONFIGA *qcfg = (QUERY_SERVICE_CONFIGA *)cfg;
                DWORD cfgneed = 0;
                char path[1024], dir[1024];
                int unquoted = 0;

                sh = ADVAPI32$OpenServiceA(scm, svc[i].lpServiceName,
                                           SERVICE_QUERY_CONFIG);
                if (!sh) continue;
                bof_memzero(cfg, 16384);
                if (!ADVAPI32$QueryServiceConfigA(sh, qcfg, 16384, &cfgneed) ||
                    !qcfg->lpBinaryPathName) {
                    ADVAPI32$CloseServiceHandle(sh);
                    continue;
                }
                bof_strncpy(path, qcfg->lpBinaryPathName, sizeof(path));
                ADVAPI32$CloseServiceHandle(sh);

                bof_trim(path);
                if (!path[0]) continue;
                expand(path, sizeof(path));
                scanned++;

                if (!path_quoted(path) && has_space(path)) unquoted = 1;
                if (split_dir(path, dir, sizeof(dir)) != 0) dir[0] = 0;

                if (unquoted) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[UNQUOTED] %s\n  %s\n",
                                 svc[i].lpServiceName, path);
                    findings++;
                }
                if (dir[0] && dir_writable(dir)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE] %s\n  %s\n",
                                 svc[i].lpServiceName, dir);
                    findings++;
                }
            }
        }
    } while (returned > 0 && resume != 0);

done:
    if (cfg) KERNEL32$VirtualFree(cfg, 0, MEM_RELEASE);
    if (list) KERNEL32$VirtualFree(list, 0, MEM_RELEASE);
    ADVAPI32$CloseServiceHandle(scm);
    BeaconPrintf(CALLBACK_OUTPUT, "\nScanned %d service path(s), %d finding(s)\n",
                 scanned, findings);
    return findings;
}

static int scan_appinit(void)
{
    const char *win = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    const char *sm = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";
    char appinit[1024], dir[1024];
    DWORD loadappinit, safesearch;
    int findings = 0;

    loadappinit = reg_dword(HKEY_LOCAL_MACHINE, win, "LoadAppInit_DLLs", 0);
    safesearch = reg_dword(HKEY_LOCAL_MACHINE, sm, "SafeDllSearchMode", 1);
    reg_sz(HKEY_LOCAL_MACHINE, win, "AppInit_DLLs", appinit, sizeof(appinit));

    BeaconPrintf(CALLBACK_OUTPUT, "SafeDllSearchMode : %lu\n",
                 (unsigned long)safesearch);
    BeaconPrintf(CALLBACK_OUTPUT, "LoadAppInit_DLLs  : %lu\n",
                 (unsigned long)loadappinit);
    BeaconPrintf(CALLBACK_OUTPUT, "AppInit_DLLs      : %s\n",
                 appinit[0] ? appinit : "(none)");

    if (appinit[0]) {
        const char *p = appinit;
        while (*p && findings < 20) {
            char item[1024];
            int n = 0;
            while (*p == ' ' || *p == ',' || *p == ';') p++;
            while (*p && *p != ' ' && *p != ',' && *p != ';' && n < (int)sizeof(item) - 1)
                item[n++] = *p++;
            item[n] = 0;
            if (!n) continue;
            expand(item, sizeof(item));
            if (split_dir(item, dir, sizeof(dir)) == 0 && dir_writable(dir)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE] AppInit dir\n  %s\n", dir);
                findings++;
            }
        }
    }

    {
        HKEY h;
        LONG rc = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
                    0, KEY_READ | KEY_WOW64_64KEY, &h);
        if (rc == ERROR_SUCCESS) {
            DWORD idx;
            BeaconPrintf(CALLBACK_OUTPUT, "\nAppCertDlls:\n");
            for (idx = 0; idx < 32; idx++) {
                char name[256], value[1024];
                DWORD nsz = sizeof(name), vsz = sizeof(value), type = 0;
                rc = ADVAPI32$RegEnumValueA(h, idx, name, &nsz, NULL, &type,
                                            (LPBYTE)value, &vsz);
                if (rc == ERROR_NO_MORE_ITEMS) break;
                if (rc != ERROR_SUCCESS) continue;
                if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
                value[sizeof(value) - 1] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, "  %s = %s\n", name, value);
                expand(value, sizeof(value));
                if (split_dir(value, dir, sizeof(dir)) == 0 && dir_writable(dir)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  [WRITABLE] %s\n", dir);
                    findings++;
                }
            }
            KERNEL32$CloseHandle(h);
        }
    }

    return findings;
}

void go(char *args, int alen)
{
    datap parser;
    char *mode = "";
    int mlen = 0;
    int do_svc, do_app;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, &mlen);
    if (!mode) mode = "";

    do_svc = (!mode[0] || bof_stricmp(mode, "services") == 0 ||
              bof_stricmp(mode, "all") == 0);
    do_app = (bof_stricmp(mode, "appinit") == 0 || bof_stricmp(mode, "all") == 0);
    if (!do_svc && !do_app) {
        BeaconPrintf(CALLBACK_ERROR, "usage: dllhijack [services|appinit|all]\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "================ dllhijack ================\n");
    if (do_svc) scan_services();
    if (do_app) scan_appinit();
}
