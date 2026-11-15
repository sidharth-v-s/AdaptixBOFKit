/*
 * whoami - user, SID, group and privilege enumeration.
 *
 * Adaptix: execute bof whoami.x64.o
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_sid(PSID sid)
{
    LPSTR s = NULL;
    if (sid && ADVAPI32$ConvertSidToStringSidA(sid, &s)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  SID : %s\n", s);
        KERNEL32$LocalFree(s);
    }
}

static void print_account(PSID sid)
{
    char name[256];
    char domain[256];
    DWORD n = sizeof(name), dn = sizeof(domain);
    SID_NAME_USE use;
    if (sid && ADVAPI32$LookupAccountSidA(NULL, sid, name, &n, domain, &dn, &use)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  Name: %s\\%s\n", domain, name);
    }
}

void go(char *args, int alen)
{
    char user[256];
    ULONG ulen = sizeof(user);
    HANDLE token = NULL;
    DWORD size = 0;
    int i;

    (void)args; (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "================ whoami ================\n");

    if (SECUR32$GetUserNameExA(NameSamCompatible, user, &ulen))
        BeaconPrintf(CALLBACK_OUTPUT, "User      : %s\n", user);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "User      : <unknown>\n");

    BeaconPrintf(CALLBACK_OUTPUT, "PID       : %lu\n", (unsigned long)KERNEL32$GetCurrentProcessId());

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    /* user SID */
    ADVAPI32$GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (size) {
        TOKEN_USER *tu = (TOKEN_USER *)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (tu && ADVAPI32$GetTokenInformation(token, TokenUser, tu, size, &size)) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[User]\n");
            print_account(tu->User.Sid);
            print_sid(tu->User.Sid);
        }
        if (tu) KERNEL32$VirtualFree(tu, 0, MEM_RELEASE);
    }

    /* elevation */
    size = 0;
    ADVAPI32$GetTokenInformation(token, TokenElevation, NULL, 0, &size);
    if (size) {
        TOKEN_ELEVATION *te = (TOKEN_ELEVATION *)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (te && ADVAPI32$GetTokenInformation(token, TokenElevation, te, size, &size))
            BeaconPrintf(CALLBACK_OUTPUT, "Elevated  : %s\n", te->TokenIsElevated ? "yes" : "no");
        if (te) KERNEL32$VirtualFree(te, 0, MEM_RELEASE);
    }

    /* groups */
    size = 0;
    ADVAPI32$GetTokenInformation(token, TokenGroups, NULL, 0, &size);
    if (size) {
        TOKEN_GROUPS *tg = (TOKEN_GROUPS *)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (tg && ADVAPI32$GetTokenInformation(token, TokenGroups, tg, size, &size)) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[Groups] (%lu)\n", (unsigned long)tg->GroupCount);
            for (i = 0; i < (int)tg->GroupCount; i++) {
                char name[256], domain[256];
                DWORD n = sizeof(name), dn = sizeof(domain);
                SID_NAME_USE use;
                LPSTR sidstr = NULL;
                const char *attrs = (tg->Groups[i].Attributes & SE_GROUP_ENABLED) ? "enabled" : "disabled";

                if (ADVAPI32$ConvertSidToStringSidA(tg->Groups[i].Sid, &sidstr)) {
                    if (ADVAPI32$LookupAccountSidA(NULL, tg->Groups[i].Sid, name, &n, domain, &dn, &use))
                        BeaconPrintf(CALLBACK_OUTPUT, "  %s\\%s [%s] %s\n", domain, name, attrs, sidstr);
                    else
                        BeaconPrintf(CALLBACK_OUTPUT, "  %s [%s]\n", sidstr, attrs);
                    KERNEL32$LocalFree(sidstr);
                }
            }
        }
        if (tg) KERNEL32$VirtualFree(tg, 0, MEM_RELEASE);
    }

    /* privileges */
    size = 0;
    ADVAPI32$GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
    if (size) {
        TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (tp && ADVAPI32$GetTokenInformation(token, TokenPrivileges, tp, size, &size)) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n[Privileges] (%lu)\n", (unsigned long)tp->PrivilegeCount);
            for (i = 0; i < (int)tp->PrivilegeCount; i++) {
                char pname[128];
                DWORD pn = sizeof(pname);
                if (ADVAPI32$LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, pname, &pn)) {
                    const char *state =
                        (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "enabled" :
                        (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) ? "default" : "disabled";
                    BeaconPrintf(CALLBACK_OUTPUT, "  %-32s %s\n", pname, state);
                }
            }
        }
        if (tp) KERNEL32$VirtualFree(tp, 0, MEM_RELEASE);
    }

    KERNEL32$CloseHandle(token);
}
