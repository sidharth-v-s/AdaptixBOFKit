/*
 * tokenpriv [privilege] - list token privileges or enable a named privilege.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void list_privileges(HANDLE token)
{
    DWORD size = 0, i;
    TOKEN_PRIVILEGES *tp;

    ADVAPI32$GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
    if (!size) return;

    tp = (TOKEN_PRIVILEGES *)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!tp) return;

    if (ADVAPI32$GetTokenInformation(token, TokenPrivileges, tp, size, &size)) {
        for (i = 0; i < tp->PrivilegeCount; i++) {
            char name[128];
            DWORD n = sizeof(name);
            if (ADVAPI32$LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, name, &n)) {
                BeaconPrintf(CALLBACK_OUTPUT, "  %-36s %s\n", name,
                             (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "enabled" : "disabled");
            }
        }
    }

    KERNEL32$VirtualFree(tp, 0, MEM_RELEASE);
}

void go(char *args, int alen)
{
    datap parser;
    char *priv = "";
    int plen = 0;
    HANDLE token = NULL;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        priv = BeaconDataExtract(&parser, &plen);
        if (!priv) priv = "";
    }

    if (!priv[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "Token privileges:\n");
        list_privileges(token);
    } else {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (!ADVAPI32$LookupPrivilegeValueA(NULL, priv, &luid)) {
            BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue failed for %s: %lu\n",
                         priv, (unsigned long)KERNEL32$GetLastError());
        } else {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (ADVAPI32$AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
                if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED)
                    BeaconPrintf(CALLBACK_ERROR, "%s is not held by this token\n", priv);
                else
                    BeaconPrintf(CALLBACK_OUTPUT, "Enabled privilege: %s\n", priv);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges failed: %lu\n",
                             (unsigned long)KERNEL32$GetLastError());
            }
        }
    }

    KERNEL32$CloseHandle(token);
}
