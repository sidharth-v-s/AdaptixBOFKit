/*
 * regsession - logged-on user SIDs from HKEY_USERS (BOFHound friendly).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    HKEY h;
    DWORD index;
    LONG rc;

    (void)args; (void)alen;

    rc = ADVAPI32$RegOpenKeyExA(HKEY_USERS, "", 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &h);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "HKEY_USERS open failed: %ld\n", (long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Loaded user hives\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-48s %s\n", "SID", "Account");

    for (index = 0; ; index++) {
        char sid[256];
        DWORD len = sizeof(sid);
        PSID psid = NULL;
        char user[128] = "-", domain[128] = "-";
        DWORD ulen = sizeof(user), dlen = sizeof(domain);
        SID_NAME_USE use;

        rc = ADVAPI32$RegEnumKeyExA(h, index, sid, &len, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;

        if (ADVAPI32$ConvertStringSidToSidA(sid, &psid) && psid) {
            if (!ADVAPI32$LookupAccountSidA(NULL, psid, user, &ulen,
                                            domain, &dlen, &use)) {
                bof_strcpy(user, "-");
                bof_strcpy(domain, "-");
            }
            KERNEL32$LocalFree(psid);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "  %-48s %s\\%s\n", sid, domain, user);
    }

    ADVAPI32$RegCloseKey(h);
}
