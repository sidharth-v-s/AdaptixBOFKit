/*
 * auditpol - dump advanced audit policy subcategory settings.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    GUID *subs = NULL;
    ULONG count = 0, i;
    int shown = 0;

    (void)args; (void)alen;

    if (!ADVAPI32$AuditEnumerateSubCategories(NULL, TRUE, &subs, &count)) {
        BeaconPrintf(CALLBACK_ERROR, "AuditEnumerateSubCategories failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Advanced audit policy (%lu subcategories)\n", (unsigned long)count);

    for (i = 0; i < count; i++) {
        PAUDIT_POLICY_INFORMATION pi = NULL;
        LPSTR name = NULL;
        const char *state;

        if (!ADVAPI32$AuditQuerySystemPolicy(&subs[i], 1, &pi) || !pi) continue;
        if (!ADVAPI32$AuditLookupSubCategoryNameA(&subs[i], &name) || !name) {
            ADVAPI32$AuditFree(pi);
            continue;
        }

        if (pi->AuditingInformation == 3)      state = "Success+Failure";
        else if (pi->AuditingInformation == 1) state = "Success";
        else if (pi->AuditingInformation == 2) state = "Failure";
        else                                   state = "None";

        BeaconPrintf(CALLBACK_OUTPUT, "  %-56s %s\n", name, state);
        ADVAPI32$AuditFree(name);
        ADVAPI32$AuditFree(pi);
        shown++;
    }

    ADVAPI32$AuditFree(subs);
    BeaconPrintf(CALLBACK_OUTPUT, "\nConfigured entries shown: %d\n", shown);
}
