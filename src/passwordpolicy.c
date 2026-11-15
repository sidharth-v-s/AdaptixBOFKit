/*
 * passwordpolicy [domain] - account and lockout policy.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *domain = "";
    int dlen = 0;
    wchar_t wdomain[256];
    LPCWSTR server = NULL;
    PUSER_MODALS_INFO_0 m0 = NULL;
    PUSER_MODALS_INFO_3 m3 = NULL;
    NET_API_STATUS st;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        domain = BeaconDataExtract(&parser, &dlen);
        if (!domain) domain = "";
    }
    if (domain[0]) {
        bof_a2w(domain, wdomain, 256);
        server = wdomain;
    }

    st = NETAPI32$NetUserModalsGet(server, 0, (LPBYTE *)&m0);
    if (st == NERR_Success && m0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Password policy for %s\n",
                     domain[0] ? domain : "local");
        BeaconPrintf(CALLBACK_OUTPUT, "  Minimum length      : %lu\n", (unsigned long)m0->usrmod0_min_passwd_len);
        BeaconPrintf(CALLBACK_OUTPUT, "  Maximum age (sec)   : %lu\n", (unsigned long)m0->usrmod0_max_passwd_age);
        BeaconPrintf(CALLBACK_OUTPUT, "  Minimum age (sec)   : %lu\n", (unsigned long)m0->usrmod0_min_passwd_age);
        BeaconPrintf(CALLBACK_OUTPUT, "  History length      : %lu\n", (unsigned long)m0->usrmod0_password_hist_len);
        NETAPI32$NetApiBufferFree(m0);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "NetUserModalsGet level 0 failed: %lu\n", (unsigned long)st);
    }

    st = NETAPI32$NetUserModalsGet(server, 3, (LPBYTE *)&m3);
    if (st == NERR_Success && m3) {
        BeaconPrintf(CALLBACK_OUTPUT, "\nLockout policy\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  Threshold           : %lu\n", (unsigned long)m3->usrmod3_lockout_threshold);
        BeaconPrintf(CALLBACK_OUTPUT, "  Duration (sec)      : %lu\n", (unsigned long)m3->usrmod3_lockout_duration);
        BeaconPrintf(CALLBACK_OUTPUT, "  Observation (sec)   : %lu\n", (unsigned long)m3->usrmod3_lockout_observation_window);
        NETAPI32$NetApiBufferFree(m3);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "NetUserModalsGet level 3 failed: %lu\n", (unsigned long)st);
    }
}
