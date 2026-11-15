/*
 * netuser <user> [domain]
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_time(DWORD unix_seconds, const char *label)
{
    ULARGE_INTEGER u;
    FILETIME ft;
    SYSTEMTIME st;
    if (unix_seconds == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %-18s never\n", label);
        return;
    }
    u.QuadPart = ((unsigned long long)unix_seconds + 11644473600ULL) * 10000000ULL;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    if (KERNEL32$FileTimeToSystemTime(&ft, &st))
        BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %04u-%02u-%02u %02u:%02u:%02u UTC\n", label,
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

void go(char *args, int alen)
{
    datap parser;
    char *user, *domain = "";
    int ulen = 0, dlen = 0;
    wchar_t wuser[256], wdomain[256];
    LPCWSTR server = NULL;
    PUSER_INFO_3 ui = NULL;
    NET_API_STATUS st;
    const char *priv = "?";

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: netuser <user> [domain]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    user = BeaconDataExtract(&parser, &ulen);
    domain = BeaconDataExtract(&parser, &dlen);
    if (!domain) domain = "";

    bof_a2w(user, wuser, 256);
    if (domain[0]) {
        bof_a2w(domain, wdomain, 256);
        server = wdomain;
    }

    st = NETAPI32$NetUserGetInfo(server, wuser, 3, (LPBYTE *)&ui);
    if (st != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "NetUserGetInfo failed for %s: %lu\n", user, (unsigned long)st);
        return;
    }

    if (ui->usri3_priv == USER_PRIV_GUEST) priv = "guest";
    else if (ui->usri3_priv == USER_PRIV_USER) priv = "user";
    else if (ui->usri3_priv == USER_PRIV_ADMIN) priv = "admin";

    BeaconPrintf(CALLBACK_OUTPUT, "User: %s\n", user);
    if (ui->usri3_full_name && ui->usri3_full_name[0]) {
        char tmp[256];
        bof_w2a(ui->usri3_full_name, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Full name", tmp);
    }
    if (ui->usri3_comment && ui->usri3_comment[0]) {
        char tmp[512];
        bof_w2a(ui->usri3_comment, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Comment", tmp);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Privilege", priv);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Disabled",
                 (ui->usri3_flags & UF_ACCOUNTDISABLE) ? "yes" : "no");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Locked out",
                 (ui->usri3_flags & UF_LOCKOUT) ? "yes" : "no");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Password never expires",
                 (ui->usri3_flags & UF_DONT_EXPIRE_PASSWD) ? "yes" : "no");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %lu\n", "User ID", (unsigned long)ui->usri3_user_id);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %lu\n", "Primary group", (unsigned long)ui->usri3_primary_group_id);

    if (ui->usri3_home_dir && ui->usri3_home_dir[0]) {
        char tmp[512];
        bof_w2a(ui->usri3_home_dir, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Home directory", tmp);
    }
    if (ui->usri3_script_path && ui->usri3_script_path[0]) {
        char tmp[512];
        bof_w2a(ui->usri3_script_path, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Logon script", tmp);
    }
    if (ui->usri3_profile && ui->usri3_profile[0]) {
        char tmp[512];
        bof_w2a(ui->usri3_profile, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", "Profile", tmp);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %lu\n", "Logons", (unsigned long)ui->usri3_num_logons);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %lu\n", "Bad passwords", (unsigned long)ui->usri3_bad_pw_count);
    print_time(ui->usri3_last_logon, "Last logon");

    NETAPI32$NetApiBufferFree(ui);
}
