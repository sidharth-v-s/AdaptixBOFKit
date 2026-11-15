/*
 * uacstatus - inspect UAC related registry configuration.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void read_dword(HKEY root, const char *key, const char *value, const char *label)
{
    HKEY h;
    DWORD data = 0, size = sizeof(data), type = 0;
    if (ADVAPI32$RegOpenKeyExA(root, key, 0, KEY_READ, &h) == ERROR_SUCCESS) {
        if (ADVAPI32$RegQueryValueExA(h, value, NULL, &type, (LPBYTE)&data, &size) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "  %-34s %lu\n", label, (unsigned long)data);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  %-34s <not set>\n", label);
        }
        ADVAPI32$RegCloseKey(h);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "  %-34s <key missing>\n", label);
    }
}

void go(char *args, int alen)
{
    const char *pol = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    (void)args; (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "UAC configuration\n");
    read_dword(HKEY_LOCAL_MACHINE, pol, "EnableLUA", "EnableLUA");
    read_dword(HKEY_LOCAL_MACHINE, pol, "ConsentPromptBehaviorAdmin", "ConsentPromptBehaviorAdmin");
    read_dword(HKEY_LOCAL_MACHINE, pol, "ConsentPromptBehaviorUser", "ConsentPromptBehaviorUser");
    read_dword(HKEY_LOCAL_MACHINE, pol, "PromptOnSecureDesktop", "PromptOnSecureDesktop");
    read_dword(HKEY_LOCAL_MACHINE, pol, "EnableInstallerDetection", "EnableInstallerDetection");
    read_dword(HKEY_LOCAL_MACHINE, pol, "EnableVirtualization", "EnableVirtualization");
    read_dword(HKEY_LOCAL_MACHINE, pol, "LocalAccountTokenFilterPolicy", "LocalAccountTokenFilterPolicy");

    BeaconPrintf(CALLBACK_OUTPUT, "\nInterpretation:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  ConsentPromptBehaviorAdmin 0 = elevate without prompting\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  ConsentPromptBehaviorAdmin 1 = prompt for credentials on secure desktop\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  ConsentPromptBehaviorAdmin 5 = prompt for consent for non-Windows binaries\n");
}
