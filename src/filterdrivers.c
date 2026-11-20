/*
 * filterdrivers - list filesystem minifilter drivers.
 *
 * FilterFindFirst is the authoritative source, but it returns access-denied
 * for unprivileged callers on some builds.  In that case fall back to the
 * service registry (Type=2 FILE_SYSTEM_DRIVER with Group=FSFilter*), which is
 * readable by normal users and still lists every registered minifilter.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void registry_fallback(void)
{
    HKEY services = NULL;
    DWORD index = 0, count = 0, skipped = 0;
    char name[256];

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ,
            &services) != ERROR_SUCCESS) {
        bof_error_win32("RegOpenKeyEx(Services)",
                        KERNEL32$GetLastError(),
                        "registry fallback needs read access to HKLM\\SYSTEM");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-32s %-24s %-6s %s\n",
                 "Filter", "Group", "Start", "ImagePath");

    for (;;) {
        DWORD nlen = sizeof(name);
        LONG rc = ADVAPI32$RegEnumKeyExA(services, index++, name, &nlen,
                                         NULL, NULL, NULL, NULL);
        HKEY key = NULL;
        char path[512], group[128] = "", image[512] = "";
        DWORD type = 0, start = 0, size;

        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) {
            bof_error_win32("RegEnumKeyEx(Services)", (DWORD)rc,
                            "enumeration stopped early");
            bof_error_num("index", (unsigned long long)index - 1);
            break;
        }

        bof_strncpy(path, "SYSTEM\\CurrentControlSet\\Services\\", sizeof(path));
        bof_strncat(path, name, sizeof(path) - bof_strlen(path) - 1);

        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ,
                                   &key) != ERROR_SUCCESS) {
            skipped++;
            continue;
        }

        size = sizeof(type);
        if (ADVAPI32$RegQueryValueExA(key, "Type", NULL, NULL, (LPBYTE)&type,
                                      &size) != ERROR_SUCCESS ||
            type != SERVICE_FILE_SYSTEM_DRIVER) {
            ADVAPI32$RegCloseKey(key);
            continue;
        }

        size = sizeof(group);
        if (ADVAPI32$RegQueryValueExA(key, "Group", NULL, NULL, (LPBYTE)group,
                                      &size) != ERROR_SUCCESS) {
            ADVAPI32$RegCloseKey(key);
            continue;
        }
        if (bof_strncmp(group, "FSFilter", 8) != 0) {
            ADVAPI32$RegCloseKey(key);
            continue;
        }

        size = sizeof(start);
        ADVAPI32$RegQueryValueExA(key, "Start", NULL, NULL, (LPBYTE)&start,
                                  &size);
        size = sizeof(image);
        if (ADVAPI32$RegQueryValueExA(key, "ImagePath", NULL, NULL,
                                      (LPBYTE)image, &size) != ERROR_SUCCESS)
            image[0] = 0;

        BeaconPrintf(CALLBACK_OUTPUT, "  %-32s %-24s %-6lu %s\n",
                     name, group, (unsigned long)start,
                     image[0] ? image : "-");
        count++;
        ADVAPI32$RegCloseKey(key);
    }

    ADVAPI32$RegCloseKey(services);
    BeaconPrintf(CALLBACK_OUTPUT,
                 "\nTotal: %lu minifilter service(s) (registry)\n",
                 (unsigned long)count);
    if (skipped)
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] %lu service key(s) could not be opened\n",
                     (unsigned long)skipped);
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] registry mode lists registered filters, not live "
                 "instances/frame IDs\n");
}

void go(char *args, int alen)
{
    HANDLE find = NULL;
    DWORD got = 0, count = 0;
    BYTE buf[2048];
    HRESULT hr;

    (void)args; (void)alen;

    hr = FLTLIB$FilterFindFirst(FilterFullInformation, buf, sizeof(buf),
                                &got, &find);
    if (hr != S_OK) {
        DWORD err = KERNEL32$GetLastError();
        bof_error_hresult("FilterFindFirst", hr,
                          "Filter Manager access denied; using registry fallback");
        bof_error_num("last_err", (unsigned long long)err);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] using the service-registry fallback\n\n");
        registry_fallback();
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Filesystem minifilters\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-32s %-10s %s\n", "Filter", "Instances", "Frame");

    for (;;) {
        PFILTER_FULL_INFORMATION fi = (PFILTER_FULL_INFORMATION)buf;
        char name[512];
        int n = fi->FilterNameLength / sizeof(WCHAR);
        int i;
        if (n > 255) n = 255;
        for (i = 0; i < n; i++) name[i] = (char)fi->FilterNameBuffer[i];
        name[n] = 0;

        BeaconPrintf(CALLBACK_OUTPUT, "  %-32s %-10lu %lu\n",
                     name, (unsigned long)fi->NumberOfInstances, (unsigned long)fi->FrameID);
        count++;

        if (FLTLIB$FilterFindNext(find, FilterFullInformation, buf, sizeof(buf), &got) != S_OK)
            break;
    }

    FLTLIB$FilterFindClose(find);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %lu minifilter(s)\n", (unsigned long)count);
}
