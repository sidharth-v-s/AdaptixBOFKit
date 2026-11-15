/*
 * drives - list logical drives, types and free space.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    DWORD mask = KERNEL32$GetLogicalDrives();
    int i;
    (void)args; (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "  %-6s %-14s %-14s %-14s\n", "Drive", "Type", "Total", "Free");
    BeaconPrintf(CALLBACK_OUTPUT, "  ------ -------------- -------------- --------------\n");

    for (i = 0; i < 26; i++) {
        char root[4];
        UINT type;
        const char *tname;
        ULARGE_INTEGER avail, total, freeb;

        if (!(mask & (1u << i))) continue;

        root[0] = (char)('A' + i);
        root[1] = ':';
        root[2] = '\\';
        root[3] = 0;

        type = KERNEL32$GetDriveTypeA(root);
        switch (type) {
        case DRIVE_REMOVABLE: tname = "removable"; break;
        case DRIVE_FIXED:     tname = "fixed"; break;
        case DRIVE_REMOTE:    tname = "network"; break;
        case DRIVE_CDROM:     tname = "cdrom"; break;
        case DRIVE_RAMDISK:   tname = "ramdisk"; break;
        default:              tname = "unknown"; break;
        }

        avail.QuadPart = total.QuadPart = freeb.QuadPart = 0;
        KERNEL32$GetDiskFreeSpaceExA(root, &avail, &total, &freeb);

        BeaconPrintf(CALLBACK_OUTPUT, "  %-6s %-14s %-14llu %-14llu\n",
                     root, tname,
                     total.QuadPart / (1024ULL * 1024ULL),
                     freeb.QuadPart / (1024ULL * 1024ULL));
    }
}
