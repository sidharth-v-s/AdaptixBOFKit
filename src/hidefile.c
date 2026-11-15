/*
 * hidefile <path> - mark a file or directory hidden + system.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *path;
    int len = 0;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: hidefile <path>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    path = BeaconDataExtract(&parser, &len);
    if (!path) return;

    if (KERNEL32$SetFileAttributesA(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
        BeaconPrintf(CALLBACK_OUTPUT, "Hidden: %s\n", path);
    else
        BeaconPrintf(CALLBACK_ERROR, "SetFileAttributes failed for %s: %lu\n",
                     path, (unsigned long)KERNEL32$GetLastError());
}
