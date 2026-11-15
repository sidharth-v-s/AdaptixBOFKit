/*
 * dir <path> [/s] - directory listing.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_attrs(DWORD a, char *out)
{
    out[0] = (a & FILE_ATTRIBUTE_DIRECTORY) ? 'D' : '-';
    out[1] = (a & FILE_ATTRIBUTE_HIDDEN) ? 'H' : '-';
    out[2] = (a & FILE_ATTRIBUTE_SYSTEM) ? 'S' : '-';
    out[3] = (a & FILE_ATTRIBUTE_READONLY) ? 'R' : '-';
    out[4] = (a & FILE_ATTRIBUTE_ARCHIVE) ? 'A' : '-';
    out[5] = 0;
}

static int list_dir(const char *path, int recursive, int depth)
{
    char pattern[1024];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    int count = 0;

    if (depth > 8) return 0;

    bof_strncpy(pattern, path, sizeof(pattern) - 4);
    if (pattern[0] && pattern[bof_strlen(pattern) - 1] != '\\')
        bof_strcat(pattern, "\\");
    bof_strcat(pattern, "*");

    h = KERNEL32$FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    do {
        char attrs[8];
        SYSTEMTIME st;
        char date[24] = "-";
        unsigned long long size = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

        if (bof_strcmp(fd.cFileName, ".") == 0 || bof_strcmp(fd.cFileName, "..") == 0)
            continue;

        if (KERNEL32$FileTimeToSystemTime(&fd.ftLastWriteTime, &st)) {
            char t[8];
            bof_itoa(st.wYear, date);
            bof_strcat(date, "-");
            bof_itoa(st.wMonth, t); if (st.wMonth < 10) bof_strcat(date, "0"); bof_strcat(date, t);
            bof_strcat(date, "-");
            bof_itoa(st.wDay, t); if (st.wDay < 10) bof_strcat(date, "0"); bof_strcat(date, t);
            bof_strcat(date, " ");
            bof_itoa(st.wHour, t); if (st.wHour < 10) bof_strcat(date, "0"); bof_strcat(date, t);
            bof_strcat(date, ":");
            bof_itoa(st.wMinute, t); if (st.wMinute < 10) bof_strcat(date, "0"); bof_strcat(date, t);
        }

        print_attrs(fd.dwFileAttributes, attrs);
        BeaconPrintf(CALLBACK_OUTPUT, "  %s %12llu  %s  %s\n", date, size, attrs, fd.cFileName);
        count++;

        if (recursive && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char sub[1024];
            bof_strncpy(sub, path, sizeof(sub) - 260);
            if (sub[0] && sub[bof_strlen(sub) - 1] != '\\')
                bof_strcat(sub, "\\");
            bof_strncat(sub, fd.cFileName, (int)sizeof(sub) - bof_strlen(sub) - 1);
            count += list_dir(sub, recursive, depth + 1);
        }
    } while (KERNEL32$FindNextFileA(h, &fd));

    KERNEL32$FindClose(h);
    return count;
}

void go(char *args, int alen)
{
    datap parser;
    wchar_t *wpath;
    int wlen = 0;
    char path[1024];
    int recursive = 0;
    int count;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: dir <path> [/s]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    wpath = (wchar_t *)BeaconDataExtract(&parser, &wlen);
    recursive = BeaconDataInt(&parser);

    if (!wpath) {
        BeaconPrintf(CALLBACK_ERROR, "invalid path\n");
        return;
    }
    bof_w2a_cp(wpath, path, sizeof(path), CP_ACP);
    if (!path[0]) bof_strcpy(path, ".\\");

    BeaconPrintf(CALLBACK_OUTPUT, "Directory: %s%s\n", path, recursive ? " (recursive)" : "");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %12s  %-5s  %s\n", "LastWrite", "Size", "Attr", "Name");

    count = list_dir(path, recursive, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d item(s)\n", count);

    (void)wlen;
}
