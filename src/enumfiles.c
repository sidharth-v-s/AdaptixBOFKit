/*
 * enumfiles <root> <pattern> [keyword] - recursive file search.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static char g_kw[256];
static int g_max = 200;
static int g_hits;

static int contains_kw(const char *path, const char *kw)
{
    HANDLE f;
    DWORD got = 0;
    char *buf;
    int found = 0;

    if (!kw[0]) return 1;
    f = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;

    buf = (char *)KERNEL32$VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { KERNEL32$CloseHandle(f); return 0; }

    while (KERNEL32$ReadFile(f, buf, 65535, &got, NULL) && got > 0) {
        buf[got] = 0;
        if (bof_strstr(buf, kw)) { found = 1; break; }
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    KERNEL32$CloseHandle(f);
    return found;
}

static void walk(const char *dir, const char *pattern, int depth)
{
    char search[1024];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    if (depth > 8 || g_hits >= g_max) return;

    bof_strncpy(search, dir, sizeof(search));
    bof_strncat(search, "\\", sizeof(search) - bof_strlen(search) - 1);
    bof_strncat(search, pattern, sizeof(search) - bof_strlen(search) - 1);

    h = KERNEL32$FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        char full[1024];
        if (bof_strcmp(fd.cFileName, ".") == 0 || bof_strcmp(fd.cFileName, "..") == 0)
            continue;

        bof_strncpy(full, dir, sizeof(full));
        bof_strncat(full, "\\", sizeof(full) - bof_strlen(full) - 1);
        bof_strncat(full, fd.cFileName, sizeof(full) - bof_strlen(full) - 1);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk(full, pattern, depth + 1);
        } else if (contains_kw(full, g_kw)) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s (%lu bytes)\n", full,
                         (unsigned long)fd.nFileSizeLow);
            if (++g_hits >= g_max) break;
        }
    } while (KERNEL32$FindNextFileA(h, &fd));

    KERNEL32$FindClose(h);
}

void go(char *args, int alen)
{
    datap parser;
    char *root, *pattern, *kw = "";
    int a, b, c;

    BeaconDataParse(&parser, args, alen);
    root    = BeaconDataExtract(&parser, &a);
    pattern = BeaconDataExtract(&parser, &b);
    kw      = BeaconDataExtract(&parser, &c);

    if (!root || !pattern) {
        BeaconPrintf(CALLBACK_ERROR, "usage: enumfiles <root> <pattern> [keyword]\n");
        return;
    }
    if (!kw) kw = "";
    bof_strncpy(g_kw, kw, sizeof(g_kw));

    BeaconPrintf(CALLBACK_OUTPUT, "Searching %s for %s%s%s\n", root, pattern,
                 g_kw[0] ? " containing " : "", g_kw);
    g_hits = 0;
    walk(root, pattern, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "\nMatches: %d%s\n", g_hits,
                 g_hits >= g_max ? " (limit reached)" : "");
}
