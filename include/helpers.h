/*
 * AdaptixBOFKit - small CRT-free helpers.
 *
 * BOFs run inside the agent process, so we avoid pulling in the C runtime.
 * Everything below is static and self contained.
 */
#ifndef ADAPTIX_HELPERS_H
#define ADAPTIX_HELPERS_H

#include <windows.h>

static inline int bof_strlen(const char *s)
{
    int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static inline int bof_wcslen(const wchar_t *s)
{
    int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static inline void bof_wcscpy(wchar_t *dst, const wchar_t *src)
{
    while ((*dst++ = *src++)) ;
}

static inline void bof_wcsncpy(wchar_t *dst, const wchar_t *src, int n)
{
    int i;
    if (n <= 0) {
        if (n == 0) dst[0] = 0;
        return;
    }
    for (i = 0; i < n - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = 0;
}

static inline void bof_wcscat(wchar_t *dst, const wchar_t *src)
{
    while (*dst) dst++;
    while ((*dst++ = *src++)) ;
}

static inline void bof_wcsncat(wchar_t *dst, const wchar_t *src, int n)
{
    while (*dst) dst++;
    while (n-- > 0 && *src) *dst++ = *src++;
    *dst = 0;
}

static inline void bof_memzero(void *p, unsigned int n)
{
    unsigned char *b = (unsigned char *)p;
    while (n--) *b++ = 0;
}

static inline void bof_memcpy(void *dst, const void *src, unsigned int n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
}

static inline void bof_memmove(void *dst, const void *src, unsigned int n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || !n) return;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
}

static inline int bof_memcmp(const void *a, const void *b, unsigned int n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n--) {
        if (*x != *y) return (int)*x - (int)*y;
        x++; y++;
    }
    return 0;
}

static inline int bof_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int bof_strncmp(const char *a, const char *b, int n)
{
    while (n-- && *a && *a == *b) { a++; b++; }
    if (n < 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int bof_stricmp(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline void bof_strcpy(char *dst, const char *src)
{
    while ((*dst++ = *src++)) ;
}

static inline void bof_strncpy(char *dst, const char *src, int n)
{
    int i;
    if (n <= 0) {
        if (n == 0) dst[0] = 0;
        return;
    }
    for (i = 0; i < n - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = 0;
}

static inline void bof_strcat(char *dst, const char *src)
{
    while (*dst) dst++;
    while ((*dst++ = *src++)) ;
}

static inline void bof_strncat(char *dst, const char *src, int n)
{
    while (*dst) dst++;
    while (n-- > 0 && *src) *dst++ = *src++;
    *dst = 0;
}

static inline char *bof_strstr(const char *hay, const char *needle)
{
    int n = bof_strlen(needle);
    if (!n) return (char *)hay;
    while (*hay) {
        if (bof_strncmp(hay, needle, n) == 0) return (char *)hay;
        hay++;
    }
    return 0;
}

static inline char *bof_strchr(const char *s, int c)
{
    while (s && *s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return NULL;
}

static inline int bof_atoi(const char *s)
{
    int v = 0;
    if (!s) return 0;
    while (*s == ' ' || *s == '\t') s++;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v;
}

static inline void bof_itoa(unsigned long long v, char *out)
{
    char tmp[24];
    int i = 0, j = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return; }
    while (v) { tmp[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i) out[j++] = tmp[--i];
    out[j] = 0;
}

/* Minimal snprintf: %s %c %d %u %x %X %% with optional zero/space padding
 * and an ignored l/ll length modifier.  Sufficient for the BOFs here. */
#include <stdarg.h>

static inline void bof_fmt_uint(unsigned long long v, unsigned int base,
                                int upper, char *out)
{
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[24];
    int i = 0, j = 0;
    if (!v) { out[0] = '0'; out[1] = 0; return; }
    while (v) { tmp[i++] = digits[v % base]; v /= base; }
    while (i) out[j++] = tmp[--i];
    out[j] = 0;
}

static inline int bof_snprintf(char *out, int cap, const char *fmt, ...)
{
    va_list ap;
    int o = 0;

    if (!out || cap <= 0) return 0;
    va_start(ap, fmt);
    while (fmt && *fmt && o < cap - 1) {
        if (*fmt != '%') {
            out[o++] = *fmt++;
            continue;
        }
        fmt++;
        if (*fmt == '%') { out[o++] = '%'; fmt++; continue; }

        {
            char pad = ' ';
            int width = 0, lmod = 0;
            char num[32];
            const char *val = NULL;
            char chr[2] = {0, 0};
            int len, neg = 0;

            if (*fmt == '0') { pad = '0'; fmt++; }
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }
            while (*fmt == 'l') { lmod++; fmt++; }

            switch (*fmt) {
            case 's':
                val = va_arg(ap, const char *);
                if (!val) val = "(null)";
                break;
            case 'c':
                chr[0] = (char)va_arg(ap, int);
                val = chr;
                break;
            case 'd': case 'i': {
                long long sv;
                if (lmod >= 2) sv = va_arg(ap, long long);
                else sv = va_arg(ap, int);
                if (sv < 0) { neg = 1; sv = -sv; }
                bof_fmt_uint((unsigned long long)sv, 10, 0, num);
                val = num;
                break;
            }
            case 'u':
                bof_fmt_uint(lmod >= 2
                             ? va_arg(ap, unsigned long long)
                             : (unsigned long long)va_arg(ap, unsigned int),
                             10, 0, num);
                val = num;
                break;
            case 'x':
                bof_fmt_uint(lmod >= 2
                             ? va_arg(ap, unsigned long long)
                             : (unsigned long long)va_arg(ap, unsigned int),
                             16, 0, num);
                val = num;
                break;
            case 'X':
                bof_fmt_uint(lmod >= 2
                             ? va_arg(ap, unsigned long long)
                             : (unsigned long long)va_arg(ap, unsigned int),
                             16, 1, num);
                val = num;
                break;
            default:
                out[o++] = '%';
                if (*fmt) out[o++] = *fmt;
                if (*fmt) fmt++;
                continue;
            }
            fmt++;

            len = bof_strlen(val) + (neg ? 1 : 0);
            while (len < width && o < cap - 1) { out[o++] = pad; width--; }
            if (neg && o < cap - 1) out[o++] = '-';
            while (*val && o < cap - 1) out[o++] = *val++;
        }
    }
    va_end(ap);
    out[o] = 0;
    return o;
}

static inline void bof_hex(unsigned long long v, int width, char *out)
{
    const char *h = "0123456789abcdef";
    int i;
    for (i = width - 1; i >= 0; i--) {
        out[i] = h[v & 0xf];
        v >>= 4;
    }
    out[width] = 0;
}

static inline int bof_is_print(int c)
{
    return c >= 0x20 && c < 0x7f;
}

/* Convert a wide string to a static-free UTF-8 buffer.  Caller supplies it.
 * Returns bytes written (without terminator). */
static inline int bof_w2a_cp(const wchar_t *src, char *dst, int dstsz, UINT cp)
{
    int n;
    if (!src || !dst || dstsz <= 0) return 0;
    n = KERNEL32$WideCharToMultiByte(cp, 0, src, -1, dst, dstsz, NULL, NULL);
    if (n <= 0) { dst[0] = 0; return 0; }
    if (n > dstsz) n = dstsz;
    dst[dstsz - 1] = 0;
    return n - 1;
}

static inline int bof_w2a(const wchar_t *src, char *dst, int dstsz)
{
    return bof_w2a_cp(src, dst, dstsz, CP_UTF8);
}

static inline int bof_a2w(const char *src, wchar_t *dst, int dstcount)
{
    int n;
    if (!src || !dst || dstcount <= 0) return 0;
    n = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dstcount);
    if (n <= 0) { dst[0] = 0; return 0; }
    dst[dstcount - 1] = 0;
    return n - 1;
}

/* Convert between network and host byte order without the CRT. */
static inline unsigned int bof_ntohl(unsigned int v)
{
    return ((v & 0x000000ffU) << 24) |
           ((v & 0x0000ff00U) <<  8) |
           ((v & 0x00ff0000U) >>  8) |
           ((v & 0xff000000U) >> 24);
}

static inline unsigned short bof_ntohs(unsigned short v)
{
    return (unsigned short)(((v & 0x00ff) << 8) | ((v & 0xff00) >> 8));
}

/* Host-order DWORD (first octet in the high byte) -> "1.2.3.4" */
static inline char *bof_ipv4(unsigned int hostorder, char *out)
{
    char *q = out;
    int i;
    for (i = 3; i >= 0; i--) {
        char t[4];
        bof_itoa((hostorder >> (i * 8)) & 0xff, t);
        bof_strcpy(q, t);
        q += bof_strlen(t);
        if (i) *q++ = '.';
    }
    *q = 0;
    return out;
}

static inline void bof_trim(char *s)
{
    int n = bof_strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\r' || s[n - 1] == '\n' || s[n - 1] == '\t'))
        s[--n] = 0;
}

/* FILETIME (100ns since 1601) -> "YYYY-MM-DD HH:MM:SS". */
static inline void bof_ft_str(unsigned long long v, char *out, int outsz)
{
    FILETIME ft;
    SYSTEMTIME st;
    char t[24];
    char *p = t;

    ft.dwLowDateTime  = (DWORD)(v & 0xffffffffULL);
    ft.dwHighDateTime = (DWORD)(v >> 32);
    if (!KERNEL32$FileTimeToSystemTime(&ft, &st)) {
        bof_strncpy(out, "?", outsz);
        return;
    }
    *p++ = (char)('0' + (st.wYear / 1000) % 10);
    *p++ = (char)('0' + (st.wYear / 100) % 10);
    *p++ = (char)('0' + (st.wYear / 10) % 10);
    *p++ = (char)('0' + st.wYear % 10);
    *p++ = '-';
    *p++ = (char)('0' + (st.wMonth / 10) % 10);
    *p++ = (char)('0' + st.wMonth % 10);
    *p++ = '-';
    *p++ = (char)('0' + (st.wDay / 10) % 10);
    *p++ = (char)('0' + st.wDay % 10);
    *p++ = ' ';
    *p++ = (char)('0' + (st.wHour / 10) % 10);
    *p++ = (char)('0' + st.wHour % 10);
    *p++ = ':';
    *p++ = (char)('0' + (st.wMinute / 10) % 10);
    *p++ = (char)('0' + st.wMinute % 10);
    *p++ = ':';
    *p++ = (char)('0' + (st.wSecond / 10) % 10);
    *p++ = (char)('0' + st.wSecond % 10);
    *p = 0;
    bof_strncpy(out, t, outsz);
}

/* ---- base64 / hex ------------------------------------------------- */

static inline int bof_b64_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

/* Returns base64 length, or -1 if it does not fit. Always NUL-terminates. */
static inline int bof_b64_encode(const unsigned char *src, int slen, char *dst, int dlen)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, o = 0;

    if (dlen <= 0) return -1;
    for (i = 0; i + 2 < slen; i += 3) {
        unsigned v = ((unsigned)src[i] << 16) | ((unsigned)src[i + 1] << 8) | src[i + 2];
        if (o + 4 >= dlen) { dst[o] = 0; return -1; }
        dst[o++] = tab[(v >> 18) & 63];
        dst[o++] = tab[(v >> 12) & 63];
        dst[o++] = tab[(v >> 6) & 63];
        dst[o++] = tab[v & 63];
    }
    if (i < slen) {
        unsigned v = (unsigned)src[i] << 16;
        if (i + 1 < slen) v |= (unsigned)src[i + 1] << 8;
        if (o + 4 >= dlen) { dst[o] = 0; return -1; }
        dst[o++] = tab[(v >> 18) & 63];
        dst[o++] = tab[(v >> 12) & 63];
        dst[o++] = (i + 1 < slen) ? tab[(v >> 6) & 63] : '=';
        dst[o++] = '=';
    }
    dst[o] = 0;
    return o;
}

/* Decodes base64, skipping whitespace. Returns byte count or -1. */
static inline int bof_b64_decode(const char *src, unsigned char *dst, int dlen)
{
    int i, o = 0, quad = 0;
    unsigned acc = 0;

    if (!src || dlen <= 0) return -1;
    for (i = 0; src[i]; i++) {
        int c = (unsigned char)src[i];
        int v;
        if (c == '=' ) break;
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        v = bof_b64_val(c);
        if (v < 0) return -1;
        acc = (acc << 6) | (unsigned)v;
        quad++;
        if (quad == 4) {
            if (o + 3 > dlen) return -1;
            dst[o++] = (unsigned char)((acc >> 16) & 0xff);
            dst[o++] = (unsigned char)((acc >> 8) & 0xff);
            dst[o++] = (unsigned char)(acc & 0xff);
            acc = 0;
            quad = 0;
        }
    }
    if (quad == 2) {
        if (o + 1 > dlen) return -1;
        dst[o++] = (unsigned char)((acc >> 4) & 0xff);
    } else if (quad == 3) {
        if (o + 2 > dlen) return -1;
        dst[o++] = (unsigned char)((acc >> 10) & 0xff);
        dst[o++] = (unsigned char)((acc >> 2) & 0xff);
    } else if (quad != 0) {
        return -1;
    }
    return o;
}

static inline int bof_hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes hex (optional 0x prefix, spaces/colons ignored). */
static inline int bof_hex_decode(const char *src, unsigned char *dst, int dlen)
{
    int o = 0, hi = -1;
    if (!src || dlen <= 0) return -1;
    if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) src += 2;
    while (*src) {
        int v;
        if (*src == ' ' || *src == ':' || *src == '-' || *src == '\r' || *src == '\n') { src++; continue; }
        v = bof_hexval((unsigned char)*src++);
        if (v < 0) return -1;
        if (hi < 0) { hi = v; continue; }
        if (o >= dlen) return -1;
        dst[o++] = (unsigned char)((hi << 4) | v);
        hi = -1;
    }
    return (hi < 0) ? o : -1;
}

/* Reads a file into RW VirtualAlloc memory. 0 on success. */
static inline int bof_read_file(const char *path, unsigned char **out, unsigned int *outsz)
{
    HANDLE h;
    LARGE_INTEGER sz;
    DWORD got = 0;
    unsigned char *p;

    *out = NULL;
    *outsz = 0;
    if (!path || !path[0]) return -1;

    h = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!KERNEL32$GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 ||
        sz.QuadPart > (LONGLONG)0x10000000) {
        KERNEL32$CloseHandle(h);
        return -1;
    }
    p = (unsigned char *)KERNEL32$VirtualAlloc(NULL, (SIZE_T)sz.QuadPart,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) {
        KERNEL32$CloseHandle(h);
        return -1;
    }
    if (!KERNEL32$ReadFile(h, p, (DWORD)sz.QuadPart, &got, NULL) ||
        got != (DWORD)sz.QuadPart) {
        KERNEL32$VirtualFree(p, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(h);
        return -1;
    }
    KERNEL32$CloseHandle(h);
    *out = p;
    *outsz = (unsigned int)sz.QuadPart;
    return 0;
}

/* True when the pointer range is committed readable memory. */
static inline int bof_mem_readable(const void *p)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!p) return 0;
    if (KERNEL32$VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    return 1;
}

static inline HKEY bof_hive(const char *s)
{
    if (!s || !s[0]) return HKEY_CURRENT_USER;
    if (bof_stricmp(s, "HKLM") == 0 || bof_stricmp(s, "HKEY_LOCAL_MACHINE") == 0) return HKEY_LOCAL_MACHINE;
    if (bof_stricmp(s, "HKCU") == 0 || bof_stricmp(s, "HKEY_CURRENT_USER") == 0)  return HKEY_CURRENT_USER;
    if (bof_stricmp(s, "HKCR") == 0 || bof_stricmp(s, "HKEY_CLASSES_ROOT") == 0)  return HKEY_CLASSES_ROOT;
    if (bof_stricmp(s, "HKU") == 0  || bof_stricmp(s, "HKEY_USERS") == 0)         return HKEY_USERS;
    if (bof_stricmp(s, "HKCC") == 0 || bof_stricmp(s, "HKEY_CURRENT_CONFIG") == 0) return HKEY_CURRENT_CONFIG;
    return HKEY_CURRENT_USER;
}

static inline const char *bof_regtype(DWORD t)
{
    switch (t) {
    case REG_SZ:        return "REG_SZ";
    case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
    case REG_BINARY:    return "REG_BINARY";
    case REG_DWORD:     return "REG_DWORD";
    case REG_QWORD:     return "REG_QWORD";
    case REG_MULTI_SZ:  return "REG_MULTI_SZ";
    }
    return "REG_UNKNOWN";
}

#endif /* ADAPTIX_HELPERS_H */
