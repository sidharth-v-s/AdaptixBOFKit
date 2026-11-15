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
