/*
 * AdaptixBOFKit - minimal read-only SQLite table reader.
 *
 * Chrome and Edge keep History / Login Data in SQLite 3 files.  Shipping a
 * full SQL engine is out of scope, so this walks table b-trees directly and
 * hands each row to a callback.  Supports what browsers actually use:
 *  - page sizes 512..65536, overflow chains, interior + leaf table pages
 *  - serial types (NULL, ints, floats, text, blob)
 *
 * Not supported: WITHOUT ROWID tables, index pages, ALTERed schemas with
 * generated columns.  Good enough for `logins`, `urls`, `downloads`.
 */
#ifndef ADAPTIX_SQLITE_H
#define ADAPTIX_SQLITE_H

#include <windows.h>

#define BOF_SQLITE_MAX_FILE (256u * 1024u * 1024u)
#define BOF_SQLITE_MAX_PAYLOAD (4u * 1024u * 1024u)

typedef struct {
    int type;                 /* 0 null, 1 int, 2 float, 3 text, 4 blob */
    long long i;
    double d;
    const char *text;         /* not NUL-terminated; use len */
    int len;
    const unsigned char *blob;
} bof_sqlite_value;

typedef int (*bof_sqlite_row_cb)(void *ctx, int ncols, bof_sqlite_value *vals);

typedef struct {
    unsigned char *data;
    unsigned int size;
    unsigned int page_size;
    unsigned int usable;
} bof_sqlite_db;

static inline unsigned int bof_sq_be16(const unsigned char *p)
{
    return ((unsigned int)p[0] << 8) | p[1];
}

static inline unsigned int bof_sq_be32(const unsigned char *p)
{
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | p[3];
}

static inline long long bof_sq_varint(const unsigned char *p, int *used)
{
    long long v = 0;
    int i;
    for (i = 0; i < 9; i++) {
        unsigned char c = p[i];
        if (i == 8) {
            v = (v << 8) | c;
            *used = 9;
            return v;
        }
        v = (v << 7) | (c & 0x7f);
        if (!(c & 0x80)) {
            *used = i + 1;
            return v;
        }
    }
    *used = 9;
    return v;
}

static inline int bof_sqlite_open(bof_sqlite_db *db, const char *path)
{
    HANDLE h;
    LARGE_INTEGER sz;
    DWORD got = 0;

    db->data = NULL;
    db->size = 0;
    db->page_size = 0;
    db->usable = 0;

    h = KERNEL32$CreateFileA(path, GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!KERNEL32$GetFileSizeEx(h, &sz) ||
        sz.QuadPart < 512 || sz.QuadPart > (LONGLONG)BOF_SQLITE_MAX_FILE) {
        KERNEL32$CloseHandle(h);
        return -1;
    }

    db->data = (unsigned char *)KERNEL32$VirtualAlloc(NULL, (SIZE_T)sz.QuadPart,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!db->data) {
        KERNEL32$CloseHandle(h);
        return -1;
    }
    if (!KERNEL32$ReadFile(h, db->data, (DWORD)sz.QuadPart, &got, NULL) ||
        got != (DWORD)sz.QuadPart) {
        KERNEL32$VirtualFree(db->data, 0, MEM_RELEASE);
        db->data = NULL;
        KERNEL32$CloseHandle(h);
        return -1;
    }
    KERNEL32$CloseHandle(h);

    db->size = (unsigned int)sz.QuadPart;
    if (bof_memcmp(db->data, "SQLite format 3\0", 16) != 0) {
        KERNEL32$VirtualFree(db->data, 0, MEM_RELEASE);
        db->data = NULL;
        return -1;
    }

    db->page_size = bof_sq_be16(db->data + 16);
    if (db->page_size == 1) db->page_size = 65536;
    if (db->page_size < 512 || db->page_size > 65536) {
        KERNEL32$VirtualFree(db->data, 0, MEM_RELEASE);
        db->data = NULL;
        return -1;
    }
    db->usable = db->page_size - db->data[20];
    if (db->usable <= 480) db->usable = db->page_size;
    return 0;
}

static inline void bof_sqlite_close(bof_sqlite_db *db)
{
    if (db->data) KERNEL32$VirtualFree(db->data, 0, MEM_RELEASE);
    db->data = NULL;
    db->size = 0;
}

static inline int bof_sq_serial_len(unsigned int t)
{
    switch (t) {
    case 0: case 8: case 9: return 0;
    case 1: return 1;
    case 2: return 2;
    case 3: return 3;
    case 4: return 4;
    case 5: return 6;
    case 6: case 7: return 8;
    case 10: case 11: return 0;
    default: return (int)((t - 12) / 2);
    }
}

static inline long long bof_sq_int(const unsigned char *p, int n)
{
    unsigned long long v = 0;
    int i, neg;
    if (n == 0) return 0;
    neg = (p[0] & 0x80) != 0;
    for (i = 0; i < n; i++) v = (v << 8) | p[i];
    if (neg && n < 8) v |= (~0ULL) << (n * 8);
    return (long long)v;
}

/* Parse a record (payload of ncells columns) and invoke the callback. */
static inline int bof_sq_record(const unsigned char *payload, unsigned int plen,
                                bof_sqlite_row_cb cb, void *ctx)
{
    bof_sqlite_value vals[64];
    int serial[64];
    int used = 0, ncols = 0, i;
    unsigned int hdr;
    unsigned int off;

    if (plen < 2) return 0;
    {
        long long h = bof_sq_varint(payload, &used);
        if (h <= 0 || (unsigned int)h > plen) return 0;
        hdr = (unsigned int)h;
    }

    off = (unsigned int)used;
    while (off < hdr && ncols < 64) {
        long long t = bof_sq_varint(payload + off, &used);
        if (used <= 0) break;
        serial[ncols++] = (int)t;
        off += (unsigned int)used;
    }

    off = hdr;
    for (i = 0; i < ncols; i++) {
        int len = bof_sq_serial_len((unsigned int)serial[i]);
        if (off + (unsigned int)len > plen) break;
        vals[i].type = 0;
        vals[i].i = 0;
        vals[i].d = 0;
        vals[i].text = NULL;
        vals[i].len = 0;
        vals[i].blob = NULL;

        if (serial[i] >= 12) {
            if ((serial[i] & 1) == 0) {
                vals[i].type = 4;
                vals[i].blob = payload + off;
                vals[i].len = len;
            } else {
                vals[i].type = 3;
                vals[i].text = (const char *)(payload + off);
                vals[i].len = len;
            }
        } else if (serial[i] >= 1 && serial[i] <= 6) {
            vals[i].type = 1;
            vals[i].i = bof_sq_int(payload + off, len);
        } else if (serial[i] == 7) {
            unsigned long long bits = 0;
            int k;
            vals[i].type = 2;
            for (k = 0; k < 8; k++) bits = (bits << 8) | payload[off + k];
            {
                double d;
                bof_memcpy(&d, &bits, 8);
                vals[i].d = d;
            }
        } else if (serial[i] == 8) {
            vals[i].type = 1;
            vals[i].i = 0;
        } else if (serial[i] == 9) {
            vals[i].type = 1;
            vals[i].i = 1;
        }
        off += (unsigned int)len;
    }

    return cb(ctx, ncols, vals);
}

static inline int bof_sq_walk(bof_sqlite_db *db, unsigned int pgno,
                              bof_sqlite_row_cb cb, void *ctx, int depth)
{
    unsigned int off;
    unsigned int ncell, i;
    int hdr;
    unsigned char type;

    if (depth > 32 || pgno < 1) return 0;
    off = (pgno - 1) * db->page_size;
    if (off + 8 >= db->size) return 0;

    type = db->data[off];
    ncell = bof_sq_be16(db->data + off + 3);
    hdr = (pgno == 1) ? 100 : 8;
    if (off + (unsigned int)hdr + ncell * 2 > db->size) return 0;

    for (i = 0; i < ncell; i++) {
        unsigned int cell = off + bof_sq_be16(db->data + off + hdr + i * 2);
        if (cell + 4 >= db->size) continue;

        if (type == 13) {              /* leaf table page */
            int u = 0, u2 = 0;
            long long payload_len = bof_sq_varint(db->data + cell, &u);
            const unsigned char *p = db->data + cell + u;
            unsigned int local, remaining;
            unsigned int maxlocal;

            if (payload_len < 0) continue;
            (void)bof_sq_varint(p, &u2);      /* rowid */
            p += u2;

            maxlocal = db->usable - 35;
            if ((unsigned int)payload_len <= maxlocal) {
                local = (unsigned int)payload_len;
            } else {
                unsigned int m = ((db->usable - 12) * 32 / 255) - 23;
                unsigned int k = m + ((unsigned int)payload_len - m) % (db->usable - 4);
                local = (k <= maxlocal) ? k : m;
            }

            remaining = (unsigned int)payload_len - local;
            if (remaining == 0) {
                if (bof_sq_record(p, local, cb, ctx) < 0) return -1;
            } else {
                unsigned char *buf;
                unsigned int copied = local;
                unsigned int next;
                if ((unsigned int)payload_len > BOF_SQLITE_MAX_PAYLOAD) continue;
                buf = (unsigned char *)KERNEL32$VirtualAlloc(NULL, (SIZE_T)payload_len,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!buf) continue;
                bof_memcpy(buf, p, local);
                next = bof_sq_be32(p + local);
                while (next && copied < (unsigned int)payload_len) {
                    unsigned int poff = (next - 1) * db->page_size;
                    unsigned int chunk = db->usable - 4;
                    if (poff + 4 >= db->size) break;
                    if (chunk > (unsigned int)payload_len - copied)
                        chunk = (unsigned int)payload_len - copied;
                    if (poff + 4 + chunk > db->size) break;
                    bof_memcpy(buf + copied, db->data + poff + 4, chunk);
                    copied += chunk;
                    next = bof_sq_be32(db->data + poff);
                }
                if (copied == (unsigned int)payload_len)
                    bof_sq_record(buf, copied, cb, ctx);
                KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
            }
        } else if (type == 2) {        /* interior table page */
            unsigned int child = bof_sq_be32(db->data + cell);
            if (bof_sq_walk(db, child, cb, ctx, depth + 1) < 0) return -1;
        }
    }
    return 0;
}

static inline int bof_sqlite_scan(bof_sqlite_db *db, unsigned int root,
                                  bof_sqlite_row_cb cb, void *ctx)
{
    return bof_sq_walk(db, root, cb, ctx, 0);
}

/* ---- sqlite_master lookup ------------------------------------------ */

typedef struct {
    const char *table;
    unsigned int root;
} bof_sq_root_ctx;

static inline int bof_sq_root_cb(void *ctx, int ncols, bof_sqlite_value *v)
{
    bof_sq_root_ctx *rc = (bof_sq_root_ctx *)ctx;
    char name[128];

    if (ncols < 4) return 0;
    if (v[0].type != 3 || v[0].len != 5) return 0;
    if (bof_memcmp(v[0].text, "table", 5) != 0) return 0;
    if (v[1].type != 3) return 0;
    if (v[1].len >= (int)sizeof(name)) return 0;
    bof_memcpy(name, v[1].text, (unsigned int)v[1].len);
    name[v[1].len] = 0;
    if (bof_stricmp(name, rc->table) != 0) return 0;
    if (v[3].type != 1) return 0;
    rc->root = (unsigned int)v[3].i;
    return 1;   /* stop */
}

/* Returns the root page for `table`, or 0 if it was not found. */
static inline unsigned int bof_sqlite_table_root(bof_sqlite_db *db, const char *table)
{
    bof_sq_root_ctx rc;
    rc.table = table;
    rc.root = 0;
    bof_sqlite_scan(db, 1, bof_sq_root_cb, &rc);
    return rc.root;
}

#endif /* ADAPTIX_SQLITE_H */
