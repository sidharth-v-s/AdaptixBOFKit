/*
 * wmi_query <wql> [prop1,prop2,...]
 *
 * Run a WQL query against the local ROOT\CIMV2 namespace.
 *   wmi_query "SELECT ProcessId,Name,CommandLine FROM Win32_Process"
 *   wmi_query "SELECT * FROM Win32_Product" Name,Version,Vendor
 *
 * With no property list every non-system property is printed.  Requires the
 * WMI service (Winmgmt) to be running.  Queries are read-only.
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

static const GUID bof_clsid_wbemlocator =
    {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
static const GUID bof_iid_iwbemlocator =
    {0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

static void fmt_double(double d, char *out, int outsz)
{
    char tmp[48];
    char frac[8];
    char *p = tmp;
    unsigned long long ip, fp;

    if (d < 0) { *p++ = '-'; d = -d; }
    ip = (unsigned long long)d;
    fp = (unsigned long long)((d - (double)ip) * 10000.0 + 0.5);
    if (fp >= 10000) { ip++; fp -= 10000; }

    {
        char a[24];
        bof_itoa(ip, a);
        bof_strcpy(p, a);
        p += bof_strlen(a);
    }
    *p++ = '.';
    frac[0] = (char)('0' + (fp / 1000) % 10);
    frac[1] = (char)('0' + (fp / 100) % 10);
    frac[2] = (char)('0' + (fp / 10) % 10);
    frac[3] = (char)('0' + fp % 10);
    frac[4] = 0;
    bof_strcpy(p, frac);
    bof_strncpy(out, tmp, outsz);
}

static void print_variant(const char *name, VARIANT *v)
{
    char tmp[1024];

    if (v->vt & VT_ARRAY) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: <array>\n", name);
        return;
    }

    switch (v->vt) {
    case VT_EMPTY:
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: <empty>\n", name);
        break;
    case VT_NULL:
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: <null>\n", name);
        break;
    case VT_BSTR:
        if (v->bstrVal) {
            bof_w2a(v->bstrVal, tmp, sizeof(tmp));
            BeaconPrintf(CALLBACK_OUTPUT, "  %s: %s\n", name, tmp);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  %s: <null>\n", name);
        }
        break;
    case VT_I1:  BeaconPrintf(CALLBACK_OUTPUT, "  %s: %d\n", name, (int)v->cVal); break;
    case VT_UI1: BeaconPrintf(CALLBACK_OUTPUT, "  %s: %u\n", name, (unsigned)v->bVal); break;
    case VT_I2:  BeaconPrintf(CALLBACK_OUTPUT, "  %s: %d\n", name, (int)v->iVal); break;
    case VT_UI2: BeaconPrintf(CALLBACK_OUTPUT, "  %s: %u\n", name, (unsigned)v->uiVal); break;
    case VT_I4:  BeaconPrintf(CALLBACK_OUTPUT, "  %s: %ld\n", name, (long)v->lVal); break;
    case VT_UI4: BeaconPrintf(CALLBACK_OUTPUT, "  %s: %lu\n", name, (unsigned long)v->ulVal); break;
    case VT_I8:  BeaconPrintf(CALLBACK_OUTPUT, "  %s: %lld\n", name, (long long)v->llVal); break;
    case VT_UI8: BeaconPrintf(CALLBACK_OUTPUT, "  %s: %llu\n", name, (unsigned long long)v->ullVal); break;
    case VT_BOOL:
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: %s\n", name,
                     v->boolVal ? "TRUE" : "FALSE");
        break;
    case VT_R4:
        fmt_double((double)v->fltVal, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: %s\n", name, tmp);
        break;
    case VT_R8:
        fmt_double(v->dblVal, tmp, sizeof(tmp));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: %s\n", name, tmp);
        break;
    case VT_DISPATCH:
    case VT_UNKNOWN:
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: <object>\n", name);
        break;
    default:
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: <vt=%u>\n", name,
                     (unsigned)v->vt);
        break;
    }
}

static void dump_all_props(IWbemClassObject *obj)
{
    SAFEARRAY *names = NULL;
    HRESULT hr;

    hr = obj->lpVtbl->GetNames(obj, NULL,
            WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY, NULL, &names);
    if (FAILED(hr) || !names) {
        BeaconPrintf(CALLBACK_OUTPUT, "  <no properties>\n");
        return;
    }

    {
        LONG lo = 0, hi = -1, idx;
        OLEAUT32$SafeArrayGetLBound(names, 1, &lo);
        OLEAUT32$SafeArrayGetUBound(names, 1, &hi);
        for (idx = lo; idx <= hi; idx++) {
            BSTR nm = NULL;
            if (SUCCEEDED(OLEAUT32$SafeArrayGetElement(names, &idx, &nm)) && nm) {
                VARIANT val;
                OLEAUT32$VariantInit(&val);
                if (SUCCEEDED(obj->lpVtbl->Get(obj, nm, 0, &val, NULL, NULL))) {
                    char name[256];
                    bof_w2a(nm, name, sizeof(name));
                    print_variant(name, &val);
                }
                OLEAUT32$VariantClear(&val);
                OLEAUT32$SysFreeString(nm);
            }
        }
    }
    OLEAUT32$SafeArrayDestroy(names);
}

void go(char *args, int alen)
{
    datap parser;
    char *wql = NULL, *propstr = "";
    int wqllen = 0, plen = 0;
    wchar_t wqlw[1024];
    BSTR ns = NULL, lang = NULL, query = NULL;
    IWbemLocator *loc = NULL;
    IWbemServices *svc = NULL;
    IEnumWbemClassObject *en = NULL;
    char *props[32];
    int nprops = 0;
    HRESULT hr;
    int coinit = 0, objects = 0;

    BeaconDataParse(&parser, args, alen);
    wql = BeaconDataExtract(&parser, &wqllen);
    propstr = BeaconDataExtract(&parser, &plen);
    if (!wql || !wql[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: wmi_query \"SELECT ... FROM Win32_Class\" [prop,prop]\n");
        return;
    }
    if (!propstr) propstr = "";

    {
        char copy[512];
        char *p;
        bof_strncpy(copy, propstr, sizeof(copy));
        p = copy;
        while (*p && nprops < 32) {
            char *comma;
            char *next;
            char *end;
            while (*p == ' ' || *p == '\t') p++;
            if (!*p) break;
            comma = p;
            while (*comma && *comma != ',') comma++;
            next = *comma ? comma + 1 : comma;
            end = comma;
            while (end > p && (end[-1] == ' ' || end[-1] == '\t')) end--;
            *end = 0;
            if (*p) props[nprops++] = p;
            p = next;
        }
    }

    if (bof_a2w(wql, wqlw, sizeof(wqlw) / sizeof(wqlw[0])) < 0) {
        BeaconPrintf(CALLBACK_ERROR, "query too long\n");
        return;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) coinit = 1;
    else if (hr != (HRESULT)0x80010106L) { /* RPC_E_CHANGED_MODE */
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx\n",
                     (unsigned long)hr);
        return;
    }

    ns = OLEAUT32$SysAllocString(L"ROOT\\CIMV2");
    lang = OLEAUT32$SysAllocString(L"WQL");
    query = OLEAUT32$SysAllocString(wqlw);
    if (!ns || !lang || !query) {
        BeaconPrintf(CALLBACK_ERROR, "SysAllocString failed\n");
        goto cleanup;
    }

    hr = OLE32$CoCreateInstance(&bof_clsid_wbemlocator, NULL, CLSCTX_INPROC_SERVER,
                                &bof_iid_iwbemlocator, (void **)&loc);
    if (FAILED(hr) || !loc) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(WbemLocator) failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    hr = loc->lpVtbl->ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL, &svc);
    if (FAILED(hr) || !svc) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectServer failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    OLE32$CoSetProxyBlanket((IUnknown *)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                            NULL, RPC_C_AUTHN_LEVEL_CALL,
                            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    hr = svc->lpVtbl->ExecQuery(svc, lang, query,
                                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                NULL, &en);
    if (FAILED(hr) || !en) {
        BeaconPrintf(CALLBACK_ERROR, "ExecQuery failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    for (;;) {
        IWbemClassObject *obj = NULL;
        ULONG got = 0;
        hr = en->lpVtbl->Next(en, 5000, 1, &obj, &got);
        if (FAILED(hr) || !got || !obj) break;

        objects++;
        BeaconPrintf(CALLBACK_OUTPUT, "--- object %d ---\n", objects);
        if (nprops) {
            int i;
            for (i = 0; i < nprops; i++) {
                wchar_t wname[128];
                VARIANT val;
                if (bof_a2w(props[i], wname, sizeof(wname) / sizeof(wname[0])) < 0)
                    continue;
                OLEAUT32$VariantInit(&val);
                if (SUCCEEDED(obj->lpVtbl->Get(obj, wname, 0, &val, NULL, NULL)))
                    print_variant(props[i], &val);
                OLEAUT32$VariantClear(&val);
            }
        } else {
            dump_all_props(obj);
        }
        obj->lpVtbl->Release(obj);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d object(s)\n", objects);

cleanup:
    if (en)  en->lpVtbl->Release(en);
    if (svc) svc->lpVtbl->Release(svc);
    if (loc) loc->lpVtbl->Release(loc);
    if (query) OLEAUT32$SysFreeString(query);
    if (lang)  OLEAUT32$SysFreeString(lang);
    if (ns)    OLEAUT32$SysFreeString(ns);
    if (coinit) OLE32$CoUninitialize();
}
