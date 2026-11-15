/*
 * addfirewallrule <add|remove|list> [args]
 *
 * Manage Windows Defender Firewall rules through the INetFwPolicy2 COM API.
 *   add <name> <port> [tcp|udp] [allow|block] [program] [in|out]
 *   remove <name>
 *   list [name]
 *
 * Adding or removing rules in the local policy needs admin.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#ifndef NET_FW_IP_PROTOCOL_ANY
#define NET_FW_IP_PROTOCOL_ANY 256
#endif

static const GUID GUID_NetFwPolicy2 =
    { 0xe2b3c97f, 0x6ae1, 0x41ac,
      { 0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd } };
static const GUID GUID_INetFwPolicy2 =
    { 0x98325047, 0xc671, 0x4174,
      { 0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86 } };
static const GUID GUID_NetFwRule =
    { 0x2c5bc43e, 0x3369, 0x4c33,
      { 0xab, 0x0c, 0xbe, 0x94, 0x69, 0x67, 0x7a, 0xf4 } };
static const GUID GUID_INetFwRule =
    { 0xaf230d27, 0xbaba, 0x4e42,
      { 0xac, 0xed, 0xf5, 0x24, 0xf2, 0x2c, 0xfc, 0xe2 } };
static const GUID GUID_IEnumVARIANT =
    { 0x00020404, 0x0000, 0x0000,
      { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

static BSTR bstr_from_a(const char *s)
{
    wchar_t w[1024];
    bof_a2w(s, w, 1024);
    return OLEAUT32$SysAllocString(w);
}

static void wide_to_a(const wchar_t *src, char *dst, int dstsz)
{
    if (src) bof_w2a(src, dst, dstsz);
    else dst[0] = 0;
}

static void print_rule(INetFwRule *r)
{
    BSTR name = NULL, ports = NULL, app = NULL;
    LONG proto = 0;
    NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_IN;
    NET_FW_ACTION act = NET_FW_ACTION_BLOCK;
    VARIANT_BOOL enabled = 0;
    char n[256], p[128], a[512];

    r->lpVtbl->get_Name(r, &name);
    r->lpVtbl->get_LocalPorts(r, &ports);
    r->lpVtbl->get_ApplicationName(r, &app);
    r->lpVtbl->get_Protocol(r, &proto);
    r->lpVtbl->get_Direction(r, &dir);
    r->lpVtbl->get_Action(r, &act);
    r->lpVtbl->get_Enabled(r, &enabled);

    wide_to_a(name, n, sizeof(n));
    wide_to_a(ports, p, sizeof(p));
    wide_to_a(app, a, sizeof(a));

    BeaconPrintf(CALLBACK_OUTPUT, "  %-40s %-3s %-7s proto=%-3ld ports=%-12s %s%s\n",
                 n, dir == NET_FW_RULE_DIR_IN ? "IN" : "OUT",
                 act == NET_FW_ACTION_ALLOW ? "ALLOW" : "BLOCK",
                 (long)proto, p[0] ? p : "*",
                 a[0] ? a : "", enabled ? "" : " (disabled)");

    if (name)  OLEAUT32$SysFreeString(name);
    if (ports) OLEAUT32$SysFreeString(ports);
    if (app)   OLEAUT32$SysFreeString(app);
}

static void do_add(INetFwPolicy2 *policy, const char *name, const char *port,
                   const char *proto, const char *action, const char *program,
                   const char *dirarg)
{
    INetFwRules *rules = NULL;
    INetFwRule *rule = NULL;
    BSTR bname = NULL, bport = NULL, bapp = NULL, bdesc = NULL;
    LONG protocol = NET_FW_IP_PROTOCOL_TCP;
    NET_FW_ACTION act = NET_FW_ACTION_ALLOW;
    NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_IN;
    HRESULT hr;

    if (!name || !name[0] || !port || !port[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: addfirewallrule add <name> <port> [tcp|udp] [allow|block] [program] [in|out]\n");
        return;
    }
    if (proto && bof_stricmp(proto, "udp") == 0) protocol = NET_FW_IP_PROTOCOL_UDP;
    else if (proto && bof_stricmp(proto, "any") == 0) protocol = NET_FW_IP_PROTOCOL_ANY;
    if (action && bof_stricmp(action, "block") == 0) act = NET_FW_ACTION_BLOCK;
    if (dirarg && bof_stricmp(dirarg, "out") == 0) dir = NET_FW_RULE_DIR_OUT;

    hr = policy->lpVtbl->get_Rules(policy, &rules);
    if (FAILED(hr) || !rules) {
        BeaconPrintf(CALLBACK_ERROR, "get_Rules failed: 0x%08lx\n", (unsigned long)hr);
        return;
    }

    hr = OLE32$CoCreateInstance(&GUID_NetFwRule, NULL, CLSCTX_INPROC_SERVER,
                                &GUID_INetFwRule, (void **)&rule);
    if (FAILED(hr) || !rule) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(NetFwRule) failed: 0x%08lx\n",
                     (unsigned long)hr);
        rules->lpVtbl->Release(rules);
        return;
    }

    bname = bstr_from_a(name);
    bport = bstr_from_a(port);
    bdesc = bstr_from_a("AdaptixBOFKit");
    rule->lpVtbl->put_Name(rule, bname);
    rule->lpVtbl->put_Description(rule, bdesc);
    rule->lpVtbl->put_Protocol(rule, protocol);
    rule->lpVtbl->put_LocalPorts(rule, bport);
    rule->lpVtbl->put_Direction(rule, dir);
    rule->lpVtbl->put_Action(rule, act);
    rule->lpVtbl->put_Profiles(rule, NET_FW_PROFILE2_ALL);
    rule->lpVtbl->put_Enabled(rule, VARIANT_TRUE);
    if (program && program[0]) {
        bapp = bstr_from_a(program);
        rule->lpVtbl->put_ApplicationName(rule, bapp);
    }

    hr = rules->lpVtbl->Add(rules, rule);
    if (SUCCEEDED(hr))
        BeaconPrintf(CALLBACK_OUTPUT, "Added rule '%s' %s %s/%s\n", name,
                     act == NET_FW_ACTION_ALLOW ? "allow" : "block",
                     dir == NET_FW_RULE_DIR_IN ? "in" : "out", port);
    else
        BeaconPrintf(CALLBACK_ERROR, "INetFwRules::Add failed: 0x%08lx (admin?)\n",
                     (unsigned long)hr);

    if (bname) OLEAUT32$SysFreeString(bname);
    if (bport) OLEAUT32$SysFreeString(bport);
    if (bdesc) OLEAUT32$SysFreeString(bdesc);
    if (bapp)  OLEAUT32$SysFreeString(bapp);
    rule->lpVtbl->Release(rule);
    rules->lpVtbl->Release(rules);
}

static void do_remove(INetFwPolicy2 *policy, const char *name)
{
    INetFwRules *rules = NULL;
    BSTR bname;
    HRESULT hr;

    if (!name || !name[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: addfirewallrule remove <name>\n");
        return;
    }
    if (FAILED(policy->lpVtbl->get_Rules(policy, &rules)) || !rules) return;

    bname = bstr_from_a(name);
    hr = rules->lpVtbl->Remove(rules, bname);
    if (SUCCEEDED(hr))
        BeaconPrintf(CALLBACK_OUTPUT, "Removed rule '%s'\n", name);
    else
        BeaconPrintf(CALLBACK_ERROR, "Remove failed: 0x%08lx\n", (unsigned long)hr);
    OLEAUT32$SysFreeString(bname);
    rules->lpVtbl->Release(rules);
}

static void do_list(INetFwPolicy2 *policy, const char *name)
{
    INetFwRules *rules = NULL;
    int count = 0;

    if (FAILED(policy->lpVtbl->get_Rules(policy, &rules)) || !rules) {
        BeaconPrintf(CALLBACK_ERROR, "get_Rules failed\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%-42s %-3s %-7s %-9s %-12s %s\n",
                 "Name", "Dir", "Action", "Protocol", "Ports", "Program");

    if (name && name[0]) {
        INetFwRule *r = NULL;
        BSTR bn = bstr_from_a(name);
        if (SUCCEEDED(rules->lpVtbl->Item(rules, bn, &r)) && r) {
            print_rule(r);
            r->lpVtbl->Release(r);
            count = 1;
        }
        OLEAUT32$SysFreeString(bn);
    } else {
        IUnknown *unk = NULL;
        IEnumVARIANT *ev = NULL;
        if (SUCCEEDED(rules->lpVtbl->get__NewEnum(rules, &unk)) && unk) {
            if (SUCCEEDED(unk->lpVtbl->QueryInterface(unk, &GUID_IEnumVARIANT,
                                                      (void **)&ev)) && ev) {
                for (;;) {
                    VARIANT v;
                    ULONG got = 0;
                    OLEAUT32$VariantInit(&v);
                    if (ev->lpVtbl->Next(ev, 1, &v, &got) != S_OK || got == 0) {
                        OLEAUT32$VariantClear(&v);
                        break;
                    }
                    if (v.vt == VT_DISPATCH && v.pdispVal) {
                        print_rule((INetFwRule *)v.pdispVal);
                        ((INetFwRule *)v.pdispVal)->lpVtbl->Release((INetFwRule *)v.pdispVal);
                        count++;
                    }
                    OLEAUT32$VariantClear(&v);
                    if (count >= 1000) break;
                }
                ev->lpVtbl->Release(ev);
            }
            unk->lpVtbl->Release(unk);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n%d rule(s)\n", count);
    rules->lpVtbl->Release(rules);
}

void go(char *args, int alen)
{
    datap parser;
    char *op = "", *a = "", *b = "", *c = "", *d = "", *e = "", *f = "";
    char bufs[7][1024];
    int i, len;
    HRESULT hr;
    int initialized = 0;
    INetFwPolicy2 *policy = NULL;

    for (i = 0; i < 7; i++) bufs[i][0] = 0;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        for (i = 0; i < 7; i++) {
            char *s = BeaconDataExtract(&parser, &len);
            if (s) bof_strncpy(bufs[i], s, sizeof(bufs[i]));
        }
        op = bufs[0]; a = bufs[1]; b = bufs[2]; c = bufs[3];
        d = bufs[4]; e = bufs[5]; f = bufs[6];
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) initialized = 1;

    hr = OLE32$CoCreateInstance(&GUID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER,
                                &GUID_INetFwPolicy2, (void **)&policy);
    if (FAILED(hr) || !policy) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(NetFwPolicy2) failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto done;
    }

    if (!op[0] || bof_stricmp(op, "add") == 0)
        do_add(policy, a, b, c, d, e, f);
    else if (bof_stricmp(op, "remove") == 0 || bof_stricmp(op, "del") == 0)
        do_remove(policy, a);
    else if (bof_stricmp(op, "list") == 0)
        do_list(policy, a);
    else
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: addfirewallrule <add|remove|list> [args]\n");

done:
    if (policy) policy->lpVtbl->Release(policy);
    if (initialized) OLE32$CoUninitialize();
}
