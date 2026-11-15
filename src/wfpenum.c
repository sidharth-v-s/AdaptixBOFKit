/*
 * wfpenum [filters|sublayers|all]
 *
 * Enumerate Windows Filtering Platform filters and sublayers.  Filter
 * names, actions and weights make it easy to spot third-party firewalls,
 * EDR network hooks and the rules an implant would need to blend in with.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

static const char *action_name(UINT32 type)
{
    switch (type) {
    case FWP_ACTION_BLOCK:               return "BLOCK";
    case FWP_ACTION_PERMIT:              return "PERMIT";
    case FWP_ACTION_CALLOUT_TERMINATING: return "CALLOUT-TERM";
    case FWP_ACTION_CALLOUT_INSPECTION:  return "CALLOUT-INSPECT";
    case FWP_ACTION_CALLOUT_UNKNOWN:     return "CALLOUT";
    case FWP_ACTION_CONTINUE:            return "CONTINUE";
    }
    return "OTHER";
}

static void guid_str(const GUID *g, char *out)
{
    char *p = out;
    int i;
    *p++ = '{';
    bof_hex(g->Data1, 8, p); p += 8; *p++ = '-';
    bof_hex(g->Data2, 4, p); p += 4; *p++ = '-';
    bof_hex(g->Data3, 4, p); p += 4; *p++ = '-';
    for (i = 0; i < 2; i++) { bof_hex(g->Data4[i], 2, p); p += 2; }
    *p++ = '-';
    for (i = 2; i < 8; i++) { bof_hex(g->Data4[i], 2, p); p += 2; }
    *p++ = '}';
    *p = 0;
}

static void value_str(const FWP_VALUE0 *v, char *out, int outsz)
{
    unsigned long long n = 0;

    switch (v->type) {
    case FWP_UINT8:  n = v->uint8;  break;
    case FWP_UINT16: n = v->uint16; break;
    case FWP_UINT32: n = v->uint32; break;
    case FWP_UINT64: n = v->uint64 ? *v->uint64 : 0; break;
    default: bof_strncpy(out, "-", outsz); return;
    }
    bof_itoa(n, out);
}

static void wide_str(const wchar_t *src, char *dst, int dstsz)
{
    if (src) bof_w2a(src, dst, dstsz);
    else dst[0] = 0;
}

static void enum_filters(HANDLE engine)
{
    HANDLE eh = NULL;
    FWPM_FILTER0 **entries = NULL;
    UINT32 n = 0, i;
    DWORD rc;
    int shown = 0;

    rc = FWPUCLNT$FwpmFilterCreateEnumHandle0(engine, NULL, &eh);
    if (rc != 0 || !eh) {
        BeaconPrintf(CALLBACK_ERROR, "FwpmFilterCreateEnumHandle failed: %lu\n",
                     (unsigned long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "WFP filters\n");
    for (;;) {
        n = 0;
        entries = NULL;
        rc = FWPUCLNT$FwpmFilterEnum0(engine, eh, 50, &entries, &n);
        if (rc != 0 || n == 0) break;

        for (i = 0; i < n; i++) {
            FWPM_FILTER0 *f = entries[i];
            char name[256], desc[256], layer[64], sublayer[64], weight[32];

            wide_str(f->displayData.name, name, sizeof(name));
            wide_str(f->displayData.description, desc, sizeof(desc));
            guid_str(&f->layerKey, layer);
            guid_str(&f->subLayerKey, sublayer);
            value_str(&f->weight, weight, sizeof(weight));

            BeaconPrintf(CALLBACK_OUTPUT,
                         "  id=%-6llu %-8s %-6s layer=%s sub=%s\n",
                         (unsigned long long)f->filterId,
                         action_name(f->action.type), weight, layer, sublayer);
            if (name[0])
                BeaconPrintf(CALLBACK_OUTPUT, "    name : %s\n", name);
            if (desc[0])
                BeaconPrintf(CALLBACK_OUTPUT, "    desc : %s\n", desc);

            shown++;
            if (shown >= 400) {
                BeaconPrintf(CALLBACK_OUTPUT, "  ... truncated\n");
                break;
            }
        }
        FWPUCLNT$FwpmFreeMemory0((void **)&entries);
        if (shown >= 400) break;
    }

    FWPUCLNT$FwpmFilterDestroyEnumHandle0(engine, eh);
    BeaconPrintf(CALLBACK_OUTPUT, "  %d filter(s)\n\n", shown);
}

static void enum_sublayers(HANDLE engine)
{
    HANDLE eh = NULL;
    FWPM_SUBLAYER0 **entries = NULL;
    UINT32 n = 0, i;
    DWORD rc;
    int shown = 0;

    rc = FWPUCLNT$FwpmSubLayerCreateEnumHandle0(engine, NULL, &eh);
    if (rc != 0 || !eh) {
        BeaconPrintf(CALLBACK_ERROR, "FwpmSubLayerCreateEnumHandle failed: %lu\n",
                     (unsigned long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "WFP sublayers\n");
    for (;;) {
        n = 0;
        entries = NULL;
        rc = FWPUCLNT$FwpmSubLayerEnum0(engine, eh, 50, &entries, &n);
        if (rc != 0 || n == 0) break;

        for (i = 0; i < n; i++) {
            FWPM_SUBLAYER0 *s = entries[i];
            char name[256], key[64];

            wide_str(s->displayData.name, name, sizeof(name));
            guid_str(&s->subLayerKey, key);
            BeaconPrintf(CALLBACK_OUTPUT, "  %s  weight=%u  %s\n",
                         key, (unsigned)s->weight, name[0] ? name : "(unnamed)");
            shown++;
        }
        FWPUCLNT$FwpmFreeMemory0((void **)&entries);
    }

    FWPUCLNT$FwpmSubLayerDestroyEnumHandle0(engine, eh);
    BeaconPrintf(CALLBACK_OUTPUT, "  %d sublayer(s)\n\n", shown);
}

void go(char *args, int alen)
{
    datap parser;
    char *op = "", opbuf[32];
    int len;
    int filters = 1, sublayers = 1;
    HANDLE engine = NULL;
    FWPM_SESSION0 session;
    DWORD rc;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        op = BeaconDataExtract(&parser, &len);
        if (op) bof_strncpy(opbuf, op, sizeof(opbuf)); else opbuf[0] = 0;
        op = opbuf;
    }

    if (op[0] && bof_stricmp(op, "all") != 0) {
        filters   = bof_stricmp(op, "filters") == 0 || bof_stricmp(op, "filter") == 0;
        sublayers = bof_stricmp(op, "sublayers") == 0 || bof_stricmp(op, "sublayer") == 0;
        if (!filters && !sublayers) {
            BeaconPrintf(CALLBACK_ERROR,
                         "usage: wfpenum [filters|sublayers|all]\n");
            return;
        }
    }

    bof_memzero(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    rc = FWPUCLNT$FwpmEngineOpen0(NULL, 10 /* RPC_C_AUTHN_WINNT */, NULL,
                                  &session, &engine);
    if (rc != 0 || !engine) {
        BeaconPrintf(CALLBACK_ERROR,
                     "FwpmEngineOpen failed: %lu (admin required)\n",
                     (unsigned long)rc);
        return;
    }

    if (filters)   enum_filters(engine);
    if (sublayers) enum_sublayers(engine);

    FWPUCLNT$FwpmEngineClose0(engine);
}
