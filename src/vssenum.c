/*
 * vssenum [list|providers]
 *
 * Enumerate Volume Shadow Copy snapshots or registered VSS providers.
 * Usually needs admin (Backup Operators).  Snapshots are useful for
 * reading locked files such as NTDS.dit, SAM and SYSTEM.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const GUID g_null_id = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };

static void guid_str(const GUID *g, char *out, int outsz)
{
    char *p = out;
    int i;

    if (outsz < 40) { bof_strncpy(out, "?", outsz); return; }
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

static const char *snap_state(VSS_SNAPSHOT_STATE s)
{
    switch (s) {
    case VSS_SS_PREPARING:         return "preparing";
    case VSS_SS_PROCESSING_PREPARE:return "processing-prepare";
    case VSS_SS_PREPARED:          return "prepared";
    case VSS_SS_PROCESSING_PRECOMMIT: return "processing-precommit";
    case VSS_SS_PRECOMMITTED:      return "precommitted";
    case VSS_SS_PROCESSING_COMMIT: return "processing-commit";
    case VSS_SS_COMMITTED:         return "committed";
    case VSS_SS_PROCESSING_POSTCOMMIT: return "processing-postcommit";
    case VSS_SS_CREATED:           return "created";
    case VSS_SS_ABORTED:           return "aborted";
    case VSS_SS_DELETED:           return "deleted";
    default:                       return "unknown";
    }
}

static const char *prov_type(VSS_PROVIDER_TYPE t)
{
    switch (t) {
    case VSS_PROV_SYSTEM:   return "system";
    case VSS_PROV_SOFTWARE: return "software";
    case VSS_PROV_HARDWARE: return "hardware";
    case VSS_PROV_FILESHARE:return "fileshare";
    default:                return "unknown";
    }
}

static void enum_snapshots(IVssBackupComponents *vbc)
{
    IVssEnumObject *en = NULL;
    VSS_OBJECT_PROP prop;
    ULONG fetched = 0;
    HRESULT hr;
    int count = 0;

    hr = vbc->lpVtbl->Query(vbc, g_null_id, VSS_OBJECT_NONE,
                            VSS_OBJECT_SNAPSHOT, &en);
    if (FAILED(hr) || !en) {
        BeaconPrintf(CALLBACK_ERROR, "VSS Query failed: 0x%08lx\n",
                     (unsigned long)hr);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Shadow copies\n");
    while (en->lpVtbl->Next(en, 1, &prop, &fetched) == S_OK && fetched == 1) {
        VSS_SNAPSHOT_PROP *s = &prop.Obj.Snap;
        char id[64], volume[512], device[512], machine[256];
        SYSTEMTIME st;

        guid_str(&s->m_SnapshotId, id, sizeof(id));
        volume[0] = device[0] = machine[0] = 0;
        if (s->m_pwszOriginalVolumeName)
            bof_w2a(s->m_pwszOriginalVolumeName, volume, sizeof(volume));
        if (s->m_pwszSnapshotDeviceObject)
            bof_w2a(s->m_pwszSnapshotDeviceObject, device, sizeof(device));
        if (s->m_pwszOriginatingMachine)
            bof_w2a(s->m_pwszOriginatingMachine, machine, sizeof(machine));

        bof_memzero(&st, sizeof(st));
        KERNEL32$FileTimeToSystemTime((const FILETIME *)&s->m_tsCreationTimestamp, &st);

        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", id);
        BeaconPrintf(CALLBACK_OUTPUT, "    volume   : %s\n", volume);
        BeaconPrintf(CALLBACK_OUTPUT, "    device   : %s\n", device);
        BeaconPrintf(CALLBACK_OUTPUT, "    machine  : %s\n", machine);
        BeaconPrintf(CALLBACK_OUTPUT, "    created  : %04u-%02u-%02u %02u:%02u:%02u\n",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        BeaconPrintf(CALLBACK_OUTPUT, "    state    : %s\n", snap_state(s->m_eStatus));

        VSSAPI$VssFreeSnapshotPropertiesInternal(s);
        count++;
    }
    en->lpVtbl->Release(en);
    BeaconPrintf(CALLBACK_OUTPUT, "\n%d snapshot(s)\n", count);
}

static void enum_providers(IVssBackupComponents *vbc)
{
    IVssEnumObject *en = NULL;
    VSS_OBJECT_PROP prop;
    ULONG fetched = 0;
    HRESULT hr;
    int count = 0;

    hr = vbc->lpVtbl->Query(vbc, g_null_id, VSS_OBJECT_NONE,
                            VSS_OBJECT_PROVIDER, &en);
    if (FAILED(hr) || !en) {
        BeaconPrintf(CALLBACK_ERROR, "VSS provider query failed: 0x%08lx\n",
                     (unsigned long)hr);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "VSS providers\n");
    while (en->lpVtbl->Next(en, 1, &prop, &fetched) == S_OK && fetched == 1) {
        VSS_PROVIDER_PROP *p = &prop.Obj.Prov;
        char name[256], ver[128], id[64];

        name[0] = ver[0] = 0;
        if (p->m_pwszProviderName)
            bof_w2a(p->m_pwszProviderName, name, sizeof(name));
        if (p->m_pwszProviderVersion)
            bof_w2a(p->m_pwszProviderVersion, ver, sizeof(ver));
        guid_str(&p->m_ProviderId, id, sizeof(id));

        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", name[0] ? name : "(unnamed)");
        BeaconPrintf(CALLBACK_OUTPUT, "    type     : %s\n", prov_type(p->m_eProviderType));
        BeaconPrintf(CALLBACK_OUTPUT, "    version  : %s\n", ver[0] ? ver : "-");
        BeaconPrintf(CALLBACK_OUTPUT, "    provider : %s\n", id);
        count++;
    }
    en->lpVtbl->Release(en);
    BeaconPrintf(CALLBACK_OUTPUT, "\n%d provider(s)\n", count);
}

void go(char *args, int alen)
{
    datap parser;
    char *op = "", opbuf[32];
    int len, providers = 0;
    HRESULT hr;
    int initialized = 0;
    IVssBackupComponents *vbc = NULL;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        op = BeaconDataExtract(&parser, &len);
        if (op) bof_strncpy(opbuf, op, sizeof(opbuf)); else opbuf[0] = 0;
        op = opbuf;
    }
    if (op[0] && (bof_stricmp(op, "providers") == 0 ||
                  bof_stricmp(op, "provider") == 0))
        providers = 1;

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) initialized = 1;

    hr = VSSAPI$CreateVssBackupComponentsInternal(&vbc);
    if (FAILED(hr) || !vbc) {
        BeaconPrintf(CALLBACK_ERROR, "CreateVssBackupComponents failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto done;
    }

    hr = vbc->lpVtbl->InitializeForBackup(vbc, NULL);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "InitializeForBackup failed: 0x%08lx (admin?)\n",
                     (unsigned long)hr);
        goto done;
    }
    vbc->lpVtbl->SetContext(vbc, VSS_CTX_BACKUP);

    if (providers) enum_providers(vbc);
    else           enum_snapshots(vbc);

done:
    if (vbc) vbc->lpVtbl->Release(vbc);
    if (initialized) OLE32$CoUninitialize();
}
