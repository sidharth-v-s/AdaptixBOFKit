/*
 * schtasks <enum|query|create|delete|run> [args]
 *
 * Task Scheduler operations through the ITaskService COM API.
 *   enum [folder]                 - list tasks (hidden included)
 *   query <task path>             - show state and XML for one task
 *   create <name> <command> [args]- register a logon-triggered task
 *   delete <task path>            - remove a task
 *   run <task path>               - start a task on demand
 *
 * create writes an XML definition and calls RegisterTask, so no
 * ITaskDefinition interface work is needed.  It needs the rights to write
 * under the target task folder (admin for the root folder).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static ITaskService *g_svc;
static int g_shown;

/* Local copies: the MinGW headers only declare these as extern. */
static const GUID GUID_TaskScheduler =
    { 0x0f87369f, 0xa4e5, 0x4cfc,
      { 0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd } };
static const GUID GUID_ITaskService =
    { 0x2faba4c7, 0x4da9, 0x4013,
      { 0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85 } };

static const char *state_name(TASK_STATE s)
{
    switch (s) {
    case TASK_STATE_UNKNOWN:  break;
    case TASK_STATE_DISABLED: return "Disabled";
    case TASK_STATE_QUEUED:   return "Queued";
    case TASK_STATE_READY:    return "Ready";
    case TASK_STATE_RUNNING:  return "Running";
    }
    return "Unknown";
}

static VARIANT var_int(LONG v)
{
    VARIANT r;
    OLEAUT32$VariantInit(&r);
    r.vt = VT_I4;
    r.lVal = v;
    return r;
}

static VARIANT var_empty(void)
{
    VARIANT r;
    OLEAUT32$VariantInit(&r);
    r.vt = VT_EMPTY;
    return r;
}

static void print_task(IRegisteredTask *t, const char *folder)
{
    BSTR name = NULL;
    TASK_STATE st = TASK_STATE_UNKNOWN;
    char name_a[256] = "(?)";

    if (g_shown >= 500) return;
    t->lpVtbl->get_Name(t, &name);
    t->lpVtbl->get_State(t, &st);
    if (name) bof_w2a(name, name_a, sizeof(name_a));
    BeaconPrintf(CALLBACK_OUTPUT, "  %-58s %-8s %s\n",
                 name_a, state_name(st), folder);
    if (name) OLEAUT32$SysFreeString(name);
    g_shown++;
}

static void walk_folder(ITaskFolder *folder, int depth)
{
    BSTR fpath = NULL;
    IRegisteredTaskCollection *tasks = NULL;
    ITaskFolderCollection *subs = NULL;
    LONG count = 0, i;
    char folder_a[512] = "";

    if (depth > 8) return;
    folder->lpVtbl->get_Path(folder, &fpath);
    if (fpath) bof_w2a(fpath, folder_a, sizeof(folder_a));

    if (SUCCEEDED(folder->lpVtbl->GetTasks(folder, TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        tasks->lpVtbl->get_Count(tasks, &count);
        for (i = 0; i < count; i++) {
            IRegisteredTask *t = NULL;
            VARIANT idx = var_int(i);
            if (SUCCEEDED(tasks->lpVtbl->get_Item(tasks, idx, &t)) && t) {
                print_task(t, folder_a);
                t->lpVtbl->Release(t);
            }
        }
        tasks->lpVtbl->Release(tasks);
    }

    count = 0;
    if (SUCCEEDED(folder->lpVtbl->GetFolders(folder, 0, &subs)) && subs) {
        subs->lpVtbl->get_Count(subs, &count);
        for (i = 0; i < count; i++) {
            ITaskFolder *sub = NULL;
            VARIANT idx = var_int(i);
            if (SUCCEEDED(subs->lpVtbl->get_Item(subs, idx, &sub)) && sub) {
                walk_folder(sub, depth + 1);
                sub->lpVtbl->Release(sub);
            }
        }
        subs->lpVtbl->Release(subs);
    }

    if (fpath) OLEAUT32$SysFreeString(fpath);
}

static void do_enum(const char *folder)
{
    BSTR bp = NULL;
    ITaskFolder *root = NULL;
    wchar_t wpath[512];

    if (!folder || !folder[0]) folder = "\\";
    bof_a2w(folder, wpath, 512);
    bp = OLEAUT32$SysAllocString(wpath);
    if (!bp) return;

    if (SUCCEEDED(g_svc->lpVtbl->GetFolder(g_svc, bp, &root)) && root) {
        BeaconPrintf(CALLBACK_OUTPUT, "%-60s %-8s %s\n", "Task", "State", "Folder");
        g_shown = 0;
        walk_folder(root, 0);
        root->lpVtbl->Release(root);
        BeaconPrintf(CALLBACK_OUTPUT, "\n%d task(s)\n", g_shown);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "GetFolder(%s) failed\n",
                     folder && folder[0] ? folder : "\\");
    }
    OLEAUT32$SysFreeString(bp);
}

static void do_query(const char *path)
{
    BSTR bp;
    ITaskFolder *root = NULL;
    IRegisteredTask *t = NULL;
    BSTR bpath = NULL, bxml = NULL, bname = NULL;
    TASK_STATE st = TASK_STATE_UNKNOWN;
    wchar_t wpath[512], wroot[] = L"\\";
    char name_a[256] = "?";

    if (!path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: schtasks query <task path>\n");
        return;
    }

    bof_a2w(path, wpath, 512);
    bp = OLEAUT32$SysAllocString(wroot);
    if (!bp) return;
    if (!SUCCEEDED(g_svc->lpVtbl->GetFolder(g_svc, bp, &root)) || !root) {
        BeaconPrintf(CALLBACK_ERROR, "cannot open root task folder\n");
        OLEAUT32$SysFreeString(bp);
        return;
    }
    OLEAUT32$SysFreeString(bp);

    bpath = OLEAUT32$SysAllocString(wpath);
    if (bpath && SUCCEEDED(root->lpVtbl->GetTask(root, bpath, &t)) && t) {
        t->lpVtbl->get_Name(t, &bname);
        if (bname) bof_w2a(bname, name_a, sizeof(name_a));
        BeaconPrintf(CALLBACK_OUTPUT, "Name : %s\n", name_a);
        if (bname) { OLEAUT32$SysFreeString(bname); bname = NULL; }
        t->lpVtbl->get_State(t, &st);
        BeaconPrintf(CALLBACK_OUTPUT, "State: %s\n\n", state_name(st));

        if (SUCCEEDED(t->lpVtbl->get_Xml(t, &bxml)) && bxml) {
            char *ansi = (char *)KERNEL32$VirtualAlloc(NULL, OLEAUT32$SysStringLen(bxml) * 3 + 4,
                                                       MEM_COMMIT | MEM_RESERVE,
                                                       PAGE_READWRITE);
            if (ansi) {
                bof_w2a(bxml, ansi, (int)(OLEAUT32$SysStringLen(bxml) * 3 + 2));
                BeaconPrintf(CALLBACK_OUTPUT, "%s\n", ansi);
                KERNEL32$VirtualFree(ansi, 0, MEM_RELEASE);
            }
            OLEAUT32$SysFreeString(bxml);
        }
        t->lpVtbl->Release(t);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "task not found: %s\n", path);
    }

    if (bpath) OLEAUT32$SysFreeString(bpath);
    root->lpVtbl->Release(root);
}

struct sb { char *buf; int cap; int len; };

static void sb_add(struct sb *s, const char *t)
{
    while (*t && s->len < s->cap - 1) s->buf[s->len++] = *t++;
    s->buf[s->len] = 0;
}

static void sb_xml(struct sb *s, const char *t)
{
    while (*t && s->len < s->cap - 7) {
        switch (*t) {
        case '&':  sb_add(s, "&amp;"); break;
        case '<':  sb_add(s, "&lt;");  break;
        case '>':  sb_add(s, "&gt;");  break;
        case '"':  sb_add(s, "&quot;");break;
        case '\'': sb_add(s, "&apos;");break;
        default:   s->buf[s->len++] = *t; s->buf[s->len] = 0;
        }
        t++;
    }
}

static void do_create(const char *name, const char *command, const char *cargs)
{
    char xmlbuf[4096];
    struct sb s;
    wchar_t wname[256], wxml[4096];
    BSTR bname, bxml;
    ITaskFolder *root = NULL;
    IRegisteredTask *t = NULL;
    VARIANT e1, e2, e3;
    wchar_t wroot[] = L"\\";
    BSTR broot;

    if (!name || !name[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: schtasks create <name> <command> [arguments]\n");
        return;
    }

    s.buf = xmlbuf; s.cap = sizeof(xmlbuf); s.len = 0; xmlbuf[0] = 0;
    sb_add(&s, "<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
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
               "<Enabled>true</Enabled><Hidden>false</Hidden>"
               "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>"
               "<Actions Context=\"Author\"><Exec><Command>");
    sb_xml(&s, command);
    sb_add(&s, "</Command><Arguments>");
    if (cargs) sb_xml(&s, cargs);
    sb_add(&s, "</Arguments></Exec></Actions></Task>");

    bof_a2w(name, wname, 256);
    bof_a2w(xmlbuf, wxml, 4096);
    bname = OLEAUT32$SysAllocString(wname);
    bxml  = OLEAUT32$SysAllocString(wxml);
    broot = OLEAUT32$SysAllocString(wroot);
    if (!bname || !bxml || !broot) goto done;

    if (!SUCCEEDED(g_svc->lpVtbl->GetFolder(g_svc, broot, &root)) || !root) {
        BeaconPrintf(CALLBACK_ERROR, "cannot open root task folder\n");
        goto done;
    }

    e1 = var_empty(); e2 = var_empty(); e3 = var_empty();
    if (SUCCEEDED(root->lpVtbl->RegisterTask(root, bname, bxml,
                                             TASK_CREATE_OR_UPDATE, e1, e2,
                                             TASK_LOGON_INTERACTIVE_TOKEN, e3,
                                             &t))) {
        BeaconPrintf(CALLBACK_OUTPUT, "Registered task: %s\n  command: %s %s\n",
                     name, command, cargs ? cargs : "");
        if (t) t->lpVtbl->Release(t);
    } else {
        BeaconPrintf(CALLBACK_ERROR,
                     "RegisterTask failed (admin required for root folder?)\n");
    }

done:
    if (root) root->lpVtbl->Release(root);
    if (bname) OLEAUT32$SysFreeString(bname);
    if (bxml)  OLEAUT32$SysFreeString(bxml);
    if (broot) OLEAUT32$SysFreeString(broot);
}

static void do_delete(const char *path)
{
    BSTR broot, bpath;
    ITaskFolder *root = NULL;
    wchar_t wpath[512];
    wchar_t wroot[] = L"\\";

    if (!path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: schtasks delete <task path>\n");
        return;
    }
    bof_a2w(path, wpath, 512);
    broot = OLEAUT32$SysAllocString(wroot);
    bpath = OLEAUT32$SysAllocString(wpath);
    if (!broot || !bpath) goto done;

    if (!SUCCEEDED(g_svc->lpVtbl->GetFolder(g_svc, broot, &root)) || !root) {
        BeaconPrintf(CALLBACK_ERROR, "cannot open root task folder\n");
        goto done;
    }
    if (SUCCEEDED(root->lpVtbl->DeleteTask(root, bpath, 0)))
        BeaconPrintf(CALLBACK_OUTPUT, "Deleted task: %s\n", path);
    else
        BeaconPrintf(CALLBACK_ERROR, "DeleteTask failed: %s\n", path);

done:
    if (root) root->lpVtbl->Release(root);
    if (broot) OLEAUT32$SysFreeString(broot);
    if (bpath) OLEAUT32$SysFreeString(bpath);
}

static void do_run(const char *path)
{
    BSTR broot, bpath;
    ITaskFolder *root = NULL;
    IRegisteredTask *t = NULL;
    IRunningTask *rt = NULL;
    wchar_t wpath[512];
    wchar_t wroot[] = L"\\";

    if (!path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: schtasks run <task path>\n");
        return;
    }
    bof_a2w(path, wpath, 512);
    broot = OLEAUT32$SysAllocString(wroot);
    bpath = OLEAUT32$SysAllocString(wpath);
    if (!broot || !bpath) goto done;

    if (!SUCCEEDED(g_svc->lpVtbl->GetFolder(g_svc, broot, &root)) || !root)
        goto done;
    if (SUCCEEDED(root->lpVtbl->GetTask(root, bpath, &t)) && t) {
        VARIANT p = var_empty();
        if (SUCCEEDED(t->lpVtbl->Run(t, p, &rt))) {
            BeaconPrintf(CALLBACK_OUTPUT, "Started task: %s\n", path);
            if (rt) rt->lpVtbl->Release(rt);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Run failed: %s\n", path);
        }
        t->lpVtbl->Release(t);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "task not found: %s\n", path);
    }

done:
    if (root) root->lpVtbl->Release(root);
    if (broot) OLEAUT32$SysFreeString(broot);
    if (bpath) OLEAUT32$SysFreeString(bpath);
}

void go(char *args, int alen)
{
    datap parser;
    char *op = "", *a = "", *b = "", *c = "";
    char opbuf[32], abuf[512], bbuf[1024], cbuf[1024];
    int len;
    HRESULT hr;
    int initialized = 0;
    VARIANT e;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        op = BeaconDataExtract(&parser, &len);
        if (op) bof_strncpy(opbuf, op, sizeof(opbuf)); else opbuf[0] = 0;
        a = BeaconDataExtract(&parser, &len);
        if (a) bof_strncpy(abuf, a, sizeof(abuf)); else abuf[0] = 0;
        b = BeaconDataExtract(&parser, &len);
        if (b) bof_strncpy(bbuf, b, sizeof(bbuf)); else bbuf[0] = 0;
        c = BeaconDataExtract(&parser, &len);
        if (c) bof_strncpy(cbuf, c, sizeof(cbuf)); else cbuf[0] = 0;
        op = opbuf; a = abuf; b = bbuf; c = cbuf;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) initialized = 1;
    else if (hr != (HRESULT)0x80010106L) {   /* RPC_E_CHANGED_MODE */
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx\n",
                     (unsigned long)hr);
        return;
    }

    hr = OLE32$CoCreateInstance(&GUID_TaskScheduler, NULL,
                                CLSCTX_INPROC_SERVER, &GUID_ITaskService,
                                (void **)&g_svc);
    if (FAILED(hr) || !g_svc) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(TaskScheduler) failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto done;
    }

    e = var_empty();
    hr = g_svc->lpVtbl->Connect(g_svc, e, e, e, e);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService::Connect failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto done;
    }

    if (!op[0] || bof_stricmp(op, "enum") == 0 || bof_stricmp(op, "list") == 0)
        do_enum(a);
    else if (bof_stricmp(op, "query") == 0)
        do_query(a);
    else if (bof_stricmp(op, "create") == 0)
        do_create(a, b, c);
    else if (bof_stricmp(op, "delete") == 0 || bof_stricmp(op, "del") == 0)
        do_delete(a);
    else if (bof_stricmp(op, "run") == 0 || bof_stricmp(op, "start") == 0)
        do_run(a);
    else
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: schtasks <enum|query|create|delete|run> [args]\n");

done:
    if (g_svc) { g_svc->lpVtbl->Release(g_svc); g_svc = NULL; }
    if (initialized) OLE32$CoUninitialize();
}
