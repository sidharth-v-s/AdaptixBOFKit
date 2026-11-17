/*
 * bof-patchwow64 <pid|exe> [dll-path]
 *
 * Restore the executable sections of a WOW64 module inside a live 32-bit
 * process from the on-disk copy.  By default the target module is
 * wow64cpu.dll, whose code is a common user-mode hook point; the file is read
 * from the target's own module path (falling back to
 * %SystemRoot%\SysWOW64\wow64cpu.dll).
 *
 * This removes inline hooks / patches in that module by rewriting its
 * executable sections with the clean image bytes.  It does not touch the
 * module's loaded image in other processes.  Requires PROCESS_VM_WRITE and
 * PROCESS_VM_OPERATION on the target (administrator / SeDebugPrivilege).
 *
 * Example: bof-patchwow64 4321
 *          bof-patchwow64 notepad.exe C:\Windows\SysWOW64\wow64cpu.dll
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *base_name(const char *path)
{
    const char *p = path, *last = path;
    for (; *p; p++)
        if (*p == '\\' || *p == '/') last = p + 1;
    return last;
}

static DWORD find_pid(const char *target)
{
    HANDLE snap;
    PROCESSENTRY32 pe;
    DWORD pid = 0;
    const char *want = base_name(target);

    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    bof_memzero(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (KERNEL32$Process32First(snap, &pe)) {
        do {
            if (bof_stricmp(pe.szExeFile, want) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (KERNEL32$Process32Next(snap, &pe));
    }
    KERNEL32$CloseHandle(snap);
    return pid;
}

static int find_module(DWORD pid, const char *dllname, unsigned long long *base,
                       unsigned int *size, char *path, int pathsz)
{
    HANDLE snap;
    MODULEENTRY32 me;
    int found = -1;

    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE |
                                             TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return -1;
    bof_memzero(&me, sizeof(me));
    me.dwSize = sizeof(me);
    if (KERNEL32$Module32First(snap, &me)) {
        do {
            if (bof_stricmp(me.szModule, dllname) == 0) {
                *base = (unsigned long long)(ULONG_PTR)me.modBaseAddr;
                *size = me.modBaseSize;
                bof_strncpy(path, me.szExePath, pathsz);
                found = 0;
                break;
            }
        } while (KERNEL32$Module32Next(snap, &me));
    }
    KERNEL32$CloseHandle(snap);
    return found;
}

void go(char *args, int alen)
{
    datap parser;
    char *target, *dllpath = "";
    int tlen, dlen;
    DWORD pid;
    HANDLE proc = NULL;
    BOOL wow = FALSE;
    unsigned long long modbase = 0;
    unsigned int modsize = 0;
    char modpath[MAX_PATH] = "";
    const char *dllname = "wow64cpu.dll";
    char disk[MAX_PATH], chosen[MAX_PATH];
    unsigned char *file = NULL;
    unsigned int filesize = 0;
    unsigned int peoff, optsize, nsect, i;
    unsigned int patched = 0, total = 0;

    BeaconDataParse(&parser, args, alen);
    target  = BeaconDataExtract(&parser, &tlen);
    dllpath = BeaconDataExtract(&parser, &dlen);
    if (!target || !target[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: patchwow64 <pid|exe> [dll-path]\n");
        return;
    }
    if (!dllpath) dllpath = "";

    if (target[0] >= '0' && target[0] <= '9') {
        pid = (DWORD)bof_atoi(target);
    } else {
        pid = find_pid(target);
        if (!pid) {
            BeaconPrintf(CALLBACK_ERROR, "process not found: %s\n", target);
            return;
        }
    }

    proc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                                FALSE, pid);
    if (!proc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess(%lu) failed: %lu\n",
                     (unsigned long)pid, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (!KERNEL32$IsWow64Process(proc, &wow) || !wow) {
        BeaconPrintf(CALLBACK_ERROR,
                     "pid %lu is not a WOW64 process (nothing to patch)\n",
                     (unsigned long)pid);
        KERNEL32$CloseHandle(proc);
        return;
    }

    if (find_module(pid, dllname, &modbase, &modsize, modpath,
                    sizeof(modpath)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "%s not loaded in pid %lu\n",
                     dllname, (unsigned long)pid);
        KERNEL32$CloseHandle(proc);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] pid %lu module %s @ 0x%llx (%u bytes)\n",
                 (unsigned long)pid, dllname, modbase, modsize);

    chosen[0] = 0;
    if (dllpath[0])
        bof_strncpy(chosen, dllpath, sizeof(chosen));
    else if (modpath[0] && KERNEL32$GetFileAttributesA(modpath) != INVALID_FILE_ATTRIBUTES)
        bof_strncpy(chosen, modpath, sizeof(chosen));
    else if (KERNEL32$ExpandEnvironmentStringsA(
                 "%SystemRoot%\\SysWOW64\\wow64cpu.dll", disk, sizeof(disk)))
        bof_strncpy(chosen, disk, sizeof(chosen));

    if (!chosen[0] ||
        KERNEL32$GetFileAttributesA(chosen) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_ERROR, "clean DLL not found (pass dll-path)\n");
        KERNEL32$CloseHandle(proc);
        return;
    }

    if (bof_read_file(chosen, &file, &filesize) != 0 || filesize < 0x200) {
        BeaconPrintf(CALLBACK_ERROR, "cannot read %s\n", chosen);
        if (file) KERNEL32$VirtualFree(file, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(proc);
        return;
    }
    if (file[0] != 'M' || file[1] != 'Z') {
        BeaconPrintf(CALLBACK_ERROR, "%s is not a PE file\n", chosen);
        KERNEL32$VirtualFree(file, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(proc);
        return;
    }

    peoff = ((unsigned int)file[0x3c]) | ((unsigned int)file[0x3d] << 8) |
            ((unsigned int)file[0x3e] << 16) | ((unsigned int)file[0x3f] << 24);
    if (peoff + 0x18 > filesize || file[peoff] != 'P' || file[peoff + 1] != 'E') {
        BeaconPrintf(CALLBACK_ERROR, "invalid PE headers in %s\n", chosen);
        KERNEL32$VirtualFree(file, 0, MEM_RELEASE);
        KERNEL32$CloseHandle(proc);
        return;
    }

    nsect = file[peoff + 6] | (file[peoff + 7] << 8);
    optsize = file[peoff + 20] | (file[peoff + 21] << 8);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] disk image: %s (%u sections)\n",
                 chosen, nsect);

    for (i = 0; i < nsect; i++) {
        unsigned int sh = peoff + 24 + optsize + i * 40;
        unsigned int vsize, vaddr, rawsize, rawptr, chars;
        unsigned long long dst;
        SIZE_T wrote = 0;
        DWORD oldprot = 0;

        if (sh + 40 > filesize) break;
        vsize   = file[sh + 8] | (file[sh + 9] << 8) |
                  (file[sh + 10] << 16) | (file[sh + 11] << 24);
        vaddr   = file[sh + 12] | (file[sh + 13] << 8) |
                  (file[sh + 14] << 16) | (file[sh + 15] << 24);
        rawsize = file[sh + 16] | (file[sh + 17] << 8) |
                  (file[sh + 18] << 16) | (file[sh + 19] << 24);
        rawptr  = file[sh + 20] | (file[sh + 21] << 8) |
                  (file[sh + 22] << 16) | (file[sh + 23] << 24);
        chars   = file[sh + 36] | (file[sh + 37] << 8) |
                  (file[sh + 38] << 16) | (file[sh + 39] << 24);

        if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!rawsize || !rawptr || rawptr + rawsize > filesize) continue;
        if (vsize && rawsize > vsize) continue;

        dst = modbase + vaddr;
        if (!KERNEL32$VirtualProtectEx(proc, (LPVOID)(ULONG_PTR)dst, rawsize,
                                       PAGE_EXECUTE_READWRITE, &oldprot)) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[!] VirtualProtectEx 0x%llx failed: %lu\n",
                         dst, (unsigned long)KERNEL32$GetLastError());
            continue;
        }
        if (KERNEL32$WriteProcessMemory(proc, (LPVOID)(ULONG_PTR)dst,
                                        file + rawptr, rawsize, &wrote)) {
            patched++;
            total += (unsigned int)wrote;
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] section %u: 0x%llx, %u bytes\n",
                         i, dst, (unsigned int)wrote);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[!] WriteProcessMemory 0x%llx failed: %lu\n",
                         dst, (unsigned long)KERNEL32$GetLastError());
        }
        KERNEL32$VirtualProtectEx(proc, (LPVOID)(ULONG_PTR)dst, rawsize,
                                  oldprot, &oldprot);
    }

    BeaconPrintf(CALLBACK_OUTPUT,
                 "\n[*] restored %u executable section(s), %u bytes\n",
                 patched, total);
    bof_memzero(file, filesize);
    KERNEL32$VirtualFree(file, 0, MEM_RELEASE);
    KERNEL32$CloseHandle(proc);
}
