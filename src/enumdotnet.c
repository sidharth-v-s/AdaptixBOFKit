/*
 * enumdotnet - find processes with the CLR loaded (assembly injection targets).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int is_clr(const char *m)
{
    return bof_stricmp(m, "mscoree.dll") == 0 ||
           bof_stricmp(m, "clr.dll") == 0 ||
           bof_stricmp(m, "coreclr.dll") == 0 ||
           bof_stricmp(m, "mscorwks.dll") == 0;
}

void go(char *args, int alen)
{
    HANDLE psnap, msnap;
    PROCESSENTRY32 pe;
    MODULEENTRY32 me;
    int hits = 0;

    (void)args; (void)alen;

    psnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (psnap == INVALID_HANDLE_VALUE) return;

    BeaconPrintf(CALLBACK_OUTPUT, "Processes with .NET loaded\n");
    bof_memzero(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (KERNEL32$Process32First(psnap, &pe)) {
        do {
            int found = 0;
            msnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                       pe.th32ProcessID);
            if (msnap == INVALID_HANDLE_VALUE) continue;

            bof_memzero(&me, sizeof(me));
            me.dwSize = sizeof(me);
            if (KERNEL32$Module32First(msnap, &me)) {
                do {
                    if (is_clr(me.szModule)) { found = 1; break; }
                } while (KERNEL32$Module32Next(msnap, &me));
            }
            KERNEL32$CloseHandle(msnap);

            if (found) {
                BeaconPrintf(CALLBACK_OUTPUT, "  PID %-6lu %s\n",
                             (unsigned long)pe.th32ProcessID, pe.szExeFile);
                hits++;
            }
        } while (KERNEL32$Process32Next(psnap, &pe));
    }

    KERNEL32$CloseHandle(psnap);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d\n", hits);
}
