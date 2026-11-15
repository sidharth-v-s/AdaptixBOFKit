/*
 * findmodule <dll> - processes that have a module loaded (substring match).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *needle;
    int nlen = 0, hits = 0;
    HANDLE psnap, msnap;
    PROCESSENTRY32 pe;
    MODULEENTRY32 me;

    BeaconDataParse(&parser, args, alen);
    needle = BeaconDataExtract(&parser, &nlen);
    if (!needle || !needle[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: findmodule <dll.dll>\n");
        return;
    }

    psnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (psnap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "process snapshot failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Processes with module matching \"%s\":\n", needle);

    bof_memzero(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (KERNEL32$Process32First(psnap, &pe)) {
        do {
            msnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                       pe.th32ProcessID);
            if (msnap == INVALID_HANDLE_VALUE) continue;

            bof_memzero(&me, sizeof(me));
            me.dwSize = sizeof(me);
            if (KERNEL32$Module32First(msnap, &me)) {
                do {
                    if (bof_strstr(me.szModule, needle) || bof_strstr(me.szExePath, needle)) {
                        BeaconPrintf(CALLBACK_OUTPUT, "  PID %-6lu %-24s %s\n",
                                     (unsigned long)pe.th32ProcessID,
                                     me.szModule, me.szExePath);
                        hits++;
                    }
                } while (KERNEL32$Module32Next(msnap, &me));
            }
            KERNEL32$CloseHandle(msnap);
        } while (KERNEL32$Process32Next(psnap, &pe));
    }
    KERNEL32$CloseHandle(psnap);

    BeaconPrintf(CALLBACK_OUTPUT, "\nMatches: %d\n", hits);
}
