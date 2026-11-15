/*
 * evtxsearch <channel> [xpath] [max] - query an event log channel and render XML.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *channel, *xpath = "", *maxarg = "";
    int clen, xlen = 0, mlen = 0, maxev = 10;
    wchar_t wch[256], wxpath[1024];
    EVT_HANDLE query, events[8];
    int shown = 0;

    BeaconDataParse(&parser, args, alen);
    channel = BeaconDataExtract(&parser, &clen);
    xpath   = BeaconDataExtract(&parser, &xlen);
    maxarg  = BeaconDataExtract(&parser, &mlen);
    if (!channel || !channel[0]) {
        BeaconPrintf(CALLBACK_ERROR, "usage: evtxsearch <channel> [xpath] [max]\n");
        return;
    }
    if (!xpath) xpath = "";
    if (maxarg && maxarg[0]) maxev = bof_atoi(maxarg);
    if (maxev <= 0) maxev = 10;
    if (maxev > 200) maxev = 200;

    bof_a2w(channel, wch, 256);
    if (xpath[0]) bof_a2w(xpath, wxpath, 1024);
    else wxpath[0] = 0;

    query = WEVTAPI$EvtQuery(NULL, wch,
                             xpath[0] ? wxpath : L"*",
                             EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!query) {
        BeaconPrintf(CALLBACK_ERROR, "EvtQuery(%s) failed: %lu\n",
                     channel, (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Querying %s (max %d)\n\n", channel, maxev);
    while (shown < maxev) {
        DWORD returned = 0, used = 0, props = 0;
        PVOID out = NULL;
        char *ansi;

        if (!WEVTAPI$EvtNext(query, 1, events, 1000, 0, &returned) || returned == 0)
            break;

        if (!WEVTAPI$EvtRender(NULL, events[0], EvtRenderEventXml, 0, NULL, &used, &props) &&
            KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER && used) {
            out = KERNEL32$VirtualAlloc(NULL, used + 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (out && WEVTAPI$EvtRender(NULL, events[0], EvtRenderEventXml,
                                         used, out, &used, &props)) {
                ansi = (char *)KERNEL32$VirtualAlloc(NULL, used * 3 + 2,
                                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (ansi) {
                    int n = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)out, -1,
                                                          ansi, (int)(used * 3), NULL, NULL);
                    if (n > 0) {
                        int cut = 0;
                        if (n > 1500) { ansi[1500] = 0; cut = 1; }
                        BeaconPrintf(CALLBACK_OUTPUT, "%s%s\n", ansi,
                                     cut ? " ..." : "");
                        shown++;
                    }
                    KERNEL32$VirtualFree(ansi, 0, MEM_RELEASE);
                }
            }
        }
        if (out) KERNEL32$VirtualFree(out, 0, MEM_RELEASE);
        WEVTAPI$EvtClose(events[0]);
    }

    WEVTAPI$EvtClose(query);
    BeaconPrintf(CALLBACK_OUTPUT, "\nEvents shown: %d\n", shown);
}
