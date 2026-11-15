/*
 * windowlist - list visible top-level windows and owning PIDs.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int g_count;

static BOOL CALLBACK enum_window(HWND hwnd, LPARAM lparam)
{
    char title[512];
    DWORD pid = 0;
    int len;
    (void)lparam;

    if (!USER32$IsWindowVisible(hwnd)) return TRUE;

    len = USER32$GetWindowTextLengthA(hwnd);
    if (len <= 0 || len >= (int)sizeof(title)) {
        len = USER32$GetWindowTextA(hwnd, title, sizeof(title) - 1);
    } else {
        USER32$GetWindowTextA(hwnd, title, sizeof(title) - 1);
    }
    title[sizeof(title) - 1] = 0;
    if (!title[0]) return TRUE;

    USER32$GetWindowThreadProcessId(hwnd, &pid);
    BeaconPrintf(CALLBACK_OUTPUT, "  [%5lu] %s\n", (unsigned long)pid, title);
    g_count++;
    return TRUE;
}

void go(char *args, int alen)
{
    (void)args; (void)alen;
    g_count = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "  %-7s %s\n", "PID", "Window title");
    BeaconPrintf(CALLBACK_OUTPUT, "  ------- ------------------------------\n");
    USER32$EnumWindows(enum_window, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "\nTotal: %d window(s)\n", g_count);
}
