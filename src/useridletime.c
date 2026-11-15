/*
 * useridletime - seconds since the last keyboard/mouse input in this session.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    LASTINPUTINFO lii;
    unsigned long long now, idle;
    char buf[32];

    (void)args; (void)alen;

    bof_memzero(&lii, sizeof(lii));
    lii.cbSize = sizeof(lii);
    if (!USER32$GetLastInputInfo(&lii)) {
        BeaconPrintf(CALLBACK_ERROR, "GetLastInputInfo failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    now  = KERNEL32$GetTickCount64();
    idle = (unsigned int)now - lii.dwTime;

    bof_itoa(idle / 1000, buf);
    BeaconPrintf(CALLBACK_OUTPUT, "Session idle for %s second(s) (%llu ms)\n", buf, idle);
}
