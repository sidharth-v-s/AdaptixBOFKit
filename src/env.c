/*
 * env - dump the agent process environment block.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    char *env = KERNEL32$GetEnvironmentStringsA();
    char *p;
    (void)args; (void)alen;

    if (!env) {
        BeaconPrintf(CALLBACK_ERROR, "GetEnvironmentStringsA failed\n");
        return;
    }

    for (p = env; *p; p += bof_strlen(p) + 1)
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", p);

    KERNEL32$FreeEnvironmentStringsA(env);
}
