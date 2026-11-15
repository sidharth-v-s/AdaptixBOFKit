/*
 * netuse <\\\\host\\share> [user] [password] - map a remote share.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *share, *user = "", *pass = "";
    int slen = 0, ulen = 0, plen = 0;
    NETRESOURCEA nr;
    DWORD rc;

    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "usage: netuse <\\\\host\\share> [user] [password]\n");
        return;
    }

    BeaconDataParse(&parser, args, alen);
    share = BeaconDataExtract(&parser, &slen);
    user = BeaconDataExtract(&parser, &ulen);
    pass = BeaconDataExtract(&parser, &plen);
    if (!share) return;
    if (!user) user = "";
    if (!pass) pass = "";

    bof_memzero(&nr, sizeof(nr));
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = share;

    rc = MPR$WNetAddConnection2A(&nr, pass[0] ? pass : NULL,
                                 user[0] ? user : NULL, 0);
    if (rc == NO_ERROR)
        BeaconPrintf(CALLBACK_OUTPUT, "Mapped %s%s%s\n", share,
                     user[0] ? " as " : "", user[0] ? user : "");
    else
        BeaconPrintf(CALLBACK_ERROR, "WNetAddConnection2 failed: %lu\n", (unsigned long)rc);
}
