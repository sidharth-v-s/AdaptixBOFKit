/*
 * locale - system and user locale information.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void loc(LCID lcid, LCTYPE type, const char *label)
{
    char buf[256];
    if (KERNEL32$GetLocaleInfoA(lcid, type, buf, sizeof(buf)))
        BeaconPrintf(CALLBACK_OUTPUT, "  %-18s %s\n", label, buf);
}

void go(char *args, int alen)
{
    LCID sys = KERNEL32$GetSystemDefaultLCID();
    LCID usr = KERNEL32$GetUserDefaultLCID();
    (void)args; (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "System LCID : 0x%08lx\n", (unsigned long)sys);
    loc(sys, LOCALE_SLOCALIZEDDISPLAYNAME, "Display name");
    loc(sys, LOCALE_SISO639LANGNAME, "ISO language");
    loc(sys, LOCALE_SISO3166CTRYNAME, "ISO country");
    loc(sys, LOCALE_SABBREVLANGNAME, "Abbrev language");
    loc(sys, LOCALE_IDEFAULTANSICODEPAGE, "ANSI codepage");
    loc(sys, LOCALE_IDEFAULTCODEPAGE, "OEM codepage");

    BeaconPrintf(CALLBACK_OUTPUT, "\nUser LCID   : 0x%08lx\n", (unsigned long)usr);
    loc(usr, LOCALE_SLOCALIZEDDISPLAYNAME, "Display name");
    loc(usr, LOCALE_SISO639LANGNAME, "ISO language");
    loc(usr, LOCALE_SISO3166CTRYNAME, "ISO country");

    BeaconPrintf(CALLBACK_OUTPUT, "\nLangID      : 0x%04x\n", (unsigned)KERNEL32$GetSystemDefaultLangID());
}
