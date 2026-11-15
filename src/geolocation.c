/*
 * geolocation - system region, country and timezone (offline, no lookups).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    GEOID gid;
    char name[128], iso2[16], iso3[16], friendly[128];
    char country[64], language[128];
    TIME_ZONE_INFORMATION tz;
    DWORD mode;
    long bias;

    (void)args; (void)alen;

    gid = KERNEL32$GetUserGeoID(GEOCLASS_NATION);
    bof_memzero(name, sizeof(name));
    bof_memzero(iso2, sizeof(iso2));
    bof_memzero(iso3, sizeof(iso3));
    bof_memzero(friendly, sizeof(friendly));
    if (gid != (GEOID)-1) {
        KERNEL32$GetGeoInfoA(gid, GEO_OFFICIALNAME, name, sizeof(name), 0);
        KERNEL32$GetGeoInfoA(gid, GEO_ISO2, iso2, sizeof(iso2), 0);
        KERNEL32$GetGeoInfoA(gid, GEO_ISO3, iso3, sizeof(iso3), 0);
        KERNEL32$GetGeoInfoA(gid, GEO_FRIENDLYNAME, friendly, sizeof(friendly), 0);
    }

    bof_memzero(country, sizeof(country));
    bof_memzero(language, sizeof(language));
    KERNEL32$GetLocaleInfoA(LOCALE_SYSTEM_DEFAULT, LOCALE_SISO3166CTRYNAME,
                            country, sizeof(country));
    KERNEL32$GetLocaleInfoA(LOCALE_SYSTEM_DEFAULT, LOCALE_SLANGUAGE,
                            language, sizeof(language));

    BeaconPrintf(CALLBACK_OUTPUT, "Region\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  GEOID      : %ld\n", (long)gid);
    BeaconPrintf(CALLBACK_OUTPUT, "  Country    : %s\n", country[0] ? country : "-");
    BeaconPrintf(CALLBACK_OUTPUT, "  ISO2/ISO3  : %s / %s\n",
                 iso2[0] ? iso2 : "-", iso3[0] ? iso3 : "-");
    BeaconPrintf(CALLBACK_OUTPUT, "  Name       : %s\n", name[0] ? name : "-");
    BeaconPrintf(CALLBACK_OUTPUT, "  Friendly   : %s\n", friendly[0] ? friendly : "-");
    BeaconPrintf(CALLBACK_OUTPUT, "  Language   : %s\n", language[0] ? language : "-");

    bof_memzero(&tz, sizeof(tz));
    mode = KERNEL32$GetTimeZoneInformation(&tz);
    bof_w2a(tz.StandardName, name, sizeof(name));
    bias = -(long)tz.Bias;

    BeaconPrintf(CALLBACK_OUTPUT, "\nTimezone\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  Name       : %s\n", name);
    BeaconPrintf(CALLBACK_OUTPUT, "  UTC offset : %+ld:%02ld\n",
                 bias / 60, (bias < 0 ? -bias : bias) % 60);
    BeaconPrintf(CALLBACK_OUTPUT, "  DST active : %s\n",
                 mode == TIME_ZONE_ID_DAYLIGHT ? "yes" :
                 (mode == TIME_ZONE_ID_UNKNOWN ? "unknown" : "no"));
}
