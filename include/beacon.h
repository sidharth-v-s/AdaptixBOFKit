/*
 * AdaptixBOFKit - Beacon API compatibility header
 *
 * Only the APIs documented as supported by Adaptix's Beacon agent are
 * declared here.  BOFs must not use the unsupported Cobalt Strike APIs.
 */
#ifndef ADAPTIX_BEACON_H
#define ADAPTIX_BEACON_H

#include <winsock2.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- data parser API ------------------------------------------------ */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void   BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int    BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short  BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int    BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char * BeaconDataExtract(datap *parser, int *size);

/* ---- format API ----------------------------------------------------- */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

DECLSPEC_IMPORT void   BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void   BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void   BeaconFormatAppend(formatp *format, const char *text, int len);
DECLSPEC_IMPORT void   BeaconFormatPrintf(formatp *format, const char *fmt, ...);
DECLSPEC_IMPORT char * BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void   BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void   BeaconFormatInt(formatp *format, int value);

/* ---- output API ----------------------------------------------------- */
#define CALLBACK_OUTPUT       0x00
#define CALLBACK_OUTPUT_OEM   0x1e
#define CALLBACK_OUTPUT_UTF8  0x20
#define CALLBACK_ERROR        0x0d

DECLSPEC_IMPORT void BeaconOutput(int type, const char *data, int len);
DECLSPEC_IMPORT void BeaconPrintf(int type, const char *fmt, ...);

/* ---- token API ------------------------------------------------------ */
DECLSPEC_IMPORT BOOL BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL BeaconIsAdmIn(void);

/* ---- misc utility --------------------------------------------------- */
DECLSPEC_IMPORT BOOL toWideChar(char *src, wchar_t *dst, int max);

/* ---- key/value store ------------------------------------------------ */
DECLSPEC_IMPORT BOOL   BeaconAddValue(const char *key, void *ptr);
DECLSPEC_IMPORT void * BeaconGetValue(const char *key);
DECLSPEC_IMPORT BOOL   BeaconRemoveValue(const char *key);

/* ---- Adaptix-specific APIs ------------------------------------------ */
DECLSPEC_IMPORT void AxAddScreenshot(char *note, char *data, int len);
DECLSPEC_IMPORT void AxDownloadMemory(char *filename, char *data, int len);

#ifdef __cplusplus
}
#endif

#endif /* ADAPTIX_BEACON_H */
