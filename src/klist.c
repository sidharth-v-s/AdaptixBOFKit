/*
 * klist - list Kerberos tickets in the current logon session.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_u(const UNICODE_STRING *us)
{
    char tmp[512];
    int i, n = us->Length / sizeof(WCHAR);
    if (!us->Buffer || n <= 0) { BeaconPrintf(CALLBACK_OUTPUT, "-"); return; }
    if (n > 255) n = 255;
    for (i = 0; i < n; i++) tmp[i] = (char)us->Buffer[i];
    tmp[n] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "%s", tmp);
}

void go(char *args, int alen)
{
    HANDLE lsa = NULL;
    LSA_STRING pkgname;
    ULONG pkg = 0;
    KERB_QUERY_TKT_CACHE_REQUEST req;
    PVOID resp = NULL;
    ULONG rlen = 0;
    NTSTATUS pst = 0, st;
    PKERB_QUERY_TKT_CACHE_RESPONSE r;
    ULONG i;

    (void)args; (void)alen;

    st = SECUR32$LsaConnectUntrusted(&lsa);
    if (st != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LsaConnectUntrusted failed: 0x%08lx\n", (unsigned long)st);
        return;
    }

    pkgname.Buffer = "Kerberos";
    pkgname.Length = 8;
    pkgname.MaximumLength = 9;
    st = SECUR32$LsaLookupAuthenticationPackage(lsa, &pkgname, &pkg);
    if (st != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LsaLookupAuthenticationPackage failed: 0x%08lx\n",
                     (unsigned long)st);
        SECUR32$LsaDeregisterLogonProcess(lsa);
        return;
    }

    bof_memzero(&req, sizeof(req));
    req.MessageType = KerbQueryTicketCacheMessage;
    req.LogonId.LowPart = 0;
    req.LogonId.HighPart = 0;

    st = SECUR32$LsaCallAuthenticationPackage(lsa, pkg, &req, sizeof(req),
                                              &resp, &rlen, &pst);
    if (st != 0 || pst != 0 || !resp) {
        BeaconPrintf(CALLBACK_ERROR, "LsaCallAuthenticationPackage failed: 0x%08lx/0x%08lx\n",
                     (unsigned long)st, (unsigned long)pst);
        if (resp) SECUR32$LsaFreeReturnBuffer(resp);
        SECUR32$LsaDeregisterLogonProcess(lsa);
        return;
    }

    r = (PKERB_QUERY_TKT_CACHE_RESPONSE)resp;
    BeaconPrintf(CALLBACK_OUTPUT, "Cached Kerberos tickets: %lu\n",
                 (unsigned long)r->CountOfTickets);
    for (i = 0; i < r->CountOfTickets; i++) {
        PKERB_TICKET_CACHE_INFO t = &r->Tickets[i];
        BeaconPrintf(CALLBACK_OUTPUT, "  [%lu] ", (unsigned long)i);
        print_u(&t->ServerName);
        BeaconPrintf(CALLBACK_OUTPUT, " @ ");
        print_u(&t->RealmName);
        BeaconPrintf(CALLBACK_OUTPUT, "  etype=%ld flags=0x%08lx\n",
                     (long)t->EncryptionType, (unsigned long)t->TicketFlags);
    }

    SECUR32$LsaFreeReturnBuffer(resp);
    SECUR32$LsaDeregisterLogonProcess(lsa);
}
