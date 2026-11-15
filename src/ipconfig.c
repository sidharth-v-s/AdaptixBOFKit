/*
 * ipconfig - IPv4 adapters, addresses, gateways and DNS servers.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void print_sockaddr(const SOCKET_ADDRESS *sa, const char *label)
{
    char ip[32];
    if (!sa || !sa->lpSockaddr) return;
    if (sa->lpSockaddr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)sa->lpSockaddr;
        bof_ipv4(bof_ntohl(in->sin_addr.S_un.S_addr), ip);
        BeaconPrintf(CALLBACK_OUTPUT, "    %-12s %s\n", label, ip);
    }
}

void go(char *args, int alen)
{
    ULONG size = 0;
    PIP_ADAPTER_ADDRESSES addrs = NULL;
    PIP_ADAPTER_ADDRESSES a;
    char name[256];
    (void)args; (void)alen;

    if (IPHLPAPI$GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
        BeaconPrintf(CALLBACK_ERROR, "GetAdaptersAddresses size query failed\n");
        return;
    }

    addrs = (PIP_ADAPTER_ADDRESSES)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!addrs) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc failed\n");
        return;
    }

    if (IPHLPAPI$GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &size) != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "GetAdaptersAddresses failed\n");
        KERNEL32$VirtualFree(addrs, 0, MEM_RELEASE);
        return;
    }

    for (a = addrs; a; a = a->Next) {
        PIP_ADAPTER_UNICAST_ADDRESS ua;
        PIP_ADAPTER_DNS_SERVER_ADDRESS da;
        PIP_ADAPTER_GATEWAY_ADDRESS ga;

        bof_w2a(a->FriendlyName, name, sizeof(name));
        BeaconPrintf(CALLBACK_OUTPUT, "\n[%s]\n", name);
        if (a->Description && a->Description[0]) {
            bof_w2a(a->Description, name, sizeof(name));
            BeaconPrintf(CALLBACK_OUTPUT, "  Description : %s\n", name);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  Status      : %s\n", a->OperStatus == IfOperStatusUp ? "up" : "down");

        for (ua = a->FirstUnicastAddress; ua; ua = ua->Next)
            print_sockaddr(&ua->Address, "IPv4");

        for (ga = a->FirstGatewayAddress; ga; ga = ga->Next)
            print_sockaddr(&ga->Address, "Gateway");

        for (da = a->FirstDnsServerAddress; da; da = da->Next)
            print_sockaddr(&da->Address, "DNS");
    }

    KERNEL32$VirtualFree(addrs, 0, MEM_RELEASE);
}
