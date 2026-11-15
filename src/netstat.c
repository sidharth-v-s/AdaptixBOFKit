/*
 * netstat - IPv4 TCP/UDP endpoints (listening and established).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *tcp_state(DWORD s)
{
    switch (s) {
    case MIB_TCP_STATE_CLOSED:      return "CLOSED";
    case MIB_TCP_STATE_LISTEN:      return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RECV";
    case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:     return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
    }
    return "?";
}

static void dump_tcp(void)
{
    DWORD size = 0, i;
    PMIB_TCPTABLE table;
    DWORD rc = IPHLPAPI$GetTcpTable(NULL, &size, TRUE);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) return;

    table = (PMIB_TCPTABLE)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!table) return;

    rc = IPHLPAPI$GetTcpTable(table, &size, TRUE);
    if (rc == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n  TCP\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-22s %s\n", "Local Address", "Remote Address", "State");
        for (i = 0; i < table->dwNumEntries; i++) {
            PMIB_TCPROW r = &table->table[i];
            char lip[32], rip[32], l[48], rr[48];
            bof_ipv4(bof_ntohl(r->dwLocalAddr), lip);
            bof_ipv4(bof_ntohl(r->dwRemoteAddr), rip);
            {
                char port[8];
                bof_itoa(bof_ntohs((unsigned short)(r->dwLocalPort & 0xffff)), port);
                bof_strcpy(l, lip); bof_strcat(l, ":"); bof_strcat(l, port);
                bof_itoa(bof_ntohs((unsigned short)(r->dwRemotePort & 0xffff)), port);
                bof_strcpy(rr, rip); bof_strcat(rr, ":"); bof_strcat(rr, port);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-22s %s\n", l, rr, tcp_state(r->dwState));
        }
    }
    KERNEL32$VirtualFree(table, 0, MEM_RELEASE);
}

static void dump_udp(void)
{
    DWORD size = 0, i;
    PMIB_UDPTABLE table;
    DWORD rc = IPHLPAPI$GetUdpTable(NULL, &size, TRUE);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) return;

    table = (PMIB_UDPTABLE)KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!table) return;

    rc = IPHLPAPI$GetUdpTable(table, &size, TRUE);
    if (rc == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n  UDP\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %s\n", "Local Address", "State");
        for (i = 0; i < table->dwNumEntries; i++) {
            PMIB_UDPROW r = &table->table[i];
            char lip[32], port[8], l[48];
            bof_ipv4(bof_ntohl(r->dwLocalAddr), lip);
            bof_itoa(bof_ntohs((unsigned short)(r->dwLocalPort & 0xffff)), port);
            bof_strcpy(l, lip); bof_strcat(l, ":"); bof_strcat(l, port);
            BeaconPrintf(CALLBACK_OUTPUT, "  %-22s LISTEN\n", l);
        }
    }
    KERNEL32$VirtualFree(table, 0, MEM_RELEASE);
}

void go(char *args, int alen)
{
    (void)args; (void)alen;
    BeaconPrintf(CALLBACK_OUTPUT, "================ netstat ================\n");
    dump_tcp();
    dump_udp();
}
