/*
 * netconn - TCP/UDP endpoints with the owning process (PID + image name).
 *
 * Uses the GetExtendedTcpTable/GetExtendedUdpTable owner-PID tables, unlike
 * `bof-netstat`, which only shows addresses and states.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

#ifndef TCP_TABLE_OWNER_PID_ALL
#define TCP_TABLE_OWNER_PID_ALL 5
#endif
#ifndef UDP_TABLE_OWNER_PID
#define UDP_TABLE_OWNER_PID 1
#endif

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

static void proc_name(DWORD pid, char *out, int outsz)
{
    HANDLE hp;
    DWORD len = outsz;

    out[0] = 0;
    if (!pid) { bof_strncpy(out, "System Idle", outsz); return; }
    if (pid == 4) { bof_strncpy(out, "System", outsz); return; }

    hp = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) { bof_strncpy(out, "?", outsz); return; }
    if (!KERNEL32$QueryFullProcessImageNameA(hp, 0, out, &len))
        bof_strncpy(out, "?", outsz);
    KERNEL32$CloseHandle(hp);
}

static void addr_port(unsigned int addr, unsigned short port, char *out)
{
    char ip[32], p[8];
    bof_ipv4(bof_ntohl(addr), ip);
    bof_itoa(bof_ntohs(port), p);
    bof_strcpy(out, ip);
    bof_strcat(out, ":");
    bof_strcat(out, p);
}

static void dump_tcp(void)
{
    DWORD size = 0, i;
    MIB_TCPTABLE_OWNER_PID *table;
    DWORD rc;

    rc = IPHLPAPI$GetExtendedTcpTable(NULL, &size, TRUE, AF_INET,
                                      TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) return;

    table = (MIB_TCPTABLE_OWNER_PID *)KERNEL32$VirtualAlloc(NULL, size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!table) return;

    rc = IPHLPAPI$GetExtendedTcpTable(table, &size, TRUE, AF_INET,
                                      TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n  TCP\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-22s %-12s %-6s %s\n",
                     "Local", "Remote", "State", "PID", "Process");
        for (i = 0; i < table->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *r = &table->table[i];
            char l[48], rr[48], name[MAX_PATH];

            addr_port(r->dwLocalAddr, (unsigned short)r->dwLocalPort, l);
            addr_port(r->dwRemoteAddr, (unsigned short)r->dwRemotePort, rr);
            proc_name(r->dwOwningPid, name, sizeof(name));
            BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-22s %-12s %-6lu %s\n",
                         l, rr, tcp_state(r->dwState),
                         (unsigned long)r->dwOwningPid, name);
        }
    }
    KERNEL32$VirtualFree(table, 0, MEM_RELEASE);
}

static void dump_udp(void)
{
    DWORD size = 0, i;
    MIB_UDPTABLE_OWNER_PID *table;
    DWORD rc;

    rc = IPHLPAPI$GetExtendedUdpTable(NULL, &size, TRUE, AF_INET,
                                      UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) return;

    table = (MIB_UDPTABLE_OWNER_PID *)KERNEL32$VirtualAlloc(NULL, size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!table) return;

    rc = IPHLPAPI$GetExtendedUdpTable(table, &size, TRUE, AF_INET,
                                      UDP_TABLE_OWNER_PID, 0);
    if (rc == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n  UDP\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-6s %s\n",
                     "Local", "PID", "Process");
        for (i = 0; i < table->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID *r = &table->table[i];
            char l[48], name[MAX_PATH];

            addr_port(r->dwLocalAddr, (unsigned short)r->dwLocalPort, l);
            proc_name(r->dwOwningPid, name, sizeof(name));
            BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-6lu %s\n",
                         l, (unsigned long)r->dwOwningPid, name);
        }
    }
    KERNEL32$VirtualFree(table, 0, MEM_RELEASE);
}

void go(char *args, int alen)
{
    (void)args; (void)alen;
    BeaconPrintf(CALLBACK_OUTPUT, "================ netconn ================\n");
    dump_tcp();
    dump_udp();
}
