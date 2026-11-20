/*
 * AdaptixBOFKit - detailed error reporting.
 *
 * BeaconPrintf output is line oriented, so each diagnostic is a short block:
 *
 *   [-] NetServerEnum failed
 *       NetAPI  : 6118 (0x000017e6) ERROR_NO_BROWSER_SERVERS_FOUND
 *       hint    : Computer Browser is unavailable; trying LDAP
 *
 * Keep secrets out of these strings: pass paths, handles, PIDs and codes,
 * never passwords or credential blobs.
 */
#ifndef ADAPTIX_ERRHELP_H
#define ADAPTIX_ERRHELP_H

#include <windows.h>

static inline const char *bof_win32_name(DWORD e)
{
    switch (e) {
    case 0:    return "ERROR_SUCCESS";
    case 2:    return "ERROR_FILE_NOT_FOUND";
    case 3:    return "ERROR_PATH_NOT_FOUND";
    case 5:    return "ERROR_ACCESS_DENIED";
    case 6:    return "ERROR_INVALID_HANDLE";
    case 8:    return "ERROR_NOT_ENOUGH_MEMORY";
    case 13:   return "ERROR_INVALID_DATA";
    case 14:   return "ERROR_OUTOFMEMORY";
    case 18:   return "ERROR_NO_MORE_FILES";
    case 32:   return "ERROR_SHARING_VIOLATION";
    case 33:   return "ERROR_LOCK_VIOLATION";
    case 50:   return "ERROR_NOT_SUPPORTED";
    case 53:   return "ERROR_BAD_NETPATH";
    case 64:   return "ERROR_NETNAME_DELETED";
    case 67:   return "ERROR_BAD_NET_NAME";
    case 87:   return "ERROR_INVALID_PARAMETER";
    case 121:  return "ERROR_SEM_TIMEOUT";
    case 122:  return "ERROR_INSUFFICIENT_BUFFER";
    case 123:  return "ERROR_INVALID_NAME";
    case 126:  return "ERROR_MOD_NOT_FOUND";
    case 127:  return "ERROR_PROC_NOT_FOUND";
    case 183:  return "ERROR_ALREADY_EXISTS";
    case 267:  return "ERROR_DIRECTORY";
    case 487:  return "ERROR_INVALID_ADDRESS";
    case 995:  return "ERROR_OPERATION_ABORTED";
    case 997:  return "ERROR_IO_PENDING";
    case 1060: return "ERROR_SERVICE_DOES_NOT_EXIST";
    case 1072: return "ERROR_SERVICE_MARKED_FOR_DELETE";
    case 1073: return "ERROR_SERVICE_EXISTS";
    case 1075: return "ERROR_SERVICE_DEPENDENCY_DELETED";
    case 1168: return "ERROR_NOT_FOUND";
    case 1314: return "ERROR_PRIVILEGE_NOT_HELD";
    case 1326: return "ERROR_LOGON_FAILURE";
    case 1327: return "ERROR_ACCOUNT_RESTRICTION";
    case 1331: return "ERROR_ACCOUNT_DISABLED";
    case 1385: return "ERROR_LOGON_TYPE_NOT_GRANTED";
    case 1722: return "RPC_S_SERVER_UNAVAILABLE";
    case 1726: return "RPC_S_CALL_FAILED";
    case 1753: return "EPT_S_NOT_REGISTERED";
    case 1816: return "ERROR_NOT_ENOUGH_QUOTA";
    case 1909: return "ERROR_ACCOUNT_LOCKED_OUT";
    case 6118: return "ERROR_NO_BROWSER_SERVERS_FOUND";
    }
    return NULL;
}

static inline const char *bof_hresult_name(HRESULT hr)
{
    switch ((DWORD)hr) {
    case 0x00000000: return "S_OK";
    case 0x00000001: return "S_FALSE";
    case 0x80004001: return "E_NOTIMPL";
    case 0x80004002: return "E_NOINTERFACE";
    case 0x80004003: return "E_POINTER";
    case 0x80004004: return "E_ABORT";
    case 0x80004005: return "E_FAIL";
    case 0x80070005: return "E_ACCESSDENIED";
    case 0x80070006: return "E_HANDLE";
    case 0x8007000E: return "E_OUTOFMEMORY";
    case 0x80070057: return "E_INVALIDARG";
    case 0x8000FFFF: return "E_UNEXPECTED";
    case 0x80010001: return "RPC_E_CALL_REJECTED";
    case 0x80010105: return "RPC_E_SERVERFAULT";
    case 0x80010108: return "RPC_E_DISCONNECTED";
    case 0x8001010A: return "RPC_E_SERVERCALL_RETRYLATER";
    case 0x8001010D: return "RPC_E_CANTCALLOUT_ININPUTSYNCCALL";
    case 0x800706BA: return "RPC_S_SERVER_UNAVAILABLE";
    case 0x800706BE: return "RPC_S_CALL_FAILED";
    }
    if (((DWORD)hr & 0xFFFF0000u) == 0x80070000u)
        return bof_win32_name((DWORD)hr & 0xFFFFu);
    return NULL;
}

static inline const char *bof_ntstatus_name(NTSTATUS st)
{
    switch ((DWORD)st) {
    case 0x00000000: return "STATUS_SUCCESS";
    case 0x80000005: return "STATUS_BUFFER_OVERFLOW";
    case 0xC0000001: return "STATUS_UNSUCCESSFUL";
    case 0xC0000002: return "STATUS_NOT_IMPLEMENTED";
    case 0xC0000005: return "STATUS_ACCESS_VIOLATION";
    case 0xC0000006: return "STATUS_IN_PAGE_ERROR";
    case 0xC0000008: return "STATUS_INVALID_HANDLE";
    case 0xC000000D: return "STATUS_INVALID_PARAMETER";
    case 0xC0000017: return "STATUS_NO_MEMORY";
    case 0xC0000022: return "STATUS_ACCESS_DENIED";
    case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
    case 0xC0000035: return "STATUS_OBJECT_NAME_COLLISION";
    case 0xC000003A: return "STATUS_OBJECT_PATH_NOT_FOUND";
    case 0xC0000043: return "STATUS_SHARING_VIOLATION";
    case 0xC0000054: return "STATUS_FILE_LOCK_CONFLICT";
    case 0xC0000061: return "STATUS_PRIVILEGE_NOT_HELD";
    case 0xC000006D: return "STATUS_LOGON_FAILURE";
    case 0xC000006E: return "STATUS_ACCOUNT_RESTRICTION";
    case 0xC000006F: return "STATUS_INVALID_LOGON_HOURS";
    case 0xC0000070: return "STATUS_INVALID_WORKSTATION";
    case 0xC0000071: return "STATUS_PASSWORD_EXPIRED";
    case 0xC0000072: return "STATUS_ACCOUNT_DISABLED";
    case 0xC00000AC: return "STATUS_PIPE_NOT_AVAILABLE";
    case 0xC00000B5: return "STATUS_IO_TIMEOUT";
    case 0xC00000CC: return "STATUS_BAD_NETWORK_NAME";
    case 0xC0000120: return "STATUS_CANCELLED";
    case 0xC0000135: return "STATUS_DLL_NOT_FOUND";
    case 0xC0000139: return "STATUS_ENTRYPOINT_NOT_FOUND";
    case 0xC0000142: return "STATUS_DLL_INIT_FAILED";
    case 0xC0000234: return "STATUS_ACCOUNT_LOCKED_OUT";
    }
    return NULL;
}

static inline const char *bof_ldap_name(ULONG rc)
{
    switch (rc) {
    case 0:  return "LDAP_SUCCESS";
    case 1:  return "LDAP_OPERATIONS_ERROR";
    case 2:  return "LDAP_PROTOCOL_ERROR";
    case 3:  return "LDAP_TIMELIMIT_EXCEEDED";
    case 4:  return "LDAP_SIZELIMIT_EXCEEDED";
    case 8:  return "LDAP_STRONG_AUTH_REQUIRED";
    case 12: return "LDAP_UNAVAILABLE_CRITICAL_EXTENSION";
    case 13: return "LDAP_CONFIDENTIALITY_REQUIRED";
    case 14: return "LDAP_SASL_BIND_IN_PROGRESS";
    case 16: return "LDAP_NO_SUCH_ATTRIBUTE";
    case 32: return "LDAP_NO_SUCH_OBJECT";
    case 34: return "LDAP_INVALID_DN_SYNTAX";
    case 48: return "LDAP_INAPPROPRIATE_AUTH";
    case 49: return "LDAP_INVALID_CREDENTIALS";
    case 50: return "LDAP_INSUFFICIENT_ACCESS";
    case 51: return "LDAP_BUSY";
    case 52: return "LDAP_UNAVAILABLE";
    case 53: return "LDAP_UNWILLING_TO_PERFORM";
    case 54: return "LDAP_LOOP_DETECT";
    case 64: return "LDAP_NAMING_VIOLATION";
    case 65: return "LDAP_OBJECT_CLASS_VIOLATION";
    case 66: return "LDAP_NOT_ALLOWED_ON_NONLEAF";
    case 67: return "LDAP_NOT_ALLOWED_ON_RDN";
    case 68: return "LDAP_ALREADY_EXISTS";
    case 80: return "LDAP_OTHER";
    case 81: return "LDAP_SERVER_DOWN";
    case 82: return "LDAP_LOCAL_ERROR";
    case 83: return "LDAP_ENCODING_ERROR";
    case 84: return "LDAP_DECODING_ERROR";
    case 85: return "LDAP_TIMEOUT";
    case 86: return "LDAP_AUTH_UNKNOWN";
    case 87: return "LDAP_FILTER_ERROR";
    case 88: return "LDAP_USER_CANCELLED";
    case 89: return "LDAP_PARAM_ERROR";
    case 90: return "LDAP_NO_MEMORY";
    case 91: return "LDAP_CONNECT_ERROR";
    case 92: return "LDAP_NOT_SUPPORTED";
    case 93: return "LDAP_CONTROL_NOT_FOUND";
    case 94: return "LDAP_NO_RESULTS_RETURNED";
    case 95: return "LDAP_MORE_RESULTS_TO_RETURN";
    case 96: return "LDAP_CLIENT_LOOP";
    case 97: return "LDAP_REFERRAL_LIMIT_EXCEEDED";
    }
    return NULL;
}

static inline const char *bof_dns_name(DWORD st)
{
    switch (st) {
    case 0:    return "DNS_STATUS_SUCCESS";
    case 9001: return "DNS_ERROR_RCODE_FORMAT_ERROR";
    case 9002: return "DNS_ERROR_RCODE_SERVER_FAILURE";
    case 9003: return "DNS_ERROR_RCODE_NAME_ERROR";
    case 9004: return "DNS_ERROR_RCODE_NOT_IMPLEMENTED";
    case 9005: return "DNS_ERROR_RCODE_REFUSED";
    case 9006: return "DNS_ERROR_RCODE_YXDOMAIN";
    case 9007: return "DNS_ERROR_RCODE_YXRRSET";
    case 9008: return "DNS_ERROR_RCODE_NXRRSET";
    case 9009: return "DNS_ERROR_RCODE_NOTAUTH";
    case 9010: return "DNS_ERROR_RCODE_NOTZONE";
    case 9501: return "DNS_INFO_NO_RECORDS";
    case 9502: return "DNS_ERROR_BAD_PACKET";
    case 9503: return "DNS_ERROR_NO_PACKET";
    case 9504: return "DNS_ERROR_RCODE";
    case 9505: return "DNS_ERROR_UNSECURE_PACKET";
    case 9552: return "DNS_ERROR_INVALID_NAME";
    case 9701: return "DNS_ERROR_NO_MORE_ITEMS";
    }
    return NULL;
}

static inline const char *bof_rpc_name(DWORD rc)
{
    switch (rc) {
    case 0:    return "RPC_S_OK";
    case 1700: return "RPC_S_INVALID_STRING_BINDING";
    case 1701: return "RPC_S_WRONG_KIND_OF_BINDING";
    case 1702: return "RPC_S_INVALID_BINDING";
    case 1703: return "RPC_S_PROTSEQ_NOT_SUPPORTED";
    case 1705: return "RPC_S_INVALID_STRING_UUID";
    case 1706: return "RPC_S_INVALID_ENDPOINT_FORMAT";
    case 1707: return "RPC_S_INVALID_NET_ADDR";
    case 1708: return "RPC_S_NO_ENDPOINT_FOUND";
    case 1719: return "RPC_S_NO_PROTSEQS";
    case 1720: return "RPC_S_CANT_CREATE_ENDPOINT";
    case 1721: return "RPC_S_OUT_OF_RESOURCES";
    case 1722: return "RPC_S_SERVER_UNAVAILABLE";
    case 1723: return "RPC_S_SERVER_TOO_BUSY";
    case 1726: return "RPC_S_CALL_FAILED";
    case 1727: return "RPC_S_CALL_FAILED_DNE";
    case 1728: return "RPC_S_PROTOCOL_ERROR";
    case 1733: return "RPC_S_INVALID_TAG";
    case 1734: return "RPC_S_INVALID_BOUND";
    case 1735: return "RPC_S_NO_ENTRY_NAME";
    case 1736: return "RPC_S_INVALID_NAME_SYNTAX";
    case 1744: return "RPC_S_PROTSEQ_NOT_FOUND";
    case 1746: return "RPC_S_BINDING_HAS_NO_AUTH";
    case 1749: return "RPC_S_INVALID_AUTH_IDENTITY";
    case 1752: return "EPT_S_CANT_PERFORM_OP";
    case 1753: return "EPT_S_NOT_REGISTERED";
    case 1764: return "RPC_S_CANNOT_SUPPORT";
    case 1766: return "RPC_S_INTERNAL_ERROR";
    }
    return NULL;
}

static inline const char *bof_service_state_name(DWORD state)
{
    switch (state) {
    case SERVICE_STOPPED:          return "STOPPED";
    case SERVICE_START_PENDING:    return "START_PENDING";
    case SERVICE_STOP_PENDING:     return "STOP_PENDING";
    case SERVICE_RUNNING:          return "RUNNING";
    case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
    case SERVICE_PAUSED:           return "PAUSED";
    }
    return "UNKNOWN";
}

static inline void bof_error_report(const char *what, const char *kind,
                                    unsigned long code, const char *name,
                                    const char *hint)
{
    BeaconPrintf(CALLBACK_ERROR, "[-] %s failed\n",
                 what ? what : "operation");
    BeaconPrintf(CALLBACK_ERROR, "    %-8s: %lu (0x%08lx)%s%s\n",
                 kind ? kind : "code", code, code,
                 name ? " " : "", name ? name : "");
    if (hint && hint[0])
        BeaconPrintf(CALLBACK_ERROR, "    hint    : %s\n", hint);
}

static inline void bof_error_win32(const char *what, DWORD err,
                                   const char *hint)
{
    bof_error_report(what, "Win32", (unsigned long)err,
                     bof_win32_name(err), hint);
}

static inline void bof_error_netapi(const char *what, DWORD err,
                                    const char *hint)
{
    bof_error_report(what, "NetAPI", (unsigned long)err,
                     bof_win32_name(err), hint);
}

static inline void bof_error_hresult(const char *what, HRESULT hr,
                                     const char *hint)
{
    bof_error_report(what, "HRESULT", (unsigned long)hr,
                     bof_hresult_name(hr), hint);
}

static inline void bof_error_ntstatus(const char *what, NTSTATUS st,
                                      const char *hint)
{
    bof_error_report(what, "NTSTATUS", (unsigned long)st,
                     bof_ntstatus_name(st), hint);
}

static inline void bof_error_ldap(const char *what, ULONG rc,
                                  const char *hint)
{
    bof_error_report(what, "LDAP", (unsigned long)rc,
                     bof_ldap_name(rc), hint);
}

static inline void bof_error_rpc(const char *what, DWORD rc,
                                 const char *hint)
{
    bof_error_report(what, "RPC", (unsigned long)rc,
                     bof_rpc_name(rc), hint);
}

static inline void bof_error_dns(const char *what, DWORD st,
                                 const char *hint)
{
    bof_error_report(what, "DNS", (unsigned long)st,
                     bof_dns_name(st), hint);
}

static inline void bof_error_text(const char *what, const char *detail)
{
    BeaconPrintf(CALLBACK_ERROR, "[-] %s%s%s\n",
                 what ? what : "error",
                 detail && detail[0] ? ": " : "",
                 detail ? detail : "");
}

static inline void bof_error_context(const char *key, const char *value)
{
    BeaconPrintf(CALLBACK_ERROR, "    %-8s: %s\n",
                 key ? key : "context", value ? value : "(null)");
}

static inline void bof_error_num(const char *key, unsigned long long value)
{
    BeaconPrintf(CALLBACK_ERROR, "    %-8s: %llu (0x%llx)\n",
                 key ? key : "value", value, value);
}

#endif /* ADAPTIX_ERRHELP_H */
