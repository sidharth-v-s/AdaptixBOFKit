/*
 * whereami - compact process/session/user context.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static const char *integrity_name(DWORD rid)
{
    if (rid >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID) return "protected";
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID)          return "system";
    if (rid >= SECURITY_MANDATORY_HIGH_RID)            return "high";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID)          return "medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID)             return "low";
    return "untrusted";
}

void go(char *args, int alen)
{
    DWORD pid, ppid = 0, session = 0;
    HANDLE snap, tok = NULL;
    PROCESSENTRY32 pe;
    char user[256], cwd[512];
    DWORD ulen = sizeof(user);
    DWORD integrity = 0;
    TOKEN_ELEVATION elev;
    DWORD elen = sizeof(elev);
    SYSTEM_INFO si;

    (void)args; (void)alen;

    pid = KERNEL32$GetCurrentProcessId();
    snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        bof_memzero(&pe, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (KERNEL32$Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) { ppid = pe.th32ParentProcessID; break; }
            } while (KERNEL32$Process32Next(snap, &pe));
        }
        KERNEL32$CloseHandle(snap);
    }

    KERNEL32$ProcessIdToSessionId(pid, &session);
    bof_memzero(&si, sizeof(si));
    KERNEL32$GetSystemInfo(&si);

    if (!SECUR32$GetUserNameExA(2 /* NameSamCompatible */, user, &ulen))
        bof_strcpy(user, "-");
    if (!KERNEL32$GetCurrentDirectoryA(sizeof(cwd), cwd))
        bof_strcpy(cwd, "-");

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                  TOKEN_QUERY, &tok)) {
        BYTE buf[256];
        DWORD len = 0;
        if (ADVAPI32$GetTokenInformation(tok, TokenIntegrityLevel, buf, sizeof(buf), &len)) {
            TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)buf;
            DWORD count = *ADVAPI32$GetSidSubAuthorityCount(tml->Label.Sid);
            integrity = *ADVAPI32$GetSidSubAuthority(tml->Label.Sid, count - 1);
        }
        ADVAPI32$GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &elen);
        KERNEL32$CloseHandle(tok);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Execution context\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  PID          : %lu\n", (unsigned long)pid);
    BeaconPrintf(CALLBACK_OUTPUT, "  PPID         : %lu\n", (unsigned long)ppid);
    BeaconPrintf(CALLBACK_OUTPUT, "  Session      : %lu\n", (unsigned long)session);
    BeaconPrintf(CALLBACK_OUTPUT, "  User         : %s\n", user);
    BeaconPrintf(CALLBACK_OUTPUT, "  Integrity    : %s (0x%lx)\n",
                 integrity_name(integrity), (unsigned long)integrity);
    BeaconPrintf(CALLBACK_OUTPUT, "  Elevated     : %s\n", elev.TokenIsElevated ? "yes" : "no");
    BeaconPrintf(CALLBACK_OUTPUT, "  Architecture : %u\n", (unsigned)si.wProcessorArchitecture);
    BeaconPrintf(CALLBACK_OUTPUT, "  CWD          : %s\n", cwd);
}
