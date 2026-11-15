/*
 * AdaptixBOFKit - Win32 declarations using Adaptix's DLL$Function
 * resolution convention.
 *
 * Adaptix's BOF loader resolves imports of the form DLL$Symbol by loading
 * the named DLL and calling GetProcAddress.  All BOFs in this project call
 * APIs through these names so no import libraries are required.
 */
#ifndef ADAPTIX_BOFDEFS_H
#define ADAPTIX_BOFDEFS_H

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <lm.h>
#include <lmjoin.h>
#include <windns.h>
#include <wlanapi.h>
#include <bcrypt.h>
#include <winsvc.h>
#include <wincred.h>
#include <winnetwk.h>
#include <sddl.h>
#define SECURITY_WIN32
#include <security.h>
#include <secext.h>
#include <ntsecapi.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <dbghelp.h>
#include <fltuser.h>
#include <winldap.h>
#include <winevt.h>
#include <winver.h>
#include <oleauto.h>
#include <objidl.h>
#include <taskschd.h>
#include <netfw.h>
#include <shobjidl.h>
#include <vss.h>
#include <vsbackup.h>
#include <fwpmu.h>

/* DNS client cache (not declared by the MinGW headers we target). */
typedef struct _DNS_CACHE_ENTRY {
    struct _DNS_CACHE_ENTRY *pNext;
    PWSTR pszName;
    WORD  wType;
    WORD  wDataLength;
    DWORD dwFlags;
} DNS_CACHE_ENTRY, *PDNS_CACHE_ENTRY;

/* ------------------------------------------------------------------ */
/* kernel32                                                            */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExA(LPCSTR, HANDLE, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalLock(HGLOBAL);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GlobalUnlock(HGLOBAL);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$UnmapViewOfFile(LPCVOID);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$SetFileAttributesA(LPCSTR, DWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLogicalDrives(void);
DECLSPEC_IMPORT UINT    WINAPI KERNEL32$GetDriveTypeA(LPCSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetDiskFreeSpaceExA(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
DECLSPEC_IMPORT LPSTR   WINAPI KERNEL32$GetEnvironmentStringsA(void);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FreeEnvironmentStringsA(LPSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetComputerNameExA(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT VOID    WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
DECLSPEC_IMPORT VOID    WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT ULONGLONG WINAPI KERNEL32$GetTickCount64(void);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *, LPSYSTEMTIME);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GlobalMemoryStatusEx(LPMEMORYSTATUSEX);
DECLSPEC_IMPORT LCID    WINAPI KERNEL32$GetSystemDefaultLCID(void);
DECLSPEC_IMPORT LCID    WINAPI KERNEL32$GetUserDefaultLCID(void);
DECLSPEC_IMPORT LANGID  WINAPI KERNEL32$GetSystemDefaultLangID(void);
DECLSPEC_IMPORT int     WINAPI KERNEL32$GetLocaleInfoA(LCID, LCTYPE, LPSTR, int);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetVersion(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Module32First(HANDLE, LPMODULEENTRY32);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Module32Next(HANDLE, LPMODULEENTRY32);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$QueryFullProcessImageNameA(HANDLE, DWORD, LPSTR, PDWORD);
DECLSPEC_IMPORT VOID    WINAPI KERNEL32$GetSystemInfo(LPSYSTEM_INFO);

/* ------------------------------------------------------------------ */
/* advapi32                                                            */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR *);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSidToSidA(LPCSTR, PSID *);
DECLSPEC_IMPORT PUCHAR WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID);
DECLSPEC_IMPORT PDWORD WINAPI ADVAPI32$GetSidSubAuthority(PSID, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteKeyA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteTreeA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);

DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$OpenEventLogA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ClearEventLogA(HANDLE, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CloseEventLog(HANDLE);

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$StartServiceA(SC_HANDLE, DWORD, LPCSTR *);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$DeleteService(SC_HANDLE);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CredEnumerateA(LPCSTR, DWORD, PDWORD, PCREDENTIALA **);
DECLSPEC_IMPORT VOID WINAPI ADVAPI32$CredFree(PVOID);

/* ------------------------------------------------------------------ */
/* iphlpapi                                                            */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetAdaptersAddresses(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpNetTable(PMIB_IPNETTABLE, PULONG, BOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetTcpTable(PMIB_TCPTABLE, PULONG, BOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetUdpTable(PMIB_UDPTABLE, PULONG, BOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpForwardTable(PMIB_IPFORWARDTABLE, PULONG, BOOL);

/* ------------------------------------------------------------------ */
/* netapi32                                                            */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetShareEnum(LPWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetServerEnum(LPCWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, DWORD, LPCWSTR, LPDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetUserGetInfo(LPCWSTR, LPCWSTR, DWORD, LPBYTE *);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetLocalGroupEnum(LPCWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetLocalGroupGetMembers(LPCWSTR, LPCWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGroupEnum(LPCWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGetJoinInformation(LPCWSTR, LPWSTR *, PNETSETUP_JOIN_STATUS);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGetDCName(LPCWSTR, LPCWSTR, LPBYTE *);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetRemoteTOD(LPCWSTR, LPBYTE *);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetWkstaUserEnum(LPCWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetSessionEnum(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGroupGetUsers(LPCWSTR, LPCWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetUserModalsGet(LPCWSTR, DWORD, LPBYTE *);

/* ------------------------------------------------------------------ */
/* ws2_32                                                              */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT int      WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int      WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET   WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int      WSAAPI WS2_32$connect(SOCKET, const struct sockaddr *, int);
DECLSPEC_IMPORT int      WSAAPI WS2_32$select(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
DECLSPEC_IMPORT int      WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT int      WSAAPI WS2_32$ioctlsocket(SOCKET, long, u_long *);
DECLSPEC_IMPORT int      WSAAPI WS2_32$getsockopt(SOCKET, int, int, char *, int *);
DECLSPEC_IMPORT u_short  WSAAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char *);
DECLSPEC_IMPORT struct hostent *WSAAPI WS2_32$gethostbyname(const char *);
DECLSPEC_IMPORT int      WSAAPI WS2_32$sendto(SOCKET, const char *, int, int, const struct sockaddr *, int);
DECLSPEC_IMPORT int      WSAAPI WS2_32$recvfrom(SOCKET, char *, int, int, struct sockaddr *, int *);
DECLSPEC_IMPORT int      WSAAPI WS2_32$setsockopt(SOCKET, int, int, const char *, int);
DECLSPEC_IMPORT int      WSAAPI WS2_32$WSAGetLastError(void);

/* ------------------------------------------------------------------ */
/* user32                                                              */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT BOOL WINAPI USER32$EnumWindows(WNDENUMPROC, LPARAM);
DECLSPEC_IMPORT int  WINAPI USER32$GetWindowTextA(HWND, LPSTR, int);
DECLSPEC_IMPORT int  WINAPI USER32$GetWindowTextLengthA(HWND);
DECLSPEC_IMPORT BOOL WINAPI USER32$IsWindowVisible(HWND);
DECLSPEC_IMPORT DWORD WINAPI USER32$GetWindowThreadProcessId(HWND, LPDWORD);

/* ------------------------------------------------------------------ */
/* wtsapi32                                                            */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSEnumerateSessionsA(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOA *, DWORD *);
DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSQuerySessionInformationA(HANDLE, DWORD, WTS_INFO_CLASS, LPSTR *, DWORD *);
DECLSPEC_IMPORT VOID WINAPI WTSAPI32$WTSFreeMemory(PVOID);

/* ------------------------------------------------------------------ */
/* secur32                                                             */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetUserNameExA(EXTENDED_NAME_FORMAT, LPSTR, PULONG);

/* ------------------------------------------------------------------ */
/* dnsapi                                                              */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsQuery_A(PCSTR, WORD, DWORD, PVOID, PDNS_RECORD *, PVOID *);
DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsRecordListFree(PDNS_RECORD, DNS_FREE_TYPE);

/* ------------------------------------------------------------------ */
/* wlanapi                                                             */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanOpenHandle(DWORD, PVOID, PDWORD, PHANDLE);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanCloseHandle(HANDLE, PVOID);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanEnumInterfaces(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST *);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanGetProfileList(HANDLE, const GUID *, PVOID, PWLAN_PROFILE_INFO_LIST *);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanGetProfile(HANDLE, const GUID *, LPCWSTR, PVOID, LPWSTR *, PDWORD, PDWORD);
DECLSPEC_IMPORT VOID  WINAPI WLANAPI$WlanFreeMemory(PVOID);

/* ------------------------------------------------------------------ */
/* bcrypt                                                              */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG *, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, PUCHAR, ULONG, ULONGLONG, PUCHAR, ULONG, ULONG);

/* ------------------------------------------------------------------ */
/* mpr                                                                 */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetAddConnection2A(LPNETRESOURCEA, LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetCancelConnection2A(LPCSTR, DWORD, BOOL);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetOpenEnumA(DWORD, DWORD, DWORD, LPNETRESOURCEA, LPHANDLE);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetEnumResourceA(HANDLE, LPDWORD, LPVOID, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI MPR$WNetCloseEnum(HANDLE);

/* ------------------------------------------------------------------ */
/* user32 / gdi32 (screen, clipboard, idle time)                       */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT BOOL   WINAPI USER32$GetLastInputInfo(PLASTINPUTINFO);
DECLSPEC_IMPORT int    WINAPI USER32$GetClassNameA(HWND, LPSTR, int);
DECLSPEC_IMPORT LRESULT WINAPI USER32$SendMessageA(HWND, UINT, WPARAM, LPARAM);
DECLSPEC_IMPORT BOOL   WINAPI USER32$OpenClipboard(HWND);
DECLSPEC_IMPORT HANDLE WINAPI USER32$GetClipboardData(UINT);
DECLSPEC_IMPORT BOOL   WINAPI USER32$IsClipboardFormatAvailable(UINT);
DECLSPEC_IMPORT BOOL   WINAPI USER32$CloseClipboard(void);
DECLSPEC_IMPORT HDC    WINAPI USER32$GetDC(HWND);
DECLSPEC_IMPORT int    WINAPI USER32$ReleaseDC(HWND, HDC);
DECLSPEC_IMPORT int    WINAPI USER32$GetSystemMetrics(int);
DECLSPEC_IMPORT HWND   WINAPI USER32$GetForegroundWindow(void);
DECLSPEC_IMPORT HWND   WINAPI USER32$GetDesktopWindow(void);
DECLSPEC_IMPORT BOOL   WINAPI USER32$EnumChildWindows(HWND, WNDENUMPROC, LPARAM);

DECLSPEC_IMPORT HDC   WINAPI GDI32$CreateCompatibleDC(HDC);
DECLSPEC_IMPORT HBITMAP WINAPI GDI32$CreateCompatibleBitmap(HDC, int, int);
DECLSPEC_IMPORT HGDIOBJ WINAPI GDI32$SelectObject(HDC, HGDIOBJ);
DECLSPEC_IMPORT BOOL  WINAPI GDI32$BitBlt(HDC, int, int, int, int, HDC, int, int, DWORD);
DECLSPEC_IMPORT int   WINAPI GDI32$GetDIBits(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);
DECLSPEC_IMPORT BOOL  WINAPI GDI32$DeleteObject(HGDIOBJ);
DECLSPEC_IMPORT BOOL  WINAPI GDI32$DeleteDC(HDC);

/* ------------------------------------------------------------------ */
/* kernel32 extras                                                     */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ProcessIdToSessionId(DWORD, DWORD *);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQuery(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentDirectoryA(DWORD, LPSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTempPathA(DWORD, LPSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetModuleFileNameA(HMODULE, LPSTR, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$SuspendThread(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$ResumeThread(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Thread32First(HANDLE, LPTHREADENTRY32);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);

/* ------------------------------------------------------------------ */
/* advapi32 extras                                                     */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSaveKeyA(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceConfig2A(SC_HANDLE, DWORD, LPBYTE, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ChangeServiceConfigA(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetNamedSecurityInfoA(LPCSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID *, PSID *, PACL *, PACL *, PSECURITY_DESCRIPTOR *);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID *);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, LPBOOL, PACL *, LPBOOL);

DECLSPEC_IMPORT BOOLEAN WINAPI ADVAPI32$AuditEnumerateSubCategories(const GUID *, BOOLEAN, GUID **, PULONG);
DECLSPEC_IMPORT BOOLEAN WINAPI ADVAPI32$AuditQuerySystemPolicy(const GUID *, ULONG, PAUDIT_POLICY_INFORMATION *);
DECLSPEC_IMPORT BOOLEAN WINAPI ADVAPI32$AuditLookupSubCategoryNameA(const GUID *, LPSTR *);
DECLSPEC_IMPORT VOID WINAPI ADVAPI32$AuditFree(PVOID);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaOpenPolicy(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaRetrievePrivateData(LSA_HANDLE, PLSA_UNICODE_STRING, PLSA_UNICODE_STRING *);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaClose(LSA_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaFreeMemory(PVOID);
DECLSPEC_IMPORT ULONG WINAPI ADVAPI32$LsaNtStatusToWinError(NTSTATUS);

/* ------------------------------------------------------------------ */
/* secur32 extras                                                      */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaGetLogonSessionData(PLUID, PSECURITY_LOGON_SESSION_DATA *);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID *, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

/* ------------------------------------------------------------------ */
/* netapi32 extras                                                     */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetWkstaGetInfo(LPCWSTR, DWORD, LPBYTE *);

/* ------------------------------------------------------------------ */
/* dnsapi extras                                                       */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsGetCacheDataTable(PDNS_CACHE_ENTRY *);

/* ------------------------------------------------------------------ */
/* fltlib                                                              */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT HRESULT WINAPI FLTLIB$FilterFindFirst(FILTER_INFORMATION_CLASS, LPVOID, DWORD, LPDWORD, LPHANDLE);
DECLSPEC_IMPORT HRESULT WINAPI FLTLIB$FilterFindNext(HANDLE, FILTER_INFORMATION_CLASS, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT HRESULT WINAPI FLTLIB$FilterFindClose(HANDLE);

/* ------------------------------------------------------------------ */
/* dbghelp                                                             */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT BOOL WINAPI DBGHELP$MiniDumpWriteDump(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

/* ------------------------------------------------------------------ */
/* crypt32                                                             */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenSystemStoreA(HCRYPTPROV_LEGACY, LPCSTR);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
DECLSPEC_IMPORT DWORD WINAPI CRYPT32$CertGetNameStringA(PCCERT_CONTEXT, DWORD, DWORD, void *, LPSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertGetCertificateContextProperty(PCCERT_CONTEXT, DWORD, void *, DWORD *);
DECLSPEC_IMPORT DWORD WINAPI CRYPT32$CertNameToStrA(DWORD, PCERT_NAME_BLOB, DWORD, LPSTR, DWORD);

/* ------------------------------------------------------------------ */
/* wldap32                                                             */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT LDAP *LDAPAPI WLDAP32$ldap_initA(const PCHAR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_bind_sA(LDAP *, PCHAR, PCHAR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP *);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_search_ext_sA(LDAP *, const PCHAR, ULONG, const PCHAR, PCHAR *, ULONG, PLDAPControlA *, PLDAPControlA *, struct l_timeval *, ULONG, LDAPMessage **);
DECLSPEC_IMPORT LDAPMessage *LDAPAPI WLDAP32$ldap_first_entry(LDAP *, LDAPMessage *);
DECLSPEC_IMPORT LDAPMessage *LDAPAPI WLDAP32$ldap_next_entry(LDAP *, LDAPMessage *);
DECLSPEC_IMPORT PCHAR LDAPAPI WLDAP32$ldap_get_dnA(LDAP *, LDAPMessage *);
DECLSPEC_IMPORT struct berval **LDAPAPI WLDAP32$ldap_get_values_lenA(LDAP *, LDAPMessage *, const PCHAR);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_count_values_len(struct berval **);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_value_free_len(struct berval **);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage *);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_add_ext_sA(LDAP *, const PCHAR, LDAPModA *[], PLDAPControlA *, PLDAPControlA *);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_modify_ext_sA(LDAP *, const PCHAR, LDAPModA *[], PLDAPControlA *, PLDAPControlA *);
DECLSPEC_IMPORT void LDAPAPI WLDAP32$ldap_memfreeA(PCHAR);
DECLSPEC_IMPORT PCHAR LDAPAPI WLDAP32$ldap_err2stringA(ULONG);

/* ------------------------------------------------------------------ */
/* winevt                                                              */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT EVT_HANDLE WINAPI WEVTAPI$EvtQuery(EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtNext(EVT_HANDLE, DWORD, EVT_HANDLE *, DWORD, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtRender(EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI WEVTAPI$EvtClose(EVT_HANDLE);
DECLSPEC_IMPORT EVT_HANDLE WINAPI WEVTAPI$EvtCreateRenderContext(DWORD, LPCWSTR *, DWORD);

/* ------------------------------------------------------------------ */
/* version                                                             */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT DWORD WINAPI VERSION$GetFileVersionInfoSizeA(LPCSTR, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI VERSION$GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI VERSION$VerQueryValueA(LPCVOID, LPCSTR, LPVOID *, PUINT);

/* ------------------------------------------------------------------ */
/* COM (ole32 / oleaut32)                                              */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(const GUID *, LPUNKNOWN, DWORD, const GUID *, LPVOID *);
DECLSPEC_IMPORT void    WINAPI OLE32$CoTaskMemFree(LPVOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateGuid(GUID *);
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR *);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT UINT    WINAPI OLEAUT32$SysStringLen(BSTR);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANT *);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANT *);

/* ------------------------------------------------------------------ */
/* more kernel32                                                       */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTimeZoneInformation(LPTIME_ZONE_INFORMATION);
DECLSPEC_IMPORT GEOID   WINAPI KERNEL32$GetUserGeoID(GEOCLASS);
DECLSPEC_IMPORT int     WINAPI KERNEL32$GetGeoInfoA(GEOID, GEOTYPE, LPSTR, int, LANGID);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetProcessHandleCount(HANDLE, PDWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

/* ------------------------------------------------------------------ */
/* more advapi32 / crypt32 / wts                                       */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CreateProcessAsUserA(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSQueryUserToken(ULONG, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertAddEncodedCertificateToStore(HCERTSTORE, DWORD, const BYTE *, DWORD, DWORD, PCCERT_CONTEXT *);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void *);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertAddCertificateContextToStore(HCERTSTORE, PCCERT_CONTEXT, DWORD, PCCERT_CONTEXT *);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertStrToNameA(DWORD, LPCSTR, DWORD, void *, BYTE *, DWORD *, LPCSTR *);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertCreateSelfSignCertificate(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, PCERT_NAME_BLOB, DWORD, PCRYPT_KEY_PROV_INFO, PCRYPT_ALGORITHM_IDENTIFIER, PSYSTEMTIME, PSYSTEMTIME, PCERT_EXTENSIONS);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);

/* ------------------------------------------------------------------ */
/* vssapi / fwpuclnt                                                   */
/* ------------------------------------------------------------------ */
DECLSPEC_IMPORT HRESULT WINAPI VSSAPI$CreateVssBackupComponentsInternal(IVssBackupComponents **);
DECLSPEC_IMPORT void    WINAPI VSSAPI$VssFreeSnapshotPropertiesInternal(VSS_SNAPSHOT_PROP *);

DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmEngineOpen0(const wchar_t *, UINT32, SEC_WINNT_AUTH_IDENTITY_W *, const FWPM_SESSION0 *, HANDLE *);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmEngineClose0(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmFilterCreateEnumHandle0(HANDLE, const FWPM_FILTER_ENUM_TEMPLATE0 *, HANDLE *);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmFilterEnum0(HANDLE, HANDLE, UINT32, FWPM_FILTER0 ***, UINT32 *);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmFilterDestroyEnumHandle0(HANDLE, HANDLE);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmSubLayerCreateEnumHandle0(HANDLE, const FWPM_SUBLAYER_ENUM_TEMPLATE0 *, HANDLE *);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmSubLayerEnum0(HANDLE, HANDLE, UINT32, FWPM_SUBLAYER0 ***, UINT32 *);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmSubLayerDestroyEnumHandle0(HANDLE, HANDLE);
DECLSPEC_IMPORT void  WINAPI FWPUCLNT$FwpmFreeMemory0(void **);

/* ------------------------------------------------------------------ */
/* NT handle table (SystemHandleInformation)                           */
/* ------------------------------------------------------------------ */
#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    ULONG  UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#endif /* ADAPTIX_BOFDEFS_H */
