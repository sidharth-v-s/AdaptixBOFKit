# AdaptixBOFKit

A self-contained [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2) extension
that implements **109 Windows x64 BOFs** (**140 registered commands**, including
aliases) across the kill chain: situational awareness, network/AD enumeration,
credential access, Kerberos key derivation, privilege escalation, defense
evasion, persistence and post-exploitation.

The BOFs are original, CRT-free C implementations that use Adaptix's
`DLL$Function` import convention and only the Beacon APIs documented as
supported by Adaptix. They are compiled to position-independent x64 COFF
objects and registered through an AxScript extension.

Coverage is tracked in [`COVERAGE.md`](COVERAGE.md): 114 native, 18 partially
native, 109 upstream-only (heavy projects such as nanodump, Kerbeus, DCSync,
ADCS, CLR hosting, SQL-BOF and BYOVD).

---

## Contents

```
AdaptixBOFKit/
├── AdaptixBOFKit.axs        # AxScript extension (command registration)
├── COVERAGE.md              # coverage map -> native command or upstream
├── Makefile                 # x64 COFF build
├── build.sh                 # convenience wrapper
├── include/
│   ├── beacon.h             # Adaptix-supported Beacon API surface
│   ├── bofdefs.h            # DLL$Function declarations
│   ├── helpers.h            # CRT-free string/memory/format helpers
│   └── ldaphelpers.h        # LDAP bind / rootDSE helpers
├── src/                     # 109 BOF sources (one go() per file)
└── _bin/                    # generated: <name>.x64.o
```

---

## Build

Requirements:

```bash
sudo apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 make
```

Build everything:

```bash
./build.sh
```

or:

```bash
make -j$(nproc)
```

Each `src/<name>.c` produces `_bin/<name>.x64.o`. The objects are stripped and
contain no CRT imports; every external call resolves through
`KERNEL32$...`, `ADVAPI32$...`, `NETAPI32$...`, `IPHLPAPI$...`, `WLDAP32$...`, etc.

---

## Install / load in Adaptix

1. Copy this directory somewhere the Adaptix client can read (the client
   sandbox must be able to access `_bin/`).
2. In the client: **Main menu → AxScript → Script manager → Load new**.
3. Select `AdaptixBOFKit.axs`.
4. Select a Beacon agent and run the new commands. BOFs run **inside** the
   agent, single-threaded and blocking. A crash takes the agent with it.

The extension registers command groups:

| Group | Commands |
|---|---|
| `AdaptixBOFKit-Recon` (46) | `bof-whoami`, `bof-env`, `bof-ipconfig`, `bof-arp`, `bof-netstat`, `bof-routeprint`, `bof-uptime`, `bof-listpipes`, `bof-drives`, `bof-locale`, `bof-resources`, `bof-windowlist`, `bof-listmods`, `bof-sessions`, `bof-dir`, `bof-proclist`, `bof-services`, `bof-drivers`, `bof-useridletime`, `bof-sessioninfo`, `bof-regqueryrec`, `bof-auditpol`, `bof-findmodule`, `bof-filterdrivers`, `bof-scenum`, `bof-regsession`, `bof-edrrecon`, `bof-enumsysmon`, `bof-whereami`, `bof-enumrwx`, `bof-vulndrivers`, `bof-enumdotnet`, `bof-safeharbor`, `bof-enumdrives`, `bof-enumlib`, `bof-cacls`, `bof-geolocation`, `bof-evtxsearch`, `bof-finduserhooks`, `bof-enumhandles`, `bof-EnumHandles`, `bof-processhandles`, `bof-ProcessListHandles`, `bof-killprocess`, `bof-vssenum`, `bof-wfpenum` |
| `AdaptixBOFKit-Network` (17) | `bof-portscan`, `bof-nslookup`, `bof-netshares`, `bof-netview`, `bof-netuse`, `bof-netuse-list`, `bof-nettime`, `bof-netloggedon`, `bof-netsession`, `bof-listdns`, `bof-probe`, `bof-smbinfo`, `bof-enumwebclient`, `bof-portscanbof`, `bof-netsession2`, `bof-netuse_add`, `bof-nbtscan` |
| `AdaptixBOFKit-AD` (20) | `bof-netuser`, `bof-netlocalgroups`, `bof-netlocalgroupmembers`, `bof-domaingroups`, `bof-netgroupmembers`, `bof-passwordpolicy`, `bof-domaininfo`, `bof-ldapsearch`, `bof-addmachineaccount`, `bof-lapsdump`, `bof-netgrouplist`, `bof-netgrouplistmembers`, `bof-netgrouplistmembers2`, `bof-netlocalgrouplist`, `bof-netlocalgrouplistmembers`, `bof-get_password_policy`, `bof-adcs_enum`, `bof-adcs_enum_com`, `bof-adcs_enum_com2`, `bof-ldapsecuritycheck` |
| `AdaptixBOFKit-Creds` (13) | `bof-credman`, `bof-wifi`, `bof-autologon`, `bof-procdump`, `bof-regsave`, `bof-dpapissystem`, `bof-certdump`, `bof-clipboard`, `bof-notethief`, `bof-klist`, `bof-kerbhash`, `bof-dumpwifi`, `bof-wifipasswords` |
| `AdaptixBOFKit-Privesc-Evasion` (14) | `bof-tokenpriv`, `bof-uacstatus`, `bof-unhook`, `bof-etwpatch`, `bof-amsipatch`, `bof-hidefile`, `bof-cleareventlog`, `bof-add-exclusion`, `bof-enableefs`, `bof-blindeventlog`, `bof-enumexclusions`, `bof-delexclusion`, `bof-get_priv`, `bof-startwebclient` |
| `AdaptixBOFKit-Persistence` (21) | `bof-regquery`, `bof-regset`, `bof-regdelete`, `bof-runkey`, `bof-svc-create`, `bof-svc-delete`, `bof-sc-config`, `bof-sc-start`, `bof-sc-stop`, `bof-schtasksenum`, `bof-schtasksquery`, `bof-schtaskscreate`, `bof-schtasksdelete`, `bof-schtasksrun`, `bof-AddTaskScheduler`, `bof-DelTaskScheduler`, `bof-comhunter`, `bof-trustme`, `bof-addlocalcert`, `bof-addfirewallrule`, `bof-lnkgenerator` |
| `AdaptixBOFKit-Post` (9) | `bof-inject`, `bof-hashfile`, `bof-download`, `bof-screenshot`, `bof-enumfiles`, `bof-md5`, `bof-sha1`, `bof-sha256`, `bof-executesession` |

All commands are registered for the `beacon` agent on Windows, all listeners.

---

## Command reference

Every command is prefixed with `bof-` (for example `bof-whoami`, `bof-netstat`)
so it cannot collide with a same-named command from the official Adaptix
Extension-Kit.

### Recon / situational awareness

| Command | Example | Notes |
|---|---|---|
| `bof-whoami` | `bof-whoami` | User, SID, elevation, groups, token privileges |
| `bof-env` | `bof-env` | Process environment block |
| `bof-ipconfig` | `bof-ipconfig` | IPv4 adapters, gateways, DNS servers |
| `bof-arp` | `bof-arp` | IPv4 ARP table |
| `bof-netstat` | `bof-netstat` | TCP/UDP endpoints and states |
| `bof-routeprint` | `bof-routeprint` | IPv4 routing table |
| `bof-uptime` | `bof-uptime` | Current/boot UTC time and uptime |
| `bof-listpipes` | `bof-listpipes` | Named pipes |
| `bof-drives` / `bof-enumdrives` | `bof-drives` | Drive letters, types, total/free MB |
| `bof-locale` | `bof-locale` | System/user locale and codepages |
| `bof-resources` | `bof-resources` | Memory, CPU, disk C: |
| `bof-windowlist` | `bof-windowlist` | Visible top-level windows + PID |
| `bof-listmods` / `bof-enumlib` | `bof-listmods 1234` | Modules in a process (`0` = current) |
| `bof-sessions` | `bof-sessions` | WTS/RDP sessions, users and clients |
| `bof-dir` | `bof-dir C:\Windows /s` | Directory listing, optional recursive |
| `bof-proclist` | `bof-proclist` | PID, PPID, threads, full image path |
| `bof-services` | `bof-services` | Win32 services, state and PID |
| `bof-drivers` | `bof-drivers` | Kernel drivers registered with SCM |
| `bof-useridletime` | `bof-useridletime` | Seconds since last keyboard/mouse input |
| `bof-sessioninfo` | `bof-sessioninfo` | LSA logon session, type, SID, LUID |
| `bof-regqueryrec` | `bof-regqueryrec HKLM SOFTWARE\Test 3` | Recursive registry dump |
| `bof-auditpol` | `bof-auditpol` | Advanced audit policy subcategories |
| `bof-findmodule` | `bof-findmodule csagent.dll` | Processes with a module loaded |
| `bof-filterdrivers` | `bof-filterdrivers` | Filesystem minifilters (Sysmon, AV) |
| `bof-scenum` | `bof-scenum WinDefend` | One service in detail, or all services |
| `bof-regsession` | `bof-regsession` | Loaded user hives from `HKEY_USERS` |
| `bof-edrrecon` | `bof-edrrecon` | Known EDR/AV service + driver names |
| `bof-enumsysmon` | `bof-enumsysmon` | Sysmon service, driver and config path |
| `bof-whereami` | `bof-whereami` | PID/PPID, session, user, integrity, CWD |
| `bof-enumrwx` | `bof-enumrwx 1234` | RWX memory regions in a process |
| `bof-vulndrivers` | `bof-vulndrivers` | Drivers matching known BYOVD names |
| `bof-enumdotnet` | `bof-enumdotnet` | Processes with the CLR loaded |
| `bof-safeharbor` | `bof-safeharbor` | Candidate low-noise injection targets |
| `bof-cacls` | `bof-cacls C:\Windows\System32` | Owner, DACL principals and access masks |
| `bof-geolocation` | `bof-geolocation` | Region/country/timezone via GeoID (offline) |
| `bof-evtxsearch` | `bof-evtxsearch Security "*[System[(EventID=4624)]]" 5` | XPath event log query, renders XML |
| `bof-finduserhooks` | `bof-finduserhooks ntdll.dll` | Hook heuristics on export prologues |
| `bof-enumhandles` / `bof-EnumHandles` | `bof-enumhandles` | Handle count per process |
| `bof-processhandles` / `bof-ProcessListHandles` | `bof-processhandles 1234` | Handle value, type index and access |
| `bof-killprocess` | `bof-killprocess 1234` | Terminate a process |
| `bof-vssenum` | `bof-vssenum list` | Shadow copies (`providers` for providers) |
| `bof-wfpenum` | `bof-wfpenum all` | WFP filters and sublayers |

### Network

| Command | Example | Notes |
|---|---|---|
| `bof-portscan` / `bof-portscanbof` | `bof-portscan 10.0.0.5 22,80,443,8000-8100` | Non-blocking TCP connect scan (500 ms) |
| `bof-nslookup` | `bof-nslookup corp.local -t A -s 10.0.0.10` | A/AAAA/CNAME/MX/NS/PTR/TXT/SRV/SOA/ANY |
| `bof-netshares` | `bof-netshares 10.0.0.5` | SMB shares via `NetShareEnum` |
| `bof-netview` | `bof-netview CORP` | Domain computer list via `NetServerEnum` |
| `bof-netuse` / `bof-netuse_add` | `bof-netuse \\10.0.0.5\C$ CORP\user pass` | Map a remote share |
| `bof-netuse-list` | `bof-netuse-list` | List mapped network resources |
| `bof-nettime` | `bof-nettime 10.0.0.5` | Remote clock, timezone and uptime |
| `bof-netloggedon` | `bof-netloggedon 10.0.0.5` | Users logged on locally/remotely |
| `bof-netsession` / `bof-netsession2` | `bof-netsession 10.0.0.5` | SMB sessions on a machine |
| `bof-listdns` | `bof-listdns` | DNS client resolver cache |
| `bof-probe` | `bof-probe 10.0.0.5 445` | Single TCP port check |
| `bof-smbinfo` | `bof-smbinfo 10.0.0.5` | Workstation/domain/OS info |
| `bof-enumwebclient` | `bof-enumwebclient 10.0.0.5` | WebClient (WebDAV) service state |
| `bof-nbtscan` | `bof-nbtscan 10.0.0.5,10.0.0.6` | NetBIOS node status names and services |

### AD / accounts

| Command | Example | Notes |
|---|---|---|
| `bof-netuser` | `bof-netuser administrator CORP` | `USER_INFO_3` details |
| `bof-netlocalgroups` / `bof-netlocalgrouplist` | `bof-netlocalgroups 10.0.0.5` | Local groups |
| `bof-netlocalgroupmembers` | `bof-netlocalgroupmembers Administrators` | Local group members |
| `bof-domaingroups` / `bof-netgrouplist` | `bof-domaingroups CORP` | Domain global groups |
| `bof-netgroupmembers` | `bof-netgroupmembers "Domain Admins" CORP` | Domain group members |
| `bof-passwordpolicy` / `bof-get_password_policy` | `bof-passwordpolicy CORP` | Password and lockout policy |
| `bof-domaininfo` | `bof-domaininfo` | Join status, FQDN, DC |
| `bof-ldapsearch` | `bof-ldapsearch (objectClass=user) cn,sAMAccountName` | Generic LDAP search |
| `bof-addmachineaccount` | `bof-addmachineaccount EVILPC01` | Add a computer object over LDAP |
| `bof-lapsdump` | `bof-lapsdump` | Read `ms-Mcs-AdmPwd` from AD |
| `bof-regsession` | `bof-regsession` | Logged-on SIDs (BOFHound input) |
| `bof-adcs_enum` | `bof-adcs_enum all` | Local CAs, templates, enrollment services, ESC1 hints |
| `bof-adcs_enum_com` / `bof-adcs_enum_com2` | `bof-adcs_enum_com templates` | Aliases of `bof-adcs_enum` |
| `bof-ldapsecuritycheck` | `bof-ldapsecuritycheck` | LDAP signing and channel-binding verdict |

### Credentials / Kerberos

| Command | Example | Notes |
|---|---|---|
| `bof-credman` | `bof-credman` | Windows Credential Manager entries |
| `bof-wifi` / `bof-dumpwifi` / `bof-wifipasswords` | `bof-wifi` | Wireless profiles and plaintext keys |
| `bof-autologon` | `bof-autologon` | Winlogon `DefaultPassword` etc. |
| `bof-procdump` | `bof-procdump 644 C:\Temp\lsass.dmp` | `MiniDumpWriteDump` (full memory) |
| `bof-regsave` | `bof-regsave HKLM SAM C:\Temp\sam.hive` | Save a hive with `SeBackupPrivilege` |
| `bof-dpapissystem` | `bof-dpapissystem` | Read the `DPAPI_SYSTEM` LSA secret |
| `bof-certdump` | `bof-certdump user` | Certificates + SHA1 thumbprints |
| `bof-clipboard` | `bof-clipboard` | Current clipboard text |
| `bof-notethief` | `bof-notethief` | Text from open Notepad windows |
| `bof-klist` | `bof-klist` | Cached Kerberos tickets |
| `bof-kerbhash` | `bof-kerbhash Password123 alice CORP.LOCAL` | RC4 + AES128/192/256 keys |

### Privilege / evasion

| Command | Example | Notes |
|---|---|---|
| `bof-tokenpriv` / `bof-get_priv` | `bof-tokenpriv SeDebugPrivilege` | List privileges or enable one |
| `bof-uacstatus` | `bof-uacstatus` | UAC registry settings |
| `bof-unhook` | `bof-unhook` | Restore ntdll executable sections from disk |
| `bof-etwpatch` | `bof-etwpatch` | Patch `ntdll!EtwEventWrite` |
| `bof-amsipatch` | `bof-amsipatch` | Patch `amsi!AmsiScanBuffer` |
| `bof-hidefile` | `bof-hidefile C:\Temp\x.exe` | Hidden + system attributes |
| `bof-cleareventlog` | `bof-cleareventlog` | Clear Application/System/Security |
| `bof-add-exclusion` | `bof-add-exclusion C:\Temp` | Defender path exclusion (admin) |
| `bof-enumexclusions` | `bof-enumexclusions` | List all Defender exclusions |
| `bof-delexclusion` | `bof-delexclusion paths C:\Temp` | Remove an exclusion |
| `bof-enableefs` | `bof-enableefs` | Start the EFS service |
| `bof-blindeventlog` | `bof-blindeventlog suspend` | Suspend/resume EventLog threads |

### Registry / persistence

| Command | Example | Notes |
|---|---|---|
| `bof-regquery` | `bof-regquery HKLM SOFTWARE\... Run` | Enumerate or query a value |
| `bof-regset` | `bof-regset HKCU Software\Test value data` | Create/set `REG_SZ` |
| `bof-regdelete` | `bof-regdelete HKCU Software\Test value` | Delete value, or empty key |
| `bof-runkey` | `bof-runkey Updater C:\Users\Public\u.exe` | `HKCU\...\Run` persistence |
| `bof-svc-create` | `bof-svc-create Updater C:\Users\Public\u.exe` | Create + start service |
| `bof-svc-delete` | `bof-svc-delete Updater` | Delete service |
| `bof-sc-config` | `bof-sc-config Spooler disabled` | Change a service start type |
| `bof-sc-start` | `bof-sc-start Spooler` | Start a service |
| `bof-sc-stop` | `bof-sc-stop Spooler` | Stop a service |
| `bof-schtasksenum` | `bof-schtasksenum` | Tasks in all folders, hidden included |
| `bof-schtasksquery` | `bof-schtasksquery \Microsoft\Windows\Defrag\ScheduledDefrag` | Task state and full XML |
| `bof-schtaskscreate` / `bof-AddTaskScheduler` | `bof-schtaskscreate Updater C:\Windows\System32\cmd.exe /c calc.exe` | Logon-triggered task via XML |
| `bof-schtasksdelete` / `bof-DelTaskScheduler` | `bof-schtasksdelete Updater` | Delete a task |
| `bof-schtasksrun` | `bof-schtasksrun Updater` | Start a task on demand |
| `bof-comhunter` | `bof-comhunter find` | Find hijackable CLSIDs; `add`, `remove`, `treatas` |
| `bof-trustme` | `bof-trustme list` | Trust-provider register/unregister (admin, noisy) |
| `bof-addlocalcert` | `bof-addlocalcert machine CN=AdaptixBOFKit` | Create self-signed cert in `MY` |
| `bof-addfirewallrule` | `bof-addfirewallrule add AdaptixC2 443 tcp allow` | Add/remove/list firewall rules |
| `bof-lnkgenerator` | `bof-lnkgenerator C:\Users\Public\Update.lnk C:\Windows\System32\cmd.exe /c calc.exe` | Create a `.lnk` shortcut |
| `bof-startwebclient` | `bof-startwebclient` | Start the WebClient (WebDAV) service |

### Post-exploitation / utility

| Command | Example | Notes |
|---|---|---|
| `bof-inject` | `bof-inject 1234 C:\Temp\payload.bin` | Read raw shellcode and remote-inject |
| `bof-hashfile` / `bof-md5` / `bof-sha1` / `bof-sha256` | `bof-sha256 C:\Windows\System32\ntdll.dll` | MD5/SHA1/SHA256 via BCrypt |
| `bof-download` | `bof-download C:\Temp\out.txt` | Queue through Adaptix downloads |
| `bof-screenshot` | `bof-screenshot C:\Temp\screen.bmp` | Desktop capture to 32-bit BMP |
| `bof-enumfiles` | `bof-enumfiles C:\Users *.txt password` | Recursive name/content search |
| `bof-executesession` | `bof-executesession 2 C:\Windows\System32\cmd.exe` | Launch in another session via WTS token |

---

## Coverage

[`COVERAGE.md`](COVERAGE.md) contains a row-by-row coverage map for all **241**
rows. The short version:

- **Native (114 rows):** recon, networking, account/AD enumeration, LDAP,
  registry, services, scheduled tasks, VSS, ADCS, WFP, handle introspection,
  credential-manager, DPAPI secret, certificate, clipboard,
  Kerberos ticket/key, injection, hashing, Defender, event log and file
  utilities, COM/trust-provider persistence, firewall rules and shortcuts.
- **Partially native (18 rows):** `tasklist`, `EnumWSC`, `EnumSecProducts`,
  `SafeHarbor`, `SilenceSysmon`, `GeoLocation_BOF`,
  `ExecuteCrossSession`, `TrustMeBOF`, LDAP/OSEP suites, etc.
- **Upstream (109 rows):** LSASS dumping suites (nanodump, PPLDump, WerDump,
  GhostKatz), Kerberos/Rubeus ports, DCSync, ADCS request/exploit chains, CLR
  hosting, PoolParty and other injection families, SQL-BOF, BYOVD,
  clipboard-history/browser credential thieves, and similar multi-file
  projects.

For the upstream rows use the **official Adaptix Extension-Kit**, which already
packages and maintains them for Adaptix:

```bash
git clone https://github.com/Adaptix-Framework/Extension-Kit
cd Extension-Kit && make
```

Load `extension-kit.axs` alongside (or instead of) this extension. It covers:

- AD: `adwssearch`, `bof-ldapsearch`, `readlaps`, `DCSync-BOF`, `Kerbeus-BOF`
  (`asktgt`, `asktgs`, `kerberoasting`, `ptt`, `bof-klist`, `tgtdeleg`, …),
  `SQL-BOF`, ADCS, BadTakeover, RelayInformer
- Credentials: `nanodump`, `lsadump`, `hashdump`, `bof-credman`, `cookie-monster`,
  `UnderlayCopy`, `askcreds`, `get-netntlm`
- Elevation: `getsystem`, Potato/PrintSpoofer, UAC bypasses
- Execution: `execute-assembly`, `No-Consolation`
- Injection: `inject-sec`, `inject-poolparty`, `inject-cfg`
- Lateral movement: `psexec`, `smbexec`, `wmiexec`, `winrm`, `scshell`, MSSQL
- Process/Postex: `nanodump`, `pshistory`, `taskhound`, `sauroneye`, `shadow`

Some command names overlap between the two extensions (for example `bof-whoami`,
`bof-env`, `bof-ipconfig`, `bof-klist`). Load one or the other if you want a single
definition per name, or keep both and use the command description to
distinguish them.

### Not implemented here

`BeaconDataPtr`, `BeaconSpawnTemporaryProcess`, `BeaconInjectProcess`,
`BeaconVirtualAlloc*`, and the other APIs in Adaptix's "unsupported" list are
intentionally unused. Where functionality required them (for example
fork-and-run injection or CLR hosting), this pack does not pretend to provide
it.

---

## Writing your own BOF for this pack

1. Add `src/name.c` with a `void go(char *args, int alen)` entry point.
2. Include `beacon.h`, `bofdefs.h`, `helpers.h`.
3. Call Win32 through `DLL$Function` names. Add the declaration to
   `include/bofdefs.h` if it is missing.
4. Parse arguments with `BeaconDataParse` / `BeaconDataExtract` /
   `BeaconDataInt`.
5. Print with `BeaconPrintf(CALLBACK_OUTPUT, ...)`.
6. Add a command to `AdaptixBOFKit.axs` and register it in a group.

Minimal example:

```c
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

void go(char *args, int alen)
{
    datap p;
    char *who;
    int len = 0;

    if (!args || alen <= 0) return;
    BeaconDataParse(&p, args, alen);
    who = BeaconDataExtract(&p, &len);
    BeaconPrintf(CALLBACK_OUTPUT, "hello %s\n", who ? who : "world");
}
```

```js
var cmd_hello = ax.create_command("bof-hello", "Say hello", "bof-hello world");
cmd_hello.addArgString("who", true, "Name");
cmd_hello.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["who"]]);
    let path = ax.script_dir() + "_bin/hello." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${path}" ${params}`, "BOF: hello");
});
```

---

## Safety notes

- BOFs run synchronously in the Beacon process. Long loops and blocking
  network calls delay every other task. `bof-portscan` uses a 500 ms per-port
  timeout; scan small ranges or expect delays.
- `bof-unhook`, `bof-etwpatch`, `bof-amsipatch`, `bof-cleareventlog`, `bof-add-exclusion`,
  `bof-blindeventlog`, `bof-svc-create`, `bof-procdump`, `bof-regsave`, `bof-dpapissystem`,
  `bof-inject`, `bof-killprocess` and `bof-executesession` are noisy/high-impact. Test in
  a lab.
- `bof-trustme`, `bof-comhunter`, `bof-addlocalcert`, `bof-schtaskscreate`, `bof-addfirewallrule`
  and `bof-lnkgenerator` change system or user state. Record the exact values
  (GUID, task name, rule name, shortcut path) and clean up afterwards.
  `bof-trustme` writes HKLM, is loaded into many processes and should be treated
  as a loud, last-resort persistence test.
- `bof-vssenum` and `bof-wfpenum` usually need admin; `bof-schtaskscreate`/`delete` need
  write access to the target task folder. `bof-addlocalcert machine` needs admin.
- `bof-evtxsearch` renders up to 200 events per call; large XPath queries can be
  slow inside the agent. `bof-wfpenum` limits output to 400 filters.
- `bof-procdump` on LSASS needs an elevated/SYSTEM context and produces a large
  file; `MiniDumpWithFullMemory` is intentionally used.
- `bof-regsave` and `bof-dpapissystem` require administrator/SYSTEM; failures are
  reported by NTSTATUS/Win32 code.
- `bof-ldapsearch`, `bof-addmachineaccount`, `bof-lapsdump`, `bof-klist` and `bof-kerbhash` run
  with the current token; `bof-kerbhash` prints derived keys, treat output as a
  secret.
- `bof-wifi` plaintext key recovery depends on OS version, privileges and the
  profile's `protected` flag.
- `bof-download` buffers the whole file in the agent process (max 128 MB).
- Always build from source and review before running on a target.

---

## License

MIT for the code in this repository. The Adaptix name and BOF API belong to
the Adaptix Framework project. The optional official Extension-Kit is GPLv3
and remains under its own license.
