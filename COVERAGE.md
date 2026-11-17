# Coverage vs. `bofs.md`

`bofs.md` is a catalog of **241 entries** aggregated from many third-party
repositories, with duplicates and multi-BOF suites. This file maps every row to
either a native command in AdaptixBOFKit or the upstream project that provides
it.

- **Native** — implemented in this kit (see `src/`, registered in the `.axs`).
- **Native (partial)** — a native command covers the common case; the upstream
  tool is still better for the full feature set.
- **Upstream** — a separate, substantial project (license, size, or technique).

Summary: **160 native**, **41 partially native**, **84 upstream-only** (285 rows).

> Commands are shown with their `bof-` prefix. See `README.md` for arguments.
>
> One command can satisfy several catalog rows (for example `bof-hashfile`
> covers `md5`, `sha1` and `sha256`; the Defender commands `bof-enumexclusions`,
> `bof-add-exclusion` and `bof-delexclusion` cover `EnumExclusions`,
> `AddExclusion` and `DelExclusion`; `bof-svc-create`, `bof-sc-config`,
> `bof-sc-start` and `bof-sc-stop` cover `SCCreate`, `SCConfig`, `SCStart`
> and `SCStop`). The native row count below therefore is not the same as the
> number of compiled objects (170 objects, 201 registered commands).

## 🔍 Reconnaissance & Situational Awareness

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `whoami` | Native | `bof-whoami` |
| `env` | Native | `bof-env` |
| `ipconfig` | Native | `bof-ipconfig` |
| `arp` | Native | `bof-arp` |
| `netstat` | Native | `bof-netstat` |
| `routeprint` | Native | `bof-routeprint` |
| `listpipes` | Native | `bof-listpipes` |
| `listmods [pid]` | Native | `bof-listmods` |
| `driversigs` | Native | `bof-driversigs` |
| `enum_filter_driver` | Native | `bof-filterdrivers` |
| `enumLocalSessions` | Native | `bof-sessions` |
| `windowlist` | Native | `bof-windowlist` |
| `resources` | Native | `bof-resources` |
| `uptime` | Native | `bof-uptime` |
| `locale` | Native | `bof-locale` |
| `get_session_info` | Native | `bof-sessioninfo` |
| `get_password_policy [host]` | Native | `bof-passwordpolicy` |
| `useridletime` | Native | `bof-useridletime` |
| `wmi_query` | Native | `bof-wmi_query` |
| `tasklist [opt:server]` | Native | `bof-tasklist` (command lines via NtQueryInformationProcess/PEB) |
| `sc_enum` | Native | `bof-scenum` |
| `schtasksenum` | Native | `bof-schtasksenum` (`schtasks enum`) |
| `schtasksquery [taskpath]` | Native | `bof-schtasksquery` (`schtasks query`) |
| `reg_query` | Native | `bof-regquery` |
| `reg_query_recursive` | Native | `bof-regqueryrec` |
| `vssenum` | Native | `bof-vssenum` |
| `adv_audit_policies` | Native | `bof-auditpol` |
| `findLoadedModule` | Native | `bof-findmodule` |
| `sha1 / sha256 / md5` | Native | `bof-hashfile (bof-md5/bof-sha1/bof-sha256)` |
| `cacls [filepath]` | Native | `bof-cacls` |
| `dir [directory] [/s]` | Native | `bof-dir` |
| `whereami` | Native | `bof-whereami` |

## 🌐 Network / Host Enumeration

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `netview` | Native | `bof-netview` |
| `netshares [host]` | Native | `bof-netshares` |
| `netsession [host]` | Native | `bof-netsession` |
| `netloggedon [host]` | Native | `bof-netloggedon` |
| `netGroupList [domain]` | Native | `bof-domaingroups` |
| `netGroupListMembers [group]` | Native | `bof-netgroupmembers` |
| `netLocalGroupList [server]` | Native | `bof-netlocalgroups` |
| `netLocalGroupListMembers` | Native | `bof-netlocalgroupmembers` |
| `nettime [host]` | Native | `bof-nettime` |
| `netuse_list` | Native | `bof-netuse-list` |
| `netuse_add` | Native | `bof-netuse` |
| `probe [host] [port]` | Native | `bof-probe` |
| `nslookup [host]` | Native | `bof-nslookup` |
| `listdns` | Native | `bof-listdns` |
| `portscanbof` | Native | `bof-portscan` |
| `NBTscan-BOF` | Native | `bof-nbtscan` |
| `Smbinfo` | Native | `bof-smbinfo` |
| `EnumWebClient` | Native | `bof-enumwebclient` |

## 🏛️ Active Directory / Domain Enumeration

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `ldapsearch` | Native | `bof-ldapsearch` |
| `ldapsecuritycheck` | Native | `bof-ldapsecuritycheck` |
| `Domaininfo` | Native | `bof-domaininfo` |
| `ReconAD` | Upstream | outflanknl/C2-Tool-Collection |
| `netuser [user]` | Native | `bof-netuser` |
| `regsession` | Native | `bof-regsession` |
| `FindObjects` | Native | `bof-findmodule` |
| `AddMachineAccount` | Native | `bof-addmachineaccount` |
| `LDAP-Bof-Collection` | Native (partial) | `bof-ldapsearch (generic)` |
| `PhantomLDAP` | Upstream | `sp4r1ng/PhantomLDAP` |
| `ADWS-BOF` | Upstream | `e-fin/ADWS-BOF` |
| `ScriptSentry-BOF` | Upstream | `An0nUD4Y/ScriptSentry-BOF` |
| `AdaptixBOFs (DNS)` | Upstream | `ADHDMurky/AdaptixBOFs` |
| `dnstool-bof` | Native (partial) | `bof-dnsdump` (AD-integrated zones over LDAP) |
| `DNSRPC-BOF` | Upstream | `Paradoxis/DNSRPC-BOF` |
| `EnumShares` | Native | `bof-netshares` |
| `EnumSysmon` | Native | `bof-enumsysmon` |
| `EnumWSC` | Native (partial) | `bof-edrrecon (heuristic)` |
| `EnumSecProducts` | Native (partial) | `bof-edrrecon (heuristic)` |
| `Adaptix-EDR-Recon` | Native | `bof-edrrecon` |
| `netGroupListMembers2 / netsession2` | Native | `bof-netgroupmembers` |

## 🔑 Credential Dumping & Access

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `nanodump` | Upstream | `fortra/nanodump` |
| `procdump` | Native | `bof-procdump` |
| `SheepClone` | Upstream | `SnoopJesus420/SheepClone` |
| `SilentLsassDump` | Upstream | see bofs.md entry |
| `PPLDump_BOF` | Upstream | `EspressoCake/PPLDump_BOF` |
| `WerDump` | Upstream | `M1ndo/WerDump` |
| `GhostKatz` | Upstream | `RainbowDynamix/GhostKatz` |
| `kslkatz_bof` | Upstream | `Muz1K1zuM/kslkatz_bof` |
| `get_dpapi_system` | Native | `bof-dpapissystem` |
| `reg_save / BOF-RegSave` | Native | `bof-regsave` |
| `RawHive` | Upstream | `nmht3t/RawHive` |
| `UnderlayCopy_bof` | Upstream | `Muz1K1zuM/UnderlayCopy_bof` |
| `LSAdump-BOF` | Native (partial) | `bof-lsasecrets` (LsaRetrievePrivateData; no offline hive parsing) |
| `DCSync-Bof` | Native (partial) | `bof-dacledit dcsync` (writes replication ACEs; replication itself upstream) |
| `dcsync-bof` | Native (partial) | `bof-dacledit dcsync` (grants DCSync rights; replication itself upstream) |
| `dumpguard_bof` | Upstream | `0xedh/dumpguard_bof` |
| `CredManBOF` | Native | `bof-credman` |
| `VaultDumpBOF` | Native | `bof-vaultdump-full` (VaultGetItem authenticators) + `bof-vaultdump` (metadata) |
| `DPAPI_BOF` | Native (partial) | `bof-dpapimasterkey` (password-based masterkey decrypt) |
| `chryzsh/redteam-bofs` | Upstream | `chryzsh/redteam-bofs` |
| `ChromeKatz` | Upstream | see bofs.md entry |
| `EdgeDumper` | Upstream | `AlexLinov/Edge-Dumper` |
| `chrome-abe-decryption-bof` | Native (partial) | `bof-chromecreds-abe` (v10/v11 DPAPI, v20 APPB; ABE-protected entries reported) |
| `firefoxdump` | Upstream | `mrrobot1o1/firefoxdump` |
| `teams-cookies-bof` | Upstream | `TierZeroSecurity/...` |
| `Cookie-Monster-BOF` | Upstream | `KingOfTheNOPs/cookie-monster` |
| `slack_cookie` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `office_tokens` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `lastpass` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `NoteThief` | Native | `bof-notethief` |
| `WiFiPasswords` | Native | `bof-wifi` |
| `dumpwifi` | Native | `bof-wifi` |
| `ClipboardStealBOF` | Native | `bof-clipboard` |
| `ClipboardHistoryThief-BOF` | Upstream | `matsmi7h/...` |
| `LSAWhisperer-BOF` | Upstream | `Art-Fakt/LSAWhisperer-BOF` |
| `certdump` | Native | `bof-certdump` |
| `aad-bofs` | Upstream | `kozmer/aad-bofs` |
| `get_azure_token` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `BAADTokenBroker` | Upstream | `temp43487580/...` |
| `dpapiblobdec` | Native | `bof-dpapiblobdec` (hex DPAPI blob) |
| `chromecreds` | Native (partial) | `bof-chromecreds` (legacy DPAPI) + `bof-chromecreds-abe` (AES-GCM/app-bound) |
| `recentfiles` | Native (partial) | `bof-recentfiles` (Recent LNKs, CFB jump-list LNK streams and DestList paths; IDList-only targets unresolved) |
| `sshagentkeys` | Native (partial) | `bof-sshagentkeys` (public identities only; agent never exposes private keys) |
| `vaultdump` | Native (partial) | `bof-vaultdump` (metadata) + `bof-vaultdump-full` (authenticators) |

## 🎫 Kerberos Attacks

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `Kerbeus-BOF` | Upstream | `RalfHacker/Kerbeus-BOF` |
| `nanorobeus` | Upstream | `wavvs/nanorobeus` |
| `Kerberoast` | Native (partial) | `bof-kerberoast` (enumerates targets) + `bof-spnroast` (requests tickets with the current TGT) |
| `BofRoast` | Upstream | `cube0x0/BofRoast` |
| `tgtdelegation` | Upstream | `connormcgarr/tgtdelegation` |
| `Klist` | Native | `bof-klist` |
| `KerbHash` | Native | `bof-kerbhash` |
| `SprayAD` | Upstream | outflanknl/C2-Tool-Collection |
| `ESC1-unPAC` | Upstream | `RayRRT/ESC1-unPAC` |
| `Timeroast-BOF` | Upstream | `Udayveer17/Timeroast-BOF` |
| `purpleranges/bofs (gmsa-readpwd)` | Native | `bof-groupmanagedpw` (MSDS_MANAGEDPASSWORD_BLOB -> NTLM) |
| `tgt-monitor-bof` | Upstream | `jakobfriedl/...` |
| `spnroast` | Native | `bof-spnroast` (SSPI TGS request -> hashcat 13100/19600/19700) |
| `asreproast` | Native | `bof-asreproast` (finds `DONT_REQ_PREAUTH` accounts) |

## 📜 ADCS (Certificate Services) Attacks

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `adcs_enum` | Native | `bof-adcs_enum` |
| `adcs_enum_com` | Native | `bof-adcs_enum_com` (alias) |
| `adcs_enum_com2` | Native | `bof-adcs_enum_com2` (alias) |
| `adcs_request` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `adcs_request_on_behalf` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `CVE-2022-26923` | Upstream | outflanknl/C2-Tool-Collection |
| `ESC1-unPAC` | Upstream | `RayRRT/ESC1-unPAC` |
| `add-rbcd-bof-fix` | Native | `bof-rbcd` (`msDS-AllowedToActOnBehalfOfOtherIdentity`) |
| `OSEP-ENUM` | Native (partial) | `bof-ldapsearch (generic)` |

## 🔺 Privilege Escalation

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `PrivKit` | Upstream | `mertdas/PrivKit` |
| `UAC-BOF-Bonanza` | Native (partial) | `bof-uacbypass` (HKCU ms-settings fodhelper/computerdefaults) |
| `SigmaPotato-BOF` | Upstream | `m4rvxpn/SigmaPotato-BOF` |
| `PrintSpoofer-BOF` | Native (partial) | `bof-printspoofer` (SpoolSS coercion + pipe impersonation) |
| `GodPotatoBOF-Sliver` | Upstream | see bofs.md entry |
| `EnableEFS` | Native | `bof-enableefs` |
| `MS16-032-BOF` | Upstream | `curtishoughton/...` |
| `get_priv` | Native | `bof-tokenpriv` |
| `WdToggle` | Upstream | outflanknl/C2-Tool-Collection |
| `Lapsdump` | Native | `bof-lapsdump` |
| `PetitPotam` | Upstream | outflanknl/C2-Tool-Collection |
| `Ada-PoisonKiller-BOF` | Upstream | `JohnRyk/...` |
| `NOFILTER-NFEXEC` | Upstream | `y637F9QQ2x/...` |
| `Vipere (lpe_vs_bootstrap_bof)` | Upstream | `0xaled/Vipere` |
| `BadTakeover-BOF` | Upstream | `logangoins/...` |
| `Set-Password-Auth-BOF` | Upstream | `0xGunrunner/...` |
| `make_token` | Native | `bof-maketoken` (plaintext logon + impersonation) |
| `steal_token` | Native | `bof-stealtoken` (duplicate a process token) |
| `revert_token` | Native | `bof-reverttoken` (`RevertToSelf`) |
| `list_impersonation` | Native | `bof-listimpersonation` |
| `getsystem-svc` | Native (partial) | `bof-getsystem-svc` (pipe server + optional self-coercion; no SYSTEM command stage) |

## 🚶 Lateral Movement

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `CobaltStrike-BOF (DCOM)` | Upstream | `Yaxser/CobaltStrike-BOF` |
| `CobaltStrike-BOF (WMI)` | Upstream | `Yaxser/CobaltStrike-BOF` |
| `shspawnas` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `Adaptix-inject-auto` | Native (partial) | `bof-inject` |
| `SeDebugPrivilege-BOF` | Native (partial) | `bof-tokenpriv + bof-inject` |
| `cSessionHop` | Upstream | `jhalon/cSessionHop` |
| `ExecuteCrossSession` | Native (partial) | `bof-executesession (WTS token, not COM)` |
| `StartWebClient` | Native | `bof-startwebclient` (`svcctl start WebClient`) |
| `make_token_cert` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `netuse_add` | Native | `bof-netuse` |
| `smbexec` | Native | `bof-smbexec` (temporary SCM service) |
| `wmiexec` | Native | `bof-wmiexec` (`Win32_Process::Create`) |
| `dcomexec` | Native | `bof-dcomexec` (Shell.Application DCOM) |
| `scshell` | Native | `bof-scshell` (reconfigure an existing service) |
| `winrm-exec` | Native (partial) | `bof-winrm-exec` (native WS-Man over WinHTTP: Create/Command/Receive/Delete) |

## 💉 Code Injection & In-Memory Execution

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `InjectPoolParty` | Upstream | REDMED-X/OperatorsKit |
| `PoolParty-BOF` | Upstream | `An0nUD4Y/PoolParty-BOF` |
| `Cryo` | Upstream | `seraphimprotocol/Cryo` |
| `BOF-APC-HOLLOW` | Upstream | `le-jordon/BOF-APC-HOLLOW` |
| `sw2-secinject` | Upstream | `ScriptIdiot/...` |
| `No-Consolation` | Upstream | `fortra/No-Consolation` |
| `CLR-Stomp` | Upstream | `nettitude/CLR-Stomp` |
| `InlineExecute-Assembly` | Upstream | see bofs.md entry |
| `BOF_RunPe` | Upstream | `NtDallas/BOF_RunPe` |
| `BOF_Spawn` | Upstream | `NtDallas/BOF_Spawn` |
| `shellwindows-BOF` | Upstream | `Beautifu1Boy-Official/...` |
| `APC injection` | Native | `bof-injectapc` (queue user APC) |
| `NtCreateThreadEx injection` | Native | `bof-injectthread` |
| `EarlyBird` | Native | `bof-earlybird` (APC before entry point) |
| `GhostWrite` | Native | `bof-ghostwrite` (section-backed write) |

## 🕵️ Defense Evasion

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `unhook-bof` | Native (partial) | `bof-unhook (ntdll sections only)` |
| `finduserhooks-bof` | Native | `bof-finduserhooks` |
| `blind` | Native | `bof-amsipatch/bof-etwpatch` |
| `BOF-BYPASSING-AMSI-AND-ETW` | Native | `bof-amsipatch/bof-etwpatch` |
| `etw` | Native | `bof-etwpatch` |
| `SilenceSysmon` | Native (partial) | `bof-etwpatch` |
| `BlindEventlog` | Native | `bof-blindeventlog` |
| `AddExclusion` | Native | `bof-add-exclusion` |
| `DelExclusion` | Native | `bof-delexclusion` |
| `EnumExclusions` | Native | `bof-enumexclusions` |
| `SafeHarbor-BOF` | Native (partial) | `bof-safeharbor (heuristic)` |
| `SilentHarbor-BOF` | Upstream | `ibaiC/SilentHarbor-BOF` |
| `DllComHijacking` | Upstream | REDMED-X/OperatorsKit |
| `DllEnvHijacking` | Native (partial) | `bof-dllhijack` (service/AppInit writable-dir scan) |
| `VulnDriverScan-BOF` | Native | `bof-vulndrivers` |
| `EnumRWX` | Native | `bof-enumrwx` |
| `ClearEventlogBOF` | Native | `bof-cleareventlog` |
| `HideFile` | Native | `bof-hidefile` |
| `ppidspoof` | Native | `bof-ppidspoof` (parent-process attribute) |
| `blockdlls` | Native | `bof-blockdlls` (non-Microsoft DLL mitigation) |
| `acldeny` | Native | `bof-acldeny` (deny ACE on a file or key) |
| `timestomp` | Native | `bof-timestomp` (`SetFileTime`; MFT `$FILE_NAME` unchanged) |
| `schtaskshide` | Native | `bof-schtaskshide` (deny Users read on a task) |
| `patchwow64` | Native | `bof-patchwow64` (restore WOW64 module sections from disk) |
| `handlestrip` | Native (partial) | `bof-handlestrip` (close foreign VM_READ handles; needs PROCESS_DUP_HANDLE) |
| `aclprotect` | Native | `bof-aclprotect` (process DACL to SYSTEM; `restore` for NULL DACL) |

## 💾 Persistence

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `AddTaskScheduler` | Native | `bof-AddTaskScheduler` (`schtasks create`) |
| `DelTaskScheduler` | Native | `bof-DelTaskScheduler` (`schtasks delete`) |
| `schtaskscreate` | Native | `bof-schtaskscreate` (`schtasks create`) |
| `ghost_task` | Native | `bof-ghost-task` (register then deny Users read) |
| `RegistryPersistence` | Native | `bof-runkey` |
| `reg_set` | Native | `bof-regset` |
| `reg_delete` | Native | `bof-regdelete` |
| `sc_create` | Native | `bof-svc-create` |
| `sc_config / sc_start / sc_stop` | Native | `bof-sc-config/bof-sc-start/bof-sc-stop` |
| `COM-Hunter` | Native | `bof-comhunter` |
| `TrustMeBOF` | Native (partial) | `bof-trustme (register/unregister; not all 8 BOFs)` |
| `PersisTask-BOF-AdaptixC2` | Upstream | `giovannicolonna/...` |
| `LNKgenerator-BOF` | Native | `bof-lnkgenerator` |
| `AddFirewallRule` | Native | `bof-addfirewallrule` |
| `AddLocalCert` | Native | `bof-addlocalcert` |
| `wmisubscription` | Native | `bof-wmisubscription` (permanent WMI filter/consumer/binding) |
| `ifeo` | Native | `bof-ifeo` (Image File Execution Options debugger) |
| `printmonitor` | Native | `bof-printmonitor` (Spooler monitor DLL registration) |

## 🏢 Active Directory Attacks (Specialized)

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `PetitPotam` | Upstream | outflanknl/C2-Tool-Collection |
| `purpleranges/bofs (regsave)` | Upstream | `purpleranges/bofs` |
| `purpleranges/bofs (groupmod)` | Upstream | `purpleranges/bofs` |
| `ndur0/bofs (dcsync)` | Native (partial) | `bof-dacledit dcsync` (replication ACEs only) |
| `SQL-BOF` | Upstream | `Tw1sm/SQL-BOF` |
| `EnumDotnet` | Native | `bof-enumdotnet` |
| `gpocheck` | Native | `bof-gpocheck` (GPO links + GPP `cpassword` decrypt) |
| `dacledit` | Native | `bof-dacledit` (DACL edit: dcsync/genericall/writeowner/remove) |
| `shadowcred` | Native | `bof-shadowcred` (`msDS-KeyCredentialLink` writer) |
| `trustdump` | Native | `bof-trustdump` (`DsEnumerateDomainTrusts`) |

## 🧰 Utility & Intel Gathering

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `KeyloggerRawInput` | Native (partial) | `bof-keylogger` (duration-limited low-level hook) |
| `Collection-BOF-Adaptix (keylogger)` | Native (partial) | `bof-keylogger` (duration-limited low-level hook) |
| `screenspy` | Native | `bof-screenspy` (repeated BMP captures) |
| `keylogger` | Native (partial) | `bof-keylogger` (duration-limited low-level hook) |
| `browserhist` | Native | `bof-browserhist` (Chrome/Edge `History` SQLite) |
| `findcreds` | Native (partial) | `bof-findcreds` (filename heuristics + built-in keywords or user regex) |
| `ScreenshotBOF` | Native | `bof-screenshot` |
| `GeoLocation_BOF` | Native (partial) | `bof-geolocation (region/timezone, not location bof-services)` |
| `msi-search` | Native | `bof-msi-search` |
| `evtxsearch-bof` | Native | `bof-evtxsearch` |
| `EnumFiles` | Native | `bof-enumfiles` |
| `ChromeHistory_bof` | Native | `bof-browserhist` |
| `EnumDrives` | Native | `bof-drives` |
| `Zip-BOF` | Upstream | `rubyattack3r/Zip-BOF` |
| `Zipper-BOF` | Upstream | `An0nUD4Y/Zipper-BOF` |
| `PortScan.c` | Native | `bof-portscan` |
| `EnumHandles` | Native | `bof-EnumHandles` (`bof-enumhandles`) |
| `ProcessListHandles` | Native | `bof-ProcessListHandles` (`bof-processhandles`) |
| `ProcessDestroy` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `selfdelete` | Native | `bof-selfdelete` (reboot/helper strategies) |
| `prefetchdel` | Native | `bof-prefetchdel` (delete `.pf` traces) |
| `threadhide` | Native | `bof-threadhide` (`ThreadHideFromDebugger`) |
| `clearmplog` | Native | `bof-clearmplog` (Defender event logs) |
| `EnumLib` | Native | `bof-listmods` |
| `proctools` | Native (partial) | `bof-proclist` |
| `cs_DriverQuery` | Native | `bof-drivers` |
| `WFPEnum` | Native | `bof-wfpenum` |

## 🔧 Adaptix-Specific / Native BOFs

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `LDAP-Bof-Collection` | Native (partial) | `bof-ldapsearch (generic)` |
| `DCSync-Bof` | Native (partial) | `bof-dacledit dcsync` (writes replication ACEs; replication itself upstream) |
| `LSAdump-BOF` | Native (partial) | `bof-lsasecrets` (LsaRetrievePrivateData; no offline hive parsing) |
| `NBTscan-BOF` | Native | `bof-nbtscan` |
| `VaultDumpBOF` | Native | `bof-vaultdump-full` (VaultGetItem authenticators) + `bof-vaultdump` (metadata) |
| `Ada-PoisonKiller-BOF` | Upstream | `JohnRyk/...` |
| `LSAWhisperer-BOF` | Upstream | `Art-Fakt/...` |
| `AdaptixBOFs (DNS)` | Upstream | `ADHDMurky/AdaptixBOFs` |
| `Collection-BOF-Adaptix` | Upstream | `Loky-rt/Collection-BOF-Adaptix` |
| `Adaptix-inject-auto` | Native (partial) | `bof-inject` |
| `Adaptix-EDR-Recon` | Native | `bof-edrrecon` |
| `SeDebugPrivilege-BOF` | Native (partial) | `bof-tokenpriv + bof-inject` |
| `Set-Password-Auth-BOF` | Upstream | `0xGunrunner/...` |
| `add-rbcd-bof-fix` | Native | `bof-rbcd` (`msDS-AllowedToActOnBehalfOfOtherIdentity`) |
| `OSEP-ENUM` | Native (partial) | `bof-ldapsearch (generic)` |
