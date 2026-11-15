# Coverage vs. `bofs.md`

`bofs.md` is a catalog of **241 entries** aggregated from many third-party
repositories, with duplicates and multi-BOF suites. This file maps every row to
either a native command in AdaptixBOFKit or the upstream project that provides
it.

- **Native** — implemented in this kit (see `src/`, registered in the `.axs`).
- **Native (partial)** — a native command covers the common case; the upstream
  tool is still better for the full feature set.
- **Upstream** — a separate, substantial project (license, size, or technique).

Summary: **114 native**, **18 partially native**, **109 upstream-only**.

> Names omit the `AdaptixBOFKit-` group prefix. See `README.md` for arguments.
>
> One command can satisfy several catalog rows (for example `hashfile` covers
> `md5`, `sha1` and `sha256`; `defender` covers `EnumExclusions`,
> `AddExclusion` and `DelExclusion`; `svcctl` covers `SCCreate`, `SCConfig`,
> `SCStart` and `SCStop`). The native row count below therefore is not the
> same as the number of compiled objects (109 objects, 140 registered
> commands).

## 🔍 Reconnaissance & Situational Awareness

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `whoami` | Native | `whoami` |
| `env` | Native | `env` |
| `ipconfig` | Native | `ipconfig` |
| `arp` | Native | `arp` |
| `netstat` | Native | `netstat` |
| `routeprint` | Native | `routeprint` |
| `listpipes` | Native | `listpipes` |
| `listmods [pid]` | Native | `listmods` |
| `driversigs` | Upstream | `trustedsec/CS-Situational-Awareness-BOF` |
| `enum_filter_driver` | Native | `filterdrivers` |
| `enumLocalSessions` | Native | `sessions` |
| `windowlist` | Native | `windowlist` |
| `resources` | Native | `resources` |
| `uptime` | Native | `uptime` |
| `locale` | Native | `locale` |
| `get_session_info` | Native | `sessioninfo` |
| `get_password_policy [host]` | Native | `passwordpolicy` |
| `useridletime` | Native | `useridletime` |
| `wmi_query` | Upstream | `trustedsec/CS-Situational-Awareness-BOF` |
| `tasklist [opt:server]` | Native (partial) | `proclist (no command line)` |
| `sc_enum` | Native | `scenum` |
| `schtasksenum` | Native | `schtasksenum` (`schtasks enum`) |
| `schtasksquery [taskpath]` | Native | `schtasksquery` (`schtasks query`) |
| `reg_query` | Native | `regquery` |
| `reg_query_recursive` | Native | `regqueryrec` |
| `vssenum` | Native | `vssenum` |
| `adv_audit_policies` | Native | `auditpol` |
| `findLoadedModule` | Native | `findmodule` |
| `sha1 / sha256 / md5` | Native | `hashfile (md5/sha1/sha256)` |
| `cacls [filepath]` | Native | `cacls` |
| `dir [directory] [/s]` | Native | `dir` |
| `whereami` | Native | `whereami` |

## 🌐 Network / Host Enumeration

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `netview` | Native | `netview` |
| `netshares [host]` | Native | `netshares` |
| `netsession [host]` | Native | `netsession` |
| `netloggedon [host]` | Native | `netloggedon` |
| `netGroupList [domain]` | Native | `domaingroups` |
| `netGroupListMembers [group]` | Native | `netgroupmembers` |
| `netLocalGroupList [server]` | Native | `netlocalgroups` |
| `netLocalGroupListMembers` | Native | `netlocalgroupmembers` |
| `nettime [host]` | Native | `nettime` |
| `netuse_list` | Native | `netuse-list` |
| `netuse_add` | Native | `netuse` |
| `probe [host] [port]` | Native | `probe` |
| `nslookup [host]` | Native | `nslookup` |
| `listdns` | Native | `listdns` |
| `portscanbof` | Native | `portscan` |
| `NBTscan-BOF` | Native | `nbtscan` |
| `Smbinfo` | Native | `smbinfo` |
| `EnumWebClient` | Native | `enumwebclient` |

## 🏛️ Active Directory / Domain Enumeration

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `ldapsearch` | Native | `ldapsearch` |
| `ldapsecuritycheck` | Native | `ldapsecuritycheck` |
| `Domaininfo` | Native | `domaininfo` |
| `ReconAD` | Upstream | outflanknl/C2-Tool-Collection |
| `netuser [user]` | Native | `netuser` |
| `regsession` | Native | `regsession` |
| `FindObjects` | Native | `findmodule` |
| `AddMachineAccount` | Native | `addmachineaccount` |
| `LDAP-Bof-Collection` | Native (partial) | `ldapsearch (generic)` |
| `PhantomLDAP` | Upstream | `sp4r1ng/PhantomLDAP` |
| `ADWS-BOF` | Upstream | `e-fin/ADWS-BOF` |
| `ScriptSentry-BOF` | Upstream | `An0nUD4Y/ScriptSentry-BOF` |
| `AdaptixBOFs (DNS)` | Upstream | `ADHDMurky/AdaptixBOFs` |
| `dnstool-bof` | Upstream | `slemire/dnstool-bof` |
| `DNSRPC-BOF` | Upstream | `Paradoxis/DNSRPC-BOF` |
| `EnumShares` | Native | `netshares` |
| `EnumSysmon` | Native | `enumsysmon` |
| `EnumWSC` | Native (partial) | `edrrecon (heuristic)` |
| `EnumSecProducts` | Native (partial) | `edrrecon (heuristic)` |
| `Adaptix-EDR-Recon` | Native | `edrrecon` |
| `netGroupListMembers2 / netsession2` | Native | `netgroupmembers` |

## 🔑 Credential Dumping & Access

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `nanodump` | Upstream | `fortra/nanodump` |
| `procdump` | Native | `procdump` |
| `SheepClone` | Upstream | `SnoopJesus420/SheepClone` |
| `SilentLsassDump` | Upstream | see bofs.md entry |
| `PPLDump_BOF` | Upstream | `EspressoCake/PPLDump_BOF` |
| `WerDump` | Upstream | `M1ndo/WerDump` |
| `GhostKatz` | Upstream | `RainbowDynamix/GhostKatz` |
| `kslkatz_bof` | Upstream | `Muz1K1zuM/kslkatz_bof` |
| `get_dpapi_system` | Native | `dpapissystem` |
| `reg_save / BOF-RegSave` | Native | `regsave` |
| `RawHive` | Upstream | `nmht3t/RawHive` |
| `UnderlayCopy_bof` | Upstream | `Muz1K1zuM/UnderlayCopy_bof` |
| `LSAdump-BOF` | Upstream | `shashinma/LSAdump-BOF` |
| `DCSync-Bof` | Upstream | `P0142/DCSync-Bof` |
| `dcsync-bof` | Upstream | `kozmer/dcsync-bof` |
| `dumpguard_bof` | Upstream | `0xedh/dumpguard_bof` |
| `CredManBOF` | Native | `credman` |
| `VaultDumpBOF` | Upstream | `MeirV2-2/VaultDumpBOF` |
| `DPAPI_BOF` | Upstream | `Bhanunamikaze/DPAPI_BOF` |
| `chryzsh/redteam-bofs` | Upstream | `chryzsh/redteam-bofs` |
| `ChromeKatz` | Upstream | see bofs.md entry |
| `EdgeDumper` | Upstream | `AlexLinov/Edge-Dumper` |
| `chrome-abe-decryption-bof` | Upstream | `mendacus/...` |
| `firefoxdump` | Upstream | `mrrobot1o1/firefoxdump` |
| `teams-cookies-bof` | Upstream | `TierZeroSecurity/...` |
| `Cookie-Monster-BOF` | Upstream | `KingOfTheNOPs/cookie-monster` |
| `slack_cookie` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `office_tokens` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `lastpass` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `NoteThief` | Native | `notethief` |
| `WiFiPasswords` | Native | `wifi` |
| `dumpwifi` | Native | `wifi` |
| `ClipboardStealBOF` | Native | `clipboard` |
| `ClipboardHistoryThief-BOF` | Upstream | `matsmi7h/...` |
| `LSAWhisperer-BOF` | Upstream | `Art-Fakt/LSAWhisperer-BOF` |
| `certdump` | Native | `certdump` |
| `aad-bofs` | Upstream | `kozmer/aad-bofs` |
| `get_azure_token` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `BAADTokenBroker` | Upstream | `temp43487580/...` |

## 🎫 Kerberos Attacks

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `Kerbeus-BOF` | Upstream | `RalfHacker/Kerbeus-BOF` |
| `nanorobeus` | Upstream | `wavvs/nanorobeus` |
| `Kerberoast` | Upstream | outflanknl/C2-Tool-Collection |
| `BofRoast` | Upstream | `cube0x0/BofRoast` |
| `tgtdelegation` | Upstream | `connormcgarr/tgtdelegation` |
| `Klist` | Native | `klist` |
| `KerbHash` | Native | `kerbhash` |
| `SprayAD` | Upstream | outflanknl/C2-Tool-Collection |
| `ESC1-unPAC` | Upstream | `RayRRT/ESC1-unPAC` |
| `Timeroast-BOF` | Upstream | `Udayveer17/Timeroast-BOF` |
| `purpleranges/bofs (gmsa-readpwd)` | Upstream | `purpleranges/bofs` |
| `tgt-monitor-bof` | Upstream | `jakobfriedl/...` |

## 📜 ADCS (Certificate Services) Attacks

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `adcs_enum` | Native | `adcs_enum` |
| `adcs_enum_com` | Native | `adcs_enum_com` (alias) |
| `adcs_enum_com2` | Native | `adcs_enum_com2` (alias) |
| `adcs_request` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `adcs_request_on_behalf` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `CVE-2022-26923` | Upstream | outflanknl/C2-Tool-Collection |
| `ESC1-unPAC` | Upstream | `RayRRT/ESC1-unPAC` |
| `add-rbcd-bof-fix` | Upstream | `0xGunrunner/...` |
| `OSEP-ENUM` | Native (partial) | `ldapsearch (generic)` |

## 🔺 Privilege Escalation

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `PrivKit` | Upstream | `mertdas/PrivKit` |
| `UAC-BOF-Bonanza` | Upstream | `icyguider/UAC-BOF-Bonanza` |
| `SigmaPotato-BOF` | Upstream | `m4rvxpn/SigmaPotato-BOF` |
| `PrintSpoofer-BOF` | Upstream | `SlimeOnSecurity/...` |
| `GodPotatoBOF-Sliver` | Upstream | see bofs.md entry |
| `EnableEFS` | Native | `enableefs` |
| `MS16-032-BOF` | Upstream | `curtishoughton/...` |
| `get_priv` | Native | `tokenpriv` |
| `WdToggle` | Upstream | outflanknl/C2-Tool-Collection |
| `Lapsdump` | Native | `lapsdump` |
| `PetitPotam` | Upstream | outflanknl/C2-Tool-Collection |
| `Ada-PoisonKiller-BOF` | Upstream | `JohnRyk/...` |
| `NOFILTER-NFEXEC` | Upstream | `y637F9QQ2x/...` |
| `Vipere (lpe_vs_bootstrap_bof)` | Upstream | `0xaled/Vipere` |
| `BadTakeover-BOF` | Upstream | `logangoins/...` |
| `Set-Password-Auth-BOF` | Upstream | `0xGunrunner/...` |

## 🚶 Lateral Movement

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `CobaltStrike-BOF (DCOM)` | Upstream | `Yaxser/CobaltStrike-BOF` |
| `CobaltStrike-BOF (WMI)` | Upstream | `Yaxser/CobaltStrike-BOF` |
| `shspawnas` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `Adaptix-inject-auto` | Native (partial) | `inject` |
| `SeDebugPrivilege-BOF` | Native (partial) | `tokenpriv + inject` |
| `cSessionHop` | Upstream | `jhalon/cSessionHop` |
| `ExecuteCrossSession` | Native (partial) | `executesession (WTS token, not COM)` |
| `StartWebClient` | Native | `startwebclient` (`svcctl start WebClient`) |
| `make_token_cert` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `netuse_add` | Native | `netuse` |

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

## 🕵️ Defense Evasion

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `unhook-bof` | Native (partial) | `unhook (ntdll sections only)` |
| `finduserhooks-bof` | Native | `finduserhooks` |
| `blind` | Native | `amsipatch/etwpatch` |
| `BOF-BYPASSING-AMSI-AND-ETW` | Native | `amsipatch/etwpatch` |
| `etw` | Native | `etwpatch` |
| `SilenceSysmon` | Native (partial) | `etwpatch` |
| `BlindEventlog` | Native | `blindeventlog` |
| `AddExclusion` | Native | `add-exclusion` |
| `DelExclusion` | Native | `delexclusion` |
| `EnumExclusions` | Native | `enumexclusions` |
| `SafeHarbor-BOF` | Native (partial) | `safeharbor (heuristic)` |
| `SilentHarbor-BOF` | Upstream | `ibaiC/SilentHarbor-BOF` |
| `DllComHijacking` | Upstream | REDMED-X/OperatorsKit |
| `DllEnvHijacking` | Upstream | REDMED-X/OperatorsKit |
| `VulnDriverScan-BOF` | Native | `vulndrivers` |
| `EnumRWX` | Native | `enumrwx` |
| `ClearEventlogBOF` | Native | `cleareventlog` |
| `HideFile` | Native | `hidefile` |

## 💾 Persistence

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `AddTaskScheduler` | Native | `AddTaskScheduler` (`schtasks create`) |
| `DelTaskScheduler` | Native | `DelTaskScheduler` (`schtasks delete`) |
| `schtaskscreate` | Native | `schtaskscreate` (`schtasks create`) |
| `ghost_task` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `RegistryPersistence` | Native | `runkey` |
| `reg_set` | Native | `regset` |
| `reg_delete` | Native | `regdelete` |
| `sc_create` | Native | `svc-create` |
| `sc_config / sc_start / sc_stop` | Native | `sc-config/sc-start/sc-stop` |
| `COM-Hunter` | Native | `comhunter` |
| `TrustMeBOF` | Native (partial) | `trustme (register/unregister; not all 8 BOFs)` |
| `PersisTask-BOF-AdaptixC2` | Upstream | `giovannicolonna/...` |
| `LNKgenerator-BOF` | Native | `lnkgenerator` |
| `AddFirewallRule` | Native | `addfirewallrule` |
| `AddLocalCert` | Native | `addlocalcert` |

## 🏢 Active Directory Attacks (Specialized)

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `PetitPotam` | Upstream | outflanknl/C2-Tool-Collection |
| `purpleranges/bofs (regsave)` | Upstream | `purpleranges/bofs` |
| `purpleranges/bofs (groupmod)` | Upstream | `purpleranges/bofs` |
| `ndur0/bofs (dcsync)` | Upstream | `ndur0/bofs` |
| `SQL-BOF` | Upstream | `Tw1sm/SQL-BOF` |
| `EnumDotnet` | Native | `enumdotnet` |

## 🧰 Utility & Intel Gathering

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `KeyloggerRawInput` | Upstream | REDMED-X/OperatorsKit |
| `Collection-BOF-Adaptix (keylogger)` | Upstream | `Loky-rt/Collection-BOF-Adaptix` |
| `ScreenshotBOF` | Native | `screenshot` |
| `GeoLocation_BOF` | Native (partial) | `geolocation (region/timezone, not location services)` |
| `msi-search` | Upstream | Mandiant |
| `evtxsearch-bof` | Native | `evtxsearch` |
| `EnumFiles` | Native | `enumfiles` |
| `ChromeHistory_bof` | Upstream | `mabangde/...` |
| `EnumDrives` | Native | `drives` |
| `Zip-BOF` | Upstream | `rubyattack3r/Zip-BOF` |
| `Zipper-BOF` | Upstream | `An0nUD4Y/Zipper-BOF` |
| `PortScan.c` | Native | `portscan` |
| `EnumHandles` | Native | `EnumHandles` (`enumhandles`) |
| `ProcessListHandles` | Native | `ProcessListHandles` (`processhandles`) |
| `ProcessDestroy` | Upstream | trustedsec/CS-Remote-OPs-BOF |
| `EnumLib` | Native | `listmods` |
| `proctools` | Native (partial) | `proclist` |
| `cs_DriverQuery` | Native | `drivers` |
| `WFPEnum` | Native | `wfpenum` |

## 🔧 Adaptix-Specific / Native BOFs

| Catalog BOF | Status | This kit / upstream |
|---|---|---|
| `LDAP-Bof-Collection` | Native (partial) | `ldapsearch (generic)` |
| `DCSync-Bof` | Upstream | `P0142/DCSync-Bof` |
| `LSAdump-BOF` | Upstream | `shashinma/LSAdump-BOF` |
| `NBTscan-BOF` | Native | `nbtscan` |
| `VaultDumpBOF` | Upstream | `MeirV2-2/VaultDumpBOF` |
| `Ada-PoisonKiller-BOF` | Upstream | `JohnRyk/...` |
| `LSAWhisperer-BOF` | Upstream | `Art-Fakt/...` |
| `AdaptixBOFs (DNS)` | Upstream | `ADHDMurky/AdaptixBOFs` |
| `Collection-BOF-Adaptix` | Upstream | `Loky-rt/Collection-BOF-Adaptix` |
| `Adaptix-inject-auto` | Native (partial) | `inject` |
| `Adaptix-EDR-Recon` | Native | `edrrecon` |
| `SeDebugPrivilege-BOF` | Native (partial) | `tokenpriv + inject` |
| `Set-Password-Auth-BOF` | Upstream | `0xGunrunner/...` |
| `add-rbcd-bof-fix` | Upstream | `0xGunrunner/...` |
| `OSEP-ENUM` | Native (partial) | `ldapsearch (generic)` |
