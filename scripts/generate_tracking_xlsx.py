"""
generate_tracking_xlsx.py
-------------------------
Master tracking workbook for the fastscan project.

Reads the live source tree (driver files, plugin YAMLs, main.go flags,
cred lists) and emits a multi-sheet xlsx that captures: what landed,
the pipeline phases, the CLI surface, external dependencies, the
bridge scripts, the rounds log, the pending backlog, and future notes.

Run from the fastscan directory:
  python scripts/generate_tracking_xlsx.py

Output: fastscan_tracking.xlsx in the project root.
"""

import os
import re
import yaml
from collections import OrderedDict, defaultdict
import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ── style helpers ─────────────────────────────────────────────────────
HEADER_FILL = PatternFill("solid", fgColor="1F3864")
ROW_ALT     = PatternFill("solid", fgColor="F2F2F2")
SEV_FILL = {
    "critical": PatternFill("solid", fgColor="C00000"),
    "high":     PatternFill("solid", fgColor="FF0000"),
    "medium":   PatternFill("solid", fgColor="FFC000"),
    "low":      PatternFill("solid", fgColor="FFFF00"),
    "info":     PatternFill("solid", fgColor="BFBFBF"),
}
HEADER_FONT = Font(name="Arial", bold=True, color="FFFFFF", size=11)
ROW_FONT    = Font(name="Arial", size=10)
TITLE_FONT  = Font(name="Arial", bold=True, size=14)

def thin():
    s = Side(style="thin", color="999999")
    return Border(left=s, right=s, top=s, bottom=s)

def write_header(ws, headers, widths, row=1):
    for i, (h, w) in enumerate(zip(headers, widths), 1):
        c = ws.cell(row=row, column=i, value=h)
        c.font = HEADER_FONT
        c.fill = HEADER_FILL
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = thin()
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.row_dimensions[row].height = 28

def write_row(ws, values, row, alt=False, sev_col=None):
    for i, v in enumerate(values, 1):
        c = ws.cell(row=row, column=i, value=v)
        c.font = ROW_FONT
        c.alignment = Alignment(vertical="top", wrap_text=True)
        c.border = thin()
        if alt:
            c.fill = ROW_ALT
        if sev_col is not None and i == sev_col:
            sev = str(v).lower()
            if sev in SEV_FILL:
                c.fill = SEV_FILL[sev]
                c.font = Font(name="Arial", bold=True, color="FFFFFF", size=10)
                c.alignment = Alignment(horizontal="center", vertical="center")

# ── source-of-truth extraction ────────────────────────────────────────
def list_drivers():
    """Return [(file, source_name)] for every <x>probe.go."""
    files = sorted(f for f in os.listdir(ROOT) if f.endswith("probe.go"))
    out = []
    for f in files:
        src = f.replace("probe.go", "").lower()
        # tcposscan is the special OS-heuristic file, not named with probe.go
        out.append((f, src))
    if "tcposscan.go" in os.listdir(ROOT):
        out.append(("tcposscan.go", "os_heuristic"))
    return out

def list_plugins():
    """Return {source: [rule_id, ...]} from plugins/<source>/*.yaml."""
    out = defaultdict(list)
    p = os.path.join(ROOT, "plugins")
    if not os.path.isdir(p):
        return out
    for src in sorted(os.listdir(p)):
        sdir = os.path.join(p, src)
        if not os.path.isdir(sdir):
            continue
        for f in sorted(os.listdir(sdir)):
            if not f.endswith(".yaml"):
                continue
            try:
                with open(os.path.join(sdir, f), "r", encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
                out[src].append({
                    "rule_id": doc.get("id", f[:-5]),
                    "title": doc.get("title", ""),
                    "severity": (doc.get("severity") or "").lower(),
                    "tags": ",".join(doc.get("tags", []) or []),
                })
            except Exception as e:
                out[src].append({"rule_id": f[:-5], "title": f"(parse error {e})", "severity": "", "tags": ""})
    return out

def list_creds():
    """Return [(service, attempts_count)]."""
    p = os.path.join(ROOT, "creds")
    if not os.path.isdir(p):
        return []
    out = []
    for f in sorted(os.listdir(p)):
        if not f.endswith(".yaml"):
            continue
        try:
            with open(os.path.join(p, f), "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            out.append((doc.get("service", f[:-5]), len(doc.get("attempts", []) or [])))
        except Exception:
            out.append((f[:-5], 0))
    return out

def parse_flags():
    """Pull every flag.String/Bool/Int/Float declaration from main.go."""
    out = []
    with open(os.path.join(ROOT, "main.go"), "r", encoding="utf-8") as fh:
        src = fh.read()
    pat = re.compile(
        r'flag\.(?P<kind>String|Bool|Int|Float\d*)\("(?P<name>[^"]+)",\s*'
        r'(?P<default>[^,]+),\s*"(?P<help>[^"]+)"\)',
        re.M)
    for m in pat.finditer(src):
        out.append({
            "name": "-" + m.group("name"),
            "type": m.group("kind"),
            "default": m.group("default").strip(),
            "help": m.group("help"),
        })
    return out

# ── sheet builders ────────────────────────────────────────────────────
def sheet_summary(wb, drivers, plugins, flags, creds):
    ws = wb.active
    ws.title = "Summary"
    ws["A1"] = "fastscan — master tracking sheet"
    ws["A1"].font = TITLE_FONT
    ws["A2"] = "Auto-generated from the live source tree. Re-run scripts/generate_tracking_xlsx.py to refresh."
    ws["A2"].font = Font(name="Arial", italic=True, color="555555")
    ws.merge_cells("A1:D1")
    ws.merge_cells("A2:D2")

    rules_total = sum(len(v) for v in plugins.values())
    sev_count = defaultdict(int)
    for src, rules in plugins.items():
        for r in rules:
            sev_count[r["severity"] or "info"] += 1

    rows = [
        ("Driver Go files", len(drivers)),
        ("Plugin source directories", len(plugins)),
        ("Plugin rules (total)", rules_total),
        ("    Critical", sev_count.get("critical", 0)),
        ("    High",     sev_count.get("high", 0)),
        ("    Medium",   sev_count.get("medium", 0)),
        ("    Low",      sev_count.get("low", 0)),
        ("    Info",     sev_count.get("info", 0)),
        ("CLI flags",   len(flags)),
        ("Credential YAML files", len(creds)),
        ("Pipeline phases", 12),
        ("External CLI tools (deps)", 8),
        ("Scan profiles (auto-tuning)", 4),
    ]
    write_header(ws, ["Item", "Count"], [40, 12], row=4)
    for i, (k, v) in enumerate(rows, start=5):
        write_row(ws, [k, v], i, alt=(i % 2 == 0))

    # signature block
    ws[f"A{5 + len(rows) + 2}"] = "Status sheets:"
    ws[f"A{5 + len(rows) + 2}"].font = Font(name="Arial", bold=True)
    for j, name in enumerate(["Pipeline", "Drivers", "Plugins", "Flags",
                              "Dependencies", "Bridges", "Rounds Log",
                              "Pending", "Future Notes"], start=1):
        ws[f"A{5 + len(rows) + 2 + j}"] = f"  - {name}"

def sheet_pipeline(wb):
    ws = wb.create_sheet("Pipeline")
    write_header(ws,
        ["Phase", "What it does", "Skip flag", "Privilege"],
        [9, 80, 22, 18])
    phases = [
        ("1",    "rustscan TCP port discovery",                                           "(none)",            "user"),
        ("1b",   "nmap -sU UDP top-50 discovery (auto, can disable)",                    "-skip-udp",         "root"),
        ("2",    "nmap -sV service fingerprint via Ullaakut lib",                        "-skip-nmap",        "user"),
        ("2.4",  "auto-fingerprint cascade for unknown ports (passive read + active TLS / HTTP / X.224 / SMB)", "-skip-autofp", "user"),
        ("2.5",  "protocol drivers + plugin engine + default-credential testing (parallel within host)",       "-skip-drivers, -skip-creds", "user"),
        ("2.6",  "nmap -O OS detection (once per host)",                                  "-skip-os",          "root"),
        ("2.6b", "cvemap CPE -> CVE lookup",                                              "-skip-cve",         "user"),
        ("2.7",  "nmap --traceroute (once per host)",                                     "-skip-traceroute",  "root"),
        ("2.8",  "OS heuristic via banner correlation (no privilege)",                    "(always on if drivers ran)", "user"),
        ("2.9",  "TLS fingerprint (JA3/JA4)",                                             "(skipped if no TLS ports)",  "user"),
        ("2.95", "testssl.sh TLS vulnerability scan (Heartbleed, POODLE, DROWN, ...)",   "-skip-tlsvuln",     "user"),
        ("3",    "httpx HTTP enrichment + aggressive fallback for unknown ports",        "(none)",            "user"),
        ("4",    "nuclei templates per service-tag bucket (configurable concurrency + rate-limit)", "-skip-nuclei", "user"),
    ]
    for i, row in enumerate(phases, start=2):
        write_row(ws, row, i, alt=(i % 2 == 0))

def sheet_drivers(wb, drivers, plugins):
    ws = wb.create_sheet("Drivers")
    write_header(ws,
        ["File", "Source (plugin bucket)", "Plugins", "Description"],
        [28, 22, 9, 78])
    descriptions = {
        "ssh": "x/crypto/ssh KEX + host key extraction + algo enumeration + cred testing",
        "smb": "go-smb SMB2/3 negotiate + null session check + SMB1 detection",
        "smbvuln": "nxc wrapper for MS17-010, Zerologon, SMBGhost detection",
        "vnc": "RFB 3.x handshake (RFC 6143), security types, no-auth detection",
        "ldap": "go-ldap anonymous bind, rootDSE enumeration, supported SASL",
        "mssql": "TDS PRELOGIN packet, version, encryption requirements",
        "rdp": "X.224 CR + RDP_NEG_REQ, NLA / TLS / standard security",
        "ftp": "net/textproto banner, anonymous login, SYST + FEAT, AUTH TLS",
        "mysql": "MySQL handshake parse, version, auth plugin, SSL capability",
        "postgresql": "SSLRequest + StartupMessage, auth method (trust/cleartext/md5/scram)",
        "snmp": "gosnmp v2c walk of sysDescr/sysName/sysObjectID with community list",
        "netbios": "NBSTAT query, name table + suffix flags + MAC",
        "smtp": "EHLO capability list, STARTTLS, AUTH, open-relay test",
        "telnet": "IAC option negotiation parse, AUTHENTICATION + ENCRYPT presence",
        "kerberos": "gokrb5 AS-REQ per username, AS-REP roastable detection",
        "ipmi": "bougou/go-ipmi Cipher Suite 0 + null auth detection",
        "rpc": "SunRPC portmap DUMP + mountd EXPORT (NFS share enumeration)",
        "ajp": "AJP13 CPing + Forward-Request (Ghostcat probe)",
        "redis": "RESP PING / INFO / CONFIG GET dir",
        "memcached": "stats command, version, key stats",
        "mongodb": "OP_QUERY isMaster + BSON parse, auth required check",
        "pop3": "net/textproto banner + CAPA + STLS + SASL",
        "imap": "net/textproto CAPABILITY + STARTTLS + LOGINDISABLED",
        "ntp": "beevik/ntp + raw mode-7 monlist (CVE-2013-5211)",
        "os": "shells out to nmap -O --osscan-guess, XML parse",
        "dns": "miekg/dns, version.bind CHAOS TXT, recursion + DNSSEC checks",
        "winrm": "POST /wsman, WWW-Authenticate parse for Negotiate/NTLM/Basic",
        "oracle": "Oracle TNS Connect packet, version banner parse",
        "msrpc": "DCERPC BIND to EPMv4 + paginated EPT_Lookup",
        "mqtt": "MQTT v3.1.1 CONNECT/CONNACK, auth required",
        "sip": "SIP OPTIONS request, Server header + Allow methods",
        "modbus": "Modbus/TCP function 0x2B, vendor + product + firmware",
        "traceroute": "shells out to nmap --traceroute -sn -Pn, hop list",
        "os_heuristic": "Banner correlation across SSH/SMB/HTTP/FTP/SMTP/MySQL for OS family inference",
        "tlsfp": "TLS handshake JA3/JA4 fingerprinting",
        "tlsvuln": "testssl.sh wrapper for Heartbleed/POODLE/CCS/DROWN/Ticketbleed/etc.",
        "jdwp": "Java Debug Wire Protocol handshake + VirtualMachine.Version",
        "dockerapi": "Docker API HTTP /version + /containers/json (unauth detection)",
        "cups": "CUPS server header + /printers/ enumeration",
        "tftp": "UDP RRQ, distinguishes DATA vs ERROR opcodes",
        "weblogic": "WebLogic T3 handshake, version banner",
        "couchdb": "GET / + /_all_dbs, version + admin-party detection",
        "hnap": "POST /HNAP1/ SOAP, D-Link router model/firmware",
        "afp": "DSI GetStatus, ServerName + MachineType + AFP versions + UAMs",
        "pjl": "UEL-framed @PJL INFO ID + STATUS for HP printers",
        "db2": "DRDA EXCSAT (Exchange Server Attributes), server class + name",
        "cassandra": "CQL native protocol v4 OPTIONS + SUPPORTED multimap",
        "hbase": "GET /jmx + / HTML for HDFS NN / RegionServer info",
        "citrix": "Citrix ICA hello packet, banner bytes",
        "ike": "IKEv1 Aggressive Mode SA proposal, vendor IDs",
        "sstp": "POST /sra_{BA195980-...} for Microsoft SSTP VPN",
        "amqp": "AMQP 0-9-1 ProtocolHeader + Connection.Start frame parse",
        "iscsi": "iSCSI Login + Text Request SendTargets=All",
        "isns": "iSNS DevAttrQry + heartbeat",
        "xmpp": "<stream:stream> open + features parse (STARTTLS, mechanisms)",
        "tn3270": "Telnet IAC + TN3270E option detection (mainframe)",
        "informix": "Banner read + Informix product match",
        "svn": "TCP banner ( success ( version capabilities ... ) )",
        "hadoop": "GET /jmx Stargate REST cluster info + HDFS NN / YARN RM",
        "cve": "cvemap CPE -> CVE lookup with severity tiering",
        "autofingerprint": "Phase 2.4 cascade: passive banner read + active TLS / HTTP / X.224 / SMB probes",
    }
    drivers = sorted(drivers, key=lambda x: x[1])
    for i, (f, src) in enumerate(drivers, start=2):
        cnt = len(plugins.get(src, []))
        write_row(ws, [f, src, cnt, descriptions.get(src, "")], i, alt=(i % 2 == 0))

def sheet_plugins(wb, plugins):
    ws = wb.create_sheet("Plugins")
    write_header(ws,
        ["Source", "Rule ID", "Severity", "Title", "Tags"],
        [16, 36, 10, 60, 30])
    row = 2
    sources_sorted = sorted(plugins.keys())
    for src in sources_sorted:
        rules = sorted(plugins[src], key=lambda r: ["critical", "high", "medium", "low", "info"].index(r["severity"] or "info"))
        for r in rules:
            write_row(ws, [src, r["rule_id"], r["severity"], r["title"], r["tags"]],
                      row, alt=(row % 2 == 0), sev_col=3)
            row += 1

def sheet_flags(wb, flags):
    ws = wb.create_sheet("Flags")
    write_header(ws,
        ["Flag", "Type", "Default", "What it controls"],
        [28, 8, 22, 80])
    flags_sorted = sorted(flags, key=lambda f: f["name"])
    for i, f in enumerate(flags_sorted, start=2):
        write_row(ws, [f["name"], f["type"], f["default"], f["help"]], i, alt=(i % 2 == 0))

def sheet_deps(wb):
    ws = wb.create_sheet("Dependencies")
    write_header(ws,
        ["Tool", "Required?", "Used By", "Install Command"],
        [18, 12, 70, 70])
    deps = [
        ("nmap",       "REQUIRED", "Phase 2 -sV, Phase 1b UDP, Phase 2.6 OS detect, Phase 2.7 traceroute", "apt install nmap"),
        ("rustscan",   "REQUIRED", "Phase 1 TCP port discovery", "snap install rustscan  OR  cargo install rustscan"),
        ("httpx",      "optional", "Phase 3 web enrichment (CLI fallback; lib is embedded)", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("nuclei",     "optional", "Phase 4 templates (CLI used for -update-templates; lib is embedded)", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("testssl.sh", "optional", "Phase 2.95 TLS vulnerability scan", "git clone https://github.com/drwetter/testssl.sh /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh"),
        ("nxc",        "optional", "Phase 2.5 SMB vuln modules (MS17-010, Zerologon, SMBGhost)", "pipx install netexec"),
        ("cvemap",     "optional", "Phase 2.6b CPE -> CVE lookup", "go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest"),
        ("gosec",      "optional", "scripts/audit.sh SAST of fastscan source", "go install github.com/securego/gosec/v2/cmd/gosec@latest"),
        ("govulncheck","optional", "scripts/audit.sh CVE check of fastscan dep tree", "go install golang.org/x/vuln/cmd/govulncheck@latest"),
    ]
    for i, row in enumerate(deps, start=2):
        write_row(ws, row, i, alt=(i % 2 == 0))

def sheet_bridges(wb):
    ws = wb.create_sheet("Bridges")
    write_header(ws,
        ["Path", "Reads", "Writes", "Purpose"],
        [55, 30, 30, 60])
    bridges = [
        ("scripts/fastscan_to_xlsx.py",     "findings.ndjson", "fastscan_findings.xlsx", "13-column engagement workbook (severity colored)"),
        ("scripts/fastscan_to_evidence.py", "findings.ndjson", "evidence/fastscan/*.txt", "One .txt per finding in nxc terminal style"),
        ("tools/scripts/txt_to_img.py",     "evidence/*.txt",  "evidence/*.png",         "1600x830 PNG screenshots for engagement report"),
        ("scripts/install_deps.sh",         "(checks PATH)",    "/usr/local/bin/...",     "One-shot installer for nmap+rustscan+testssl+nxc"),
        ("scripts/audit.sh",                "fastscan source", "audit/*.json",           "gosec SAST + govulncheck CVE audit of fastscan code"),
        ("scripts/generate_tracking_xlsx.py", "live source tree", "fastscan_tracking.xlsx", "This file: regenerates tracking workbook"),
    ]
    for i, row in enumerate(bridges, start=2):
        write_row(ws, row, i, alt=(i % 2 == 0))

def sheet_rounds(wb):
    ws = wb.create_sheet("Rounds Log")
    write_header(ws,
        ["Round", "Date", "Theme", "What landed", "M2 smoke findings", "Wall time"],
        [8, 12, 28, 80, 14, 12])
    rounds = [
        (2,  "2026-06-13", "Initial driver pattern + plugin engine", "SSH driver + 5 plugins, plugin YAML loader, expr-lang", "5", ""),
        (3,  "2026-06-13", "SMB / VNC / LDAP / MSSQL / RDP drivers", "+ 5 drivers; full pipeline", "5", "212s"),
        (4,  "2026-06-13", "FTP / MySQL / PG / SNMP / NetBIOS / SMTP / Telnet / Kerberos / IPMI", "+9 drivers", "11", "85s"),
        (5,  "2026-06-13", "OS detection + DNS + WinRM", "+3 drivers, Phase 2.6/2.7/2.8", "24", "85s"),
        (6,  "2026-06-13", "xlsx report bridge", "scripts/fastscan_to_xlsx.py", "20", "n/a"),
        (7,  "2026-06-13", "Cred testing + tlsfp + Multi-host CIDR", "creds layer, JA3/JA4 driver, -max-hosts", "22", "62s"),
        (8,  "2026-06-13", "Scan modes + auto-tuning profiles", "fast/deep/custom ports, fast/medium/slow/crawl profiles", "26", "52s"),
        (9,  "2026-06-13", "HIGH NSE gap closure", "+13 drivers (jdwp,docker,cups,tftp,nfs,weblogic,couchdb,hnap,afp,pjl,db2,cassandra,hbase)", "28", "85s"),
        (10, "2026-06-13", "MEDIUM NSE gap closure", "+11 drivers (citrix,ike,sstp,amqp,iscsi,isns,xmpp,tn3270,informix,svn,hadoop)", "31", "86s"),
        (11, "2026-06-13", "Engagement-critical batch", "testssl wrapper + nxc wrapper + cvemap + nuclei update + differential + webhook", "31", "87s"),
        (12, "2026-06-14", "Unknown-port coverage", "Phase 2.4 auto-fingerprint cascade + -force-service + httpx unknown-port fallback + testssl STARTTLS routing", "36", "n/a"),
        (13, "2026-06-14", "LOW backlog", "-autofp-test flag + MS-RPC EPM Lookup pagination + parallel drivers-per-host + audit.sh", "41", "491s"),
        (14, "2026-06-14", "Nuclei concurrency", "Per-profile nuclei concurrency + rate-limit + override flags", "n/a", "n/a"),
    ]
    for i, row in enumerate(rounds, start=2):
        write_row(ws, row, i, alt=(i % 2 == 0))

def sheet_pending(wb):
    ws = wb.create_sheet("Pending")
    write_header(ws,
        ["Priority", "Item", "Effort", "Engagement Value", "Notes"],
        [10, 50, 14, 22, 60])
    items = [
        ("HIGH",   "Authenticated scanning (SSH key, SMB user+hash, LDAP creds)",      "~half day",       "Common engagement ask",     "Touches ~3 driver files. New -auth-config YAML flag."),
        ("HIGH",   "CISA KEV cross-reference",                                          "~half day",       "Tags findings 'known exploited'", "Download JSON weekly, cross-ref with our CVE rows."),
        ("MEDIUM", "Vulners CLI integration",                                           "~half day",       "Exploit availability per CVE", "Shellout pattern like cvemap. Marks findings exploited=true."),
        ("MEDIUM", "OpenVAS / Greenbone NVT shellout",                                  "1-2 days install + wrapper", "150k NVT coverage", "Big install, big coverage uplift if engagement justifies."),
        ("MEDIUM", "Standalone evidence pack generator",                                "~2 hrs",          "Single deliverable bundle",    "Zip xlsx + evidence/ + manifest into engagement-<name>-<date>.zip"),
        ("LOW",    "Web UI for config + live results",                                  "2-3 days",        "Multi-user team workflow",     "User's stated future ask. Likely nuxt or htmx over the NDJSON."),
        ("LOW",    "API server mode (-serve)",                                          "~1 day",          "CI/CD integration",            "HTTP API exposes scan endpoints. Companion of the Web UI."),
        ("LOW",    "Self-updater (fastscan -update)",                                  "~half day",       "Distribution UX",              "Pull latest binary from a release endpoint."),
        ("LOW",    "Docker container with all deps pre-installed",                      "~half day",       "Onboarding speed",             "Bundles nmap+rustscan+testssl+nxc+cvemap. Single image to run."),
        ("LOW",    "Schedule / cron integration (skipped originally)",                  "~2 hrs",          "Periodic rescans",             "User asked to skip. Could revisit if periodic monitoring needed."),
        ("LOW",    "SARIF output format",                                               "~1 hr",           "GitHub Security tab",          "User asked to skip. Add only if CI pipeline asks for it."),
        ("LOW",    "PPT report template",                                               "~half day",       "Slide deliverable",            "User asked to skip. xlsx + evidence already cover the data."),
    ]
    for i, row in enumerate(items, start=2):
        write_row(ws, row, i, alt=(i % 2 == 0))

def sheet_future(wb):
    ws = wb.create_sheet("Future Notes")
    write_header(ws,
        ["Topic", "Note"],
        [28, 100])
    notes = [
        ("NSE engine in Go",        "DECIDED NOT TO BUILD. NSE depends on nmap's protocol libs (http.lua/smb.lua/...). Porting them is 4-6 weeks for partial coverage. Instead: shell out to `nmap --script=...` if specific NSE scripts are needed."),
        ("OpenVAS NVT -> nuclei converter", "DECIDED NOT TO BUILD. NASL conversion is a research project. Run OpenVAS scanner alongside if 150k NVT depth is needed."),
        ("siemens/GoScans",         "20-star Go library covering SMB / NFS / SSH / TLS / HTTP. Their NFS v4 ACL depth exceeds ours. Not worth embedding given our existing coverage; reference only if NFS ACL enumeration becomes a real engagement requirement."),
        ("gosec + govulncheck",     "Not for scanning targets. They audit fastscan's own source (gosec = SAST, govulncheck = dep CVE check). Wired into scripts/audit.sh."),
        ("Plugin orchestration",    "Driver name -> source bucket (driverSourceFor map). Source -> plugin list (plugins[source]). Per-port loop dispatches driver, then evaluates only that source's plugins. Adding a new field to a driver report does NOT break existing plugins; they read JSON tags."),
        ("Concurrency layers",      "1) -max-hosts: concurrent hosts in CIDR (profile-driven). 2) -drivers-per-host: concurrent drivers within one host's port set. 3) -nuclei-concurrency: templates in flight in Phase 4. 4) -nuclei-rate-limit: req/sec global ceiling. ALL configurable per profile + manually overrideable."),
        ("Profile auto-detect",     "On startup fastscan does TCP connect to 443/80/22/445/3389 on the first target host and times the best response. RTT brackets pick fast (<50ms) / medium (50-200ms) / slow (200-500ms) / crawl (500ms+). Each profile sets batch / timeout / driver-timeout / max-hosts / 3 HTTP timeouts / nuclei concurrency + rate-limit."),
        ("Plugin YAML gotchas",     "expr-lang treats absent JSON fields as nil. nil != \"\" is TRUE -> false positives on bare 'when: field != \"\"'. Guard with 'field != nil and field != \"\"'. Similarly, len(nil) > 0 PANICS -> guard with 'field != nil and len(field) > 0'. RE2 regex has no lookaheads."),
        ("Force-service flag",      "-force-service \"PORT=NAME[,PORT=NAME...]\" overrides nmap's classification. Useful when nmap probes are blocked or wrong. Phase 2.4 cascade still runs unless the override is recognized."),
        ("Test target",             "Metasploitable2 at 172.17.0.3 (Docker bridge IP, NOT 127.0.0.1). Container is restart=unless-stopped. ~20 services. Used for every round's smoke test."),
        ("Acunetix at 127.0.0.1:3443", "Acunetix-scanner web UI on the dev box. Real TLS cert. Used for TLS / httpx / driver smoke tests."),
        ("Plugin authoring (no rebuild)", "Drop a YAML in plugins/<source>/<rule-id>.yaml. Engine loads at next startup. Schema: id / title / severity / source / when (expr) / evidence (Go template) / references / remediation / tags. Same authoring model as nuclei templates."),
        ("Webhook payload shape",   "POST JSON: {rule_id, severity, host, port, evidence, references, timestamp}. Fires only for severity in {critical, high}. Skipped for phase=baseline-existing rows."),
        ("Differential workflow",   "1st run: -save-baseline /path/baseline.ndjson stores normalized findings. 2nd run: -diff-against /path/baseline.ndjson emits only NEW findings as phase=finding, existing baseline as phase=baseline-existing for context."),
        ("Nuclei templates path",   "/tmp/all-tpl/ on idsserver (custom + community). Update with `nuclei -update-templates` or the auto-warn after 7 days."),
        ("Cred YAMLs",              "creds/<service>.yaml lists default credential attempts. Engagement-specific guesses added in copies. Editable without rebuild."),
        ("Memory file",             "fastscan-state.md in the project memory dir is the authoritative resume point. Loaded into every new Claude session. Update it any time a new round lands."),
        ("Going-forward tracking",  "Re-run scripts/generate_tracking_xlsx.py whenever a new driver, plugin, flag, or pipeline phase is added. Workbook regenerates from the live source tree, so it never drifts from reality."),
    ]
    for i, row in enumerate(notes, start=2):
        write_row(ws, row, i, alt=(i % 2 == 0))

def main():
    drivers = list_drivers()
    plugins = list_plugins()
    flags   = parse_flags()
    creds   = list_creds()

    wb = openpyxl.Workbook()
    sheet_summary(wb, drivers, plugins, flags, creds)
    sheet_pipeline(wb)
    sheet_drivers(wb, drivers, plugins)
    sheet_plugins(wb, plugins)
    sheet_flags(wb, flags)
    sheet_deps(wb)
    sheet_bridges(wb)
    sheet_rounds(wb)
    sheet_pending(wb)
    sheet_future(wb)

    out = os.path.join(ROOT, "fastscan_tracking.xlsx")
    wb.save(out)
    print(f"wrote: {out}")
    print(f"  drivers: {len(drivers)}")
    print(f"  plugin sources: {len(plugins)}")
    print(f"  plugin rules: {sum(len(v) for v in plugins.values())}")
    print(f"  flags: {len(flags)}")
    print(f"  cred YAMLs: {len(creds)}")

if __name__ == "__main__":
    main()
