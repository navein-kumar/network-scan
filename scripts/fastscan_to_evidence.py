"""
fastscan_to_evidence.py
-----------------------
Bridge: fastscan NDJSON -> evidence .txt files (one per fired finding)
in the nxc terminal-output style that scripts/txt_to_img.py colourises.

Each .txt is pure scanner output: a leading "# fastscan -..." command
line and one or more "PROTO  host  Port: N  [+/-/*] ..." rows. No
commentary, no plugin names, no references to "fastscan plugin" or
similar. Matches the project rule for evidence going into
deliverables/images/.

Output layout:
  evidence/fastscan/<rule_id>/<host>_<port>.txt

Then run:
  python tools/scripts/txt_to_img.py evidence/fastscan/<rule_id>/<host>_<port>.txt
to render the matching PNG. The engagement lead later moves each .txt
into the appropriate evidence/vul-NN/ directory and renames per the
report's vulnerability numbering.

Usage:
  python fastscan_to_evidence.py -i findings.ndjson -o evidence/fastscan/
"""

import argparse
import json
import os
import re

import re as _re
_NESSUS_RE = _re.compile(r'^(nessus-)?[a-z]+-\d{4,6}$')

def _extract_product(title):
    return (title or '').split()[0] or 'unknown'

def _build_merged_cve_txt(product, cve_items, host, port, httpx_rec, ts, source):
    label = SOURCE_LABEL.get(source, source.upper())[:7]
    lines = []
    lines.extend(make_header(host, port, ts))
    cmd = f"# fastscan -{source}-test {host}:{port}" if port else f"# fastscan -{source}-test {host}"
    lines.append(cmd)
    lines.append("")
    if source == "http" and httpx_rec:
        lines.extend(http_context_lines(httpx_rec, label, host, port))
    lines.append("")
    lines.extend(wrap_line(label, host, port, "[+]",
                           f"{product} - {len(cve_items)} CVE vulnerabilities detected"))
    for rid, title, sev in cve_items:
        clean = rid.replace("nessus-", "")
        lines.extend(wrap_line(label, host, port, "   ",
                               f"[{sev.upper()}] {title}  ({clean})"))
    return "\n".join(lines)

import sys


# Source -> nxc-style protocol label shown as the first column of every line.
# Matches the PROTO_WORDS set in txt_to_img.py so the colouriser hits the
# right palette (blue for SMB/LDAP/FTP/SSH/MSSQL/RDP, plus we add more).
SOURCE_LABEL = {
    "ssh": "SSH", "smb": "SMB", "vnc": "VNC", "ldap": "LDAP",
    "mssql": "MSSQL", "rdp": "RDP", "ftp": "FTP", "mysql": "MYSQL",
    "postgresql": "PGSQL", "snmp": "SNMP", "netbios": "NBT",
    "smtp": "SMTP", "telnet": "TELNET", "kerberos": "KRB5",
    "ipmi": "IPMI", "rpc": "RPC", "ajp": "AJP", "redis": "REDIS",
    "memcached": "MEMC", "mongodb": "MONGO", "pop3": "POP3",
    "dockerapi": "DOCKER", "rsync": "RSYNC", "finger": "FINGER",
    "imap": "IMAP", "ntp": "NTP", "os": "OS", "dns": "DNS",
    "winrm": "WINRM", "oracle": "ORA", "msrpc": "MSRPC",
    "mqtt": "MQTT", "sip": "SIP", "modbus": "MODBUS",
    "traceroute": "TRACE", "os_heuristic": "OS",
    "tlsfp": "TLS", "nuclei": "NUCLEI",
}


_NUCLEI_ACRONYMS = {"tls", "ssl", "ssh", "http", "https", "ftp", "smb",
                    "dns", "rdp", "ip", "cve", "smtp", "ldap", "snmp"}


def nuclei_title(tid):
    """tls-deprecated-protocols -> TLS Deprecated Protocols"""
    words = tid.replace("_", "-").split("-")
    return " ".join(w.upper() if w.lower() in _NUCLEI_ACRONYMS
                    else w.capitalize() for w in words)


def parse_nuclei_url(u):
    """(host, port) from nuclei url/matched field."""
    if not u:
        return "", 0
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0]
    if ":" in u:
        host, _, p = u.rpartition(":")
        try:
            return host, int(p)
        except ValueError:
            return u, 0
    return u, 0

# Driver fields worth surfacing as [*] context lines per source. Keep the
# list small (4-6 fields) so the rendered image fits at a readable font.
DRIVER_CONTEXT_FIELDS = {
    "ssh":        ["banner", "host_key_algorithms", "weak_algos", "command_output"],
    "smb":        ["dialect", "os", "signing_required", "null_session", "smbv1_enabled", "shares"],
    "nfs":        ["nfs_reachable", "rpcbind_open", "anon_mount_ok", "exports"],
    "vnc":        ["protocol_version", "security_types", "screenshot_path"],
    "ldap":       ["is_tls", "anonymous_bind_ok", "naming_contexts", "entries"],
    "mssql":      ["version", "encryption_required", "instance", "databases"],
    "rdp":        ["nla_enabled", "tls_offered", "rdp_security_offered", "target_name",
                   "dns_computer_name", "dns_domain_name", "netbios_computer_name",
                   "netbios_domain_name", "os_version", "screenshot_path"],
    "ftp":        ["banner", "anonymous_login", "system", "root_listing", "auth_tls_offered"],
    "mysql":      ["server_version", "auth_plugin", "ssl_supported", "databases"],
    "postgresql": ["ssl_supported", "auth_method", "databases"],
    "snmp":       ["community_hit", "sys_descr", "sys_name", "network_interfaces",
                   "running_processes", "installed_software", "user_accounts"],
    "netbios":    ["names", "mac"],
    "smtp":       ["banner", "starttls_offered", "open_relay", "auth_methods", "vrfy_users"],
    "telnet":     ["banner", "authentication_offered", "encrypt_offered"],
    "kerberos":   ["realm", "existing_users", "as_rep_roastable"],
    "ipmi":       ["ipmi_version", "null_auth_allowed", "cipher_zero_allowed", "rakp_hashes", "users"],
    "rpc":        ["nfs_enabled", "exported_paths", "programs"],
    "ajp":        ["ajp13_responding", "ghostcat_probe_status"],
    "redis":      ["version", "role", "auth_required", "data_dir", "key_count", "keys"],
    "memcached":  ["version"],
    "mongodb":    ["version", "auth_required", "replica_set", "databases"],
    "dockerapi":  ["api_version", "version", "container_count", "containers", "images"],
    "pop3":       ["banner", "stls_offered", "message_count", "messages"],
    "imap":       ["banner", "starttls_offered", "login_disabled", "mailboxes"],
    "ntp":        ["version", "stratum", "monlist_responding", "monlist_entries", "system_info", "peers"],
    "os":         ["best"],
    "dns":        ["version_bind", "recursion_allowed", "dnssec_capable"],
    "winrm":      ["is_tls", "auth_methods_offered", "server_header", "command_output"],
    "oracle":     ["version", "banner", "sids", "tables"],
    "amqp":       ["product", "version", "guest_access", "vhosts", "queues"],
    "afp":        ["server_name", "machine_type", "uams", "volumes"],
    "cassandra":  ["cql_versions", "keyspaces", "tables"],
    "tftp":       ["accepts_requests", "retrieved_files"],
    "svn":        ["repo_uuid", "repo_root_url", "repo_listing"],
    "db2":        ["server_class", "server_rel", "server_version"],
    "msrpc":      ["bind_ack_received", "endpoints"],
    "mqtt":       ["connack_return_code", "auth_required", "broker_info", "topics"],
    "sip":        ["status_code", "server_header", "allow_methods", "extensions"],
    "modbus":     ["vendor_name", "product_code", "major_minor_revision",
                   "units_responding", "holding_registers", "coils"],
    "ike":        ["ike_version", "aggressive_mode_accepted", "vendor_ids",
                   "psk_hash", "psk_hash_format"],
    "jdwp":       ["jdwp_version", "vm_version", "vm_name", "description"],
    "iscsi":      ["targets", "target_addresses"],
    "rsync":      ["version", "modules"],
    "finger":     ["users"],
    "traceroute": ["hops"],
    "os_heuristic": ["os_family", "os_guess", "confidence", "matched_signals"],
    "tlsfp":      ["tls_version", "cipher_suite", "ja4", "ja4s"],
}


def safe_filename(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:64]


# Fields to surface as [*] context lines when the finding comes from
# the httpx phase (source=http) since there is no driver report.
HTTP_CONTEXT_FIELDS = ["title", "server", "tech", "meta.status_code", "url"]


def index_httpx_records(records):
    """Build (host, port) -> httpx Finding dict so source=http findings
    can borrow title/server/tech/status as context lines."""
    out = {}
    for r in records:
        if r.get("phase") != "httpx":
            continue
        host = r.get("host") or ""
        port = r.get("port") or 0
        if not host:
            continue
        out[(host, int(port))] = r
    return out


def http_context_lines(httpx_rec, label, host, port):
    """Build [*] context lines for HTTP findings using the httpx record."""
    if not httpx_rec:
        return []
    out = []
    for f in HTTP_CONTEXT_FIELDS:
        if f == "meta.status_code":
            v = (httpx_rec.get("meta") or {}).get("status_code")
            if v:
                out.append(line(label, host, port, "[*]", f"status_code: {v}"))
            continue
        v = httpx_rec.get(f)
        if v in (None, "", [], {}):
            continue
        rendered = format_value(v) if not isinstance(v, str) else v
        if len(rendered) > 400:
            rendered = rendered[:397] + "..."
        out.extend(wrap_line(label, host, port, "[*]", f"{f}: {rendered}"))
    sp = (httpx_rec.get("meta") or {}).get("screenshot_path") or httpx_rec.get("screenshot_path")
    if sp:
        out.append(line(label, host, port, "[*]", f"screenshot_path: {sp}"))
    return out


def make_header(host, port, ts):
    """Nmap-style preamble: timestamp + target up. ts is RFC3339 string."""
    import datetime
    try:
        d = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        when = d.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        when = ts or "n/a"
    target = host if not port else f"{host}:{port}"
    return [
        f"fastscan report at {when}",
        f"target {target}",
        "Host is up.",
        "",
    ]


def read_ndjson(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def index_driver_reports(records):
    """Build (host, port, source) -> driver report dict."""
    out = {}
    for r in records:
        if r.get("phase") != "driver":
            continue
        meta = r.get("meta") or {}
        source = meta.get("source") or ""
        report = meta.get("report") or {}
        host = r.get("host") or report.get("host") or ""
        port = r.get("port") or report.get("port") or 0
        if not source or not host:
            continue
        out[(host, int(port), source)] = report
    return out


def format_value(v):
    """Render a Python value the way nxc / banner output reads."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        if not v:
            return ""
        if isinstance(v[0], dict):
            # Compact list of dicts (e.g. host_keys, names, hops, endpoints)
            return "; ".join(
                ", ".join(f"{k}={fv}" for k, fv in d.items()
                          if fv not in (None, "", [], {}))
                for d in v[:6])
        return ", ".join(str(x) for x in v[:8])
    if isinstance(v, dict):
        return ", ".join(f"{k}={format_value(fv)}" for k, fv in v.items()
                         if fv not in (None, "", [], {}))
    return str(v)


def line(label, host, port, marker, text):
    """Format one line in nxc style: PROTO  host  Port: N  [x] text"""
    host_p = f"{host:<15}" if len(host) <= 15 else host
    return f"{label:<7} {host_p}  Port: {port:<5}  {marker} {text}"


# Max width in characters for a single evidence line (for readable screenshots).
MAX_LINE_WIDTH = 160


def wrap_line(label, host, port, marker, text):
    """Format one evidence line with wrap-to-next-line if too wide.
    Continuation lines use a blank marker (spaces) so they align under
    the first line's text but stay readable.
    """
    first = line(label, host, port, marker, text)
    if len(first) <= MAX_LINE_WIDTH:
        return [first]
    # Compute the prefix width (everything before "text"). All wraps
    # use a continuation marker of "   " (3 spaces) instead of "[*]".
    prefix_first = line(label, host, port, marker, "")
    prefix_cont = line(label, host, port, "   ", "")
    body_width = MAX_LINE_WIDTH - len(prefix_first)
    if body_width < 30:
        body_width = 30
    out = []
    # Prefer splitting at commas when present
    if "," in text:
        parts = [p.strip() for p in text.split(",")]
        cur = ""
        for p in parts:
            piece = p if cur == "" else ", " + p
            if len(cur) + len(piece) > body_width and cur != "":
                out.append(cur)
                cur = p
            else:
                cur += piece
        if cur:
            out.append(cur)
    else:
        # Hard-wrap by character count if no commas to split on
        s = text
        while len(s) > body_width:
            out.append(s[:body_width])
            s = s[body_width:]
        if s:
            out.append(s)
    rendered = [prefix_first + out[0]]
    for chunk in out[1:]:
        rendered.append(prefix_cont + chunk)
    return rendered


def build_txt(finding, driver_report, httpx_rec=None):
    """Build the evidence .txt body for one finding."""
    source = finding.get("source", "")
    host = finding.get("host", "")
    port = finding.get("port") or 0
    rule_id = finding.get("rule_id", "")
    evidence = (finding.get("evidence") or "").strip()
    ts = finding.get("ts") or ""
    label = SOURCE_LABEL.get(source, source.upper())[:7]

    lines = []
    # Nmap-style preamble: timestamp + target up
    lines.extend(make_header(host, port, ts))

    # Command header (rendered bright white by txt_to_img.py)
    if source == "os":
        cmd = f"# fastscan --os-test {host}"
    elif source == "traceroute":
        cmd = f"# fastscan --traceroute-test {host}"
    elif port:
        cmd = f"# fastscan --{source}-test {host}:{port}"
    else:
        cmd = f"# fastscan --{source}-test {host}"
    lines.append(cmd)
    lines.append("")

    # Context lines from the driver report ([*] info)
    if driver_report:
        # Fields that are file/share/export listings: render one entry per
        # line instead of a single comma-joined line.
        LIST_FIELDS = ("root_listing", "exported_paths", "exports", "shares",
                       "share_files", "readable_shares", "keys", "databases",
                       "collections", "tables", "entries", "vrfy_users",
                       "naming_contexts", "auth_methods", "command_output",
                       "running_processes", "installed_software",
                       "network_interfaces", "user_accounts",
                       "containers", "images", "sids", "keyspaces",
                       "vhosts", "queues", "volumes", "retrieved_files",
                       "repo_listing", "mailboxes", "messages", "uams",
                       "rakp_hashes", "users", "broker_info", "topics",
                       "system_info", "peers", "monlist_entries", "modules",
                       "targets", "target_addresses", "holding_registers",
                       "coils", "extensions", "units_responding", "vendor_ids")
        for f in DRIVER_CONTEXT_FIELDS.get(source, []):
            v = driver_report.get(f)
            if v in (None, "", [], {}, 0, False):
                continue
            if f in LIST_FIELDS and isinstance(v, list):
                lines.append(line(label, host, port, "[*]", f + ":"))
                for entry in v[:60]:
                    if isinstance(entry, dict):
                        # e.g. NFS export: {path, allowed_hosts, world_readable}
                        text = entry.get("path") or entry.get("name") or str(entry)
                        if entry.get("world_readable"):
                            text += "  (world-readable)"
                        hosts_allowed = entry.get("allowed_hosts")
                        if hosts_allowed:
                            text += "  [" + ", ".join(str(h) for h in hosts_allowed) + "]"
                    else:
                        text = str(entry)
                    lines.extend(wrap_line(label, host, port, "   ", "  " + text))
                continue
            rendered = format_value(v)
            if not rendered:
                continue
            # Cap absurd lengths (above 400 chars) then let wrap_line
            # split the rest across multiple visual rows.
            if len(rendered) > 400:
                rendered = rendered[:397] + "..."
            lines.extend(wrap_line(label, host, port, "[*]",
                                   f"{f}: {rendered}"))

    # HTTP findings have no driver report; pull context from httpx record
    if source == "http" and httpx_rec:
        lines.extend(http_context_lines(httpx_rec, label, host, port))

    # Nuclei findings: synthesize context lines so the evidence image is
    # not a single line. Template + matched target as [*], extract as [+].
    if source == "nuclei":
        lines.extend(wrap_line(label, host, port, "[*]",
                               f"template: {rule_id}"))
        tgt = f"{host}:{port}" if port else host
        lines.extend(wrap_line(label, host, port, "[*]",
                               f"matched: {tgt}"))
        if finding.get("severity"):
            lines.extend(wrap_line(label, host, port, "[*]",
                                   f"severity: {finding.get('severity')}"))

    # tlsvuln findings: render actual protocol/cipher detail from driver report
    # so the evidence proves the vulnerability rather than just asserting it.
    if source == "tlsvuln" and driver_report:
        vulns  = driver_report.get("vulnerabilities") or []
        protos = driver_report.get("protocols") or []
        sc     = driver_report.get("server_ciphers") or []

        # Map rule_id to testssl vuln id substrings (comma-separated for multi-match).
        _RULE_VULN = {
            "tls-drown":                "DROWN",
            "tls-ccs-injection":        "CCS",
            "tls-poodle-ssl":           "POODLE",
            "tls-heartbleed":           "HEARTBLEED",
            "tls-logjam-common-primes": "LOGJAM",
            "tls-sweet32":              "SWEET32",
            "tls-ticketbleed":          "TICKETBLEED",
            "tls-freak":                "FREAK",
            "tls-deprecated-protocol": None,
            "tls-weak-cipher":          "RC4,BEAST",
        }
        key_pat = _RULE_VULN.get(rule_id, "")

        def _matches(vid):
            return any(k.lower() in vid.lower() for k in key_pat.split(",")) if key_pat else False

        for v in vulns:
            vid = v.get("id", "")
            vf  = v.get("finding", "")
            cve = v.get("cve", "")
            if not _matches(vid):
                continue
            # BEAST_CBC_* and RC4 embed space-separated cipher names inside the finding text.
            if vid.startswith("BEAST_CBC_") or vid == "RC4":
                hdr = vid if not cve else "%s (%s)" % (vid, cve)
                lines.extend(wrap_line(label, host, port, "[*]", hdr + ":"))
                raw = vf.split(":", 1)[-1] if ":" in vf else vf
                cipher_names = [w for w in raw.split() if re.match(r"^[A-Z][A-Z0-9]", w)]
                for c in cipher_names[:8]:
                    lines.extend(wrap_line(label, host, port, "[*]", "  " + c))
            else:
                detail = vf[:120]
                if cve:
                    detail = "(%s): %s" % (cve, detail)
                lines.extend(wrap_line(label, host, port, "[*]", "%s %s" % (vid, detail)))

        # DROWN: list every SSLv2 cipher from serverPreferences with enc/bits.
        if rule_id == "tls-drown":
            ssl2 = [c for c in sc if c.get("id", "").startswith("cipher-ssl2_")]
            if ssl2:
                lines.extend(wrap_line(label, host, port, "[*]",
                    "SSLv2 accepted ciphers (%d):" % len(ssl2)))
                for c in ssl2:
                    parts = c["finding"].split()
                    if len(parts) >= 6:
                        lines.extend(wrap_line(label, host, port, "[*]",
                            "  %-30s %s %s" % (parts[2], parts[4], parts[5])))
            else:
                for p in protos:
                    if "sslv2" in p.get("id", "").lower():
                        lines.extend(wrap_line(label, host, port, "[*]",
                            "SSLv2: " + p.get("finding", "")))

        # POODLE: SSLv3 cipher names confirm CBC mode negotiation.
        if rule_id == "tls-poodle-ssl":
            ssl3 = [c for c in sc if c.get("id", "").startswith("cipher-ssl3_")][:4]
            if ssl3:
                lines.extend(wrap_line(label, host, port, "[*]", "SSLv3 accepted ciphers (sample):"))
                for c in ssl3:
                    parts = c["finding"].split()
                    if len(parts) >= 3:
                        lines.extend(wrap_line(label, host, port, "[*]", "  " + parts[2]))

        # Deprecated TLS (1.0/1.1): list which deprecated versions are offered.
        if rule_id == "tls-deprecated-protocol":
            for p in protos:
                pid = p.get("id", "")
                pf  = p.get("finding", "")
                if pid in ("TLS1", "TLS1_1") and "offered" in pf.lower() and "not offered" not in pf.lower():
                    label_map = {"TLS1": "TLS 1.0", "TLS1_1": "TLS 1.1"}
                    lines.extend(wrap_line(label, host, port, "[*]",
                        "%s: %s" % (label_map.get(pid, pid), pf)))

        # Protocol context lines for SSLv2 / SSLv3 rules.
        if rule_id in ("tls-poodle-ssl", "tls-sslv3-enabled"):
            for p in protos:
                if "sslv3" in p.get("id", "").lower():
                    lines.extend(wrap_line(label, host, port, "[*]",
                        "SSLv3: " + p.get("finding", "")))
        if rule_id == "tls-sslv2-enabled":
            for p in protos:
                if "sslv2" in p.get("id", "").lower():
                    lines.extend(wrap_line(label, host, port, "[*]",
                        "SSLv2: " + p.get("finding", "")))
            ssl2 = [c for c in sc if c.get("id", "").startswith("cipher-ssl2_")]
            for c in ssl2:
                parts = c["finding"].split()
                if len(parts) >= 3:
                    lines.extend(wrap_line(label, host, port, "[*]", "  " + parts[2]))

    # tlsfp cert expiry: show cert details for expired/expiring-soon findings.
    if source == "tlsfp" and driver_report and rule_id in ("tls-cert-expired", "tls-cert-expiring-soon"):
        cn       = driver_report.get("peer_cn") or ""
        issuer   = driver_report.get("peer_issuer") or ""
        not_bef  = driver_report.get("cert_not_before") or ""
        not_aft  = driver_report.get("cert_not_after") or ""
        days     = driver_report.get("cert_days_remaining", 0)
        serial   = driver_report.get("cert_serial") or ""
        sans     = driver_report.get("cert_sans") or []
        if cn:
            lines.extend(wrap_line(label, host, port, "[*]", "CN: " + cn))
        if not_bef and not_aft:
            status = "EXPIRED" if days < 0 else ("%d days remaining" % days)
            lines.extend(wrap_line(label, host, port, "[*]",
                "Validity: %s to %s (%s)" % (not_bef, not_aft, status)))
        if serial:
            lines.extend(wrap_line(label, host, port, "[*]", "Serial: " + serial))
        if sans:
            lines.extend(wrap_line(label, host, port, "[*]",
                "SANs: " + ", ".join(sans[:6])))
        if issuer:
            lines.extend(wrap_line(label, host, port, "[*]", "Issuer: " + issuer[:100]))

    # If cred attempts present, show successful ones as [+] lines
    cred_attempts = (driver_report or {}).get("cred_attempts") or []
    for ca in cred_attempts:
        if ca.get("success"):
            user = ca.get("user", "")
            pwd = ca.get("pass", "")
            lines.extend(wrap_line(label, host, port, "[+]",
                                   f"{user}:{pwd}  AUTHENTICATED"))

    # The finding evidence string (the [+] marker that earns the colour)
    if evidence:
        # Strip the per-host prefix that the plugin evidence template
        # already includes so we don't duplicate it
        prefix = f"{host}:{port}"
        if evidence.startswith(prefix):
            evidence = evidence[len(prefix):].lstrip(" -:")
        lines.extend(wrap_line(label, host, port, "[+]", evidence))

    lines.append("DONE")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="fastscan NDJSON -> evidence .txt files")
    ap.add_argument("-i", "--input", required=True,
                    help="path to findings.ndjson")
    ap.add_argument("-o", "--out", default="evidence/fastscan",
                    help="output directory (default: evidence/fastscan)")
    ap.add_argument("--severity", default="",
                    help="comma-separated severity filter (e.g. critical,high)")
    args = ap.parse_args()

    records = list(read_ndjson(args.input))
    drivers = index_driver_reports(records)
    httpx_idx = index_httpx_records(records)

    sev_filter = {s.strip().lower() for s in args.severity.split(",") if s.strip()}

    # One file per rule_id (one vulnerability = one .txt), with every
    # affected host appended inside it. Easier to review than a separate
    # file per host. Blocks are collected here then written once per rule.
    from collections import OrderedDict
    blocks_by_rule = OrderedDict()  # rule_id -> list of (host, port, block)
    seen = set()                    # dedupe identical (rule, host, port)

    for r in records:
        phase = r.get("phase")
        if phase == "finding":
            finding = r
            host = r.get("host") or ""
            port = r.get("port") or 0
            source = r.get("source") or ""
            rule_id = r.get("rule_id") or "unknown"
        elif phase == "nuclei":
            # Build a finding-shaped dict from the nuclei hit record.
            host, port = parse_nuclei_url(r.get("url") or "")
            source = "nuclei"
            rule_id = r.get("template") or "nuclei-finding"
            finding = {
                "source": source,
                "host": host,
                "port": port,
                "rule_id": rule_id,
                "evidence": (r.get("extract") or "").strip(),
                "severity": r.get("severity") or "",
                "ts": r.get("ts") or "",
            }
        else:
            continue
        if sev_filter and (r.get("severity") or "").lower() not in sev_filter:
            continue
        if not host:
            continue
        key = (rule_id, host, int(port))
        if key in seen:
            continue
        seen.add(key)
        driver_report = drivers.get((host, int(port), source), {})
        httpx_rec = httpx_idx.get((host, int(port))) if source == "http" else None
        block = build_txt(finding, driver_report, httpx_rec)
        blocks_by_rule.setdefault(rule_id, []).append((host, int(port), block, finding.get('title', ''), finding.get('severity', ''), source, finding.get('ts', '')))

    os.makedirs(args.out, exist_ok=True)
    written = 0

    # Merge same-product nessus CVE rules on same host:port into one file.
    from collections import defaultdict
    nessus_groups = defaultdict(list)
    merged_rule_ids = set()

    for rule_id, items in blocks_by_rule.items():
        if _NESSUS_RE.match(rule_id):
            for h, p, b, title, sev, so, ts in items:
                product = _extract_product(title)
                nessus_groups[(h, p, product)].append((rule_id, title, sev, so, ts))

    for (host, port, product), entries in nessus_groups.items():
        if len(entries) <= 1:
            continue
        for rid, _, _, _, _ in entries:
            merged_rule_ids.add((rid, host, port))
        first_source = entries[0][3]
        first_ts     = entries[0][4]
        http_rec     = httpx_idx.get((host, int(port))) if first_source == 'http' else None
        cve_items    = [(rid, title, sev) for rid, title, sev, _, _ in entries]
        block        = _build_merged_cve_txt(product, cve_items, host, port,
                                             http_rec, first_ts, first_source)
        fname        = safe_filename(f"{product}-multiple-cves-{host}-{port}") + ".txt"
        out_path     = os.path.join(args.out, fname)
        with open(out_path, 'w', encoding='utf-8') as fh:
            fh.write(block)
        written += 1

    for rule_id, items in blocks_by_rule.items():
        remaining = [(h, p, b, ti, se, so, ts) for h, p, b, ti, se, so, ts in items
                     if (rule_id, h, p) not in merged_rule_ids]
        if not remaining:
            continue
        remaining.sort(key=lambda t: (t[0], t[1]))
        out_path = os.path.join(args.out, safe_filename(rule_id) + ".txt")
        with open(out_path, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(b for _, _, b, *_ in remaining))
        written += 1

    total_hosts = sum(len(v) for v in blocks_by_rule.values())
    print(f'wrote {written} evidence files ({total_hosts} host blocks) to {args.out}/')
    print(f'render with: python tools/scripts/txt_to_img.py {args.out}/<file>.txt')


if __name__ == "__main__":
    main()
