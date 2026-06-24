"""
fastscan_to_xlsx.py
-------------------
Bridge: fastscan NDJSON (findings.ndjson) -> engagement xlsx workbook.

Reads `phase: finding` rows, groups by rule_id (so the same plugin firing
across N hosts becomes one row), maps each rule to the column schema used
by the existing engagement xlsx (Internal_Network_Findings template):

  No., Vulnerability Name, Severity, CVSS, CVE/Type, MITRE ATT&CK,
  Vulnerable IP, Group, Vulnerability Description, POC Description,
  Fix, Status, Pages Need

What's auto-derived vs manual:
  - CVSS:        heuristic from severity (engagement lead can override)
  - MITRE ATT&CK: left blank (fastscan doesn't track this)
  - Pages Need:  left blank (screenshot mapping is manual)
  - Group:       RFC1918 -> "Private IP", else "Public IP"
  - Description: short auto-built from rule title + tags; engagement
                 lead rewrites for the 80-word prose constraint
  - POC:         joins per-host evidence strings
  - Fix:         from the plugin's remediation field

Usage:
  python fastscan_to_xlsx.py -i findings.ndjson -o fastscan_findings.xlsx
"""

import argparse
import ipaddress
import json
import os
import sys
from collections import OrderedDict, defaultdict

import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter


HEADERS = [
    "No.", "Vulnerability Name", "Severity", "CVSS", "CVE/Type",
    "MITRE ATT&CK", "Vulnerable IP", "Group",
    "Vulnerability Description (Exactly 80 Words)",
    "POC Description", "Fix", "Status", "Pages Need",
]
COL_WIDTHS = [5, 38, 12, 7, 22, 20, 60, 12, 80, 55, 55, 12, 10]

COLOURS = {
    "Critical": "C00000",
    "High":     "FF0000",
    "Medium":   "FFC000",
    "Low":      "FFFF00",
    "Info":     "BFBFBF",
    "header":   "1F3864",
    "row_alt":  "F2F2F2",
}

# Severity -> heuristic CVSS. Engagement lead is expected to override
# from the actual CVE record for CVE-tagged findings.
CVSS_BY_SEVERITY = {
    "Critical": "9.5",
    "High":     "8.0",
    "Medium":   "6.0",
    "Low":      "3.5",
    "Info":     "0.0",
}

# severity (lowercase as stored in fastscan NDJSON) -> Title-case label
SEVERITY_RANK = OrderedDict([
    ("critical", "Critical"),
    ("high",     "High"),
    ("medium",   "Medium"),
    ("low",      "Low"),
    ("info",     "Info"),
])


def fill(hex_colour):
    return PatternFill("solid", fgColor=hex_colour)


def thin_border():
    s = Side(style="thin", color="000000")
    return Border(left=s, right=s, top=s, bottom=s)


def is_private(ip):
    """RFC1918 check. Returns True for 10/8, 172.16/12, 192.168/16; False
    on parse error or public address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def cve_type_from_tags(tags):
    """Pick the most descriptive tag for the CVE/Type column."""
    if not tags:
        return "Configuration Issue"
    priority = [
        "default-credentials", "eternalblue", "critical-cve", "cve-",
        "eol", "weak-crypto", "no-tls", "info-disclosure",
        "relay", "ntlm", "credential-exposure", "amplification",
        "open-resolver", "recon", "logjam",
    ]
    lower = [t.lower() for t in tags]
    for p in priority:
        for t in lower:
            if p in t:
                return t.replace("-", " ").title()
    return lower[0].title()


def read_ndjson(path):
    """Yield each NDJSON record. Skips blank lines and parse errors."""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


_ACRONYMS = {"tls", "ssl", "ssh", "http", "https", "ftp", "smb", "dns",
             "rdp", "ip", "cve", "smtp", "ldap", "snmp", "vnc", "rpc",
             "nfs", "waf", "api", "xss", "ssrf", "rce", "lfi", "sqli"}


def nuclei_title(tid):
    """Turn a nuclei template id into a readable title.
    tls-deprecated-protocols -> TLS Deprecated Protocols
    """
    words = tid.replace("_", "-").split("-")
    out = []
    for w in words:
        out.append(w.upper() if w.lower() in _ACRONYMS else w.capitalize())
    return " ".join(out)


def parse_nuclei_url(u):
    """Extract (host, port) from a nuclei url/matched field.
    Handles "host:port", "http://host:port/path", bare "host"."""
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


def group_findings(ndjson_path, include_info=False):
    """Read findings, group by rule_id. Returns a dict keyed by rule_id."""
    by_rule = OrderedDict()
    for r in read_ndjson(ndjson_path):
        phase = r.get("phase")
        if phase == "finding":
            sev = (r.get("severity") or "").lower()
            rid = r.get("rule_id") or "unknown-rule"
            title = r.get("title") or rid
            source = r.get("source") or ""
            tags = r.get("tags") or []
            refs = r.get("references") or []
            remediation = r.get("remediation") or ""
            host = r.get("host") or ""
            port = r.get("port") or 0
            ev = (r.get("evidence") or "").strip()
        elif phase == "nuclei":
            # Nuclei hits are recorded separately (template/url/extract).
            # Fold them into the same grouped-by-rule structure so they
            # land in the engagement workbook alongside plugin findings.
            sev = (r.get("severity") or "").lower()
            rid = r.get("template") or "nuclei-finding"
            title = nuclei_title(rid)
            source = "nuclei"
            tags = ["nuclei", rid]
            refs = ["https://github.com/projectdiscovery/nuclei-templates"]
            remediation = ""
            host, port = parse_nuclei_url(r.get("url") or "")
            ev = (r.get("extract") or "").strip()
            if ev:
                ev = (f"{host}:{port} {ev}" if host else ev)
        else:
            continue
        if not include_info and sev == "info":
            continue
        slot = by_rule.setdefault(rid, {
            "rule_id":     rid,
            "title":       title,
            "severity":    sev,
            "source":      source,
            "tags":        tags,
            "references":  refs,
            "remediation": remediation,
            "hosts":       [],
            "evidence":    [],
        })
        if host:
            tag = host if not port else f"{host} (Port: {port})"
            if tag not in slot["hosts"]:
                slot["hosts"].append(tag)
        if ev and ev not in slot["evidence"]:
            slot["evidence"].append(ev)
    return by_rule


def build_row(no, finding):
    """Map a grouped finding into the 13-column row tuple."""
    sev_label = SEVERITY_RANK.get(finding["severity"], finding["severity"].title())

    # Vulnerable IP column: comma-separated host:port list
    ips = ", ".join(finding["hosts"]) if finding["hosts"] else ""

    # Group: Private if ALL hosts private; Public if any public address present
    raw_hosts = [h.split(" ")[0] for h in finding["hosts"]]
    if raw_hosts and all(is_private(h) for h in raw_hosts):
        group = "Private IP"
    elif raw_hosts:
        group = "Public IP"
    else:
        group = ""

    # Auto-built description: title + first reference (engagement lead
    # rewrites for the 80-word prose constraint)
    parts = [finding["title"].rstrip(".") + "."]
    if finding["references"]:
        parts.append("Reference: " + finding["references"][0])
    desc = " ".join(parts)

    # POC = evidence strings concatenated, one per line
    poc = "\n".join(finding["evidence"]) if finding["evidence"] else \
          "See raw fastscan NDJSON for the driver output that triggered this rule."

    fix = finding["remediation"] or "See plugin remediation field."

    return [
        no,
        finding["title"],
        sev_label,
        CVSS_BY_SEVERITY.get(sev_label, ""),
        cve_type_from_tags(finding["tags"]),
        "",          # MITRE ATT&CK -- manual
        ips,
        group,
        desc,
        poc,
        fix,
        "Unresolved",
        "",          # Pages Need -- manual
    ]


def write_xlsx(findings, out_path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"

    # Header row
    for ci, (h, w) in enumerate(zip(HEADERS, COL_WIDTHS), 1):
        cell = ws.cell(row=1, column=ci, value=h)
        cell.font = Font(bold=True, color="FFFFFF", size=11)
        cell.fill = fill(COLOURS["header"])
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = thin_border()
        ws.column_dimensions[get_column_letter(ci)].width = w
    ws.row_dimensions[1].height = 30

    sev_colour = {
        "Critical": COLOURS["Critical"],
        "High":     COLOURS["High"],
        "Medium":   COLOURS["Medium"],
        "Low":      COLOURS["Low"],
        "Info":     COLOURS["Info"],
    }

    # Sort: severity desc, then rule_id alpha so output is deterministic
    rank = {s: i for i, s in enumerate(SEVERITY_RANK.keys())}
    grouped = sorted(findings.values(),
                     key=lambda f: (rank.get(f["severity"], 99), f["rule_id"]))

    for ri, finding in enumerate(grouped, 2):
        row = build_row(ri - 1, finding)
        bg = COLOURS["row_alt"] if ri % 2 == 0 else "FFFFFF"
        for ci, val in enumerate(row, 1):
            cell = ws.cell(row=ri, column=ci, value=val)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            cell.border = thin_border()
            if ci == 3:  # Severity column
                cell.fill = fill(sev_colour.get(row[2], "FFFFFF"))
                cell.font = Font(bold=True, color="FFFFFF")
                cell.alignment = Alignment(horizontal="center", vertical="center")
            else:
                cell.fill = fill(bg)
        ws.row_dimensions[ri].height = 75

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    wb.save(out_path)
    return len(grouped)


def main():
    ap = argparse.ArgumentParser(description="fastscan NDJSON -> engagement xlsx")
    ap.add_argument("-i", "--input", required=True,
                    help="path to findings.ndjson produced by fastscan")
    ap.add_argument("-o", "--output", default="fastscan_findings.xlsx",
                    help="output xlsx path (default: fastscan_findings.xlsx)")
    ap.add_argument("--include-info", action="store_true",
                    help="include severity=info rows (skipped by default)")
    args = ap.parse_args()

    findings = group_findings(args.input, include_info=args.include_info)
    if not findings:
        print(f"no findings in {args.input} (or all were info-level and "
              f"--include-info was not set)", file=sys.stderr)
        sys.exit(1)
    n = write_xlsx(findings, args.output)

    sev_count = defaultdict(int)
    for f in findings.values():
        sev_count[SEVERITY_RANK.get(f["severity"], f["severity"])] += 1
    print(f"saved: {args.output}")
    print(f"total rule groups: {n}")
    for s in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev_count[s]:
            print(f"  {s}: {sev_count[s]}")


if __name__ == "__main__":
    main()
