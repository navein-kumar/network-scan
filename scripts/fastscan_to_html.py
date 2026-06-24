#!/usr/bin/env python3
"""
fastscan_to_html.py
-------------------
Bridge: fastscan NDJSON -> one self-contained .html report.

Reads findings.ndjson (-i) and writes a single .html file (-o) that needs
no external assets. Content:
  * a header with scan id and counts,
  * a severity summary (critical / high / medium / low / info badges),
  * a per-host section,
  * per-finding cards (title, rule_id, severity badge, host:port, the
    evidence as a monospace block, remediation and references).

Any finding (or driver record) carrying a screenshot_path that points at a
real PNG on disk is embedded inline as a base64 <img>, so RDP / VNC / web
screenshots travel inside the report.

The output is a client deliverable: no em-dash (U+2014) or en-dash (U+2013)
characters are emitted anywhere.

Usage:
  python fastscan_to_html.py -i findings.ndjson -o report.html
"""

import argparse
import base64
import html
import json
import os
import sys
import time

# Reuse the evidence bridge's full-evidence renderer so the HTML report shows
# the same complete deep-content listing (keys, shares, databases, command
# output, etc.) as the .txt evidence files, not just the one-line summary.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fastscan_to_evidence as fte


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
}

SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def esc(value):
    """HTML-escape a value, coercing None to an empty string."""
    if value is None:
        return ""
    return html.escape(str(value))


def norm_sev(value):
    s = (value or "info").strip().lower()
    return s if s in SEVERITY_COLOR else "info"


def read_findings(path):
    """Return the list of finding records (phase == finding, has rule_id)."""
    findings = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("rule_id") and (
                obj.get("phase") in (None, "finding") or obj.get("title")
            ):
                findings.append(obj)
    return findings


def collect_screenshots(path):
    """Map host -> first readable screenshot_path PNG found in the stream."""
    shots = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            sp = obj.get("screenshot_path")
            host = obj.get("host") or ""
            if sp and os.path.isfile(sp) and host not in shots:
                shots[host] = sp
    return shots


def img_data_uri(path):
    """Read a PNG off disk and return a base64 data: URI, or '' on failure."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return ""
    if not raw:
        return ""
    enc = base64.b64encode(raw).decode("ascii")
    return "data:image/png;base64," + enc


def hostport(finding):
    host = finding.get("host") or ""
    port = finding.get("port")
    if port:
        return "{0}:{1}".format(host, port)
    return host or "(no host)"


def badge(sev):
    sev = norm_sev(sev)
    color = SEVERITY_COLOR[sev]
    label = SEVERITY_LABEL[sev]
    return (
        '<span class="badge" style="background:{0}">{1}</span>'.format(color, label)
    )


def render(findings, shots, scan_label):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[norm_sev(f.get("severity"))] += 1
    total = len(findings)

    # Group by host, preserving severity order within each host.
    by_host = {}
    for f in findings:
        by_host.setdefault(f.get("host") or "(no host)", []).append(f)
    for host in by_host:
        by_host[host].sort(key=lambda f: SEVERITY_ORDER.index(norm_sev(f.get("severity"))))
    host_names = sorted(by_host.keys())

    generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    out = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en">')
    out.append("<head>")
    out.append('<meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    out.append("<title>fastscan report: {0}</title>".format(esc(scan_label)))
    out.append("<style>")
    out.append(CSS)
    out.append("</style>")
    out.append("</head>")
    out.append("<body>")

    # Header.
    out.append('<header class="report-header">')
    out.append('<h1>fastscan Report</h1>')
    out.append('<div class="meta">')
    out.append("<span><strong>Scan:</strong> {0}</span>".format(esc(scan_label)))
    out.append("<span><strong>Generated:</strong> {0}</span>".format(esc(generated)))
    out.append("<span><strong>Findings:</strong> {0}</span>".format(total))
    out.append("<span><strong>Hosts:</strong> {0}</span>".format(len(host_names)))
    out.append("</div>")
    out.append("</header>")

    # Severity summary.
    out.append('<section class="summary">')
    out.append("<h2>Severity Summary</h2>")
    out.append('<div class="summary-grid">')
    for sev in SEVERITY_ORDER:
        out.append('<div class="summary-card" style="border-top:3px solid {0}">'.format(SEVERITY_COLOR[sev]))
        out.append('<div class="summary-label" style="color:{0}">{1}</div>'.format(SEVERITY_COLOR[sev], SEVERITY_LABEL[sev]))
        out.append('<div class="summary-count">{0}</div>'.format(counts[sev]))
        out.append("</div>")
    out.append("</div>")
    out.append("</section>")

    if total == 0:
        out.append('<section class="empty"><p>No findings were recorded for this scan.</p></section>')
        out.append("</body></html>")
        return "\n".join(out)

    # Per-host overview.
    out.append('<section class="hosts">')
    out.append("<h2>Hosts</h2>")
    for host in host_names:
        flist = by_host[host]
        hcounts = {s: 0 for s in SEVERITY_ORDER}
        for f in flist:
            hcounts[norm_sev(f.get("severity"))] += 1
        out.append('<div class="host-row">')
        out.append('<a class="host-name" href="#host-{0}">{1}</a>'.format(esc(host), esc(host)))
        out.append('<div class="host-badges">')
        for sev in SEVERITY_ORDER:
            if hcounts[sev]:
                out.append('<span class="mini-badge" style="background:{0}">{1} {2}</span>'.format(
                    SEVERITY_COLOR[sev], hcounts[sev], SEVERITY_LABEL[sev]))
        out.append("</div>")
        out.append("</div>")
    out.append("</section>")

    # Per-finding cards, grouped by host.
    out.append('<section class="findings">')
    out.append("<h2>Findings</h2>")
    for host in host_names:
        out.append('<h3 class="host-heading" id="host-{0}">{1}</h3>'.format(esc(host), esc(host)))
        shot = shots.get(host)
        if shot:
            uri = img_data_uri(shot)
            if uri:
                out.append('<div class="shot"><img alt="screenshot of {0}" src="{1}"></div>'.format(esc(host), uri))
        for f in by_host[host]:
            sev = norm_sev(f.get("severity"))
            out.append('<article class="card" style="border-left:4px solid {0}">'.format(SEVERITY_COLOR[sev]))
            out.append('<div class="card-head">')
            out.append('<span class="card-title">{0}</span>'.format(esc(f.get("title") or f.get("rule_id"))))
            out.append(badge(sev))
            out.append("</div>")
            out.append('<div class="card-sub">')
            out.append('<span class="kv"><span class="k">rule</span> {0}</span>'.format(esc(f.get("rule_id"))))
            out.append('<span class="kv"><span class="k">target</span> {0}</span>'.format(esc(hostport(f))))
            if f.get("source"):
                out.append('<span class="kv"><span class="k">source</span> {0}</span>'.format(esc(f.get("source"))))
            out.append("</div>")

            evidence = f.get("_full_evidence") or f.get("evidence")
            if evidence:
                out.append('<div class="block-label">Evidence</div>')
                out.append('<pre class="evidence">{0}</pre>'.format(esc(evidence)))

            # Per-finding screenshot (overrides host-level if present).
            fshot = f.get("screenshot_path")
            if fshot and os.path.isfile(fshot):
                uri = img_data_uri(fshot)
                if uri:
                    out.append('<div class="shot"><img alt="screenshot for {0}" src="{1}"></div>'.format(
                        esc(f.get("rule_id")), uri))

            remediation = f.get("remediation")
            if remediation:
                out.append('<div class="block-label">Remediation</div>')
                out.append('<pre class="remediation">{0}</pre>'.format(esc(remediation)))

            refs = f.get("references")
            if isinstance(refs, list) and refs:
                out.append('<div class="block-label">References</div>')
                out.append('<ul class="refs">')
                for r in refs:
                    out.append('<li><a href="{0}" rel="noopener noreferrer">{1}</a></li>'.format(esc(r), esc(r)))
                out.append("</ul>")
            out.append("</article>")
    out.append("</section>")

    out.append('<footer class="report-footer">Generated by fastscan. {0} findings across {1} hosts.</footer>'.format(
        total, len(host_names)))
    out.append("</body></html>")
    return "\n".join(out)


CSS = """
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --panel-2: #1c2330;
  --border: #2a3340;
  --fg: #c9d1d9;
  --fg-dim: #8b949e;
  --mono: ui-monospace, SFMono-Regular, "DejaVu Sans Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
  font-size: 14px;
}
h1, h2, h3 { color: #f0f6fc; font-weight: 600; }
h2 { font-size: 18px; margin: 0 0 14px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
a { color: #58a6ff; text-decoration: none; word-break: break-all; }
a:hover { text-decoration: underline; }
.report-header {
  padding: 28px 32px;
  background: linear-gradient(180deg, #161b22, #0d1117);
  border-bottom: 1px solid var(--border);
}
.report-header h1 { margin: 0 0 10px; font-size: 26px; }
.report-header .meta { display: flex; flex-wrap: wrap; gap: 18px; color: var(--fg-dim); font-size: 13px; }
.report-header .meta strong { color: var(--fg); font-weight: 600; }
section { padding: 24px 32px; }
.summary-grid { display: flex; flex-wrap: wrap; gap: 14px; }
.summary-card {
  flex: 1 1 130px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}
.summary-label { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; }
.summary-count { font-size: 30px; font-weight: 700; margin-top: 6px; color: #f0f6fc; }
.badge {
  display: inline-block;
  color: #fff;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .04em;
  padding: 3px 9px;
  border-radius: 999px;
}
.mini-badge {
  display: inline-block;
  color: #fff;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 999px;
}
.host-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 14px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 8px;
}
.host-name { font-family: var(--mono); font-size: 14px; font-weight: 600; }
.host-badges { display: flex; flex-wrap: wrap; gap: 6px; }
.host-heading {
  font-family: var(--mono);
  font-size: 16px;
  margin: 26px 0 12px;
  padding: 8px 12px;
  background: var(--panel-2);
  border-radius: 6px;
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 18px;
  margin-bottom: 14px;
}
.card-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.card-title { font-size: 15px; font-weight: 600; color: #f0f6fc; }
.card-sub { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 6px; color: var(--fg-dim); font-size: 12px; }
.kv .k {
  display: inline-block;
  text-transform: uppercase;
  font-size: 10px;
  letter-spacing: .05em;
  color: var(--fg-dim);
  margin-right: 4px;
}
.kv { font-family: var(--mono); color: var(--fg); }
.block-label {
  margin-top: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: var(--fg-dim);
}
pre.evidence, pre.remediation {
  margin: 6px 0 0;
  padding: 12px 14px;
  background: #0b0f14;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-family: var(--mono);
  font-size: 12.5px;
  white-space: pre-wrap;
  word-break: break-word;
  overflow-x: auto;
}
pre.remediation { color: var(--fg-dim); }
ul.refs { margin: 6px 0 0; padding-left: 20px; font-size: 12.5px; }
ul.refs li { margin: 2px 0; }
.shot { margin: 10px 0; }
.shot img {
  max-width: 100%;
  border: 1px solid var(--border);
  border-radius: 6px;
  display: block;
}
.empty p { color: var(--fg-dim); }
.report-footer {
  padding: 20px 32px;
  border-top: 1px solid var(--border);
  color: var(--fg-dim);
  font-size: 12px;
}
"""


def main():
    ap = argparse.ArgumentParser(description="fastscan NDJSON -> self-contained HTML report")
    ap.add_argument("-i", "--input", required=True, help="findings.ndjson path")
    ap.add_argument("-o", "--output", required=True, help="output .html path")
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        sys.stderr.write("input not found: {0}\n".format(args.input))
        return 2

    findings = read_findings(args.input)
    shots = collect_screenshots(args.input)

    # Attach the FULL evidence (driver deep-content rendered one-per-line) to
    # each finding, mapped to its driver report exactly the way the evidence
    # bridge does. Falls back to the short evidence string if anything fails.
    try:
        records = list(fte.read_ndjson(args.input))
        drivers = fte.index_driver_reports(records)
        httpx_idx = fte.index_httpx_records(records)
    except Exception as exc:  # noqa: BLE001
        drivers, httpx_idx = {}, {}
        sys.stderr.write("full-evidence index skipped: {0}\n".format(exc))
    for f in findings:
        try:
            host = f.get("host") or ""
            port = int(f.get("port") or 0)
            source = f.get("source") or ""
            dr = drivers.get((host, port, source), {})
            hx = httpx_idx.get((host, port)) if source == "http" else None
            f["_full_evidence"] = fte.build_txt(f, dr, hx)
        except Exception:  # noqa: BLE001
            pass

    scan_label = os.path.basename(os.path.dirname(os.path.abspath(args.input))) or "scan"

    doc = render(findings, shots, scan_label)

    # Hard guarantee: strip any stray em-dash (U+2014) / en-dash (U+2013)
    # before writing, so the deliverable stays free of AI-tell dash glyphs.
    doc = doc.replace(chr(0x2014), "-").replace(chr(0x2013), "-")

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(doc)
    sys.stderr.write("wrote {0} ({1} findings)\n".format(args.output, len(findings)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
