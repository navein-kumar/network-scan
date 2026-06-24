# fastscan-ui API contract (shared by backend + frontend)

Both the Go backend and the React frontend MUST conform to this exact contract.
Base URL: same origin. All bodies are JSON. Times are RFC3339 strings.

## Directory layout (on idsserver)
```
/tmp/fastscan-ui/
  server/      Go backend (REST + SSE), go.mod module "fastscanui"
  web/         React + Vite + TypeScript + Tailwind frontend
  data/        runtime scan storage: data/<scanId>/ {config.json, findings.ndjson, stderr.log, status.json}
```
The fastscan engine binary is at /tmp/fastscan/fastscan (DO NOT modify it).
Bridge scripts at /tmp/fastscan/scripts/{fastscan_to_xlsx.py,fastscan_to_evidence.py}.

## Scan config object (used in POST body and stored as config.json)
```json
{
  "name": "string (required)",
  "targets": "string, newline or comma separated IPs/CIDRs/hostnames (required)",
  "template": "fast | standard | deep",
  "ports": "string, '' = default top ports, 'all' = 1-65535, or '21-80,443'",
  "udp_ports": "string, '' = default",
  "skip_udp": false,
  "skip_nuclei": false,
  "deep_tls": false,
  "max_hosts": 0,
  "nmap_intensity": 0,
  "force_service": "string, e.g. '8888=ssh,55555=http' or ''"
}
```
Template -> flags mapping (backend builds the fastscan argv):
- always: `-target-file <data/<id>/targets.txt> -out <data/<id>>`
- template fast    -> `-profile fast`
- template standard-> (no profile flag, auto)
- template deep    -> `-deep`
- ports != ''      -> `-ports <ports>` (if 'all' -> `-ports 1-65535`)
- udp_ports != ''  -> `-udp-ports <udp_ports>`
- skip_udp         -> `-skip-udp`
- skip_nuclei      -> `-skip-nuclei`
- deep_tls         -> `-deep` (also implied by template deep)
- max_hosts > 0    -> `-max-hosts <n>`
- nmap_intensity>0 -> `-nmap-intensity <n>`
- force_service!='' -> `-force-service <val>`

## Endpoints

### GET /api/meta
```json
{ "profiles": ["fast","medium","slow","crawl"],
  "driver_count": 60, "plugin_count": 168,
  "deps": [ {"name":"nmap","present":true}, {"name":"nuclei","present":true} ] }
```

### GET /api/deps
```json
[ {"name":"nmap","present":true,"path":"/usr/bin/nmap"}, ... ]
```

### POST /api/scans   (create + launch)
body = scan config object.  Response:
```json
{ "id": "scan_<timestamp>_<rand>", "status": "running" }
```

### GET /api/scans   (list, newest first)
```json
[ { "id":"...", "name":"...", "status":"running|done|failed",
    "progress": 0,            // 0-100 overall
    "started":"RFC3339", "finished":"RFC3339 or null",
    "host_count": 0, "finding_count": 0,
    "severity": {"critical":0,"high":0,"medium":0,"low":0,"info":0} } ]
```

### GET /api/scans/{id}
Same shape as a list item PLUS `"config": {scan config}` and `"hosts_done": N`, `"hosts_total": N`.

### GET /api/scans/{id}/findings   (flat, frontend groups)
```json
[ { "rule_id":"...", "title":"...", "severity":"critical|high|medium|low|info",
    "host":"1.2.3.4", "port":443, "source":"tlsfp", "evidence":"..." } ]
```
Include both plugin findings (phase=finding) AND nuclei (phase=nuclei: rule_id=template, evidence=extract, host/port parsed from url).

### GET /api/scans/{id}/hosts
```json
[ { "host":"1.2.3.4",
    "ports":[ {"port":443,"proto":"tcp","service":"https","version":"nginx 1.18"} ],
    "finding_count": 3,
    "severity": {"critical":0,"high":1,"medium":2,"low":0,"info":0} } ]
```

### GET /api/scans/{id}/stream   (Server-Sent Events; Content-Type text/event-stream)
The backend tails fastscan stderr (progress) + findings.ndjson and emits:
```
event: progress
data: {"overall": 42, "hosts_done": 3, "hosts_total": 8,
       "hosts":[ {"host":"1.2.3.4","phase":"2.5","percent":41,"status":"running|done|lost"} ]}

event: finding
data: {"rule_id":"...","title":"...","severity":"high","host":"1.2.3.4","port":445}

event: log
data: {"line":"raw progress/log line for the live console"}

event: done
data: {"status":"done","severity":{"critical":1,"high":3,"medium":16,"low":6,"info":0}}
```
Frontend uses EventSource. Heartbeat comment line every ~15s to keep alive.

### GET /api/scans/{id}/export?format=xlsx|docx|evidence
Streams a file download. xlsx -> fastscan_to_xlsx.py; evidence -> zip of fastscan_to_evidence.py output; docx -> (optional, may 501 if not wired).
Set Content-Disposition. If a format is not implemented, return 501 JSON {"error":"not implemented"}.

### DELETE /api/scans/{id}
```json
{ "ok": true }
```

## Conventions
- Errors: HTTP 4xx/5xx with JSON `{"error":"message"}`.
- CORS not needed (same origin, SPA served by the Go binary).
- The backend serves the embedded SPA at `/` and static assets; all non-/api routes return index.html (SPA routing).
- Bind to 0.0.0.0:8888 by default, configurable via `-addr` flag. (User reaches via SSH tunnel.)
- No auth in v1 (tunnel-only). Keep a single optional `-token` flag stub for later.

## Severity ordering everywhere
critical > high > medium > low > info. Colors (frontend):
critical #b91c1c, high #ea580c, medium #d97706, low #65a30d, info #6b7280.
