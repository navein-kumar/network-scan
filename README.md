# fastscan

A fast, multi-protocol network vulnerability scanner with a built-in web UI.
Detects misconfigurations, default credentials, EOL software, and known CVEs
across 70+ protocol drivers and 245+ detection rules.

## Quick start

### Option 1: Docker (recommended)

Requires Docker and Docker Compose. Works on any Linux host.

```bash
git clone <repo-url>
cd fastscan

# Start with host network (default — required for VPN/internal targets)
docker-compose up -d

# Open the UI
# http://<host-ip>:8888   login: admin / changeme
```

Set a custom password before exposing to a network:

```bash
UI_USER=admin UI_PASS=yourpassword docker-compose up -d
```

Or use a `.env` file (see `fastscan.env.example`):

```bash
cp fastscan.env.example .env
# edit .env, then:
docker-compose up -d
```

**macOS / Windows Docker Desktop** — host network is not supported; use the bridge override:

```bash
docker-compose -f docker-compose.yml -f docker-compose.bridge.yml up -d
```

---

### Option 2: Direct install (Linux)

```bash
# 1. Install all prerequisites (Go, Python3/pip, Node.js/npm, nmap, rustscan, testssl.sh, ...)
sudo ./install-prereqs.sh

# 2. Build the engine binary
./install-prereqs.sh --build
# binary written to ./fastscan

# 3. Build the UI binary
cd ui && ./build.sh && cd ..
# binary written to ./ui/fastscan-ui

# 4. Start the UI (auto-finds and launches the engine)
./ui/fastscan-ui -addr 0.0.0.0:8888 -data ./data -auth admin:changeme
```

All paths are derived from the binary location at runtime — install anywhere, no config files needed.

---

## Prerequisites

`install-prereqs.sh` installs everything automatically. Manual reference:

| Dependency | Required | Purpose |
|------------|----------|---------|
| Go 1.21+ | Build only | Compile engine + UI |
| Python 3 + pip | Yes | Export to XLSX, HTML, evidence bundle |
| Node.js + npm | Build only | Build React UI |
| nmap | Yes | Service version detection, OS detection |
| rustscan | Recommended | Fast port discovery (falls back to nmap) |
| testssl.sh | Recommended | Deep TLS vulnerability scanning |
| nxc / netexec | Optional | Credential testing helper |
| ike-scan | Optional | IKE/IPsec Aggressive Mode PSK hash |
| vncsnapshot + imagemagick | Optional | VNC login screen screenshots |
| scrying | Optional | RDP login screen screenshots |

```bash
# Check what is missing without installing anything
sudo ./install-prereqs.sh --check

# Install everything + build the engine
sudo ./install-prereqs.sh --build
```

---

## Docker commands

```bash
# Build image
docker build -t fastscan:latest .

# Start — host network (default, Linux only)
docker-compose up -d

# Start — bridge network (macOS / Windows Docker Desktop)
docker-compose -f docker-compose.yml -f docker-compose.bridge.yml up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down

# Rebuild after code changes
docker-compose build && docker-compose up -d
```

---

## Direct deployment commands

```bash
# Install prerequisites
sudo ./install-prereqs.sh

# Build engine (output: ./fastscan)
/usr/local/go/bin/go build -buildvcs=false -o ./fastscan .

# Build UI (output: ./ui/fastscan-ui)
cd ui && ./build.sh && cd ..

# Run UI in foreground
./ui/fastscan-ui -addr 0.0.0.0:8888 -data ./data -auth admin:changeme

# Run UI in background with tmux
tmux new-session -d -s fastscan \
  "./ui/fastscan-ui -addr 0.0.0.0:8888 -data ./data -auth admin:changeme"

# Run engine standalone (no UI)
./fastscan -target 192.168.1.0/24 -out ./results/

# Run engine with full options
./fastscan \
  -target 10.0.0.1 \
  -out ./results/ \
  -plugins ./plugins \
  -creds-dir ./creds \
  -profile medium \
  -deep
```

---

## Engine flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | IP, hostname, or CIDR to scan |
| `-target-file` | | File with one target per line |
| `-out` | | Output directory |
| `-plugins` | `<binary-dir>/plugins` | YAML rule directory |
| `-creds-dir` | `<binary-dir>/creds` | Default-credential YAML lists |
| `-profile` | auto | Scan profile: `fast`, `medium`, `slow`, `crawl` |
| `-deep` | false | Enable testssl.sh TLS deep scan |
| `-skip-udp` | false | Skip UDP discovery |
| `-skip-nuclei` | false | Skip Nuclei phase |
| `-ports` | built-in list | Custom TCP port list |
| `-check-deps` | | Print dependency status and exit |

---

## Output files

Each scan creates its own directory under `-out`:

```
<out>/
  findings.ndjson   newline-delimited JSON: findings + phase events
  stderr.log        full engine log
  config.json       scan configuration snapshot
  targets.txt       resolved target list
```

Export from the UI: XLSX report, HTML report, or evidence bundle (ZIP).

---

## Updating detection rules

Plugin rules are plain YAML files — no rebuild required:

```bash
# Edit or add a rule
vim plugins/ssh/ssh-weak-cipher.yaml

# Version currency rules (auto-generates "outdated version" findings)
vim plugins/versions.yaml
```

Rule format:

```yaml
id: my-rule-id
title: Short human-readable title
severity: critical|high|medium|low|info
source: ssh
when: <expr-lang boolean over driver report fields>
evidence: "{{ .host }}:{{ .port }} ..."
tags: [example]
remediation: |
  How to fix it.
```
