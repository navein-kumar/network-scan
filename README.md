# fastscan

Multi-protocol network vulnerability scanner with a built-in web UI.
Covers 70+ protocol drivers and 245+ detection rules across SSH, FTP, SMB,
RDP, HTTP/S, databases, VPN, ICS, and more.

---

## Docker Hub

```bash
docker pull navinkr431/network-scan:latest
```

### Run

```bash
# Recommended — with volume (scan data survives image updates)
docker run -d \
  --name fastscan \
  --network host \
  --restart unless-stopped \
  -v /opt/fastscan/data:/data \
  navinkr431/network-scan

# Without volume — scan data persists across restarts/reboots but is lost
# when you update the image (docker rm + docker run)
docker run -d \
  --name fastscan \
  --network host \
  --restart unless-stopped \
  navinkr431/network-scan
```

Open `http://<server-ip>:8888`
Default login: `admin` / `NetworkScan@2026`

### Data persistence explained

| Scenario | With `-v` | Without `-v` |
|---|---|---|
| `docker restart fastscan` | Persists | Persists |
| Server reboot | Persists | Persists |
| Image update (`docker rm` + `docker run`) | Persists | **Lost** |

Without `-v`, scan data lives inside the container's writable layer and
survives normal restarts. It is only lost when the container is removed
(i.e., when pulling and applying a new image version).

### Update image

```bash
docker pull navinkr431/network-scan:latest
docker rm -f fastscan
docker run -d \
  --name fastscan \
  --network host \
  --restart unless-stopped \
  -v /opt/fastscan/data:/data \
  navinkr431/network-scan
```

### Change password

Pass the new password via environment variable at runtime:

```bash
docker run -d --network host \
  -e UI_USER=admin \
  -e UI_PASS=YourNewPassword \
  navinkr431/network-scan
```

With docker-compose, edit `.env` before starting:

```bash
cp fastscan.env.example .env
# edit .env
UI_USER=admin
UI_PASS=YourNewPassword
docker-compose up -d
```

---

## Build and push to Docker Hub

### Prerequisites

- Docker 20+ with buildx
- Docker Hub account, already logged in (`docker login`)
- Git

### Build

```bash
git clone https://github.com/navein-kumar/network-scan.git
cd network-scan/tools/recon/fastscan

docker build -t navinkr431/network-scan:latest .
```

The build compiles the Go engine, the React frontend, and installs all runtime
tools (nmap, rustscan, testssl.sh, httpx, nuclei) in a single multi-stage build.
Expect 15 to 25 minutes on first run. Subsequent builds use layer cache and
finish in under 3 minutes.

### Push

```bash
docker push navinkr431/network-scan:latest

# Tag a release version at the same time
docker tag navinkr431/network-scan:latest navinkr431/network-scan:v1.2.0
docker push navinkr431/network-scan:v1.2.0
```

---

## Install from source (Linux, recommended for pentest servers)

Installs all prerequisites, compiles both binaries, and starts the UI as a
systemd service that auto-starts on boot.

```bash
git clone https://github.com/navein-kumar/network-scan.git fastscan
cd fastscan/tools/recon/fastscan
sudo ./install-prereqs.sh --start
```

The script prints the URL and password when done. Credentials are saved to
`fastscan.env` (never committed).

---

## Deploy to a remote server

Use `deploy.sh` to push source, rebuild, and restart from your local machine.
Requires SSH alias `uiprod` in `~/.ssh/config` pointing to the target.

```bash
bash deploy.sh
```

Steps: tar-over-SSH source sync, npm build, Go UI binary build, engine build,
systemd restart (tmux fallback), then a smoke test.

---

## Build from source manually

Requires Go 1.21+, Node.js 18+, npm.

```bash
# Engine binary
cd engine
go build -buildvcs=false -o ../fastscan .
cd ..

# React frontend
cd ui/web
npm ci && npm run build
cd ../..

# Copy built assets into Go embed directory
rm -rf ui/server/static
cp -r ui/web/dist ui/server/static

# UI binary (embeds the React assets)
cd ui/server
go build -buildvcs=false -o ../fastscan-ui .
cd ..
```

---

## Running a scan

Open `http://<server-ip>:8888`, log in, click **New Scan**, enter a target
(IP, hostname, or CIDR), pick a profile, and click **Start Scan**.

Profiles:

| Profile | Speed | Depth |
|---|---|---|
| fast | ~20s/host | Top ports, basic detection |
| medium | ~60s/host | More ports, credential checks |
| slow | ~3m/host | Full port range, deep TLS |
| crawl | ~10m/host | Exhaustive including UDP |

Engine CLI (direct, no UI):

```bash
# Single host
./fastscan -target 192.168.1.1 -profile fast

# CIDR range
./fastscan -target 10.0.0.0/24 -profile medium

# All ports, deep TLS
./fastscan -target 10.0.0.1 -ports 1-65535 -deep
```

---

## Detection rules

Rules live in `engine/plugins/` as plain YAML. No rebuild needed to add or edit.

```yaml
id: my-rule-id
title: Short human-readable title
severity: critical|high|medium|low|info
source: ssh
when: version != "" && vlt(version, "8.0.0")
evidence: "{{ .host }}:{{ .port }} running SSH {{ .version }}"
tags: [ssh, outdated]
remediation: |
  Upgrade to the latest stable release.
```

---

## Exports

From the UI scan detail page:

| Format | Contents |
|---|---|
| XLSX | All findings with severity, host, evidence, remediation |
| HTML | Self-contained report with inline screenshots |
| Evidence ZIP | Per-finding .txt files, PNG renders, web/RDP/VNC screenshots |

---

## Service management (systemd install)

```bash
journalctl -u fastscan -f        # live logs
systemctl restart fastscan        # restart
systemctl stop fastscan           # stop
cat /opt/fastscan/fastscan.env    # view credentials and listen address
```

---

## Prerequisites

`install-prereqs.sh` handles everything on Debian/Ubuntu automatically.

| Tool | Required | Purpose |
|---|---|---|
| Go 1.21+ | Build | Compile engine + UI |
| Node.js 18+ | Build | Compile React frontend |
| Python 3 + pip | Runtime | Export scripts |
| nmap | Yes | Service detection, OS fingerprinting |
| rustscan | Recommended | Fast port discovery |
| testssl.sh | Recommended | Deep TLS vulnerability analysis |
| nxc/netexec | Optional | SMB and credential testing |
| ike-scan | Optional | IKE/IPsec aggressive mode |
| scrying | Optional | RDP login screen screenshots |
