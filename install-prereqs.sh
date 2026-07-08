#!/usr/bin/env bash
#
# fastscan prerequisite auto-installer.
#
# The fastscan engine itself is a single self-contained Go binary: every
# protocol driver added so far (FTP, SMB, NFS, Redis, LDAP, SMTP, DNS, Telnet,
# MongoDB, SNMP, Docker API, SSH, MySQL, PostgreSQL, MSSQL, CouchDB, Memcached,
# and the rest) is pure Go and pulls in zero external command line tools.
#
# This script provisions the two things the binary cannot ship inside itself:
#   1. the Go toolchain (only needed to BUILD the binary), and
#   2. the external CLIs the engine optionally shells out to at runtime:
#        nmap, rustscan, testssl.sh, nxc (netexec), and the screenshot tools
#        (vncsnapshot + imagemagick for VNC, scrying for RDP).
#
# It is idempotent: re-running installs only what is missing. Targets Debian
# and Ubuntu (apt). Run as root (or with sudo).
#
# Usage:
#   sudo ./install-prereqs.sh            # install everything that is missing
#   sudo ./install-prereqs.sh --check    # report only, install nothing
#   sudo ./install-prereqs.sh --build    # also build the engine afterwards
#   sudo ./install-prereqs.sh --start    # build engine + UI, install systemd service, start it
#
set -u

GO_VERSION="1.25.7"
GO_ROOT="/usr/local/go"
GO_BIN=""
TESTSSL_DIR="/opt/testssl.sh"
FASTSCAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CHECK_ONLY=0
DO_BUILD=0
DO_START=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --build) DO_BUILD=1 ;;
    --start) DO_BUILD=1; DO_START=1 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red() { printf '\033[31m%s\033[0m\n' "$1"; }
log() { printf '[*] %s\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    red "This step needs root. Re-run with sudo."
    exit 1
  fi
}

apt_ready=0
apt_update_once() {
  if [ "$apt_ready" -eq 0 ]; then
    log "apt-get update"
    apt-get update -y >/dev/null 2>&1
    apt_ready=1
  fi
}

# ---------------------------------------------------------------------------
# Go toolchain
# ---------------------------------------------------------------------------
go_ok() {
  # Accept any system go (PATH or $GO_ROOT) at version 1.21 or newer. go.mod
  # declares "go 1.25.7"; since Go 1.21 the toolchain directive makes the
  # build auto-fetch that exact toolchain on demand, so a 1.21+ base is enough.
  local gobin=""
  [ -x "$GO_ROOT/bin/go" ] && gobin="$GO_ROOT/bin/go"
  [ -z "$gobin" ] && have go && gobin="$(command -v go)"
  [ -z "$gobin" ] && return 1
  GO_BIN="$gobin"
  local v
  v="$("$gobin" version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')"
  [ -n "$v" ] && awk "BEGIN{exit !($v >= 1.21)}" && return 0
  return 1
}

install_go() {
  if go_ok; then
    green "Go toolchain present: $($GO_ROOT/bin/go version)"
    return 0
  fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: Go $GO_VERSION (at $GO_ROOT)"; return 0; }
  need_root
  local arch tgz url
  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) red "unsupported arch $(uname -m) for Go auto-install"; return 1 ;;
  esac
  tgz="go${GO_VERSION}.linux-${arch}.tar.gz"
  url="https://go.dev/dl/${tgz}"
  log "downloading $url"
  if ! curl -fsSL "$url" -o "/tmp/$tgz"; then
    red "Go download failed. Install Go $GO_VERSION manually into $GO_ROOT."
    return 1
  fi
  rm -rf "$GO_ROOT"
  tar -C /usr/local -xzf "/tmp/$tgz"
  rm -f "/tmp/$tgz"
  if ! grep -q "$GO_ROOT/bin" /etc/profile.d/go.sh 2>/dev/null; then
    echo "export PATH=\$PATH:$GO_ROOT/bin" > /etc/profile.d/go.sh
  fi
  green "Go installed: $($GO_ROOT/bin/go version)"
}

# ---------------------------------------------------------------------------
# Python 3 + pip (required for export scripts: xlsx, evidence, html)
# ---------------------------------------------------------------------------
install_python() {
  local py3=""
  have python3 && py3="python3"
  [ -z "$py3" ] && have python && py3="python"
  if [ -n "$py3" ]; then
    green "Python present: $($py3 --version 2>&1)"
    if ! "$py3" -m pip --version >/dev/null 2>&1; then
      [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: pip (Python package manager)"; return 0; }
      need_root; apt_update_once
      apt-get install -y python3-pip >/dev/null 2>&1
    fi
    green "pip present: $($py3 -m pip --version 2>&1 | head -1)"
    return 0
  fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: python3"; return 0; }
  need_root; apt_update_once
  log "apt-get install python3 python3-pip"
  apt-get install -y python3 python3-pip >/dev/null 2>&1
  have python3 && green "python3 installed: $(python3 --version)" || red "python3 install failed"
}

install_python_deps() {
  local py3="python3"
  have python3 || py3="python"
  have "$py3" || return 0
  local reqs="$FASTSCAN_DIR/scripts/requirements.txt"
  if [ -f "$reqs" ]; then
    log "installing Python packages from scripts/requirements.txt"
    "$py3" -m pip install -q -r "$reqs" 2>/dev/null \
      && green "Python packages installed" \
      || yellow "Some Python packages failed (exports may not work)"
  fi
}

# ---------------------------------------------------------------------------
# Node.js + npm (required for the React UI build step)
# ---------------------------------------------------------------------------
install_node() {
  if have node && have npm; then
    green "Node.js present: $(node --version), npm: $(npm --version)"
    return 0
  fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: node/npm (required for UI build)"; return 0; }
  need_root; apt_update_once
  # Try NodeSource LTS first, fall back to distro package
  if curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1; then
    apt-get install -y nodejs >/dev/null 2>&1
  else
    apt-get install -y nodejs npm >/dev/null 2>&1
  fi
  have node && green "Node.js installed: $(node --version), npm: $(npm --version)" \
    || yellow "Node.js not installed (optional; only needed to rebuild UI from source)"
}

# ---------------------------------------------------------------------------
# nmap (NSE scripts used by the engine for deep host scanning)
# ---------------------------------------------------------------------------
install_nmap() {
  if have nmap; then green "nmap present: $(nmap --version | head -1)"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: nmap"; return 0; }
  need_root; apt_update_once
  log "apt-get install nmap"
  apt-get install -y nmap >/dev/null 2>&1
  have nmap && green "nmap installed: $(nmap --version | head -1)" || red "nmap install failed"
}

# ---------------------------------------------------------------------------
# rustscan (fast port discovery front-end)
# ---------------------------------------------------------------------------
install_rustscan() {
  if have rustscan; then green "rustscan present: $(rustscan --version 2>/dev/null | head -1)"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: rustscan"; return 0; }
  need_root
  local arch deb url
  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) arch="" ;;
  esac
  if [ -n "$arch" ]; then
    deb="rustscan_2.4.1_${arch}.deb"
    url="https://github.com/bee-san/RustScan/releases/download/2.4.1/${deb}"
    log "downloading $url"
    if curl -fsSL "$url" -o "/tmp/$deb"; then
      dpkg -i "/tmp/$deb" >/dev/null 2>&1 || { apt_update_once; apt-get -f install -y >/dev/null 2>&1; }
      rm -f "/tmp/$deb"
    fi
  fi
  if ! have rustscan && have cargo; then
    log "falling back to cargo install rustscan"
    cargo install rustscan >/dev/null 2>&1
  fi
  have rustscan && green "rustscan installed" || yellow "rustscan not installed (optional; engine degrades to nmap/native discovery)"
}

# ---------------------------------------------------------------------------
# testssl.sh (only invoked behind the engine -deep flag)
# ---------------------------------------------------------------------------
install_testssl() {
  if have testssl.sh || [ -x "$TESTSSL_DIR/testssl.sh" ]; then
    green "testssl.sh present"; return 0
  fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: testssl.sh"; return 0; }
  need_root; apt_update_once
  have git || apt-get install -y git >/dev/null 2>&1
  log "cloning testssl.sh into $TESTSSL_DIR"
  if git clone --depth 1 https://github.com/testssl/testssl.sh.git "$TESTSSL_DIR" >/dev/null 2>&1; then
    ln -sf "$TESTSSL_DIR/testssl.sh" /usr/local/bin/testssl.sh
    green "testssl.sh installed at $TESTSSL_DIR"
  else
    yellow "testssl.sh clone failed (optional; only used with -deep)"
  fi
}

# ---------------------------------------------------------------------------
# nxc / netexec (optional manual-exploitation helper)
# ---------------------------------------------------------------------------
install_nxc() {
  if have nxc || have netexec; then green "nxc/netexec present"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: nxc (netexec)"; return 0; }
  need_root; apt_update_once
  if apt-get install -y netexec >/dev/null 2>&1 && have nxc; then
    green "netexec installed via apt"; return 0
  fi
  log "installing netexec via pipx"
  have pipx || apt-get install -y pipx >/dev/null 2>&1
  if have pipx; then
    pipx install netexec >/dev/null 2>&1
    pipx ensurepath >/dev/null 2>&1
  fi
  have nxc || have netexec && green "netexec installed" || yellow "netexec not installed (optional)"
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# httpx (required: HTTP probing and tech fingerprinting used by the engine's
# http phase — without it web findings are incomplete).
# ---------------------------------------------------------------------------
install_httpx() {
  if have httpx; then green "httpx present: $(httpx --version 2>/dev/null | head -1)"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: httpx (HTTP probing — web findings will be limited)"; return 0; }
  log "installing httpx via go install"
  local gobin
  gobin="${GO_ROOT:-/usr/local/go}/bin/go"
  "$gobin" install -v github.com/projectdiscovery/httpx/cmd/httpx@latest >/dev/null 2>&1
  # go install puts binary in $GOPATH/bin or $HOME/go/bin — symlink into /usr/local/bin
  local src
  src="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin/httpx"
  [ -f "$src" ] && ln -sf "$src" /usr/local/bin/httpx 2>/dev/null || true
  have httpx && green "httpx installed" || yellow "httpx not installed (optional; web detection degraded)"
}

# ---------------------------------------------------------------------------
# nuclei (required: CVE/misconfiguration templates used in the engine's
# nuclei phase — without it ~40% of findings are missed).
# ---------------------------------------------------------------------------
install_nuclei() {
  if have nuclei; then green "nuclei present: $(nuclei --version 2>/dev/null | head -1)"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: nuclei (CVE templates — significant finding loss without it)"; return 0; }
  log "installing nuclei via go install"
  local gobin
  gobin="${GO_ROOT:-/usr/local/go}/bin/go"
  "$gobin" install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >/dev/null 2>&1
  local src
  src="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin/nuclei"
  [ -f "$src" ] && ln -sf "$src" /usr/local/bin/nuclei 2>/dev/null || true
  if have nuclei; then
    green "nuclei installed"
    log "pulling nuclei templates (first run)"
    nuclei -update-templates >/dev/null 2>&1 || true
  else
    yellow "nuclei not installed (optional; CVE detection reduced)"
  fi
}

# ---------------------------------------------------------------------------
# ike-scan (optional; the IKE/IPsec driver shells out to it to dump the
# IKEv1 Aggressive Mode PSK hash for offline cracking). The native driver
# already detects ike_version, main/aggressive mode and vendor IDs over UDP
# 500 without it; ike-scan only adds the psk-crack hash line.
# ---------------------------------------------------------------------------
install_ikescan() {
  if have ike-scan; then green "ike-scan present: $(ike-scan --version 2>&1 | head -1)"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: ike-scan (Aggressive Mode PSK hash dump)"; return 0; }
  need_root; apt_update_once
  log "apt-get install ike-scan"
  apt-get install -y ike-scan >/dev/null 2>&1
  have ike-scan && green "ike-scan installed" \
    || yellow "ike-scan not installed (optional; IKE Aggressive Mode PSK hash dump skipped)"
}

# ---------------------------------------------------------------------------
# scrying — handles RDP and VNC screenshots (replaces vncsnapshot + imagemagick)
# ---------------------------------------------------------------------------
install_screenshot() {
  { have scrying || [ -x /usr/local/bin/scrying ]; } && {
    green "scrying present (RDP + VNC screenshots)"
    return 0
  }
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: scrying (RDP/VNC screenshots skipped)"; return 0; }

  local arch deb url
  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) arch="" ;;
  esac
  # scrying v0.9.2 is compiled against libssl1.1; Ubuntu 22.04+ ships libssl3.
  # Install the compat package first if needed.
  if ! ldconfig -p 2>/dev/null | grep -q 'libssl.so.1.1'; then
    log "installing libssl1.1 compat for scrying"
    local ssl_deb="libssl1.1_1.1.1f-1ubuntu2_${arch}.deb"
    curl -fsSL "http://security.ubuntu.com/ubuntu/pool/main/o/openssl/${ssl_deb}" \
      -o "/tmp/${ssl_deb}" 2>/dev/null \
      && dpkg -i "/tmp/${ssl_deb}" >/dev/null 2>&1 || true
    rm -f "/tmp/${ssl_deb}"
  fi

  if [ -n "$arch" ]; then
    deb="scrying_0.9.2_${arch}.deb"
    url="https://github.com/nccgroup/scrying/releases/download/v0.9.2/${deb}"
    log "downloading scrying from $url"
    if curl -fsSL "$url" -o "/tmp/$deb"; then
      dpkg -i "/tmp/$deb" >/dev/null 2>&1 || { apt-get -f install -y >/dev/null 2>&1; }
      rm -f "/tmp/$deb"
    else
      yellow "scrying download failed (optional; RDP/VNC screenshots skipped)"
    fi
  fi
  { have scrying || [ -x /usr/local/bin/scrying ]; } && green "scrying installed" \
    || yellow "scrying not installed (optional; RDP/VNC screenshots skipped)"
}

# ---------------------------------------------------------------------------
# Web screenshots (headless Chrome/Chromium)
#   The engine takes PNG screenshots of HTTP/HTTPS services using the system
#   Chrome or Chromium binary. Degrades gracefully if not installed.
# ---------------------------------------------------------------------------
webshot_ok() {
  command -v google-chrome-stable >/dev/null 2>&1 \
    || command -v google-chrome >/dev/null 2>&1 \
    || command -v chromium-browser >/dev/null 2>&1 \
    || command -v chromium >/dev/null 2>&1
}

install_webshot() {
  if webshot_ok; then green "Chrome/Chromium present (web screenshots)"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: Chrome/Chromium (web screenshots)"; return 0; }
  need_root
  if command -v apt-get >/dev/null 2>&1; then
    log "installing Google Chrome stable (web screenshots)"
    curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
      | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg 2>/dev/null
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" \
      > /etc/apt/sources.list.d/google-chrome.list
    apt-get update -qq && apt-get install -y --no-install-recommends google-chrome-stable >/dev/null 2>&1
    webshot_ok && green "Google Chrome installed" \
      || yellow "Chrome install failed (optional; web screenshots skipped)"
  else
    yellow "Non-Debian system: install Chrome/Chromium manually for web screenshots (optional)"
  fi
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
echo "=============================================="
echo " fastscan prerequisite installer"
[ "$CHECK_ONLY" -eq 1 ] && echo " mode: CHECK ONLY (no changes)"
echo "=============================================="

install_go
install_python
install_python_deps
install_node
install_nmap
install_rustscan
install_testssl
install_nxc
install_httpx
install_nuclei
install_ikescan
install_screenshot
install_webshot

# tmux — required for the UI to auto-start in background
if ! have tmux; then
  if [ "$CHECK_ONLY" -eq 1 ]; then
    yellow "MISSING: tmux (UI will not auto-start without it)"
  else
    log "apt-get install tmux"
    apt-get install -y tmux >/dev/null 2>&1 \
      && green "tmux installed" \
      || yellow "tmux not installed (UI must be started manually)"
  fi
fi

echo "----------------------------------------------"
log "summary"
go_ok && green "  go          OK" || red "  go          MISSING"
{ have python3 || have python; } && green "  python3     OK" || yellow "  python3     MISSING (exports broken)"
have node && green "  node/npm    OK" || yellow "  node/npm    optional/missing"
have nmap && green "  nmap        OK" || red "  nmap        MISSING"
have rustscan && green "  rustscan    OK" || yellow "  rustscan    optional/missing"
{ have testssl.sh || [ -x "$TESTSSL_DIR/testssl.sh" ]; } && green "  testssl.sh  OK" || yellow "  testssl.sh  optional/missing"
{ have nxc || have netexec; } && green "  nxc         OK" || yellow "  nxc         optional/missing"
have httpx   && green "  httpx       OK" || yellow "  httpx       MISSING (web detection degraded)"
have nuclei  && green "  nuclei      OK" || yellow "  nuclei      MISSING (~40% finding loss)"
have ike-scan && green "  ike-scan    OK" || yellow "  ike-scan    optional/missing"
{ have scrying || [ -x /usr/local/bin/scrying ]; } && green "  scrying      OK (RDP+VNC)" || yellow "  scrying      optional/missing"
{ have scrying || [ -x /usr/local/bin/scrying ]; } && green "  scrying     OK" || yellow "  scrying     optional/missing"
webshot_ok && green "  webshot     OK" || yellow "  webshot     optional/missing"
echo "----------------------------------------------"

build_frontend() {
  # Build the React frontend and embed it into the Go UI server static dir.
  # Must run BEFORE building the Go UI binary — go:embed needs the files present.
  UI_WEB="$FASTSCAN_DIR/ui/web"
  UI_STATIC="$FASTSCAN_DIR/ui/server/static"
  if [ ! -f "$UI_WEB/package.json" ]; then
    yellow "  ui/web/package.json not found — skipping frontend build"
    return 0
  fi
  if ! have node || ! have npm; then
    yellow "  node/npm not found — skipping frontend build (UI will show blank page if static/ is empty)"
    return 0
  fi
  log "installing frontend dependencies (npm ci)"
  ( cd "$UI_WEB" && npm ci --silent ) \
    && log "building React frontend (npm run build)" \
    || { red "npm ci failed"; return 1; }
  ( cd "$UI_WEB" && npm run build --silent ) \
    || { red "npm run build failed"; return 1; }
  rm -rf "$UI_STATIC"
  cp -r "$UI_WEB/dist" "$UI_STATIC"
  green "frontend built and embedded into $UI_STATIC"
}

if [ "$DO_BUILD" -eq 1 ] && [ "$CHECK_ONLY" -eq 0 ]; then
  if go_ok; then
    local_go="${GO_BIN:-$GO_ROOT/bin/go}"

    log "building fastscan engine"
    ( cd "$FASTSCAN_DIR/engine" && "$local_go" build -buildvcs=false -o "$FASTSCAN_DIR/fastscan" . ) \
      && green "built: $FASTSCAN_DIR/fastscan" \
      || { red "engine build failed"; exit 1; }

    UI_SERVER="$FASTSCAN_DIR/ui/server"
    UI_BIN="$FASTSCAN_DIR/ui/fastscan-ui"
    if [ -d "$UI_SERVER" ]; then
      build_frontend
      log "building fastscan UI binary"
      ( cd "$UI_SERVER" && "$local_go" build -buildvcs=false -o "$UI_BIN" . ) \
        && green "built: $UI_BIN" \
        || red "UI build failed (engine still works standalone)"
    fi
  else
    red "cannot build: Go toolchain missing"
    exit 1
  fi
fi

if [ "$DO_START" -eq 1 ] && [ "$CHECK_ONLY" -eq 0 ]; then
  UI_BIN="$FASTSCAN_DIR/ui/fastscan-ui"
  if [ ! -x "$UI_BIN" ]; then
    red "--start requires the UI binary; build failed or ui/server missing"
    exit 1
  fi

  ENV_FILE="$FASTSCAN_DIR/fastscan.env"
  if [ ! -f "$ENV_FILE" ] && [ -f "$FASTSCAN_DIR/fastscan.env.example" ]; then
    cp "$FASTSCAN_DIR/fastscan.env.example" "$ENV_FILE"
    # Generate a random password
    RAND_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 16)
    sed -i "s/^UI_PASS=.*/UI_PASS=$RAND_PASS/" "$ENV_FILE"
    green "created $ENV_FILE (UI_PASS=$RAND_PASS)"
  fi

  UI_USER=$(grep '^UI_USER=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo admin)
  UI_PASS=$(grep '^UI_PASS='  "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo changeme)
  UI_ADDR=$(grep '^UI_ADDR='  "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo 0.0.0.0:8888)
  DATA_DIR="$FASTSCAN_DIR/data"
  mkdir -p "$DATA_DIR"

  SERVICE_FILE="/etc/systemd/system/fastscan.service"
  log "installing systemd service: $SERVICE_FILE"
  cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=fastscan vulnerability scanner UI
After=network.target

[Service]
ExecStart=$UI_BIN -addr $UI_ADDR -data $DATA_DIR -auth ${UI_USER}:${UI_PASS}
WorkingDirectory=$FASTSCAN_DIR
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable fastscan
  systemctl restart fastscan
  sleep 2

  if systemctl is-active --quiet fastscan; then
    green "fastscan service started (auto-starts on boot)"
    green "  URL  : http://$(hostname -I | awk '{print $1}'):${UI_ADDR##*:}"
    green "  user : $UI_USER"
    green "  pass : $UI_PASS"
    green "  logs : journalctl -u fastscan -f"
  else
    red "service failed to start — check: journalctl -u fastscan -n 20"
  fi
fi

green "done."
