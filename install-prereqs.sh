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
#
set -u

GO_VERSION="1.25.7"
GO_ROOT="/usr/local/go"
GO_BIN=""
TESTSSL_DIR="/opt/testssl.sh"
FASTSCAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CHECK_ONLY=0
DO_BUILD=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --build) DO_BUILD=1 ;;
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
# screenshot tools (optional; RDP/VNC drivers grab a PNG of the login screen)
#   - vncsnapshot + imagemagick: VNC desktop capture, then JPEG->PNG convert
#   - scrying: purpose-built RDP/VNC/HTTP headless screenshotter (RDP capture)
# ---------------------------------------------------------------------------
install_screenshot() {
  local have_vnc=0 have_conv=0 have_scry=0
  have vncsnapshot && have_vnc=1
  have convert && have_conv=1
  { have scrying || [ -x /usr/local/bin/scrying ]; } && have_scry=1

  if [ "$have_vnc" -eq 1 ] && [ "$have_conv" -eq 1 ] && [ "$have_scry" -eq 1 ]; then
    green "screenshot tools present: vncsnapshot, imagemagick, scrying"
    return 0
  fi
  [ "$CHECK_ONLY" -eq 1 ] && {
    [ "$have_vnc" -eq 1 ]  || yellow "MISSING: vncsnapshot (VNC screenshot)"
    [ "$have_conv" -eq 1 ] || yellow "MISSING: imagemagick (JPEG->PNG convert)"
    [ "$have_scry" -eq 1 ] || yellow "MISSING: scrying (RDP screenshot)"
    return 0
  }
  need_root; apt_update_once

  if [ "$have_vnc" -eq 0 ]; then
    log "apt-get install vncsnapshot"
    apt-get install -y vncsnapshot >/dev/null 2>&1
    have vncsnapshot && green "vncsnapshot installed" \
      || yellow "vncsnapshot not installed (optional; VNC screenshots skipped)"
  fi
  if [ "$have_conv" -eq 0 ]; then
    log "apt-get install imagemagick"
    apt-get install -y imagemagick >/dev/null 2>&1
    have convert && green "imagemagick installed" \
      || yellow "imagemagick not installed (optional; VNC screenshots skipped)"
  fi

  # scrying ships as a static release binary; no apt package. Best-effort fetch.
  if [ "$have_scry" -eq 0 ]; then
    local arch deb url
    case "$(uname -m)" in
      x86_64) arch="amd64" ;;
      aarch64|arm64) arch="arm64" ;;
      *) arch="" ;;
    esac
    if [ -n "$arch" ]; then
      deb="scrying_0.9.1-1_${arch}.deb"
      url="https://github.com/nccgroup/scrying/releases/download/v0.9.1/${deb}"
      log "downloading $url"
      if curl -fsSL "$url" -o "/tmp/$deb"; then
        dpkg -i "/tmp/$deb" >/dev/null 2>&1 || { apt-get -f install -y >/dev/null 2>&1; }
        rm -f "/tmp/$deb"
      fi
    fi
    { have scrying || [ -x /usr/local/bin/scrying ]; } && green "scrying installed" \
      || yellow "scrying not installed (optional; RDP screenshots skipped)"
  fi
}

# ---------------------------------------------------------------------------
# Web screenshots (playwright-go headless Chromium)
#   The engine grabs a PNG of every HTTP/HTTPS service via playwright-go. That
#   needs the Chromium browser + driver in the playwright cache. Web
#   screenshots degrade gracefully without it, so this step is optional.
# ---------------------------------------------------------------------------
webshot_ok() {
  # The playwright-go headless browser unpacks as
  # /root/.cache/ms-playwright/chromium_headless_shell-<rev>.
  ls -d /root/.cache/ms-playwright/chromium_headless_shell-* >/dev/null 2>&1
}

install_webshot() {
  if webshot_ok; then green "playwright Chromium present (web screenshots)"; return 0; fi
  [ "$CHECK_ONLY" -eq 1 ] && { yellow "MISSING: playwright Chromium (web screenshots)"; return 0; }
  if ! go_ok; then
    yellow "playwright Chromium not installed (optional; Go missing, web screenshots skipped)"
    return 0
  fi
  need_root
  log "installing playwright Chromium browser + driver"
  # Run from the fastscan source dir so the CLI version matches go.mod.
  ( cd "$FASTSCAN_DIR" && "$GO_BIN" run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps chromium ) >/dev/null 2>&1
  webshot_ok && green "playwright Chromium installed" \
    || yellow "playwright Chromium not installed (optional; web screenshots skipped)"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
echo "=============================================="
echo " fastscan prerequisite installer"
[ "$CHECK_ONLY" -eq 1 ] && echo " mode: CHECK ONLY (no changes)"
echo "=============================================="

install_go
install_nmap
install_rustscan
install_testssl
install_nxc
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
have nmap && green "  nmap        OK" || red "  nmap        MISSING"
have rustscan && green "  rustscan    OK" || yellow "  rustscan    optional/missing"
{ have testssl.sh || [ -x "$TESTSSL_DIR/testssl.sh" ]; } && green "  testssl.sh  OK" || yellow "  testssl.sh  optional/missing"
{ have nxc || have netexec; } && green "  nxc         OK" || yellow "  nxc         optional/missing"
have ike-scan && green "  ike-scan    OK" || yellow "  ike-scan    optional/missing"
have vncsnapshot && green "  vncsnapshot OK" || yellow "  vncsnapshot optional/missing"
have convert && green "  imagemagick OK" || yellow "  imagemagick optional/missing"
{ have scrying || [ -x /usr/local/bin/scrying ]; } && green "  scrying     OK" || yellow "  scrying     optional/missing"
webshot_ok && green "  webshot     OK" || yellow "  webshot     optional/missing"
echo "----------------------------------------------"

if [ "$DO_BUILD" -eq 1 ] && [ "$CHECK_ONLY" -eq 0 ]; then
  if go_ok; then
    log "building fastscan engine with ${GO_BIN:-$GO_ROOT/bin/go}"
    ( cd "$FASTSCAN_DIR" && "${GO_BIN:-$GO_ROOT/bin/go}" build -o /tmp/fastscan/fastscan . ) \
      && green "built: /tmp/fastscan/fastscan" \
      || red "build failed"
  else
    red "cannot build: Go toolchain missing"
  fi
fi

green "done."
