#!/usr/bin/env bash
#
# fastscan install script.
#
# Clone the repo anywhere, then run this script once:
#   git clone <repo> /opt/fastscan && cd /opt/fastscan && sudo ./install.sh
#
# The script is idempotent — re-running only does what is missing.
# All paths are relative to wherever you cloned the repo; nothing is
# hardcoded to /tmp or /root.
#
# Usage:
#   sudo ./install.sh                  full install: prereqs + engine + UI
#   sudo ./install.sh --engine-only    prereqs + engine only, skip UI
#   sudo ./install.sh --restart-ui     restart the UI with current fastscan.env
#   sudo ./install.sh --check          report what is present/missing, no changes
#
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/fastscan.env"
ENV_EXAMPLE="$SCRIPT_DIR/fastscan.env.example"

MODE=full
for a in "$@"; do
  case "$a" in
    --engine-only) MODE=engine ;;
    --restart-ui)  MODE=restart-ui ;;
    --check)       MODE=check ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done

green()  { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red()    { printf '\033[31m%s\033[0m\n' "$1"; }
log()    { printf '[*] %s\n' "$1"; }
die()    { red "$1"; exit 1; }
have()   { command -v "$1" >/dev/null 2>&1; }

echo "=================================================="
echo " fastscan installer   (mode: $MODE)"
echo " install root: $SCRIPT_DIR"
echo "=================================================="

# ---------------------------------------------------------------------------
# 1. Config: create fastscan.env on first run
# ---------------------------------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
  if [ "$MODE" = check ]; then
    yellow "fastscan.env missing (first run would create it from example with random UI_PASS)"
  else
    log "creating $ENV_FILE from template"
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    RANDPASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
    sed -i "s/^UI_PASS=.*/UI_PASS=$RANDPASS/" "$ENV_FILE"
    green "created fastscan.env with random UI_PASS"
  fi
fi

# Defaults (all relative to SCRIPT_DIR); fastscan.env can override UI_USER,
# UI_PASS, UI_ADDR, and VNC_PASSWD_FILE only.
UI_USER=admin
UI_PASS=changeme
UI_ADDR=0.0.0.0:8888
VNC_PASSWD_FILE=

# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

# These paths are always derived from SCRIPT_DIR so the install is portable.
UI_DATA_DIR="$SCRIPT_DIR/data"
ENGINE_BIN="$SCRIPT_DIR/fastscan"
UI_SRC_DIR="$SCRIPT_DIR/ui"
UI_BIN="$UI_SRC_DIR/fastscan-ui"

# ---------------------------------------------------------------------------
# Go toolchain: prefer /usr/local/go, fall back to PATH
# ---------------------------------------------------------------------------
GO_BIN=""
[ -x /usr/local/go/bin/go ] && GO_BIN=/usr/local/go/bin/go
[ -z "$GO_BIN" ] && have go && GO_BIN="$(command -v go)"

# ---------------------------------------------------------------------------
# Helper: start the UI server
# ---------------------------------------------------------------------------
start_ui() {
  [ -x "$UI_BIN" ] || die "UI binary not found at $UI_BIN — run a full ./install.sh first"
  mkdir -p "$UI_DATA_DIR"
  local envprefix=""
  if [ -n "${VNC_PASSWD_FILE:-}" ] && [ -f "${VNC_PASSWD_FILE}" ]; then
    envprefix="FASTSCAN_VNC_PASSWD=$VNC_PASSWD_FILE "
  fi
  local cmd="${envprefix}${UI_BIN} -addr ${UI_ADDR} -data ${UI_DATA_DIR} -auth ${UI_USER}:${UI_PASS}"
  if have tmux; then
    tmux kill-session -t fastscan-ui 2>/dev/null || true
    tmux new-session -d -s fastscan-ui \
      "exec $cmd 2>&1 | tee $UI_SRC_DIR/server.log"
    green "UI started in tmux session 'fastscan-ui'"
  else
    yellow "tmux not found — start the UI manually:"
    echo "  $cmd"
    return 0
  fi
  sleep 1
  local port="${UI_ADDR##*:}"
  if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
    local_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")"
    green "UI listening on http://${local_ip}:${port}"
  else
    yellow "UI may still be starting — check: tmux attach -t fastscan-ui"
  fi
}

# ---------------------------------------------------------------------------
# Helper: build the UI (Vite frontend + Go server)
# ---------------------------------------------------------------------------
build_ui() {
  if [ ! -d "$UI_SRC_DIR/server" ] || [ ! -d "$UI_SRC_DIR/web" ]; then
    yellow "ui/server or ui/web not found — skipping UI build"
    return 0
  fi

  # Frontend
  if [ -f "$UI_SRC_DIR/web/package.json" ]; then
    if ! have npm; then
      log "installing nodejs + npm"
      apt-get install -y nodejs npm >/dev/null 2>&1 \
        || yellow "could not install npm; will reuse existing build if present"
    fi
    if have npm; then
      log "building UI frontend (npm ci + vite build)"
      if ( cd "$UI_SRC_DIR/web" && npm ci --silent && npm run build --silent ); then
        green "frontend built"
        if [ -d "$UI_SRC_DIR/web/dist" ]; then
          rm -rf "$UI_SRC_DIR/server/static"
          cp -r "$UI_SRC_DIR/web/dist" "$UI_SRC_DIR/server/static"
        fi
      else
        yellow "npm build failed — reusing existing server/static if present"
      fi
    fi
  fi

  # Go server
  log "building UI server binary"
  [ -n "$GO_BIN" ] || die "Go toolchain not found — run install-prereqs.sh first"
  if ( cd "$UI_SRC_DIR/server" && "$GO_BIN" build -o "$UI_BIN" . ); then
    green "UI binary built: $UI_BIN"
  else
    die "UI server build failed"
  fi
}

# ---------------------------------------------------------------------------
# --restart-ui: just reload env and restart, no rebuild
# ---------------------------------------------------------------------------
if [ "$MODE" = restart-ui ]; then
  log "restarting UI"
  start_ui
  echo "=================================================="
  green "UI restarted."
  echo "  web UI : http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost):${UI_ADDR##*:}"
  echo "  login  : ${UI_USER} / <UI_PASS from fastscan.env>"
  echo "=================================================="
  exit 0
fi

# ---------------------------------------------------------------------------
# 2. Prerequisites
# ---------------------------------------------------------------------------
if [ -f "$SCRIPT_DIR/install-prereqs.sh" ]; then
  if [ "$MODE" = check ]; then
    bash "$SCRIPT_DIR/install-prereqs.sh" --check
  else
    bash "$SCRIPT_DIR/install-prereqs.sh"
  fi
else
  yellow "install-prereqs.sh not found — skipping prereq step"
fi
# Re-resolve Go after prereqs may have installed it
[ -x /usr/local/go/bin/go ] && GO_BIN=/usr/local/go/bin/go
[ -z "$GO_BIN" ] && have go && GO_BIN="$(command -v go)"

# ---------------------------------------------------------------------------
# 3. Engine build
# ---------------------------------------------------------------------------
if [ "$MODE" = check ]; then
  [ -x "$ENGINE_BIN" ] \
    && green "engine: $ENGINE_BIN" \
    || yellow "engine not built (would build to $ENGINE_BIN)"
  [ -x "$UI_BIN" ] \
    && green "UI: $UI_BIN" \
    || yellow "UI not built (would build to $UI_BIN)"
  for d in scripts creds plugins; do
    [ -d "$SCRIPT_DIR/$d" ] \
      && green "  $d/ present" \
      || yellow "  $d/ missing"
  done
  echo "=================================================="
  green "check complete (no changes made)."
  exit 0
fi

log "building engine"
[ -n "$GO_BIN" ] || die "Go toolchain not found — cannot build engine"
( cd "$SCRIPT_DIR" && "$GO_BIN" build -o "$ENGINE_BIN" . ) \
  && green "engine built: $ENGINE_BIN" \
  || die "engine build failed"

chmod +x "$SCRIPT_DIR"/scripts/*.py 2>/dev/null || true

for d in scripts creds plugins; do
  [ -d "$SCRIPT_DIR/$d" ] \
    && green "  $d/ ready" \
    || yellow "  $d/ missing (features that need it will be skipped)"
done

# ---------------------------------------------------------------------------
# 4. UI build + start
# ---------------------------------------------------------------------------
if [ "$MODE" = full ]; then
  echo "--------------------------------------------------"
  build_ui && start_ui
fi

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------
local_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")"
echo "=================================================="
green "fastscan install complete."
echo "  engine  : $ENGINE_BIN"
if [ "$MODE" = full ] && [ -x "$UI_BIN" ]; then
  echo "  web UI  : http://${local_ip}:${UI_ADDR##*:}"
  echo "  login   : ${UI_USER} / <see UI_PASS in fastscan.env>"
fi
echo
echo "  Change UI password: edit UI_PASS in fastscan.env then run:"
echo "    ./install.sh --restart-ui"
echo "  Rebuild:  ./install.sh"
echo "=================================================="
