#!/usr/bin/env bash
#
# fastscan full installer for a fresh system.
#
# One command to stand the whole thing up: it checks prerequisites and installs
# any that are missing (via install-prereqs.sh), builds the engine binary, puts
# the support files (scripts, creds, plugins) in place, and optionally builds
# and deploys the web UI. It is idempotent, so re-running only does what is
# needed.
#
# Configuration lives in fastscan.env, which is created from
# fastscan.env.example on the first run with a randomly generated UI password.
# To change the UI password later: edit fastscan.env, then run
# "./install.sh --restart-ui".
#
# Usage:
#   ./install.sh                full install: prereqs + engine + UI
#   ./install.sh --engine-only  prereqs + engine, skip the UI
#   ./install.sh --restart-ui   reload fastscan.env and restart the UI only
#   ./install.sh --check        report what is present/missing, change nothing
#
set -u

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

green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red() { printf '\033[31m%s\033[0m\n' "$1"; }
log() { printf '[*] %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "=================================================="
echo " fastscan installer   (mode: $MODE)"
echo "=================================================="

# ---------------------------------------------------------------------------
# 1. Config: create fastscan.env on first run with a random UI password
# ---------------------------------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
  if [ "$MODE" = check ]; then
    yellow "fastscan.env missing (first run would create it from the example with a random UI password)"
  else
    log "creating fastscan.env from template"
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    RANDPASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)"
    sed -i "s/^UI_PASS=.*/UI_PASS=$RANDPASS/" "$ENV_FILE"
    green "generated a random UI password in fastscan.env"
  fi
fi

# Defaults, then overlay fastscan.env if present.
ENGINE_BIN_DIR=/tmp/fastscan
UI_USER=admin
UI_PASS=changeme
UI_ADDR=0.0.0.0:8888
UI_DATA_DIR=/root/fastscan-ui-data
UI_SRC_DIR=/tmp/fastscan-ui
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

# ---------------------------------------------------------------------------
# UI deploy helper (used by full and restart-ui modes)
# ---------------------------------------------------------------------------
GO_BIN=/usr/local/go/bin/go
have "$GO_BIN" || GO_BIN="$(command -v go 2>/dev/null || echo go)"

start_ui() {
  local bin="$UI_SRC_DIR/fastscan-ui"
  [ -x "$bin" ] || { red "UI binary $bin not found (run a full ./install.sh first)"; return 1; }
  mkdir -p "$UI_DATA_DIR"
  # Optional: a VNC password file enables RDP/VNC screenshot capture in scans
  # launched from the UI (the engine reads FASTSCAN_VNC_PASSWD). Without it,
  # only no-auth VNC servers get screenshotted.
  local envprefix=""
  if [ -n "${VNC_PASSWD_FILE:-}" ] && [ -f "${VNC_PASSWD_FILE}" ]; then
    envprefix="FASTSCAN_VNC_PASSWD=$VNC_PASSWD_FILE "
  fi
  if have tmux; then
    tmux kill-session -t fsui 2>/dev/null
    tmux new-session -d -s fsui \
      "${envprefix}$bin -addr $UI_ADDR -data $UI_DATA_DIR -auth $UI_USER:$UI_PASS 2>&1 | tee $UI_SRC_DIR/server.log"
    green "UI running on $UI_ADDR (tmux session fsui), login $UI_USER : <UI_PASS from fastscan.env>"
  else
    yellow "tmux not installed; start the UI manually:"
    echo "    ${envprefix}$bin -addr $UI_ADDR -data $UI_DATA_DIR -auth $UI_USER:\$UI_PASS"
  fi
}

build_ui() {
  [ -d "$UI_SRC_DIR" ] || { yellow "UI source $UI_SRC_DIR not present; skipping UI"; return 0; }
  local srv="$UI_SRC_DIR/server" web="$UI_SRC_DIR/web"
  # Rebuild the frontend if its source is present.
  if [ -f "$web/package.json" ]; then
    if ! have npm; then
      log "installing nodejs + npm for the UI frontend"
      apt-get install -y nodejs npm >/dev/null 2>&1 || yellow "could not install npm; will reuse any existing build"
    fi
    if have npm; then
      log "building UI frontend (npm)"
      if ( cd "$web" && npm ci >/dev/null 2>&1 && npm run build >/dev/null 2>&1 ); then
        # Server embeds server/static; refresh it from the new build.
        if [ -d "$web/dist" ]; then
          rm -rf "$srv/static" && cp -r "$web/dist" "$srv/static"
        fi
        green "frontend built"
      else
        yellow "npm build failed; reusing existing server/static"
      fi
    fi
  fi
  log "building UI server -> $UI_SRC_DIR/fastscan-ui"
  if ( cd "$srv" && "$GO_BIN" build -o "$UI_SRC_DIR/fastscan-ui" . ); then
    green "UI server built"
  else
    red "UI server build failed (is server/static present?)"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# restart-ui mode: just reload env + restart, no rebuild
# ---------------------------------------------------------------------------
if [ "$MODE" = restart-ui ]; then
  log "restarting UI with settings from fastscan.env"
  start_ui
  exit $?
fi

# ---------------------------------------------------------------------------
# 2. Prerequisites
# ---------------------------------------------------------------------------
if [ -x "$SCRIPT_DIR/install-prereqs.sh" ] || [ -f "$SCRIPT_DIR/install-prereqs.sh" ]; then
  if [ "$MODE" = check ]; then
    bash "$SCRIPT_DIR/install-prereqs.sh" --check
  else
    bash "$SCRIPT_DIR/install-prereqs.sh"
  fi
else
  yellow "install-prereqs.sh not found next to install.sh; skipping prereq step"
fi
# Re-resolve go in case prereqs just installed it.
have "$GO_BIN" || { [ -x /usr/local/go/bin/go ] && GO_BIN=/usr/local/go/bin/go; }
have "$GO_BIN" || GO_BIN="$(command -v go 2>/dev/null || echo go)"

# ---------------------------------------------------------------------------
# 3. Engine build + file setup
# ---------------------------------------------------------------------------
echo "--------------------------------------------------"
if [ "$MODE" = check ]; then
  [ -x "$ENGINE_BIN_DIR/fastscan" ] \
    && green "engine present: $ENGINE_BIN_DIR/fastscan" \
    || yellow "engine NOT built (would build to $ENGINE_BIN_DIR/fastscan)"
  for d in scripts creds plugins; do
    [ -d "$SCRIPT_DIR/$d" ] && green "  $d/ present" || yellow "  $d/ missing"
  done
  echo "--------------------------------------------------"
  green "check complete (no changes made)."
  exit 0
fi

log "building engine -> $ENGINE_BIN_DIR/fastscan"
mkdir -p "$ENGINE_BIN_DIR"
if ( cd "$SCRIPT_DIR" && "$GO_BIN" build -o "$ENGINE_BIN_DIR/fastscan" . ); then
  green "engine built: $ENGINE_BIN_DIR/fastscan"
else
  red "engine build failed"
  exit 1
fi
# The web UI invokes the engine from its source directory. Point that path at
# the freshly built binary (symlink) so the UI always runs the current engine
# and never a stale copy.
if [ "$ENGINE_BIN_DIR/fastscan" != "$SCRIPT_DIR/fastscan" ]; then
  ln -sf "$ENGINE_BIN_DIR/fastscan" "$SCRIPT_DIR/fastscan"
  green "  linked $SCRIPT_DIR/fastscan -> $ENGINE_BIN_DIR/fastscan (UI engine path)"
fi
# Support files: make the evidence/xlsx bridges executable; creds + plugins
# already live in the source tree and are read from there by the engine/UI.
chmod +x "$SCRIPT_DIR"/scripts/*.py 2>/dev/null || true
for d in scripts creds plugins; do
  [ -d "$SCRIPT_DIR/$d" ] && green "  $d/ ready" || yellow "  $d/ missing (engine features that use it will be skipped)"
done

# ---------------------------------------------------------------------------
# 4. Web UI build + deploy
# ---------------------------------------------------------------------------
if [ "$MODE" = full ]; then
  echo "--------------------------------------------------"
  build_ui && start_ui
fi

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------
echo "=================================================="
green "fastscan install complete."
echo "  engine : $ENGINE_BIN_DIR/fastscan"
[ "$MODE" = full ] && echo "  web UI : http://$UI_ADDR  (login $UI_USER, password in fastscan.env)"
echo
echo "  To change the UI password: edit UI_PASS in fastscan.env, then run:"
echo "      ./install.sh --restart-ui"
echo "=================================================="
