#!/usr/bin/env bash
# deploy.sh — build fastscan-ui and deploy to idsserver.
#
# Run from the fastscan-ui repo root on your LOCAL machine:
#   bash deploy.sh
#
# Requires ssh access to idsserver (key-based, no password prompt).

set -euo pipefail

REMOTE=idsserver
REMOTE_DIR=/root/fastscan/ui
BINARY_NAME=fastscan-ui
DATA_DIR=/root/fastscan-ui-data
AUTH="admin:d7d9212ae97546c0"
ADDR="0.0.0.0:8888"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== [1/4] Building frontend ==="
( cd "$SCRIPT_DIR/web" && npm ci --silent && npm run build --silent )
echo "  frontend build OK"

echo "=== [2/4] Pushing source to $REMOTE ==="
tar -czf - -C "$SCRIPT_DIR" \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='web/node_modules' \
  --exclude='web/dist' \
  --exclude='*.log' \
  . | ssh "$REMOTE" "tar xzf - -C $REMOTE_DIR"
# push the built frontend dist separately
tar -czf - -C "$SCRIPT_DIR/web" dist | ssh "$REMOTE" "tar xzf - -C $REMOTE_DIR/web"
echo "  source sync done"

echo "=== [3/4] Building server binary on $REMOTE ==="
ssh "$REMOTE" bash <<ENDSSH
  set -e
  GO=/usr/local/go/bin/go
  cd $REMOTE_DIR
  rm -rf server/static && cp -r web/dist server/static
  ( cd server && \$GO build -buildvcs=false -o $REMOTE_DIR/$BINARY_NAME . )
  echo "  server binary built"
ENDSSH

echo "=== [4/4] Restarting service ==="
ssh "$REMOTE" bash <<ENDSSH
  if systemctl is-enabled fastscan-ui &>/dev/null 2>&1; then
    systemctl restart fastscan-ui
    sleep 2
    systemctl is-active --quiet fastscan-ui && echo "  systemd service restarted OK" || { journalctl -u fastscan-ui -n 10 --no-pager; exit 1; }
  else
    pkill -f fastscan-ui 2>/dev/null || true
    sleep 1
    nohup $REMOTE_DIR/$BINARY_NAME -addr $ADDR -data $DATA_DIR -auth $AUTH \
      > /tmp/fastscan-ui.log 2>&1 &
    sleep 2
    echo "  UI started (nohup)"
  fi
ENDSSH

echo ""
IP=$(ssh "$REMOTE" 'hostname -I | awk "{print \$1}"')
echo "Deploy complete. UI: http://${IP}:8888"
