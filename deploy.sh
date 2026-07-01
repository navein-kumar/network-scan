#!/usr/bin/env bash
# deploy.sh — push source to uiprod, rebuild, restart.
#
# Run from the fastscan repo root on your LOCAL machine:
#   bash deploy.sh
#
# Requires: ssh access to uiprod (key-based, no password prompt)
#
# fastscan.env on uiprod controls the UI password. Edit it before
# running deploy.sh to change credentials. The file is never overwritten.

set -euo pipefail

REMOTE=uiprod
REMOTE_DIR=/opt/fastscan
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== [1/5] Pushing source to $REMOTE ==="
tar -czf - -C "$SCRIPT_DIR" \
  --exclude='.git' \
  --exclude='data' \
  --exclude='fastscan' \
  --exclude='fastscan.bak' \
  --exclude='*.env' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='report.html' \
  --exclude='report.xlsx' \
  . | ssh "$REMOTE" "tar xzf - -C $REMOTE_DIR"
echo "  source sync done"

echo "=== [2/5] Building UI on $REMOTE ==="
ssh "$REMOTE" "cd $REMOTE_DIR/ui/web && npm ci --silent && npm run build --silent && rm -rf $REMOTE_DIR/ui/server/static && cp -r $REMOTE_DIR/ui/web/dist $REMOTE_DIR/ui/server/static && echo '  frontend build OK'"
ssh "$REMOTE" "PATH=\$PATH:/usr/local/go/bin && cd $REMOTE_DIR/ui/server && go build -buildvcs=false -o $REMOTE_DIR/ui/fastscan-ui . && echo '  ui build OK'"

echo "=== [3/5] Building engine on $REMOTE ==="
ssh "$REMOTE" "PATH=\$PATH:/usr/local/go/bin && cd $REMOTE_DIR/engine && go build -buildvcs=false -o $REMOTE_DIR/fastscan . && echo '  engine build OK'"

echo "=== [4/5] Restarting UI ==="
ssh "$REMOTE" bash <<'ENDSSH'
  if systemctl is-enabled fastscan &>/dev/null; then
    systemctl restart fastscan
    sleep 2
    systemctl is-active --quiet fastscan && echo "  systemd service restarted" || { echo "  service failed"; journalctl -u fastscan -n 10 --no-pager; exit 1; }
  else
    ENV=/opt/fastscan/fastscan.env
    UI_BIN=/opt/fastscan/ui/fastscan-ui
    DATA=/opt/fastscan/data
    UI_USER=$(grep '^UI_USER=' "$ENV" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo admin)
    UI_PASS=$(grep '^UI_PASS='  "$ENV" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo changeme)
    UI_ADDR=$(grep '^UI_ADDR='  "$ENV" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo 0.0.0.0:8888)
    pkill -f fastscan-ui 2>/dev/null || true
    sleep 1
    tmux kill-session -t fastscan-ui 2>/dev/null || true
    tmux new-session -d -s fastscan-ui \
      "$UI_BIN -addr $UI_ADDR -data $DATA -auth ${UI_USER}:${UI_PASS} 2>&1 | tee $DATA/../ui/server.log"
    sleep 2
    echo "  UI started via tmux (run install-prereqs.sh --start to enable systemd)"
  fi
ENDSSH

echo "=== [5/5] Smoke test ==="
ssh "$REMOTE" bash <<'ENDSSH'
  ENV=/opt/fastscan/fastscan.env
  UI_USER=$(grep '^UI_USER=' "$ENV" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo admin)
  UI_PASS=$(grep '^UI_PASS='  "$ENV" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || echo changeme)

  HTTP=$(curl -s -o /dev/null -w '%{http_code}' -u "${UI_USER}:${UI_PASS}" http://localhost:8888/)
  HTML=$(curl -s -u "${UI_USER}:${UI_PASS}" http://localhost:8888/)
  API=$(curl -s -o /dev/null -w '%{http_code}' -u "${UI_USER}:${UI_PASS}" http://localhost:8888/api/meta)
  META=$(curl -s -u "${UI_USER}:${UI_PASS}" http://localhost:8888/api/meta)
  HAS_ASSETS=$(echo "$HTML" | grep -c '/assets/' || true)

  echo "  HTML  : HTTP $HTTP"
  echo "  Assets: $([ "$HAS_ASSETS" -gt 0 ] && echo 'embedded OK' || echo 'MISSING — blank page!')"
  echo "  /api/meta: HTTP $API"
  echo "  $META"

  [ "$HTTP" = "200" ] && [ "$HAS_ASSETS" -gt 0 ] && [ "$API" = "200" ] && echo "  PASS" || { echo "  FAIL"; exit 1; }
ENDSSH

IP=$(ssh "$REMOTE" 'curl -s ifconfig.me 2>/dev/null || hostname -I | awk "{print \$1}"')
echo ""
echo "Deploy complete. UI: http://${IP}:8888"
echo "Password is in $REMOTE:/opt/fastscan/fastscan.env"
