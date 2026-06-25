#!/usr/bin/env bash
# Build fastscan-ui: frontend (Vite) then embed into the Go server binary.
set -e
cd "$(dirname "$0")"

# The server needs Go 1.20+ (uses strings.CutPrefix). Prefer a modern Go at
# /usr/local/go; fall back to whatever "go" is on PATH.
GO=go
if [ -x /usr/local/go/bin/go ]; then GO=/usr/local/go/bin/go; fi

echo '[1/3] building frontend'
( cd web && npm install && npm run build )
echo '[2/3] embedding frontend into server'
rm -rf server/static && cp -r web/dist server/static
echo '[3/3] building server binary'
( cd server && "$GO" build -o ../fastscan-ui . )
echo 'done -> ./fastscan-ui   (run: ./fastscan-ui -addr 0.0.0.0:8888 -data ./data -auth user:pass)'
