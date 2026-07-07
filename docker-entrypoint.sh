#!/bin/sh
# Starts the fastscan UI server using environment variables for configuration.
# Override any variable in docker-compose.yml or with -e flags.
exec /opt/fastscan/ui/fastscan-ui \
  -addr  "${UI_ADDR:-0.0.0.0:8888}" \
  -data  "${UI_DATA_DIR:-/data}" \
  -auth  "${UI_USER:-admin}:${UI_PASS:-NetworkScan@2026}"
