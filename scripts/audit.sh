#!/usr/bin/env bash
# audit.sh: run gosec (SAST) + govulncheck (CVE check) over the fastscan
# Go source. Both tools are optional. If a tool is not installed, the
# script prints an install hint and skips it. At the end a one-line
# summary is printed for each tool.
#
# Usage:
#   bash scripts/audit.sh
#
# Output:
#   audit/gosec.json          (raw gosec JSON report, if gosec ran)
#   audit/govulncheck.txt     (raw govulncheck output, if govulncheck ran)

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$PROJ_DIR/audit"
mkdir -p "$OUT_DIR"

cyan()   { printf '\033[36m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

cyan "=== fastscan audit ==="
echo "Project:   $PROJ_DIR"
echo "Output:    $OUT_DIR"
echo

# ── gosec ────────────────────────────────────────────────────────────
gosec_total=""
gosec_high=""
gosec_med=""
gosec_low=""
gosec_status="skipped"
if have gosec; then
    cyan "[*] running gosec ./..."
    pushd "$PROJ_DIR" >/dev/null
    # gosec exits non-zero when issues are found; do not let that abort
    # the script.
    set +e
    gosec -quiet -fmt=json -out="$OUT_DIR/gosec.json" ./...
    gosec_rc=$?
    set -e
    popd >/dev/null
    if [ -s "$OUT_DIR/gosec.json" ]; then
        gosec_status="ran"
        if have jq; then
            gosec_total=$(jq -r '.Stats.found // (.Issues | length) // 0' "$OUT_DIR/gosec.json" 2>/dev/null || echo "?")
            gosec_high=$(jq -r '[.Issues[]? | select(.severity=="HIGH")]   | length' "$OUT_DIR/gosec.json" 2>/dev/null || echo "?")
            gosec_med=$(jq  -r '[.Issues[]? | select(.severity=="MEDIUM")] | length' "$OUT_DIR/gosec.json" 2>/dev/null || echo "?")
            gosec_low=$(jq  -r '[.Issues[]? | select(.severity=="LOW")]    | length' "$OUT_DIR/gosec.json" 2>/dev/null || echo "?")
        else
            gosec_total=$(grep -c '"severity"' "$OUT_DIR/gosec.json" || true)
            gosec_high=$(grep -c '"severity": "HIGH"'   "$OUT_DIR/gosec.json" || true)
            gosec_med=$(grep  -c '"severity": "MEDIUM"' "$OUT_DIR/gosec.json" || true)
            gosec_low=$(grep  -c '"severity": "LOW"'    "$OUT_DIR/gosec.json" || true)
        fi
        green "[+] gosec done (rc=$gosec_rc, report: $OUT_DIR/gosec.json)"
    else
        red "[!] gosec produced no report (rc=$gosec_rc)"
    fi
else
    yellow "[!] gosec not installed. Install with:"
    echo   "      go install github.com/securego/gosec/v2/cmd/gosec@latest"
fi
echo

# ── govulncheck ──────────────────────────────────────────────────────
govuln_status="skipped"
govuln_vulns=""
govuln_modules=""
if have govulncheck; then
    cyan "[*] running govulncheck ./..."
    pushd "$PROJ_DIR" >/dev/null
    set +e
    govulncheck ./... > "$OUT_DIR/govulncheck.txt" 2>&1
    govuln_rc=$?
    set -e
    popd >/dev/null
    govuln_status="ran"
    # Best-effort parse: counts lines like "Vulnerability #N: GO-YYYY-NNNN"
    govuln_vulns=$(grep -c '^Vulnerability #' "$OUT_DIR/govulncheck.txt" 2>/dev/null || echo 0)
    govuln_modules=$(grep -c '^Module: '       "$OUT_DIR/govulncheck.txt" 2>/dev/null || echo 0)
    green "[+] govulncheck done (rc=$govuln_rc, report: $OUT_DIR/govulncheck.txt)"
else
    yellow "[!] govulncheck not installed. Install with:"
    echo   "      go install golang.org/x/vuln/cmd/govulncheck@latest"
fi
echo

# ── summary ──────────────────────────────────────────────────────────
cyan "=== Summary ==="
printf "  gosec:        %-8s" "$gosec_status"
if [ "$gosec_status" = "ran" ]; then
    printf " total=%s  HIGH=%s  MEDIUM=%s  LOW=%s" \
        "${gosec_total:-?}" "${gosec_high:-?}" "${gosec_med:-?}" "${gosec_low:-?}"
fi
echo
printf "  govulncheck:  %-8s" "$govuln_status"
if [ "$govuln_status" = "ran" ]; then
    printf " vulns=%s  affected_modules=%s" \
        "${govuln_vulns:-?}" "${govuln_modules:-?}"
fi
echo
