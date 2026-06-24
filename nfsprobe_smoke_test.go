// nfsprobe_smoke_test.go: Round 18 smoke test for ProbeNFS.
// Only runs when env FASTSCAN_NFS_TARGET=host:port is set, so it's a no-op
// in normal CI / `go test ./...`.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNFSSmoke(t *testing.T) {
	target := os.Getenv("FASTSCAN_NFS_TARGET")
	if target == "" {
		t.Skip("FASTSCAN_NFS_TARGET not set; skipping")
	}
	host, portStr, ok := strings.Cut(target, ":")
	if !ok {
		t.Fatalf("bad target %q (want host:port)", target)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("bad port %q: %v", portStr, err)
	}
	rep, err := ProbeNFS(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("ProbeNFS: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))

	// Evaluate plugin rules and print findings.
	eng, err := LoadPlugins("plugins")
	if err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	findings, err := eng.Evaluate("nfs", rep)
	if err != nil {
		t.Fatalf("Evaluate nfs: %v", err)
	}
	fmt.Fprintf(os.Stderr, "\n=== nfs rules fired: %d ===\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "FIRE %s [%s] %s\n", f.RuleID, f.Severity, f.Evidence)
	}
}
