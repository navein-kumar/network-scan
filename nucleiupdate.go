// nucleiupdate.go: nuclei template freshness check.
//
// fastscan ships a copy of the projectdiscovery nuclei templates under
// -templates (default /tmp/all-tpl/). Templates ship hundreds of fresh
// CVE checks each week; running with stale templates means missed
// findings. This helper:
//
//   1. exposes UpdateNucleiTemplatesForce(): runs `nuclei
//      -update-templates -silent` and refreshes the marker file.
//   2. exposes WarnStaleTemplates(): non-fatal startup check that logs a
//      hint when the marker file is older than 7 days.
//
// Marker file: <templatesDir>/.nuclei-last-update (mtime is the only
// thing we look at).
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	nucleiMarkerFile  = ".nuclei-last-update"
	nucleiStaleAfter  = 7 * 24 * time.Hour
)

// UpdateNucleiTemplatesForce runs `nuclei -update-templates -silent`
// and writes a fresh marker file under templatesDir. Returns an error
// only when nuclei is missing or the update command fails.
func UpdateNucleiTemplatesForce(templatesDir string) error {
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		return fmt.Errorf("nuclei not in PATH: %w", err)
	}
	log.Printf("[nuclei] running %s -update-templates", bin)
	cmd := exec.Command(bin, "-update-templates", "-silent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nuclei -update-templates: %w", err)
	}
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", templatesDir, err)
	}
	marker := filepath.Join(templatesDir, nucleiMarkerFile)
	if err := os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write marker %s: %w", marker, err)
	}
	log.Printf("[nuclei] templates updated; marker %s", marker)
	return nil
}

// WarnStaleTemplates checks the marker file and logs a non-fatal hint
// when templates are missing or older than 7 days. Quiet on fresh
// templates. Safe to call from main() before the scan loop.
func WarnStaleTemplates(templatesDir string) {
	if templatesDir == "" {
		return
	}
	marker := filepath.Join(templatesDir, nucleiMarkerFile)
	info, err := os.Stat(marker)
	if err != nil {
		log.Printf("[nuclei] templates last update unknown (no %s); consider -update-templates",
			marker)
		return
	}
	age := time.Since(info.ModTime())
	if age > nucleiStaleAfter {
		log.Printf("[nuclei] templates last updated %.0f days ago; consider -update-templates",
			age.Hours()/24)
	}
}
