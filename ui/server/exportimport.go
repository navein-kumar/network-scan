package main

import (
	"archive/zip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleImportScan serves POST /api/scans/import: it unpacks an uploaded
// .fsbundle.zip into a new scan directory and registers it.
func (srv *Server) handleImportScan(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "file field is required")
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "fsbundle-*.zip")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot buffer upload")
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		writeErr(w, http.StatusInternalServerError, "cannot read upload")
		return
	}
	tmp.Close()

	id := newScanID()
	dir := filepath.Join(srv.store.dataDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot create scan dir")
		return
	}
	if err := unzipInto(tmpPath, dir); err != nil {
		_ = os.RemoveAll(dir)
		writeErr(w, http.StatusBadRequest, "invalid bundle: "+err.Error())
		return
	}

	sc := &Scan{dir: dir, Status: Status{ID: id, State: "imported"}}
	loadImportedStatus(sc)
	srv.store.add(sc)
	sc.save()

	writeJSONResp(w, http.StatusOK, map[string]string{"id": id, "status": "imported"})
}

// loadImportedStatus reconstructs scan status from a bundle's meta.json (if
// present) and recomputes counts from findings.ndjson.
func loadImportedStatus(sc *Scan) {
	if b, err := os.ReadFile(filepath.Join(sc.dir, "meta.json")); err == nil {
		var meta Status
		if json.Unmarshal(b, &meta) == nil {
			sc.Status.Name = meta.Name
			sc.Status.Started = meta.Started
			sc.Status.Finished = meta.Finished
			sc.Status.Config = meta.Config
		}
	}
	name := strings.TrimSpace(sc.Status.Name)
	if name == "" {
		name = "scan"
	}
	sc.Status.Name = name + " (imported)"
	sc.Status.Config.Name = sc.Status.Name

	hostCount, findingCount, rulesFired, sev := computeCounts(filepath.Join(sc.dir, "findings.ndjson"))
	sc.Status.HostCount = hostCount
	sc.Status.FindingCount = findingCount
	sc.Status.RulesFired = rulesFired
	sc.Status.Severity = sev
	sc.Status.HostsTotal = hostCount
	sc.Status.HostsDone = hostCount
	sc.Status.Progress = 100
	if sc.Status.Started == "" {
		sc.Status.Started = nowRFC3339()
	}
	if sc.Status.Finished == "" {
		sc.Status.Finished = nowRFC3339()
	}
}

// unzipInto extracts a zip into dir with a zip-slip guard.
func unzipInto(zipPath, dir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	dest := filepath.Clean(dir)
	for _, f := range zr.File {
		target := filepath.Join(dest, filepath.FromSlash(f.Name))
		// zip-slip guard: the resolved path must stay within dest.
		if target != dest && !strings.HasPrefix(target, dest+string(os.PathSeparator)) {
			return os.ErrPermission
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := extractOne(f, target); err != nil {
			return err
		}
	}
	return nil
}

// extractOne writes a single zip entry to target.
func extractOne(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}

// evidenceForRule serves GET /api/scans/{id}/evidence/{ruleId}: it runs the
// evidence bridge and returns the per-rule .txt as plain text.
func evidenceForRule(w http.ResponseWriter, sc *Scan, ruleID string) {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		writeErr(w, http.StatusBadRequest, "rule id required")
		return
	}
	evDir := filepath.Join(sc.dir, "evidence")
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot create evidence dir")
		return
	}
	findings := filepath.Join(sc.dir, "findings.ndjson")
	txtPath := filepath.Join(evDir, safeRuleFilename(ruleID)+".txt")
	if !fileExists(txtPath) {
		if err := runScript(scriptEvidence, findings, evDir); err != nil {
			writeErr(w, http.StatusInternalServerError, "evidence bridge failed: "+err.Error())
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !streamFile(w, txtPath) {
		writeErr(w, http.StatusNotFound, "no evidence for rule")
	}
}

// safeRuleFilename mirrors the bridge's safe_filename:
// re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:64] -- collapse runs of disallowed
// characters to a single underscore, then truncate to 64 bytes.
func safeRuleFilename(ruleID string) string {
	var b strings.Builder
	prevRepl := false
	for _, r := range ruleID {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		if allowed {
			b.WriteRune(r)
			prevRepl = false
		} else if !prevRepl {
			b.WriteByte('_')
			prevRepl = true
		}
	}
	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
