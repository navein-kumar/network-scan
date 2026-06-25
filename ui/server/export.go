package main

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// script paths for the export bridges.
const (
	scriptXLSX     = "/root/fastscan/scripts/fastscan_to_xlsx.py"
	scriptEvidence = "/root/fastscan/scripts/fastscan_to_evidence.py"
	scriptHTML     = "/root/fastscan/scripts/fastscan_to_html.py"
	scriptTxtToImg = "/root/fastscan/scripts/txt_to_img.py"
)

// handleExport serves GET /api/scans/{id}/export?format=xlsx|evidence|bundle|html.
func (srv *Server) handleExport(w http.ResponseWriter, r *http.Request, sc *Scan) {
	switch r.URL.Query().Get("format") {
	case "xlsx":
		exportXLSX(w, sc)
	case "evidence":
		exportEvidence(w, sc)
	case "bundle":
		exportBundle(w, sc)
	case "html", "":
		exportHTML(w, sc)
	default:
		writeErr(w, http.StatusBadRequest, "unknown export format")
	}
}

// runScript invokes `python3 <script> -i <findings> -o <out>` for the bridges
// that share this signature.
func runScript(script, findings, out string) error {
	cmd := exec.Command(pythonBin(), script, "-i", findings, "-o", out)
	cmd.Dir = engineRoot
	return cmd.Run()
}

// serveFileDownload streams a file as an attachment with the given name and
// content type.
func serveFileDownload(w http.ResponseWriter, path, filename, ctype string) {
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export not available")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = io.Copy(w, f)
}

// exportXLSX runs the xlsx bridge and streams the workbook.
func exportXLSX(w http.ResponseWriter, sc *Scan) {
	findings := filepath.Join(sc.dir, "findings.ndjson")
	out := filepath.Join(sc.dir, sc.Status.ID+".xlsx")
	if err := runScript(scriptXLSX, findings, out); err != nil {
		writeErr(w, http.StatusInternalServerError, "xlsx export failed: "+err.Error())
		return
	}
	serveFileDownload(w, out, sc.Status.ID+".xlsx",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
}

// exportHTML runs the html bridge and streams the report.
func exportHTML(w http.ResponseWriter, sc *Scan) {
	findings := filepath.Join(sc.dir, "findings.ndjson")
	out := filepath.Join(sc.dir, sc.Status.ID+".html")
	if err := runScript(scriptHTML, findings, out); err != nil {
		writeErr(w, http.StatusInternalServerError, "html export failed: "+err.Error())
		return
	}
	serveFileDownload(w, out, sc.Status.ID+".html", "text/html; charset=utf-8")
}

// buildEvidenceDir runs the evidence bridge into <scanDir>/evidence, copies the
// ports report and any referenced screenshots, then renders text to images.
func buildEvidenceDir(sc *Scan) (string, error) {
	findings := filepath.Join(sc.dir, "findings.ndjson")
	evDir := filepath.Join(sc.dir, "evidence")
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		return "", err
	}
	if err := runScript(scriptEvidence, findings, evDir); err != nil {
		return "", err
	}

	// Copy ports_report.txt if present.
	if src := filepath.Join(sc.dir, "ports_report.txt"); fileExists(src) {
		copyFile(src, filepath.Join(evDir, "ports_report.txt"))
	}

	// Copy any screenshot PNGs referenced in findings.
	shotDir := filepath.Join(evDir, "screenshots")
	_ = os.MkdirAll(shotDir, 0o755)
	for _, p := range screenshotPaths(findings) {
		if fileExists(p) {
			copyFile(p, filepath.Join(shotDir, filepath.Base(p)))
		}
	}

	// Render the evidence .txt files into images/.
	cmd := exec.Command(pythonBin(), scriptTxtToImg, evDir)
	cmd.Dir = engineRoot
	_ = cmd.Run()

	return evDir, nil
}

// exportEvidence builds the evidence directory and streams it as a zip.
func exportEvidence(w http.ResponseWriter, sc *Scan) {
	evDir, err := buildEvidenceDir(sc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "evidence export failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sc.Status.ID+`_evidence.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()
	_ = addDirToZip(zw, evDir, "evidence")
}

// exportBundle streams a .fsbundle.zip of the core scan artifacts.
func exportBundle(w http.ResponseWriter, sc *Scan) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sc.Status.ID+`.fsbundle.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()

	writeBundleMeta(zw, sc)
	for _, name := range []string{"findings.ndjson", "ports_report.txt"} {
		path := filepath.Join(sc.dir, name)
		if fileExists(path) {
			_ = addFileToZip(zw, path, name)
		}
	}
	evDir := filepath.Join(sc.dir, "evidence")
	if dirExists(evDir) {
		_ = addDirToZip(zw, evDir, "evidence")
	}
}

// bundleMeta is the curated meta.json embedded in an .fsbundle.zip. It mirrors
// the scan status minus live-progress fields and carries an export timestamp.
type bundleMeta struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	State        string   `json:"status"`
	Started      string   `json:"started"`
	Finished     string   `json:"finished,omitempty"`
	HostCount    int      `json:"host_count"`
	FindingCount int      `json:"finding_count"`
	Severity     Severity `json:"severity"`
	Config       Config   `json:"config"`
	ExportedAt   string   `json:"exported_at"`
}

// writeBundleMeta writes meta.json (the curated scan status) into the bundle
// zip.
func writeBundleMeta(zw *zip.Writer, sc *Scan) {
	sc.mu.Lock()
	st := sc.Status
	sc.mu.Unlock()
	meta := bundleMeta{
		ID:           st.ID,
		Name:         st.Name,
		State:        st.State,
		Started:      st.Started,
		Finished:     st.Finished,
		HostCount:    st.HostCount,
		FindingCount: st.FindingCount,
		Severity:     st.Severity,
		Config:       st.Config,
		ExportedAt:   nowRFC3339(),
	}
	fw, err := zw.Create("meta.json")
	if err != nil {
		return
	}
	_, _ = fw.Write([]byte(mustJSON(meta)))
}

// copyFile copies src to dst (best-effort).
func copyFile(src, dst string) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer out.Close()
	_, _ = io.Copy(out, in)
}

// dirExists reports whether path is an existing directory.
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// addFileToZip adds a single file under name within the zip.
func addFileToZip(zw *zip.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fw, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(fw, f)
	return err
}

// addDirToZip recursively adds dir under prefix within the zip.
func addDirToZip(zw *zip.Writer, dir, prefix string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		name := prefix + "/" + filepath.ToSlash(rel)
		return addFileToZip(zw, path, name)
	})
}

// screenshotPaths extracts screenshot_path values referenced by findings.
func screenshotPaths(findingsPath string) []string {
	var paths []string
	seen := map[string]bool{}
	for _, e := range readEventsRaw(findingsPath) {
		meta, ok := e["meta"].(map[string]any)
		if !ok {
			continue
		}
		if sp, ok := meta["screenshot_path"].(string); ok && sp != "" && !seen[sp] {
			seen[sp] = true
			paths = append(paths, sp)
		}
	}
	return paths
}
