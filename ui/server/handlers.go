package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// newScanID returns a unique scan id of the form scan_<unixsec>_<4hex>.
func newScanID() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("scan_%d_%04x", time.Now().Unix(), b)
}

// nowRFC3339 returns the current UTC time formatted as RFC3339 (Z-suffixed).
func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// handleCreateScan serves POST /api/scans: it validates and starts a new scan.
func (srv *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.Targets = strings.TrimSpace(cfg.Targets)
	if cfg.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if cfg.Targets == "" {
		writeErr(w, http.StatusBadRequest, "targets is required")
		return
	}
	if cfg.Template == "" {
		cfg.Template = "standard"
	}

	sc, err := srv.startScan(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]string{"id": sc.Status.ID, "status": "running"})
}

// handleListScans serves GET /api/scans.
func (srv *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans := srv.store.list()
	out := make([]listItem, 0, len(scans))
	for _, sc := range scans {
		sc.mu.Lock()
		out = append(out, sc.Status.toListItem())
		sc.mu.Unlock()
	}
	writeJSONResp(w, http.StatusOK, out)
}

// handleGetScan serves GET /api/scans/{id}.
func (srv *Server) handleGetScan(w http.ResponseWriter, sc *Scan) {
	sc.mu.Lock()
	st := sc.Status
	sc.mu.Unlock()
	writeJSONResp(w, http.StatusOK, st)
}

// handleDeleteScan serves DELETE /api/scans/{id}.
func (srv *Server) handleDeleteScan(w http.ResponseWriter, sc *Scan) {
	srv.store.remove(sc.Status.ID)
	writeJSONResp(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleFindings serves GET /api/scans/{id}/findings.
func (srv *Server) handleFindings(w http.ResponseWriter, sc *Scan) {
	findings := readFindings(filepath.Join(sc.dir, "findings.ndjson"))
	writeJSONResp(w, http.StatusOK, findings)
}

// handleHosts serves GET /api/scans/{id}/hosts.
func (srv *Server) handleHosts(w http.ResponseWriter, sc *Scan) {
	hosts := readHosts(filepath.Join(sc.dir, "findings.ndjson"))
	writeJSONResp(w, http.StatusOK, hosts)
}

// handleRescan serves POST /api/scans/{id}/rescan: clone the stored config and
// start a fresh scan, returning the new id and the baseline (original) id.
func (srv *Server) handleRescan(w http.ResponseWriter, sc *Scan) {
	sc.mu.Lock()
	cfg := sc.Status.Config
	origID := sc.Status.ID
	sc.mu.Unlock()

	if cfg.Name == "" {
		cfg.Name = origID
	}
	cfg.Name = cfg.Name + " (rescan)"

	newScan, err := srv.startScan(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]string{
		"id":       newScan.Status.ID,
		"status":   "running",
		"baseline": origID,
	})
}
