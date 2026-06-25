package main

import (
	"fmt"
	"net/http"
	"syscall"
)

// handleStopScan serves POST /api/scans/{id}/stop.
// Sends SIGKILL to the engine process group; marks the scan "stopped".
func (srv *Server) handleStopScan(w http.ResponseWriter, sc *Scan) {
	sc.mu.Lock()
	state := sc.Status.State
	cmd := sc.cmd
	sc.mu.Unlock()

	if state != "running" && state != "paused" {
		writeErr(w, http.StatusConflict, fmt.Sprintf("scan is %s, not running or paused", state))
		return
	}
	if cmd != nil && cmd.Process != nil {
		// Resume first if paused so the process can accept SIGKILL.
		if state == "paused" {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGCONT)
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	srv.finishScan(sc, "stopped")
	writeJSONResp(w, http.StatusOK, map[string]string{"status": "stopped"})
}

// handlePauseScan serves POST /api/scans/{id}/pause.
// Sends SIGSTOP to the engine process group; marks the scan "paused".
func (srv *Server) handlePauseScan(w http.ResponseWriter, sc *Scan) {
	sc.mu.Lock()
	state := sc.Status.State
	cmd := sc.cmd
	sc.mu.Unlock()

	if state != "running" {
		writeErr(w, http.StatusConflict, fmt.Sprintf("scan is %s, not running", state))
		return
	}
	if cmd != nil && cmd.Process != nil {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGSTOP); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not pause process: "+err.Error())
			return
		}
	}
	sc.mu.Lock()
	sc.Status.State = "paused"
	sc.mu.Unlock()
	sc.save()
	writeJSONResp(w, http.StatusOK, map[string]string{"status": "paused"})
}

// handleResumeScan serves POST /api/scans/{id}/resume.
// Sends SIGCONT to the engine process group; marks the scan "running".
func (srv *Server) handleResumeScan(w http.ResponseWriter, sc *Scan) {
	sc.mu.Lock()
	state := sc.Status.State
	cmd := sc.cmd
	sc.mu.Unlock()

	if state != "paused" {
		writeErr(w, http.StatusConflict, fmt.Sprintf("scan is %s, not paused", state))
		return
	}
	if cmd != nil && cmd.Process != nil {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGCONT); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not resume process: "+err.Error())
			return
		}
	}
	sc.mu.Lock()
	sc.Status.State = "running"
	sc.mu.Unlock()
	sc.save()
	writeJSONResp(w, http.StatusOK, map[string]string{"status": "running"})
}
