package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// enginePath is the scan engine binary. Derived from engineRoot (meta.go).
var enginePath = filepath.Join(engineRoot, "fastscan")

// phasePercent maps engine phase labels to an overall progress percentage.
var phasePercent = map[string]int{
	"1":    5,
	"1b":   5,
	"2":    15,
	"2.4":  22,
	"2.5":  30,
	"2.6":  45,
	"2.6b": 55,
	"2.7":  65,
	"2.8":  70,
	"2.9":  75,
	"2.95": 80,
	"3":    88,
	"4":    95,
}

// hostPhasePercent maps phase labels to a per-host progress percentage.
var hostPhasePercent = map[string]int{
	"1":    8,
	"1b":   15,
	"2":    25,
	"2.4":  35,
	"2.5":  45,
	"2.6":  55,
	"2.6b": 60,
	"2.7":  65,
	"2.8":  70,
	"2.9":  75,
	"2.95": 80,
	"3":    88,
	"4":    95,
}

var (
	phaseRe         = regexp.MustCompile(`\[phase ([0-9.b]+)\]`)
	hostRe          = regexp.MustCompile(`\[host=([0-9a-fA-F.:]+)\]`)
	newHostRe       = regexp.MustCompile(`\[phase 1\] (?:rustscan|nmap) (\S+)`)
	phase4SummaryRe = regexp.MustCompile(`\[phase 4\]\s+(?:\d+|done)`)
)

// hostProgStat tracks per-host progress state during a scan.
type hostProgStat struct {
	phase   string
	percent int
	done    bool
}

// startScan creates the scan directory, persists the config, registers the scan
// and spawns the engine. It returns immediately with the scan in "running"
// state.
func (srv *Server) startScan(cfg Config) (*Scan, error) {
	id := newScanID()
	dir := filepath.Join(srv.store.dataDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create scan dir: %w", err)
	}

	sc := &Scan{
		dir: dir,
		Status: Status{
			ID:         id,
			Name:       cfg.Name,
			State:      "running",
			Progress:   0,
			Started:    nowRFC3339(),
			HostsTotal: countTargets(cfg.Targets),
			Config:     cfg,
		},
	}

	if b, err := json.MarshalIndent(cfg, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "config.json"), b, 0o644)
	}
	_ = os.WriteFile(filepath.Join(dir, "targets.txt"), []byte(strings.ReplaceAll(cfg.Targets, ",", "\n")+"\n"), 0o644)

	srv.store.add(sc)
	sc.save()

	go srv.runEngine(sc, cfg)
	return sc, nil
}

// countTargets returns the number of non-empty, non-comment lines in a
// comma-or-newline-separated target string.
func countTargets(targets string) int {
	n := 0
	for _, t := range strings.Split(strings.ReplaceAll(targets, ",", "\n"), "\n") {
		t = strings.TrimSpace(t)
		if t != "" && !strings.HasPrefix(t, "#") {
			n++
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

// engineArgs builds the engine command line from a config.
func engineArgs(cfg Config, dir string) []string {
	args := []string{
		"-target-file", filepath.Join(dir, "targets.txt"),
		"-out", dir,
		"-plugins", filepath.Join(engineRoot, "plugins"),
	}
	switch cfg.Template {
	case "fast":
		args = append(args, "-profile", "fast")
	case "deep":
		args = append(args, "-deep")
	}
	if cfg.Ports != "" {
		args = append(args, "-ports", cfg.Ports)
	}
	if cfg.UDPPorts != "" {
		args = append(args, "-udp-ports", cfg.UDPPorts)
	}
	if cfg.SkipUDP {
		args = append(args, "-skip-udp")
	}
	if cfg.SkipNuclei {
		args = append(args, "-skip-nuclei")
	}
	if cfg.MaxHosts > 0 {
		args = append(args, "-max-hosts", fmt.Sprintf("%d", cfg.MaxHosts))
	}
	if cfg.NmapIntensity > 0 {
		args = append(args, "-nmap-intensity", fmt.Sprintf("%d", cfg.NmapIntensity))
	}
	if cfg.ForceService != "" {
		args = append(args, "-force-service", cfg.ForceService)
	}
	return args
}

// runEngine executes the engine, tails its progress and finalizes status.
func (srv *Server) runEngine(sc *Scan, cfg Config) {
	dir := sc.dir
	logPath := filepath.Join(dir, "stderr.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		srv.finishScan(sc, "error")
		return
	}

	cmd := exec.Command(enginePath, engineArgs(cfg, dir)...)
	cmd.Dir = engineRoot
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		srv.finishScan(sc, "error")
		return
	}

	sc.mu.Lock()
	sc.cmd = cmd
	sc.mu.Unlock()

	done := make(chan struct{})
	go func() {
		srv.tailProgress(sc, logPath, done)
	}()

	waitErr := cmd.Wait()
	close(done)
	logFile.Close()

	sc.mu.Lock()
	sc.cmd = nil
	sc.mu.Unlock()

	state := "done"
	if waitErr != nil {
		if _, ok := waitErr.(*exec.ExitError); ok {
			state = "error"
		} else {
			state = "error"
		}
	}
	srv.finishScan(sc, state)
}

// tailProgress follows stderr.log, mapping phase/host lines to progress, until
// done is closed. It maintains per-host progress state across ticks.
func (srv *Server) tailProgress(sc *Scan, logPath string, done chan struct{}) {
	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()
	var offset int64
	currentHost := ""
	hstats := map[string]*hostProgStat{}
	for {
		select {
		case <-done:
			srv.scanProgress(sc, logPath, &offset, &currentHost, hstats)
			return
		case <-ticker.C:
			srv.scanProgress(sc, logPath, &offset, &currentHost, hstats)
		}
	}
}

// scanProgress reads new bytes from logPath and updates monotonic progress,
// including per-host state.
func (srv *Server) scanProgress(sc *Scan, logPath string, offset *int64, currentHost *string, hstats map[string]*hostProgStat) {
	f, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(*offset, 0); err != nil {
		return
	}

	hosts := map[string]bool{}
	maxPct := 0

	const maxBuf = 8 * 1024 * 1024
	buf := make([]byte, maxBuf)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(buf, maxBuf)

	for scanner.Scan() {
		line := scanner.Text()
		*offset += int64(len(line)) + 1

		if m := newHostRe.FindStringSubmatch(line); m != nil {
			h := m[1]
			*currentHost = h
			if _, exists := hstats[h]; !exists {
				hstats[h] = &hostProgStat{phase: "1", percent: 8, done: false}
			}
		}

		if m := phaseRe.FindStringSubmatch(line); m != nil {
			phaseTag := m[1]
			if p, ok := phasePercent[phaseTag]; ok && p > maxPct {
				maxPct = p
			}
			if *currentHost != "" {
				if hs, ok := hstats[*currentHost]; ok && !hs.done {
					if hp, ok2 := hostPhasePercent[phaseTag]; ok2 {
						hs.phase = phaseTag
						hs.percent = hp
					}
				}
			}
			if phaseTag == "4" && phase4SummaryRe.MatchString(line) {
				if *currentHost != "" {
					if hs, ok := hstats[*currentHost]; ok {
						hs.phase = "4"
						hs.percent = 100
						hs.done = true
					}
				}
			}
		}

		if m := hostRe.FindStringSubmatch(line); m != nil {
			hosts[m[1]] = true
		}
	}

	hostStatsList := make([]HostStat, 0, len(hstats))
	for h, hs := range hstats {
		st := "running"
		if hs.done {
			st = "done"
		}
		hostStatsList = append(hostStatsList, HostStat{
			Host:    h,
			Phase:   hs.phase,
			Percent: hs.percent,
			Status:  st,
		})
	}

	sc.mu.Lock()
	if sc.Status.State == "running" {
		if maxPct > sc.Status.Progress {
			sc.Status.Progress = maxPct
		}
		if len(hosts) > sc.Status.HostsDone {
			sc.Status.HostsDone = len(hosts)
		}
		if len(hostStatsList) > 0 {
			sc.Status.HostStats = hostStatsList
		}
	}
	sc.mu.Unlock()
	sc.save()
}

// finishScan recomputes counts from findings.ndjson and persists the terminal
// state.
func (srv *Server) finishScan(sc *Scan, state string) {
	findingsPath := filepath.Join(sc.dir, "findings.ndjson")
	hostCount, findingCount, rulesFired, sev := computeCounts(findingsPath)

	sc.mu.Lock()
	if sc.Status.State != "running" && sc.Status.State != "paused" {
		sc.mu.Unlock()
		return
	}
	sc.Status.State = state
	if state == "done" {
		sc.Status.Progress = 100
	}
	sc.Status.Finished = nowRFC3339()
	sc.Status.HostCount = hostCount
	sc.Status.FindingCount = findingCount
	sc.Status.RulesFired = rulesFired
	sc.Status.Severity = sev
	if hostCount > 0 {
		sc.Status.HostsTotal = hostCount
		sc.Status.HostsDone = hostCount
	}
	sc.mu.Unlock()
	sc.save()
}

// progressEvent is the SSE progress payload.
type progressEvent struct {
	Hosts      []HostStat `json:"hosts"`
	HostsDone  int        `json:"hosts_done"`
	HostsTotal int        `json:"hosts_total"`
	Overall    int        `json:"overall"`
}

// doneEvent is the SSE terminal payload.
type doneEvent struct {
	Severity Severity `json:"severity"`
	State    string   `json:"status"`
}

// handleStream serves GET /api/scans/{id}/stream as Server-Sent Events.
func (srv *Server) handleStream(w http.ResponseWriter, r *http.Request, sc *Scan) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	logPath := filepath.Join(sc.dir, "stderr.log")
	var logOffset int64

	emitLogs := func() {
		f, err := os.Open(logPath)
		if err != nil {
			return
		}
		defer f.Close()
		if _, err := f.Seek(logOffset, 0); err != nil {
			return
		}
		const maxBuf = 8 * 1024 * 1024
		buf := make([]byte, maxBuf)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(buf, maxBuf)
		for scanner.Scan() {
			line := scanner.Text()
			logOffset += int64(len(line)) + 1
			if len(line) > 400 {
				line = line[:400]
			}
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", mustJSON(map[string]string{"line": line}))
		}
		flusher.Flush()
	}

	emitProgress := func() bool {
		sc.mu.Lock()
		st := sc.Status
		sc.mu.Unlock()

		hostStats := st.HostStats
		if hostStats == nil {
			hostStats = []HostStat{}
		}

		fmt.Fprintf(w, "event: progress\ndata: %s\n\n", mustJSON(progressEvent{
			Hosts:      hostStats,
			HostsDone:  st.HostsDone,
			HostsTotal: st.HostsTotal,
			Overall:    st.Progress,
		}))
		flusher.Flush()

		if st.State != "running" {
			fmt.Fprintf(w, "event: done\ndata: %s\n\n", mustJSON(doneEvent{
				Severity: st.Severity,
				State:    st.State,
			}))
			flusher.Flush()
			return true
		}
		return false
	}

	emitLogs()
	if emitProgress() {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			emitLogs()
			if emitProgress() {
				return
			}
		}
	}
}

// mustJSON marshals v, returning "{}" on error.
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}