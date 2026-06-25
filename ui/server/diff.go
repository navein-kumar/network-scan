package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
)

// diffFinding is a finding entry in a diff bucket (rule_id/title/severity/host/port).
type diffFinding struct {
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

// diffResult is the GET /api/scans/{id}/diff response shape.
type diffResult struct {
	BaselineID   string        `json:"baseline_id"`
	RescanID     string        `json:"rescan_id"`
	BaselineName string        `json:"baseline_name"`
	RescanName   string        `json:"rescan_name"`
	Counts       struct {
		Fixed     int `json:"fixed"`
		StillOpen int `json:"still_open"`
		New       int `json:"new"`
	} `json:"counts"`
	Fixed     []diffFinding `json:"fixed"`
	StillOpen []diffFinding `json:"still_open"`
	New       []diffFinding `json:"new"`
}

// findingKey identifies a finding across scans by rule, host and port.
func findingKey(f Finding) string {
	return fmt.Sprintf("%s|%s|%d", f.RuleID, f.Host, f.Port)
}

// sevRank orders severities critical(0) > high > medium > low > info(4).
func sevRank(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// sortBucket orders a bucket by severity (critical first) then host.
func sortBucket(b []diffFinding) {
	sort.SliceStable(b, func(i, j int) bool {
		if ri, rj := sevRank(b[i].Severity), sevRank(b[j].Severity); ri != rj {
			return ri < rj
		}
		return b[i].Host < b[j].Host
	})
}

// computeDiff compares baseline against rescan findings, keyed by rule|host|port.
//   fixed      = in baseline, not in rescan
//   still_open = in both
//   new        = in rescan, not in baseline
func computeDiff(baseline, rescan []Finding) (fixed, stillOpen, ne []diffFinding) {
	baseByKey := map[string]Finding{}
	for _, f := range baseline {
		baseByKey[findingKey(f)] = f
	}
	rescanByKey := map[string]Finding{}
	for _, f := range rescan {
		rescanByKey[findingKey(f)] = f
	}

	fixed = []diffFinding{}
	stillOpen = []diffFinding{}
	ne = []diffFinding{}

	for k, f := range baseByKey {
		if _, ok := rescanByKey[k]; ok {
			stillOpen = append(stillOpen, toDiffFinding(f))
		} else {
			fixed = append(fixed, toDiffFinding(f))
		}
	}
	for k, f := range rescanByKey {
		if _, ok := baseByKey[k]; !ok {
			ne = append(ne, toDiffFinding(f))
		}
	}

	sortBucket(fixed)
	sortBucket(stillOpen)
	sortBucket(ne)
	return fixed, stillOpen, ne
}

func toDiffFinding(f Finding) diffFinding {
	return diffFinding{
		RuleID:   f.RuleID,
		Title:    f.Title,
		Severity: f.Severity,
		Host:     f.Host,
		Port:     f.Port,
	}
}

// handleDiff serves GET /api/scans/{id}/diff?baseline={baselineId}.
// id is the newer (rescan) scan; baseline is the older scan to compare against.
func (srv *Server) handleDiff(w http.ResponseWriter, r *http.Request, rescan *Scan) {
	baselineID := r.URL.Query().Get("baseline")
	if baselineID == "" {
		writeErr(w, http.StatusBadRequest, "baseline query parameter is required")
		return
	}
	if baselineID == rescan.Status.ID {
		writeErr(w, http.StatusBadRequest, "baseline and rescan must be different scans")
		return
	}
	baseline, found := srv.store.get(baselineID)
	if !found {
		writeErr(w, http.StatusNotFound, "baseline scan not found")
		return
	}

	baselineFindings := readFindings(filepath.Join(baseline.dir, "findings.ndjson"))
	rescanFindings := readFindings(filepath.Join(rescan.dir, "findings.ndjson"))

	fixed, stillOpen, ne := computeDiff(baselineFindings, rescanFindings)

	var out diffResult
	out.BaselineID = baseline.Status.ID
	out.RescanID = rescan.Status.ID
	baseline.mu.Lock()
	out.BaselineName = baseline.Status.Name
	baseline.mu.Unlock()
	rescan.mu.Lock()
	out.RescanName = rescan.Status.Name
	rescan.mu.Unlock()
	out.Fixed = fixed
	out.StillOpen = stillOpen
	out.New = ne
	out.Counts.Fixed = len(fixed)
	out.Counts.StillOpen = len(stillOpen)
	out.Counts.New = len(ne)

	writeJSONResp(w, http.StatusOK, out)
}
