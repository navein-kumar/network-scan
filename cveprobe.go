// cveprobe.go: CPE → CVE lookup via ProjectDiscovery's `cvemap` CLI.
//
// Phase 2.6b runs after nmap fingerprint (Phase 2) and the protocol
// drivers (Phase 2.5). We collect every unique CPE for the host
// (nmap-attached CPEs + any driver-extracted version strings the
// drivers convert into CPEs) and call:
//
//   cvemap -cpe <cpe> -silent -json
//
// for each. The JSON cvemap returns is an array of CVE objects; we map
// the ones we care about into CVEEntry. Missing binary → ProbeError
// with install hint; scan continues without CVE coverage.
package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// CVEReport is one cvemap run for one host:port (one CPE per query but
// the report aggregates multiple CPEs).
type CVEReport struct {
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	CPE         string     `json:"cpe,omitempty"`
	CVEs        []CVEEntry `json:"cves,omitempty"`
	MaxSeverity string     `json:"max_severity,omitempty"`
	ProbeErrors []string   `json:"probe_errors,omitempty"`
}

// CVEEntry is one cvemap result row, narrowed to fields the plugin
// rules consume.
type CVEEntry struct {
	ID           string   `json:"id"`
	Severity     string   `json:"severity,omitempty"`
	CVSS         float64  `json:"cvss,omitempty"`
	EPSS         float64  `json:"epss,omitempty"`
	Description  string   `json:"description,omitempty"`
	References   []string `json:"references,omitempty"`
	IsExploited  bool     `json:"is_exploited,omitempty"`
}

// cvemapRaw matches the cvemap -json shape. Field names follow what
// cvemap actually emits as of mid-2024; tags are tolerant to upstream
// schema drift via the "json:" fallbacks.
type cvemapRaw struct {
	CVEID       string  `json:"cve_id"`
	Description string  `json:"cve_description"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	EPSS        struct {
		Score float64 `json:"epss_score"`
	} `json:"epss"`
	References  []string `json:"reference"`
	IsExploited bool     `json:"is_exploited"`
	IsKev       bool     `json:"is_kev"`
}

// cvemapBinary returns the resolved path to cvemap, or "".
func cvemapBinary() string {
	if p, err := exec.LookPath("cvemap"); err == nil {
		return p
	}
	return ""
}

// ProbeCVE shells out to cvemap once per CPE and aggregates results.
// Returns a report with empty CVEs when no CPEs were resolvable or the
// binary is missing. host/port are stamped into the report for the
// NDJSON output; pass empty / 0 for the standalone -cve-test path.
func ProbeCVE(host string, port int, cpes []string, timeout time.Duration) (*CVEReport, error) {
	rep := &CVEReport{Host: host, Port: port}

	bin := cvemapBinary()
	if bin == "" {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"cvemap not in PATH (install hint: go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest)")
		return rep, nil
	}

	// Deduplicate the CPE list. cvemap accepts cpe2.3 syntax too.
	seen := map[string]bool{}
	var unique []string
	for _, c := range cpes {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		unique = append(unique, c)
	}
	if len(unique) == 0 {
		return rep, nil
	}
	// Stash first CPE for evidence templates.
	rep.CPE = unique[0]

	for _, cpe := range unique {
		entries, err := cvemapLookup(bin, cpe, timeout)
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("cvemap %s: %v", cpe, err))
			continue
		}
		rep.CVEs = append(rep.CVEs, entries...)
	}
	// Deduplicate by CVE id (one CVE often matches multiple CPE variants).
	rep.CVEs = dedupCVEs(rep.CVEs)
	rep.MaxSeverity = maxSeverity(rep.CVEs)
	return rep, nil
}

// cvemapLookup runs one cvemap query and returns the parsed entries.
func cvemapLookup(bin, cpe string, timeout time.Duration) ([]CVEEntry, error) {
	args := []string{"-cpe", cpe, "-silent", "-json"}
	cmd := exec.Command(bin, args...)
	wall := timeout
	if wall < 15*time.Second {
		wall = 15 * time.Second
	}
	timer := time.AfterFunc(wall, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	defer timer.Stop()
	out, err := cmd.Output()
	if err != nil {
		// cvemap returns non-zero on "no results". Empty output is fine.
		if len(out) == 0 {
			return nil, nil
		}
	}
	// cvemap -json emits one JSON object per line (NDJSON-ish) or a
	// single JSON array depending on version. Handle both.
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	var raws []cvemapRaw
	if strings.HasPrefix(trimmed, "[") {
		if jerr := json.Unmarshal([]byte(trimmed), &raws); jerr != nil {
			return nil, fmt.Errorf("parse array: %w", jerr)
		}
	} else {
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}
			var r cvemapRaw
			if jerr := json.Unmarshal([]byte(line), &r); jerr != nil {
				continue
			}
			raws = append(raws, r)
		}
	}
	out2 := make([]CVEEntry, 0, len(raws))
	for _, r := range raws {
		if r.CVEID == "" {
			continue
		}
		out2 = append(out2, CVEEntry{
			ID:          r.CVEID,
			Severity:    strings.ToLower(r.Severity),
			CVSS:        r.CVSSScore,
			EPSS:        r.EPSS.Score,
			Description: r.Description,
			References:  r.References,
			IsExploited: r.IsExploited || r.IsKev,
		})
	}
	return out2, nil
}

// dedupCVEs collapses duplicate CVE ids, keeping the row with the
// highest CVSS.
func dedupCVEs(in []CVEEntry) []CVEEntry {
	if len(in) <= 1 {
		return in
	}
	byID := map[string]CVEEntry{}
	for _, e := range in {
		prev, ok := byID[e.ID]
		if !ok || e.CVSS > prev.CVSS {
			byID[e.ID] = e
		}
	}
	out := make([]CVEEntry, 0, len(byID))
	for _, v := range byID {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CVSS > out[j].CVSS
	})
	return out
}

// maxSeverity returns the highest-severity label in the list.
// Tiers: critical > high > medium > low > info.
func maxSeverity(cves []CVEEntry) string {
	rank := map[string]int{
		"critical": 5, "high": 4, "medium": 3, "moderate": 3,
		"low": 2, "info": 1, "informational": 1,
	}
	best, bestRank := "", 0
	for _, c := range cves {
		s := strings.ToLower(c.Severity)
		if r, ok := rank[s]; ok && r > bestRank {
			best, bestRank = s, r
		}
	}
	if best == "moderate" {
		return "medium"
	}
	return best
}

// collectCPEsForHost returns the union of nmap-attached CPEs across all
// ports of the host, plus driver-derived CPEs (currently a no-op; the
// drivers do not expose CPEs yet, but we leave the hook for future).
func collectCPEsForHost(ports []*Port, host string, _ map[string][]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ports {
		if p.Host != host {
			continue
		}
		for _, c := range p.CPE {
			c = normalizeCPE(c)
			if c == "" || seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// normalizeCPE strips the "a:" prefix variations and returns a stable
// form. Empty string means we should not query this CPE (too generic).
func normalizeCPE(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	// cvemap accepts both cpe:/a:vendor:product:version and the
	// cpe:2.3:a:vendor:product:version:* form. We pass through.
	if !strings.HasPrefix(c, "cpe:") {
		return ""
	}
	// Skip cpe entries that have no version pinned (just vendor:product).
	// Those return huge lists from cvemap and most are irrelevant.
	parts := strings.Split(c, ":")
	// cpe:/a:vendor:product:version → 5 parts.
	// cpe:2.3:a:vendor:product:version:... → 6+ parts.
	if len(parts) < 5 {
		return ""
	}
	// version slot (index 4 for /a: style, 5 for 2.3 style).
	versionSlot := 4
	if strings.HasPrefix(c, "cpe:2.3:") {
		versionSlot = 5
	}
	if len(parts) <= versionSlot || parts[versionSlot] == "" || parts[versionSlot] == "-" || parts[versionSlot] == "*" {
		return ""
	}
	return c
}
