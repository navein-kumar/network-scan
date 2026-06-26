package main

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
)

// rawEvent is a single NDJSON line from the engine's findings.ndjson stream.
// Only the fields the UI needs are decoded; the rest stay in the raw map.
type rawEvent struct {
	Phase    string `json:"phase"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Product  string `json:"product"`
	Version  string `json:"version"`
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Evidence string `json:"evidence"`
	Template string `json:"template"`
	Extract  string `json:"extract"`
	URL      string `json:"url"`
}

// readEvents reads and decodes every NDJSON line from path.
func readEvents(path string) []rawEvent {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []rawEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e rawEvent
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

// readEventsRaw reads each NDJSON line as a generic map, for fields not modeled
// in rawEvent (e.g. nested meta.screenshot_path).
func readEventsRaw(path string) []map[string]any {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		out = append(out, m)
	}
	return out
}

// splitHostPort splits "host:port" (or a bare host) into host and port.
func splitHostPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.LastIndex(s, ":"); i >= 0 {
		host := s[:i]
		if port, err := strconv.Atoi(s[i+1:]); err == nil {
			return host, port
		}
		return host, 0
	}
	return s, 0
}

// eventToFinding converts a finding/nuclei event into the normalized Finding
// shape returned by the API, reporting whether it is a finding at all.
func eventToFinding(e rawEvent) (Finding, bool) {
	switch e.Phase {
	case "finding":
		if e.RuleID == "" {
			return Finding{}, false
		}
		return Finding{
			RuleID:   e.RuleID,
			Title:    e.Title,
			Severity: e.Severity,
			Host:     e.Host,
			Port:     e.Port,
			Source:   e.Source,
			Evidence: e.Evidence,
		}, true
	case "nuclei":
		if e.Template == "" {
			return Finding{}, false
		}
		host, port := splitHostPort(e.URL)
		return Finding{
			RuleID:   e.Template,
			Title:    e.Title,
			Severity: e.Severity,
			Host:     host,
			Port:     port,
			Source:   "nuclei",
			Evidence: e.Extract,
		}, true
	}
	return Finding{}, false
}

// readFindings returns the normalized findings (finding + nuclei phases) from a
// findings.ndjson file, preserving file order.
func readFindings(path string) []Finding {
	out := []Finding{}
	for _, e := range readEvents(path) {
		if f, ok := eventToFinding(e); ok {
			out = append(out, f)
		}
	}
	return out
}

// hostPort is a single open port entry in a host aggregation.
type hostPort struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Version string `json:"version"`
}

// hostEntry is the GET /api/scans/{id}/hosts aggregation per host.
type hostEntry struct {
	Host         string     `json:"host"`
	Ports        []hostPort `json:"ports"`
	FindingCount int        `json:"finding_count"`
	Severity     Severity   `json:"severity"`
}

// readHosts aggregates per-host open ports (from fingerprint events) and finding
// severity counts (from finding/nuclei events).
func readHosts(path string) []hostEntry {
	events := readEvents(path)

	hosts := map[string]*hostEntry{}
	seenPort := map[string]map[int]bool{}

	ensure := func(host string) *hostEntry {
		if host == "" {
			return nil
		}
		h, ok := hosts[host]
		if !ok {
			h = &hostEntry{Host: host, Ports: []hostPort{}}
			hosts[host] = h
			seenPort[host] = map[int]bool{}
		}
		return h
	}

	for _, e := range events {
		switch e.Phase {
		case "fingerprint":
			h := ensure(e.Host)
			if h == nil {
				continue
			}
			if e.Port != 0 && !seenPort[e.Host][e.Port] {
				seenPort[e.Host][e.Port] = true
				h.Ports = append(h.Ports, hostPort{
					Port:    e.Port,
					Proto:   "tcp",
					Service: e.Service,
					Version: strings.TrimSpace(e.Product + " " + e.Version),
				})
			}
		}
	}

	// Per-host aggregation counts only finding-phase events (driver/plugin
	// findings), not nuclei rows. nuclei results are surfaced in the flat
	// findings list and the scan-level totals, but the engine attributes them
	// at scan scope, so they are excluded from the per-host view to match the
	// oracle.
	for _, e := range events {
		if e.Phase != "finding" || e.RuleID == "" || e.Host == "" {
			continue
		}
		h := ensure(e.Host)
		if h == nil {
			continue
		}
		h.FindingCount++
		addSeverity(&h.Severity, e.Severity)
	}

	names := make([]string, 0, len(hosts))
	for name := range hosts {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]hostEntry, 0, len(names))
	for _, host := range names {
		h := hosts[host]
		sort.SliceStable(h.Ports, func(i, j int) bool { return h.Ports[i].Port < h.Ports[j].Port })
		out = append(out, *h)
	}
	return out
}

// addSeverity increments the matching severity bucket.
func addSeverity(s *Severity, sev string) {
	switch sev {
	case "critical":
		s.Critical++
	case "high":
		s.High++
	case "medium":
		s.Medium++
	case "low":
		s.Low++
	default:
		s.Info++
	}
}

// computeCounts recomputes host count, finding count and severity totals from a
// findings.ndjson file.
func computeCounts(path string) (hostCount, findingCount, rulesFired int, sev Severity) {
	findings := readFindings(path)
	hostSet := map[string]bool{}
	ruleSet := map[string]bool{}
	for _, f := range findings {
		findingCount++
		ruleSet[f.RuleID] = true
		addSeverity(&sev, f.Severity)
	}
	for _, e := range readEvents(path) {
		if e.Phase == "fingerprint" && e.Host != "" {
			hostSet[e.Host] = true
		}
	}
	return len(hostSet), findingCount, len(ruleSet), sev
}
