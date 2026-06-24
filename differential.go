// differential.go: baseline / differential scanning support.
//
// Two flags:
//
//   -save-baseline <path>     after the scan, dump a normalized snapshot
//                             of every finding (rule_id + host + port).
//                             Replaces any existing file.
//
//   -diff-against <path>      load baseline at startup. Findings that
//                             match a baseline entry get re-emitted with
//                             phase=baseline-existing. Brand-new findings
//                             keep phase=finding so the operator can
//                             focus on what changed.
//
// Key derivation: sha256(rule_id|host|port). Stable across scans.
//
// Implementation: a `baseline` wrapper sits inside the writer. The
// writer routes every finding through it before serialization. The
// baseline file is plain NDJSON (one BaselineEntry per line).
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
)

// BaselineEntry is one normalized snapshot row.
type BaselineEntry struct {
	Key     string `json:"key"`     // sha256 of rule_id|host|port
	RuleID  string `json:"rule_id"`
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title,omitempty"`
}

// Baseline holds the loaded baseline keys (for -diff-against) and the
// live accumulator for -save-baseline.
type Baseline struct {
	mu       sync.Mutex
	loaded   map[string]BaselineEntry // populated by Load
	current  []BaselineEntry          // populated as findings stream in
}

// LoadBaseline reads the NDJSON baseline file. Returns an empty
// Baseline when path is empty.
func LoadBaseline(path string) (*Baseline, error) {
	b := &Baseline{loaded: map[string]BaselineEntry{}}
	if path == "" {
		return b, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline %s: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e BaselineEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if e.Key == "" {
			e.Key = baselineKey(e.RuleID, e.Host, e.Port)
		}
		b.loaded[e.Key] = e
	}
	return b, sc.Err()
}

// baselineKey returns the deterministic key for a finding.
func baselineKey(ruleID, host string, port int) string {
	h := sha256.Sum256([]byte(ruleID + "|" + host + "|" + strconv.Itoa(port)))
	return hex.EncodeToString(h[:])
}

// Classify takes one finding and reports whether it's new, plus the
// existing baseline entry (when matched).
func (b *Baseline) Classify(f PluginFinding) (isNew bool, existing BaselineEntry) {
	key := baselineKey(f.RuleID, f.Host, f.Port)
	if b == nil || len(b.loaded) == 0 {
		return true, BaselineEntry{}
	}
	e, ok := b.loaded[key]
	if !ok {
		return true, BaselineEntry{}
	}
	return false, e
}

// Record appends the finding to the in-memory current snapshot.
func (b *Baseline) Record(f PluginFinding) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.current = append(b.current, BaselineEntry{
		Key:      baselineKey(f.RuleID, f.Host, f.Port),
		RuleID:   f.RuleID,
		Host:     f.Host,
		Port:     f.Port,
		Severity: f.Severity,
		Title:    f.Title,
	})
}

// Save writes the in-memory snapshot to path as NDJSON.
func (b *Baseline) Save(path string) error {
	if b == nil || path == "" {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create baseline %s: %w", path, err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, e := range b.current {
		b, _ := json.Marshal(e)
		w.Write(b)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// LoadedCount returns the number of entries loaded from the baseline.
func (b *Baseline) LoadedCount() int {
	if b == nil {
		return 0
	}
	return len(b.loaded)
}
