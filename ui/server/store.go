package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Store is the in-memory registry of scans backed by per-scan directories on
// disk. Each scan lives in <dataDir>/<id>/ with status.json, config.json and
// findings.ndjson.
type Store struct {
	mu      sync.RWMutex
	dataDir string
	scans   map[string]*Scan
}

// NewStore creates an empty store rooted at dataDir.
func NewStore(dataDir string) *Store {
	return &Store{
		dataDir: dataDir,
		scans:   map[string]*Scan{},
	}
}

// loadFromDisk scans dataDir for scan directories and loads their status.json.
func (s *Store) loadFromDisk() {
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "scan_") {
			continue
		}
		dir := filepath.Join(s.dataDir, e.Name())
		sc := &Scan{dir: dir, Status: Status{ID: e.Name()}}
		if b, err := os.ReadFile(filepath.Join(dir, "status.json")); err == nil {
			_ = json.Unmarshal(b, &sc.Status)
		}
		if sc.Status.ID == "" {
			sc.Status.ID = e.Name()
		}
		// A scan still marked running after a restart never finished.
		if sc.Status.State == "running" || sc.Status.State == "paused" {
			sc.Status.State = "error"
		}
		s.mu.Lock()
		s.scans[sc.Status.ID] = sc
		s.mu.Unlock()
	}
}

// get returns the scan with the given id.
func (s *Store) get(id string) (*Scan, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.scans[id]
	return sc, ok
}

// add registers a scan.
func (s *Store) add(sc *Scan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans[sc.Status.ID] = sc
}

// remove deletes a scan from the registry and removes its directory.
func (s *Store) remove(id string) {
	s.mu.Lock()
	sc, ok := s.scans[id]
	if ok {
		delete(s.scans, id)
	}
	s.mu.Unlock()
	if ok && sc.dir != "" {
		_ = os.RemoveAll(sc.dir)
	}
}

// list returns all scans sorted by start time descending (newest first).
func (s *Store) list() []*Scan {
	s.mu.RLock()
	out := make([]*Scan, 0, len(s.scans))
	for _, sc := range s.scans {
		out = append(out, sc)
	}
	s.mu.RUnlock()
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Status.Started > out[j].Status.Started
	})
	return out
}

// save persists a scan's status to <dir>/status.json atomically.
func (sc *Scan) save() {
	sc.mu.Lock()
	st := sc.Status
	dir := sc.dir
	sc.mu.Unlock()
	if dir == "" {
		return
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	tmp := filepath.Join(dir, "status.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, filepath.Join(dir, "status.json"))
}
