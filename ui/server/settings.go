package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// Settings is the persisted global default scan configuration, served by
// GET/PUT /api/settings and stored at <dataDir>/settings.json.
type Settings struct {
	Ports      string `json:"ports"`
	UDPPorts   string `json:"udp_ports"`
	SkipUDP    bool   `json:"skip_udp"`
	SkipNuclei bool   `json:"skip_nuclei"`
	MaxHosts   int    `json:"max_hosts"`
	Template   string `json:"template"`
}

// defaultSettings returns the builtin defaults.
func defaultSettings() Settings {
	return Settings{
		Ports:      "",
		UDPPorts:   "",
		SkipUDP:    false,
		SkipNuclei: false,
		MaxHosts:   0,
		Template:   "standard",
	}
}

// validTemplates are the accepted template values.
var validTemplates = map[string]bool{"fast": true, "standard": true, "deep": true}

// SettingsStore persists Settings to disk with a mutex and atomic writes.
type SettingsStore struct {
	mu   sync.Mutex
	path string
	cur  Settings
}

// NewSettingsStore loads settings.json from dataDir, falling back to defaults.
func NewSettingsStore(dataDir string) *SettingsStore {
	s := &SettingsStore{
		path: filepath.Join(dataDir, "settings.json"),
		cur:  defaultSettings(),
	}
	if b, err := os.ReadFile(s.path); err == nil {
		var loaded Settings
		if json.Unmarshal(b, &loaded) == nil {
			s.cur = sanitizeSettings(loaded)
		}
	}
	return s
}

// get returns a copy of the current settings.
func (s *SettingsStore) get() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// put sanitizes and persists new settings atomically, returning the stored copy.
func (s *SettingsStore) put(in Settings) Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = sanitizeSettings(in)
	if b, err := json.MarshalIndent(s.cur, "", "  "); err == nil {
		tmp := s.path + ".tmp"
		if os.WriteFile(tmp, b, 0o644) == nil {
			_ = os.Rename(tmp, s.path)
		}
	}
	return s.cur
}

// sanitizeSettings clamps invalid values to safe defaults.
func sanitizeSettings(in Settings) Settings {
	if in.MaxHosts < 0 {
		in.MaxHosts = 0
	}
	if !validTemplates[in.Template] {
		in.Template = "standard"
	}
	return in
}

// handleGetSettings serves GET /api/settings.
func (srv *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSONResp(w, http.StatusOK, srv.settings.get())
}

// handlePutSettings serves PUT /api/settings.
func (srv *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid settings body")
		return
	}
	writeJSONResp(w, http.StatusOK, srv.settings.put(in))
}
