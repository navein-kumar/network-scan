package main

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// engineRoot is the working directory of the scan engine; driver and plugin
// counts are derived from it. Computed at startup from the UI binary's own
// location: UI binary lives at <repo>/ui/fastscan-ui, engine root is <repo>/.
var engineRoot = func() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Dir(os.Args[0])
	}
	// Resolve symlinks in case the binary was invoked through one.
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	// /opt/fastscan/fastscan-ui  →  Dir = /opt/fastscan  (binary and data co-located)
	return filepath.Dir(exe)
}()

// dep describes an external tool dependency.
type dep struct {
	Name        string `json:"name"`
	Present     bool   `json:"present"`
	Path        string `json:"path,omitempty"`
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
}

// metaResponse is the GET /api/meta body.
type metaResponse struct {
	Version     string   `json:"version"`
	User        string   `json:"user,omitempty"`
	Profiles    []string `json:"profiles"`
	DriverCount int      `json:"driver_count"`
	PluginCount int      `json:"plugin_count"`
	Deps        []dep    `json:"deps"`
}

// fixedProfiles are the network-tuning profiles the engine exposes.
var fixedProfiles = []string{"fast", "medium", "slow", "crawl"}

// depSpecs lists the external tools probed for /api/deps and /api/meta. Each
// entry may carry candidate binary names (httpx ships as httpx-pd) and explicit
// fallback paths for tools not on PATH.

// nxcFallbacks returns user-relative fallback paths for nxc so the check
// works regardless of which user runs the service.
func nxcFallbacks() []string {
	paths := []string{"/usr/local/bin/nxc"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append([]string{filepath.Join(home, ".local", "bin", "nxc")}, paths...)
	}
	return paths
}

var depSpecs = []struct {
	name        string
	candidates  []string
	fallbacks   []string
	required    bool
	description string
}{
	{name: "nmap", candidates: []string{"nmap"}, required: true, description: "Port scanning — core engine requirement"},
	{name: "rustscan", candidates: []string{"rustscan"}, required: true, description: "Fast port discovery (nmap fallback if absent)"},
	{name: "httpx", candidates: []string{"httpx-pd", "httpx"}, required: true, description: "HTTP probing and web fingerprinting"},
	{name: "nuclei", candidates: []string{"nuclei"}, required: true, description: "Template-based vuln detection (accounts for ~40% of findings)"},
	{name: "testssl.sh", candidates: []string{"testssl.sh"}, fallbacks: []string{"/usr/local/bin/testssl.sh"}, description: "TLS/SSL vulnerability scanning"},
	{name: "nxc", candidates: []string{"nxc", "netexec"}, fallbacks: nxcFallbacks(), description: "SMB/AD enumeration and relay testing"},
	{name: "ike-scan", candidates: []string{"ike-scan"}, description: "IKE/IPsec VPN protocol fingerprinting"},
	{name: "scrying", candidates: []string{"scrying"}, description: "RDP and VNC desktop screenshots"},
	{name: "python3", candidates: []string{"python3", "python"}, required: true, description: "Evidence and Excel export scripts"},
}

// resolveDeps probes each dependency and reports presence + resolved path.
func resolveDeps() []dep {
	out := make([]dep, 0, len(depSpecs))
	for _, spec := range depSpecs {
		d := dep{Name: spec.name, Required: spec.required, Description: spec.description}
		for _, c := range spec.candidates {
			if p, err := exec.LookPath(c); err == nil {
				d.Present = true
				d.Path = p
				break
			}
		}
		if !d.Present {
			for _, fb := range spec.fallbacks {
				if fileExists(fb) {
					d.Present = true
					d.Path = fb
					break
				}
			}
		}
		out = append(out, d)
	}
	return out
}

// countDrivers counts the engine's protocol probe drivers. In source
// deployments it counts *probe.go files; in binary-only deployments (Docker)
// it falls back to a drivers.count marker file written at build time.
func countDrivers() int {
	matches, _ := filepath.Glob(filepath.Join(engineRoot, "*probe.go"))
	if len(matches) == 0 {
		matches, _ = filepath.Glob(filepath.Join(engineRoot, "engine", "*probe.go"))
	}
	n := 0
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		n++
	}
	if n > 0 {
		return n
	}
	// Binary-only deployment: read pre-computed count from marker file.
	if data, err := os.ReadFile(filepath.Join(engineRoot, "drivers.count")); err == nil {
		var count int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &count); err == nil && count > 0 {
			return count
		}
	}
	return 0
}

// countPlugins counts the YAML plugin rule files anywhere under the engine's
// plugins tree.
func countPlugins() int {
	root := filepath.Join(engineRoot, "plugins")
	n := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			n++
		}
		return nil
	})
	return n
}

// handleMeta serves GET /api/meta.
func (srv *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	resp := metaResponse{
		Version:     uiVersion,
		User:        srv.authUser,
		Profiles:    fixedProfiles,
		DriverCount: countDrivers(),
		PluginCount: countPlugins(),
		Deps:        metaDeps(resolveDeps()),
	}
	writeJSONResp(w, http.StatusOK, resp)
}

// metaDeps strips the path field for the /api/meta deps view.
func metaDeps(deps []dep) []dep {
	out := make([]dep, len(deps))
	for i, d := range deps {
		out[i] = dep{Name: d.Name, Present: d.Present, Required: d.Required, Description: d.Description}
	}
	return out
}

// handleDeps serves GET /api/deps.
func (srv *Server) handleDeps(w http.ResponseWriter, r *http.Request) {
	writeJSONResp(w, http.StatusOK, resolveDeps())
}
