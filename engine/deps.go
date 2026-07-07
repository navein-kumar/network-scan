// deps.go: dependency-presence check.
//
// fastscan is a Go binary but it shells out to a handful of external
// CLI tools at runtime. This file probes each, prints a compact status
// table, and tells the user how to install whichever is missing.
//
// Called automatically at startup (warning only, never fatal) and via
// the -check-deps flag for manual verification.
package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// Dep describes one external CLI tool fastscan calls.
type Dep struct {
	Name        string   // friendly name shown in the report
	Binary      []string // candidate binary names to look up via exec.LookPath
	UsedBy      string   // which phase / driver needs it
	Required    bool     // true = core tool, false = optional driver shellout
	InstallHint string   // one-line install command
}

var deps = []Dep{
	{
		Name: "nmap", Binary: []string{"nmap"},
		UsedBy:      "Phase 2 -sV, Phase 1b UDP, Phase 2.6 OS detect, Phase 2.7 traceroute",
		Required:    true,
		InstallHint: "apt install nmap",
	},
	{
		Name: "rustscan", Binary: []string{"rustscan"},
		UsedBy:      "Phase 1 TCP port discovery",
		Required:    true,
		InstallHint: "snap install rustscan  OR  cargo install rustscan",
	},
	{
		Name: "httpx", Binary: []string{"httpx-pd", "httpx"},
		UsedBy:      "Phase 3 web enrichment (also linked as a library, fallback to CLI)",
		Required:    false,
		InstallHint: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
	},
	{
		Name: "nuclei", Binary: []string{"nuclei"},
		UsedBy:      "Phase 4 templates (also linked as a library, used for -update-templates)",
		Required:    false,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
	},
	{
		Name: "testssl.sh", Binary: []string{"testssl.sh", "testssl"},
		UsedBy:      "Phase 2.9 TLS vulnerability scan (Heartbleed, POODLE, DROWN, ...)",
		Required:    false,
		InstallHint: "git clone https://github.com/drwetter/testssl.sh /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh",
	},
	{
		Name: "nxc (netexec)", Binary: []string{"nxc", "netexec", "/root/.local/bin/nxc"},
		UsedBy:      "Phase 2.5 SMB vuln modules (MS17-010, Zerologon, SMBGhost)",
		Required:    false,
		InstallHint: "pipx install netexec",
	},
}

// CheckDeps probes each dep and returns the list with resolved paths.
func CheckDeps() []DepStatus {
	out := make([]DepStatus, 0, len(deps))
	for _, d := range deps {
		st := DepStatus{Dep: d}
		for _, name := range d.Binary {
			// support absolute paths in the binary list (some tools
			// install into per-user directories not on PATH)
			if strings.HasPrefix(name, "/") {
				if _, err := exec.LookPath(name); err == nil {
					st.Path = name
					st.Version = probeVersion(name)
					break
				}
				continue
			}
			if p, err := exec.LookPath(name); err == nil {
				st.Path = p
				st.Version = probeVersion(name)
				break
			}
		}
		out = append(out, st)
	}
	return out
}

// DepStatus is the resolved result for one Dep.
type DepStatus struct {
	Dep
	Path    string // empty if not found
	Version string // best-effort first version line
}

// probeVersion runs `<tool> --version` (or fallback) and returns the
// first line. Best-effort; failure returns empty.
func probeVersion(bin string) string {
	for _, flag := range []string{"-version", "--version", "-v"} {
		cmd := exec.Command(bin, flag)
		out, err := cmd.CombinedOutput()
		if err == nil || len(out) > 0 {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					if len(line) > 60 {
						line = line[:60] + "..."
					}
					return line
				}
			}
		}
	}
	return ""
}

// PrintDeps writes a human-readable status table to stdout.
func PrintDeps(statuses []DepStatus) {
	fmt.Println("Dependency check:")
	fmt.Println()
	missingRequired := 0
	missingOptional := 0
	for _, s := range statuses {
		mark := "[x]"
		if s.Path != "" {
			mark = "[+]"
		}
		req := "optional"
		if s.Required {
			req = "REQUIRED"
		}
		fmt.Printf("  %s %-15s  %-9s  %s\n", mark, s.Name, req, s.Path)
		if s.Version != "" {
			fmt.Printf("                                  %s\n", s.Version)
		}
		fmt.Printf("                                  used by: %s\n", s.UsedBy)
		if s.Path == "" {
			fmt.Printf("                                  install: %s\n", s.InstallHint)
			if s.Required {
				missingRequired++
			} else {
				missingOptional++
			}
		}
		fmt.Println()
	}
	if missingRequired > 0 {
		fmt.Printf("%d REQUIRED tool(s) missing -- the corresponding phases will fail.\n", missingRequired)
	}
	if missingOptional > 0 {
		fmt.Printf("%d optional tool(s) missing -- the corresponding plugins will not fire.\n", missingOptional)
	}
	if missingRequired == 0 && missingOptional == 0 {
		fmt.Println("All dependencies satisfied.")
	}
}

// WarnMissingAtStartup is the non-fatal startup-time check. Prints a
// compact summary, does not exit. Skipped when -check-deps was already
// invoked (caller handles that branch).
func WarnMissingAtStartup() {
	statuses := CheckDeps()
	var missing []string
	for _, s := range statuses {
		if s.Path == "" {
			tag := s.Name
			if s.Required {
				tag = "*" + s.Name
			}
			missing = append(missing, tag)
		}
	}
	if len(missing) == 0 {
		return
	}
	fmt.Printf("[deps] missing: %s   (run with -check-deps for install hints; * = required)\n",
		strings.Join(missing, ", "))
}
