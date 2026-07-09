// smbvulnprobe.go: nxc (netexec) wrapper for the three big SMB CVEs:
// MS17-010 (EternalBlue), Zerologon (CVE-2020-1472), SMBGhost
// (CVE-2020-0796).
//
// We shell out to nxc smb -M <module>. Parsing is line-based: a
// successful detection prints a line like:
//   SMB    HOST    445    HOSTNAME    [+] Vulnerable to MS17-010
// We just look for the [+] marker plus the module's identifying
// substring. Modules that return "not vulnerable" / "N/A" leave the
// corresponding bool at false.
//
// nxc lives at /root/.local/bin/nxc on idsserver. We also probe
// regular PATH names (nxc, netexec) so the driver works on dev boxes.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SMBVulnReport is one nxc run aggregating MS17-010 / Zerologon /
// SMBGhost results for host:port.
type SMBVulnReport struct {
	Host                 string   `json:"host"`
	Port                 int      `json:"port"`
	MS17010Vulnerable    bool     `json:"ms17010_vulnerable"`
	ZerologonVulnerable  bool     `json:"zerologon_vulnerable"`
	SMBGhostVulnerable   bool     `json:"smbghost_vulnerable"`
	WindowsProduct       string   `json:"windows_product,omitempty"` // e.g. "Windows Server 2019 Standard"
	WindowsBuild         int      `json:"windows_build,omitempty"`   // e.g. 17763
	WindowsArch          string   `json:"windows_arch,omitempty"`    // e.g. "x64"
	NetBIOSName          string   `json:"netbios_name,omitempty"`
	Domain               string   `json:"domain,omitempty"`
	RawOutput            string   `json:"raw_output,omitempty"`
	ProbeErrors          []string `json:"probe_errors,omitempty"`
}

// nxcInfoRe matches the identity header line every nxc smb module prints, e.g.
//   SMB   172.19.12.65   445   VDSELT218  [*] Windows 11 / Server 2025 Build 26100 x64 (name:VDSELT218) (domain:VDARTINC.COM) (signing:True) (SMBv1:None)
// Groups: 1=netbios name  2=product string  3=build number  4=arch  5=domain
var nxcInfoRe = regexp.MustCompile(
	`^SMB\s+\S+\s+\d+\s+(\S+)\s+\[\*\]\s+(.+?)\s+Build\s+(\d{3,6})\s+(x\d+)(?:.*\(domain:([^)]+)\))?`,
)

// nxcCandidates returns every place we look for nxc, in preference order.
// Uses os.UserHomeDir() so it works for any user, not just root.
func nxcCandidates() []string {
	base := []string{"nxc", "netexec"}
	if home, err := os.UserHomeDir(); err == nil {
		return append([]string{filepath.Join(home, ".local", "bin", "nxc")}, base...)
	}
	return base
}

// nxcBinary returns the first nxc binary that exists, or "" if none.
func nxcBinary() string {
	for _, c := range nxcCandidates() {
		if strings.HasPrefix(c, "/") {
			if _, err := os.Stat(c); err == nil {
				return c
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// ProbeSMBVuln runs `nxc smb <host> -M ms17-010 / zerologon / smbghost`
// in turn, parses stdout, and returns the aggregate report. Missing
// binary returns ProbeError without erroring.
func ProbeSMBVuln(host string, port int, timeout time.Duration) (*SMBVulnReport, error) {
	rep := &SMBVulnReport{Host: host, Port: port}

	bin := nxcBinary()
	if bin == "" {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"nxc not found (install hint: pipx install netexec)")
		return rep, nil
	}

	// One nxc invocation per module. Each is bounded by `timeout`. We
	// accumulate raw output for evidence.
	var rawBuf strings.Builder
	for _, mod := range []string{"ms17-010", "zerologon", "smbghost"} {
		out, err := runNXCModule(bin, host, mod, timeout)
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("nxc %s: %v", mod, err))
		}
		rawBuf.WriteString(fmt.Sprintf("--- %s ---\n", mod))
		rawBuf.WriteString(out)
		rawBuf.WriteString("\n")
		// Classify
		if classifyNXC(out, mod) {
			switch mod {
			case "ms17-010":
				rep.MS17010Vulnerable = true
			case "zerologon":
				rep.ZerologonVulnerable = true
			case "smbghost":
				rep.SMBGhostVulnerable = true
			}
		}
	}
	rep.RawOutput = strings.TrimSpace(rawBuf.String())
	parseNXCWindowsInfo(rep)
	return rep, nil
}

// parseNXCWindowsInfo scans the aggregated nxc output for the [*] identity
// line and populates the Windows product / build / arch / netbios / domain
// fields on the report. Each module prints the same line; the first match
// wins so we get consistent values.
func parseNXCWindowsInfo(rep *SMBVulnReport) {
	if rep.RawOutput == "" {
		return
	}
	for _, line := range strings.Split(rep.RawOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := nxcInfoRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rep.NetBIOSName = m[1]
		rep.WindowsProduct = strings.TrimSpace(m[2])
		if n, err := strconv.Atoi(m[3]); err == nil {
			rep.WindowsBuild = n
		}
		rep.WindowsArch = m[4]
		if len(m) > 5 && m[5] != "" {
			rep.Domain = m[5]
		}
		return
	}
}

// runNXCModule runs a single nxc smb module and returns combined output.
// (We don't pass --no-color: nxc doesn't accept it; it auto-detects TTY.)
func runNXCModule(bin, host, mod string, timeout time.Duration) (string, error) {
	args := []string{"smb", host, "-M", mod}
	cmd := exec.Command(bin, args...)
	wall := timeout
	if wall < 20*time.Second {
		wall = 20 * time.Second
	}
	timer := time.AfterFunc(wall, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	defer timer.Stop()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// classifyNXC returns true if the nxc output for `mod` reports the
// target as vulnerable. We look for "[+]" markers AND the module's
// signature word so we don't false-positive on a generic banner line.
func classifyNXC(out, mod string) bool {
	lo := strings.ToLower(out)
	// Each module name appears in the [+] vulnerable line. Match the
	// shorthand that nxc actually prints.
	var needle string
	switch mod {
	case "ms17-010":
		needle = "ms17-010"
	case "zerologon":
		needle = "zerologon"
	case "smbghost":
		needle = "smbghost"
	default:
		return false
	}
	if !strings.Contains(lo, needle) {
		return false
	}
	// Look for a positive marker. nxc prints "[+] Vulnerable" on a hit.
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(line)
		if !strings.Contains(l, needle) {
			continue
		}
		if strings.Contains(l, "[+]") && strings.Contains(l, "vulnerable") &&
			!strings.Contains(l, "not vulnerable") {
			return true
		}
	}
	return false
}
