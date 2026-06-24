// osprobe.go: phase 3 driver for OS fingerprinting.
//
// nmap is the only tool with a serious TCP/IP-stack OS fingerprint
// database, so we shell out. One nmap -O invocation per host (not per
// port) emits XML which we parse for <osmatch> entries plus their
// <osclass> family / vendor / generation tags.
//
// Note: nmap -O requires CAP_NET_RAW or root for SYN/UDP probes. If
// run unprivileged, OS detection silently returns no matches. The
// driver records this in ProbeErrors.
package main

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type OSReport struct {
	Host        string    `json:"host"`
	Port        int       `json:"port"` // 0 — OS detection is per-host
	Matches     []OSMatch `json:"matches,omitempty"`
	Best        OSMatch   `json:"best"`
	ProbeErrors []string  `json:"probe_errors,omitempty"`
}

type OSMatch struct {
	Name       string `json:"name"`
	Accuracy   int    `json:"accuracy"`
	Family     string `json:"family,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Generation string `json:"generation,omitempty"`
	OSType     string `json:"os_type,omitempty"`
}

func ProbeOS(host string, port int, timeout time.Duration) (*OSReport, error) {
	rep := &OSReport{Host: host, Port: port}

	// Hand a small port set to -O so nmap has at least one open + one
	// closed port to fingerprint with. Use a generous timeout knob.
	args := []string{
		"-O", "--osscan-guess",
		"-Pn", "-n",
		"-p", "22,80,135,139,443,445,3389",
		"--max-os-tries", "1",
		"--host-timeout", fmt.Sprintf("%ds", int(timeout.Seconds())+30),
		"-oX", "-",
		host,
	}
	cmd := exec.Command("nmap", args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("nmap exit: %v stderr=%s", err, string(ee.Stderr)))
		}
		return rep, fmt.Errorf("nmap exec: %w", err)
	}

	var run struct {
		Hosts []struct {
			OS struct {
				Matches []struct {
					Name     string `xml:"name,attr"`
					Accuracy string `xml:"accuracy,attr"`
					Classes  []struct {
						Vendor     string `xml:"vendor,attr"`
						Family     string `xml:"osfamily,attr"`
						Generation string `xml:"osgen,attr"`
						Type       string `xml:"type,attr"`
					} `xml:"osclass"`
				} `xml:"osmatch"`
			} `xml:"os"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(out, &run); err != nil {
		return rep, fmt.Errorf("xml parse: %w", err)
	}

	var bestAcc int
	for _, h := range run.Hosts {
		for _, m := range h.OS.Matches {
			acc, _ := strconv.Atoi(m.Accuracy)
			om := OSMatch{Name: m.Name, Accuracy: acc}
			if len(m.Classes) > 0 {
				om.Family = m.Classes[0].Family
				om.Vendor = m.Classes[0].Vendor
				om.Generation = m.Classes[0].Generation
				om.OSType = m.Classes[0].Type
			}
			rep.Matches = append(rep.Matches, om)
			if acc > bestAcc {
				bestAcc = acc
				rep.Best = om
			}
		}
	}
	if len(rep.Matches) == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"nmap returned no OS matches (run as root for raw-socket probes)")
	}
	return rep, nil
}

// unused: silence linter if we ever drop the os_type field
var _ = strings.TrimSpace
