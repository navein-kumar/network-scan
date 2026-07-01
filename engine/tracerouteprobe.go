// tracerouteprobe.go: phase 2.7 traceroute via `nmap --traceroute`.
//
// One nmap invocation per unique host. Parses <trace><hop> XML
// elements from -oX -. Like osprobe.go, this needs raw-socket privilege
// (CAP_NET_RAW or root); without it, nmap returns no hops and the
// driver records that in ProbeErrors.
package main

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

type TracerouteHop struct {
	TTL      int     `json:"ttl"`
	Address  string  `json:"address"`
	RTTms    float64 `json:"rtt_ms"`
	Hostname string  `json:"hostname,omitempty"`
}

type TracerouteReport struct {
	Host        string          `json:"host"`
	Hops        []TracerouteHop `json:"hops"`
	ProbeErrors []string        `json:"probe_errors,omitempty"`
}

// ProbeTraceroute shells out to nmap --traceroute -sn -Pn and parses
// the hop list. port is ignored (traceroute is per-host).
func ProbeTraceroute(host string, port int, timeout time.Duration) (*TracerouteReport, error) {
	rep := &TracerouteReport{Host: host}

	args := []string{
		"--traceroute", "-sn", "-Pn", "-n",
		"--host-timeout", fmt.Sprintf("%ds", int(timeout.Seconds())+10),
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
			Trace struct {
				Hops []struct {
					TTL      string `xml:"ttl,attr"`
					IPAddr   string `xml:"ipaddr,attr"`
					RTT      string `xml:"rtt,attr"`
					Host     string `xml:"host,attr"`
				} `xml:"hop"`
			} `xml:"trace"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(out, &run); err != nil {
		return rep, fmt.Errorf("xml parse: %w", err)
	}
	for _, h := range run.Hosts {
		for _, hop := range h.Trace.Hops {
			ttl, _ := strconv.Atoi(hop.TTL)
			rtt, _ := strconv.ParseFloat(hop.RTT, 64)
			rep.Hops = append(rep.Hops, TracerouteHop{
				TTL:      ttl,
				Address:  hop.IPAddr,
				RTTms:    rtt,
				Hostname: hop.Host,
			})
		}
	}
	if len(rep.Hops) == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"nmap returned no trace hops (run as root for raw-socket probes)")
	}
	return rep, nil
}
