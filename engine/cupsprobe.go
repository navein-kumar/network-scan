// cupsprobe.go: phase 3 driver for CUPS print server (631/tcp).
//
// stdlib HTTP GET /. CUPS identifies itself in the Server: header. Also
// fetches /printers/ to enumerate any exposed printer queues.
package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type CUPSReport struct {
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	Reachable          bool     `json:"reachable"`
	ServerHeader       string   `json:"server_header,omitempty"`
	Version            string   `json:"version,omitempty"`
	PrinterCount       int      `json:"printer_count,omitempty"`
	AccessiblePrinters []string `json:"accessible_printers,omitempty"`
	ProbeErrors        []string `json:"probe_errors,omitempty"`
}

var cupsVerRE = regexp.MustCompile(`(?i)CUPS/([\d.]+)`)
var cupsPrinterRE = regexp.MustCompile(`(?i)<A HREF="/printers/([^"/]+)"`)

func ProbeCUPS(host string, port int, timeout time.Duration) (*CUPSReport, error) {
	rep := &CUPSReport{Host: host, Port: port}
	cli := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
	base := fmt.Sprintf("http://%s:%d", host, port)

	resp, err := cli.Get(base + "/")
	if err != nil {
		return rep, fmt.Errorf("get /: %w", err)
	}
	defer resp.Body.Close()
	rep.ServerHeader = resp.Header.Get("Server")
	if strings.Contains(strings.ToLower(rep.ServerHeader), "cups") {
		rep.Reachable = true
		if m := cupsVerRE.FindStringSubmatch(rep.ServerHeader); len(m) > 1 {
			rep.Version = m[1]
		}
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if !rep.Reachable {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("server header %q", rep.ServerHeader))
		return rep, nil
	}

	// /printers/ enumeration.
	presp, perr := cli.Get(base + "/printers/")
	if perr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("get /printers/: %v", perr))
		return rep, nil
	}
	defer presp.Body.Close()
	if presp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(presp.Body, 1<<20))
		seen := map[string]bool{}
		for _, m := range cupsPrinterRE.FindAllStringSubmatch(string(body), -1) {
			name := m[1]
			if !seen[name] {
				seen[name] = true
				rep.AccessiblePrinters = append(rep.AccessiblePrinters, name)
			}
		}
		rep.PrinterCount = len(rep.AccessiblePrinters)
	}
	return rep, nil
}
