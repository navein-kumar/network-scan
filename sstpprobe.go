// sstpprobe.go: phase 3 driver for SSTP (Secure Socket Tunneling Protocol,
// Microsoft VPN over HTTPS).
//
// stdlib HTTPS. SSTP servers listen on 443 (or a configurable port) at
// path /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/. We send the
// SSTP_DUPLEX_POST request and look for HTTP/1.1 200 in the response.
// TLS verification is disabled because we are fingerprinting, not
// authenticating.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type SSTPReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Reachable       bool     `json:"reachable"`
	SSTPResponding  bool     `json:"sstp_responding"`
	StatusCode      int      `json:"status_code,omitempty"`
	ServerHeader    string   `json:"server_header,omitempty"`
	ProbeErrors     []string `json:"probe_errors,omitempty"`
}

const sstpPath = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"

func ProbeSSTP(host string, port int, timeout time.Duration) (*SSTPReport, error) {
	rep := &SSTPReport{Host: host, Port: port}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}
	cli := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	url := fmt.Sprintf("https://%s:%d%s", host, port, sstpPath)
	req, _ := http.NewRequest("SSTP_DUPLEX_POST", url, nil)
	req.Header.Set("Content-Length", "18446744073709551615")
	req.Header.Set("SSTPCORRELATIONID", "{00000000-0000-0000-0000-000000000000}")
	req.Header.Set("Host", host)
	resp, err := cli.Do(req)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("do: %v", err))
		return rep, nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	rep.Reachable = true
	rep.StatusCode = resp.StatusCode
	rep.ServerHeader = resp.Header.Get("Server")
	// 200 = SSTP server accepted the duplex POST.
	// 401 / 200 with Server: Microsoft-HTTPAPI also indicates SSTP.
	if resp.StatusCode == 200 {
		rep.SSTPResponding = true
	} else if strings.Contains(strings.ToLower(rep.ServerHeader), "microsoft-httpapi") &&
		strings.Contains(strings.ToLower(resp.Header.Get("Www-Authenticate")), "negotiate") {
		// Some SSTP listeners respond 401 to unauthenticated probes.
		rep.SSTPResponding = true
	}
	return rep, nil
}
