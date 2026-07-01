// winrmprobe.go: phase 3 driver for Windows Remote Management.
//
// WinRM speaks SOAP over HTTP(S). A POST to /wsman without a body
// triggers a 401 Unauthorized whose WWW-Authenticate headers list the
// supported auth schemes (Negotiate, Kerberos, NTLM, CredSSP, Basic).
// Server header reveals the WinRM build (e.g. "Microsoft-HTTPAPI/2.0").
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

type WinRMReport struct {
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	IsTLS              bool     `json:"is_tls"`
	Reachable          bool     `json:"reachable"`
	StatusCode         int      `json:"status_code,omitempty"`
	AuthMethodsOffered []string `json:"auth_methods_offered,omitempty"`
	ServerHeader       string        `json:"server_header,omitempty"`
	CredAttempts       []CredAttempt `json:"cred_attempts,omitempty"`
	CommandOutput      []string      `json:"command_output,omitempty"`
	ProbeErrors        []string      `json:"probe_errors,omitempty"`
}

func ProbeWinRM(host string, port int, timeout time.Duration) (*WinRMReport, error) {
	rep := &WinRMReport{Host: host, Port: port}
	scheme := "http"
	if port == 5986 || port == 443 {
		scheme = "https"
		rep.IsTLS = true
	}
	url := fmt.Sprintf("%s://%s:%d/wsman", scheme, host, port)

	cl := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(""))
	if err != nil {
		return rep, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("User-Agent", "Microsoft WinRM Client")

	resp, err := cl.Do(req)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("http: %v", err))
		return rep, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	rep.Reachable = true
	rep.StatusCode = resp.StatusCode
	rep.ServerHeader = resp.Header.Get("Server")
	for _, h := range resp.Header.Values("WWW-Authenticate") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		// "Negotiate", "Kerberos", "NTLM" come alone; "Basic realm=..."
		// has the scheme as the first token.
		sp := strings.SplitN(h, " ", 2)
		rep.AuthMethodsOffered = append(rep.AuthMethodsOffered, sp[0])
	}
	return rep, nil
}

// winrmRunCommandsWithLogin authenticates over WinRM with a recovered
// default credential and captures the output of a few host-enumeration
// commands, mirroring the SSH driver's post-login capture. Best-effort:
// any error yields an empty slice and never panics.
func winrmRunCommandsWithLogin(host string, port int, user, pass string, timeout time.Duration) []string {
	endpoint := winrm.NewEndpoint(host, port, false, false, nil, nil, nil, timeout)
	client, err := winrm.NewClient(endpoint, user, pass)
	if err != nil || client == nil {
		return nil
	}

	cmds := []string{"whoami", "hostname", "ipconfig /all", "systeminfo"}
	var out []string
	const maxLines = 40
	for _, cmd := range cmds {
		if len(out) >= maxLines {
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		var stdout, stderr bytes.Buffer
		_, runErr := client.RunWithContext(ctx, cmd, &stdout, &stderr)
		cancel()
		if runErr != nil {
			continue
		}
		out = append(out, "> "+cmd)
		for _, line := range strings.Split(strings.TrimRight(stdout.String(), "\r\n"), "\n") {
			if len(out) >= maxLines {
				break
			}
			out = append(out, strings.TrimRight(line, "\r"))
		}
	}
	if len(out) > maxLines {
		out = out[:maxLines]
	}
	return out
}
