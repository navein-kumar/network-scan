// ftpprobe.go: phase 3 driver for FTP (21).
//
// Stdlib net/textproto. Probe:
//   1. read 220 banner
//   2. USER anonymous -> PASS anon@example.com; 230 = anonymous login OK
//   3. SYST (system type)
//   4. FEAT (multi-line feature list)
package main

import (
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// FTPReport is what Phase 3 emits per FTP port.
type FTPReport struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Banner         string   `json:"banner,omitempty"`
	Product        string   `json:"product,omitempty"`
	ProductVersion string   `json:"product_version,omitempty"`
	AnonymousLogin bool     `json:"anonymous_login"`
	System         string   `json:"system,omitempty"`
	RootListing    []string `json:"root_listing,omitempty"`
	Features       []string `json:"features,omitempty"`
	AUTHTLSOffered bool          `json:"auth_tls_offered"`
	CredAttempts   []CredAttempt `json:"cred_attempts,omitempty"`
	ProbeErrors    []string      `json:"probe_errors,omitempty"`
}

// ftpListRootWithLogin dials, logs in with the given credentials, and lists
// the FTP root. Used when anonymous is rejected but a default credential
// succeeds, so the evidence still shows the exposed contents.
func ftpListRootWithLogin(host string, port int, user, pass string, timeout time.Duration) ([]string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	tc := textproto.NewConn(conn)
	defer tc.Close()
	if _, _, err := tc.ReadResponse(220); err != nil {
		return nil, err
	}
	if err := tc.PrintfLine("USER %s", user); err != nil {
		return nil, err
	}
	code, _, _ := tc.ReadResponse(0)
	if code == 331 || code == 332 {
		_ = tc.PrintfLine("PASS %s", pass)
		code, _, _ = tc.ReadResponse(0)
	}
	if code != 230 {
		return nil, fmt.Errorf("login failed: %d", code)
	}
	defer func() { _ = tc.PrintfLine("QUIT"); _, _, _ = tc.ReadResponse(0) }()
	return ftpListRoot(tc, host, timeout)
}

// ftpListRoot enters passive mode and runs LIST against the FTP root,
// returning the directory listing lines (capped). Best-effort.
func ftpListRoot(tc *textproto.Conn, host string, timeout time.Duration) ([]string, error) {
	if err := tc.PrintfLine("PASV"); err != nil {
		return nil, err
	}
	code, resp, err := tc.ReadResponse(0)
	if err != nil || code != 227 {
		return nil, fmt.Errorf("PASV: %d", code)
	}
	o := strings.IndexByte(resp, "("[0])
	cl := strings.IndexByte(resp, ")"[0])
	if o < 0 || cl <= o {
		return nil, fmt.Errorf("bad PASV response")
	}
	nums := strings.Split(resp[o+1:cl], ",")
	if len(nums) != 6 {
		return nil, fmt.Errorf("bad PASV tuple")
	}
	p1, _ := strconv.Atoi(strings.TrimSpace(nums[4]))
	p2, _ := strconv.Atoi(strings.TrimSpace(nums[5]))
	// Some servers report an internal/zero IP; fall back to the control host.
	dataIP := strings.Join([]string{nums[0], nums[1], nums[2], nums[3]}, ".")
	if strings.HasPrefix(dataIP, "0.") || strings.HasPrefix(dataIP, "127.") {
		dataIP = host
	}
	dataConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dataIP, p1*256+p2), timeout)
	if err != nil {
		return nil, err
	}
	defer dataConn.Close()
	dataConn.SetDeadline(time.Now().Add(timeout))

	if err := tc.PrintfLine("LIST"); err != nil {
		return nil, err
	}
	_, _, _ = tc.ReadResponse(0) // 150 opening data connection

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 2048)
	for len(buf) < 16384 {
		n, rerr := dataConn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	_, _, _ = tc.ReadResponse(0) // 226 transfer complete

	var lines []string
	for _, l := range strings.Split(string(buf), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		lines = append(lines, l)
		if len(lines) >= 60 {
			break
		}
	}
	return lines, nil
}

// ProbeFTP opens an FTP session and harvests banner / features /
// anonymous-login status.
func ProbeFTP(host string, port int, timeout time.Duration) (*FTPReport, error) {
	rep := &FTPReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	tc := textproto.NewConn(conn)
	defer tc.Close()

	// 220 banner
	code, banner, err := tc.ReadResponse(220)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read banner: %v", err))
		return rep, nil
	}
	rep.Banner = fmt.Sprintf("%d %s", code, strings.TrimSpace(banner))
	rep.Product, rep.ProductVersion = parseProductVersion(rep.Banner)

	// anonymous login attempt
	if err := tc.PrintfLine("USER anonymous"); err == nil {
		userCode, _, _ := tc.ReadResponse(0)
		if userCode == 331 || userCode == 230 {
			if userCode == 230 {
				rep.AnonymousLogin = true
			} else {
				_ = tc.PrintfLine("PASS anon@example.com")
				passCode, _, _ := tc.ReadResponse(0)
				if passCode == 230 {
					rep.AnonymousLogin = true
				}
			}
		}
	}

	// On anonymous login, list the FTP root so the evidence shows the
	// actual exposed contents (matches the Nessus anon-FTP plugin output).
	if rep.AnonymousLogin {
		if listing, err := ftpListRoot(tc, host, timeout); err == nil {
			rep.RootListing = listing
		}
	}

	// SYST
	if err := tc.PrintfLine("SYST"); err == nil {
		systCode, systResp, _ := tc.ReadResponse(0)
		if systCode == 215 {
			rep.System = strings.TrimSpace(systResp)
		}
	}

	// FEAT
	if err := tc.PrintfLine("FEAT"); err == nil {
		featCode, featResp, _ := tc.ReadResponse(0)
		if featCode == 211 {
			for _, l := range strings.Split(featResp, "\n") {
				feat := strings.TrimSpace(l)
				if feat == "" {
					continue
				}
				// Skip the human-readable first/last lines like
				// "Features:" and "End"
				if strings.HasPrefix(strings.ToLower(feat), "features") ||
					strings.EqualFold(feat, "end") {
					continue
				}
				rep.Features = append(rep.Features, feat)
				upper := strings.ToUpper(feat)
				if strings.HasPrefix(upper, "AUTH TLS") ||
					strings.HasPrefix(upper, "AUTH SSL") ||
					upper == "AUTH" {
					rep.AUTHTLSOffered = true
				}
			}
		}
	}

	_ = tc.PrintfLine("QUIT")
	_, _, _ = tc.ReadResponse(0)
	return rep, nil
}
