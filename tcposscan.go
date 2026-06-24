// tcposscan.go: OS heuristic via banner correlation (no raw sockets).
//
// Why no raw TCP IP-header inspection: Go's net.Conn does not expose
// the remote SYN/ACK's IP TTL or TCP window size; reading those needs
// a raw socket (CAP_NET_RAW + AF_PACKET on Linux), which we deliberately
// avoid in the unprivileged path. So instead of inventing a brittle
// raw-socket fallback that crashes on every Docker container with no
// NET_RAW capability, we lean on the data the other 30+ drivers
// already extract: SSH banner, SMB OS string, HTTP Server header, FTP
// banner, and so on. The fingerprint is less precise than nmap -O but
// it never needs privilege.
//
// This file is wired in as a Phase 2.8 step that walks per-host
// aggregated driver reports and emits one os_heuristic report per
// host. It runs AFTER Phase 2.5/2.6/2.7 so all driver data is in hand.
package main

import (
	"regexp"
	"strings"
)

type OSHeuristicReport struct {
	Host        string   `json:"host"`
	OSFamily    string   `json:"os_family,omitempty"`
	OSGuess     string   `json:"os_guess,omitempty"`
	Confidence  int      `json:"confidence,omitempty"`  // 0..100
	Signals     []string `json:"signals,omitempty"`
	ProbeErrors []string `json:"probe_errors,omitempty"`
}

// HostBanners is the aggregated set of strings we mined from other
// drivers' reports for one host. main.go fills this in.
type HostBanners struct {
	SSHBanner  string   // sshprobe.go banner
	SMBOSStr   string   // smbprobe.go OS field
	SMBVersion string
	FTPBanner  string
	SMTPBanner string
	MySQLVer   string
	HTTPServer []string // httpx Server headers
}

// ProbeOSHeuristic runs the regex ruleset over the aggregated banners
// and picks the highest-confidence match.
func ProbeOSHeuristic(host string, banners HostBanners) *OSHeuristicReport {
	rep := &OSHeuristicReport{Host: host}

	rules := []struct {
		family     string
		guess      string
		confidence int
		signal     string
		match      bool
	}{
		// SMB OS string: highest fidelity
		{"Windows", findWindowsRelease(banners.SMBOSStr), 90,
			"smb_os=" + banners.SMBOSStr,
			banners.SMBOSStr != "" && strings.Contains(banners.SMBOSStr, "Windows")},
		// HTTP Server: Microsoft-IIS → Windows
		{"Windows", "Windows (IIS)", 90,
			"http_server contains Microsoft-IIS",
			anyMatches(banners.HTTPServer, `(?i)Microsoft-IIS`)},
		// FTP banner: Microsoft FTP
		{"Windows", "Windows (Microsoft FTP)", 80,
			"ftp_banner contains Microsoft FTP",
			regexp.MustCompile(`(?i)Microsoft FTP`).MatchString(banners.FTPBanner)},

		// SSH banner: distro substrings
		{"Linux", "Linux (Ubuntu)", 80,
			"ssh_banner contains Ubuntu",
			regexp.MustCompile(`(?i)Ubuntu`).MatchString(banners.SSHBanner)},
		{"Linux", "Linux (Debian)", 80,
			"ssh_banner contains Debian",
			regexp.MustCompile(`(?i)Debian`).MatchString(banners.SSHBanner)},
		{"Linux", "Linux (Raspbian)", 80,
			"ssh_banner contains Raspbian",
			regexp.MustCompile(`(?i)Raspbian`).MatchString(banners.SSHBanner)},
		{"Linux", "Linux (Red Hat / CentOS)", 70,
			"ssh_banner contains Red Hat or CentOS",
			regexp.MustCompile(`(?i)RHEL|CentOS|Red Hat`).MatchString(banners.SSHBanner)},
		{"Linux", "Linux (Alpine)", 70,
			"ssh_banner contains Alpine",
			regexp.MustCompile(`(?i)Alpine`).MatchString(banners.SSHBanner)},

		// HTTP nginx / Apache: lower confidence (run on Linux usually, but Windows builds exist).
		{"Linux", "Linux (nginx)", 50,
			"http_server contains nginx",
			anyMatches(banners.HTTPServer, `(?i)nginx`)},
		{"Linux", "Linux (Apache)", 50,
			"http_server contains Apache",
			anyMatches(banners.HTTPServer, `(?i)Apache`)},

		// SMTP banner: Postfix on a Linux box
		{"Linux", "Linux (Postfix MTA)", 50,
			"smtp_banner contains Postfix",
			regexp.MustCompile(`(?i)Postfix`).MatchString(banners.SMTPBanner)},

		// MySQL "Linux" or "Ubuntu" or "Debian" in version
		{"Linux", "Linux (MySQL package)", 60,
			"mysql_version contains debian/ubuntu/linux",
			regexp.MustCompile(`(?i)ubuntu|debian|linux`).MatchString(banners.MySQLVer)},
	}

	for _, r := range rules {
		if !r.match {
			continue
		}
		rep.Signals = append(rep.Signals, r.signal)
		if r.confidence > rep.Confidence {
			rep.Confidence = r.confidence
			rep.OSFamily = r.family
			rep.OSGuess = r.guess
		}
	}
	if rep.OSGuess == "" && rep.OSFamily == "" && len(rep.Signals) == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"no banner signals matched heuristic ruleset")
	}
	return rep
}

func anyMatches(strs []string, pat string) bool {
	re := regexp.MustCompile(pat)
	for _, s := range strs {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// findWindowsRelease pulls a Windows release substring out of an SMB
// OS string like "Windows 10 Enterprise 19041".
func findWindowsRelease(s string) string {
	if s == "" {
		return ""
	}
	patterns := []string{
		`Windows Server \d+(?: R2)?`,
		`Windows \d+(?:\.\d+)?`,
	}
	for _, p := range patterns {
		if m := regexp.MustCompile(p).FindString(s); m != "" {
			return m
		}
	}
	return "Windows (unknown release)"
}

