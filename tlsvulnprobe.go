// tlsvulnprobe.go: phase 2.95 wrapper driver around testssl.sh.
//
// Shells out to testssl.sh with --quiet --json-pretty against host:port
// and parses the "scanResult" array (vulnerabilities + protocols) into a
// TLSVulnReport. If testssl.sh is not installed, ProbeTLSVuln returns a
// report with an install-hint ProbeError instead of erroring out. The
// scan run continues normally without TLS vuln coverage.
//
// We do NOT pull in testssl.sh as a library (it is a 14k-line bash
// script). We just call the CLI; the JSON it emits is stable enough.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// TLSVulnReport is one testssl.sh run for a host:port.
type TLSVulnReport struct {
	Host            string                `json:"host"`
	Port            int                   `json:"port"`
	Vulnerabilities []TLSVulnFinding      `json:"vulnerabilities,omitempty"`
	Protocols       []TLSProtocolFinding  `json:"protocols,omitempty"`
	// CipherLists holds named cipher-suite lists from testssl.sh "ciphers"
	// section, e.g. cipherlist_SSLv2, cipherlist_3DES_IDEA.  The Finding
	// field is space-separated cipher names accepted by the server.
	CipherLists     []TLSCipherList       `json:"cipher_lists,omitempty"`
	// ServerCiphers holds per-cipher rows from testssl.sh serverPreferences
	// section, giving full suite name, key-exchange, bits, and protocol.
	ServerCiphers   []TLSServerCipher     `json:"server_ciphers,omitempty"`
	RawCount        int                   `json:"raw_count,omitempty"`
	ProbeErrors     []string              `json:"probe_errors,omitempty"`
}

// TLSCipherList is one row from the testssl.sh "ciphers" section,
// e.g. id=cipherlist_SSLv2, finding="DES-CBC-MD5 RC4-MD5 RC4-64-MD5 ...".
type TLSCipherList struct {
	ID      string `json:"id"`
	Finding string `json:"finding"`
}

// TLSServerCipher is one cipher row from testssl.sh serverPreferences,
// e.g. id=cipher-tls1_xc013, finding="TLSv1 xc013 ECDHE-RSA-AES128-SHA ECDH 256 AES 128 ...".
type TLSServerCipher struct {
	ID      string `json:"id"`
	Finding string `json:"finding"`
}

// TLSVulnFinding is one row from testssl.sh vulnerabilities section.
type TLSVulnFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve,omitempty"`
}

// TLSProtocolFinding is one row from testssl.sh protocols section.
type TLSProtocolFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
}

// testsslScanRow matches the JSON schema testssl.sh emits with
// --json-pretty: a top-level "scanResult" array of host objects, each
// with "vulnerabilities" and "protocols" arrays of {id, severity,
// finding, cve} rows. We unmarshal into this loose shape and then
// classify by section_name.
type testsslScanFile struct {
	ScanResult []testsslHostResult `json:"scanResult"`
}
type testsslHostResult struct {
	Vulnerabilities []testsslRow `json:"vulnerabilities"`
	Protocols       []testsslRow `json:"protocols"`
	Ciphers         []testsslRow `json:"ciphers"`
	ServerPrefs     []testsslRow `json:"serverPreferences"`
}
type testsslRow struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve,omitempty"`
}

// ProbeTLSVuln runs testssl.sh against host:port and returns a parsed
// TLSVulnReport. Missing binary is not an error: the report comes back
// with a ProbeError describing the install hint.
func ProbeTLSVuln(host string, port int, timeout time.Duration) (*TLSVulnReport, error) {
	return ProbeTLSVulnService(host, port, "", timeout)
}

// ProbeTLSVulnService is the service-aware variant. The service hint is
// used to route to the right --starttls=<proto> arg so testssl.sh can
// scan TLS vulns over SMTP / IMAP / POP3 / FTP / LDAP / MySQL / Postgres
// / XMPP / RDP / NNTP STARTTLS endpoints.
func ProbeTLSVulnService(host string, port int, service string, timeout time.Duration) (*TLSVulnReport, error) {
	rep := &TLSVulnReport{Host: host, Port: port}

	bin, err := exec.LookPath("testssl.sh")
	if err != nil {
		bin, err = exec.LookPath("testssl")
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				"testssl.sh not in PATH (install hint: git clone https://github.com/drwetter/testssl.sh /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh)")
			return rep, nil
		}
	}

	// testssl.sh writes JSON to a file via --jsonfile, NOT stdout. Stage
	// a temp file, run, read it back, delete.
	tmp, err := os.CreateTemp("", "testssl-*.json")
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("tempfile: %v", err))
		return rep, nil
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	target := fmt.Sprintf("%s:%d", host, port)
	args := []string{
		"--quiet",
		"--jsonfile-pretty", tmpPath,
		"--severity", "LOW",
		"--warnings", "off",
		"--openssl-timeout", "30",
	}
	if starttls := testsslStartTLSArg(service); starttls != "" {
		args = append(args, "--starttls", starttls)
	}
	args = append(args, target)
	cmd := exec.Command(bin, args...)
	// Use a hard wallclock cap. testssl.sh on a TLS 1.2-only host with
	// many cipher suites typically finishes in 60-180s; we set a 300s
	// ceiling so legitimate scans complete and pathological ones die.
	wall := timeout
	if wall < 300*time.Second {
		wall = 300 * time.Second
	}
	timer := time.AfterFunc(wall, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	defer timer.Stop()
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		// testssl.sh exits non-zero when it finds vulns. We still want
		// the JSON file. Only treat as fatal if the file is empty.
		_ = out
	}

	raw, err := os.ReadFile(tmpPath)
	if err != nil || len(raw) == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("testssl.sh produced no JSON (exit: %v)", runErr))
		return rep, nil
	}
	var parsed testsslScanFile
	if jerr := json.Unmarshal(raw, &parsed); jerr != nil {
		// Some testssl.sh versions emit a top-level array, not an
		// object. Try the alternate shape.
		var altRows []testsslRow
		if a2 := json.Unmarshal(raw, &altRows); a2 == nil {
			for _, r := range altRows {
				if isProtocolID(r.ID) {
					rep.Protocols = append(rep.Protocols, TLSProtocolFinding(r.toProto()))
				} else {
					rep.Vulnerabilities = append(rep.Vulnerabilities, r.toVuln())
				}
			}
			rep.RawCount = len(altRows)
			return rep, nil
		}
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("json parse: %v", jerr))
		return rep, nil
	}
	for _, h := range parsed.ScanResult {
		for _, r := range h.Vulnerabilities {
			rep.Vulnerabilities = append(rep.Vulnerabilities, r.toVuln())
		}
		for _, r := range h.Protocols {
			rep.Protocols = append(rep.Protocols, TLSProtocolFinding(r.toProto()))
		}
		// Capture named cipher lists (cipherlist_SSLv2, cipherlist_3DES_IDEA, etc.)
		// The Finding field contains space-separated cipher suite names accepted by the server.
		for _, r := range h.Ciphers {
			if strings.HasPrefix(r.ID, "cipherlist_") && r.Finding != "" &&
				r.Finding != "not offered" && r.Finding != "-" {
				rep.CipherLists = append(rep.CipherLists, TLSCipherList{ID: r.ID, Finding: r.Finding})
			}
		}
		// Capture per-cipher rows from serverPreferences for weak cipher evidence.
		// Each row finding is: "TLSv1 xHHHH CIPHER-NAME   KEXCH bits  ENC bits  RFC-name"
		for _, r := range h.ServerPrefs {
			if strings.HasPrefix(r.ID, "cipher-") {
				rep.ServerCiphers = append(rep.ServerCiphers, TLSServerCipher{ID: r.ID, Finding: r.Finding})
			}
		}
	}
	rep.RawCount = len(rep.Vulnerabilities) + len(rep.Protocols)
	return rep, nil
}

func (r testsslRow) toVuln() TLSVulnFinding {
	return TLSVulnFinding{ID: r.ID, Severity: r.Severity, Finding: r.Finding, CVE: r.CVE}
}
func (r testsslRow) toProto() TLSProtocolFinding {
	return TLSProtocolFinding{ID: r.ID, Severity: r.Severity, Finding: r.Finding}
}

// isProtocolID returns true if the row id looks like a protocol row
// (SSLv2, SSLv3, TLS1, TLS1_1, TLS1_2, TLS1_3).
func isProtocolID(id string) bool {
	up := strings.ToUpper(id)
	return strings.HasPrefix(up, "SSLV") || strings.HasPrefix(up, "TLS1")
}

// testsslStartTLSArg maps a port.Service string to the testssl.sh
// --starttls=<proto> value. Returns "" if the service is direct-TLS
// (https, ssl/http, etc.) or unknown, in which case no flag is passed.
func testsslStartTLSArg(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "smtp", "smtps", "submission":
		return "smtp"
	case "ftp", "ftps":
		return "ftp"
	case "imap", "imaps":
		return "imap"
	case "pop3", "pop3s":
		return "pop3"
	case "ldap", "ldaps":
		return "ldap"
	case "mysql":
		return "mysql"
	case "postgresql", "postgres":
		return "postgres"
	case "xmpp", "xmpp-client", "xmpp-server", "jabber":
		return "xmpp"
	case "ms-wbt-server", "rdp":
		return "rdp"
	case "nntp", "nntps":
		return "nntp"
	}
	return ""
}

// TLSVulnBinaryAvailable reports whether testssl.sh resolves on PATH.
// Used by the phase runner to skip silently when the binary is absent.
func TLSVulnBinaryAvailable() bool {
	if _, err := exec.LookPath("testssl.sh"); err == nil {
		return true
	}
	if _, err := exec.LookPath("testssl"); err == nil {
		return true
	}
	// Some installs leave only the script at a known directory.
	for _, p := range []string{"/opt/testssl.sh/testssl.sh", "/usr/local/bin/testssl.sh"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

