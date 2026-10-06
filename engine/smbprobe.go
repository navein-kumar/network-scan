// smbprobe.go: phase 3 driver for SMB (replaces nmap smb-os-discovery,
// smb-security-mode, smb-protocols, and the unauthenticated part of `nxc smb`).
//
// Uses jfjallid/go-smb which speaks SMB2/3 natively. SMBv1 detection is a
// separate hand-rolled NEGOTIATE PROTOCOL probe (the library does not speak
// SMBv1). No shell-out to nmap/nxc.
package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

// SMBReport is what Phase 3 emits per SMB port (139 or 445).
type SMBReport struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	Dialect          string   `json:"dialect"`
	OS               string   `json:"os,omitempty"`
	OSVersion        string   `json:"os_version,omitempty"`      // e.g. "Windows NT 10.0 Build 17763"
	WindowsBuild     int      `json:"windows_build,omitempty"`   // e.g. 17763
	NetBIOSName      string   `json:"netbios_name,omitempty"`
	DNSName          string   `json:"dns_name,omitempty"`
	Domain           string   `json:"domain,omitempty"`
	SigningRequired  bool     `json:"signing_required"`
	NullSession      bool     `json:"null_session"`
	SMBv1Enabled     bool     `json:"smbv1_enabled"`
	Shares           []string      `json:"shares,omitempty"`
	CredAttempts     []CredAttempt `json:"cred_attempts,omitempty"`
	ProbeErrors      []string      `json:"probe_errors,omitempty"`
}

// smbBuildRe extracts the numeric build from go-smb's GuessedOSVersion
// string, formatted as "Windows NT <maj>.<min> Build <build>".
var smbBuildRe = regexp.MustCompile(`Build (\d{3,6})`)

// enumSMBShares lists the server's shares via srvsvc NetShareEnumAll over the
// existing (null/guest) session. Best-effort: returns nil on any failure and
// recovers from library panics so a hostile server cannot crash the scan.
func enumSMBShares(conn *smb.Connection, host string) (out []string) {
	defer func() { _ = recover() }()
	const ipc = "IPC$"
	if err := conn.TreeConnect(ipc); err != nil {
		return nil
	}
	defer conn.TreeDisconnect(ipc)
	f, err := conn.OpenFile(ipc, mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		return nil
	}
	defer f.CloseFile()
	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return nil
	}
	bind, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc,
		mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion,
		dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil
	}
	rpccon := mssrvs.NewRPCCon(bind)
	shares, err := rpccon.NetShareEnumAll(host)
	if err != nil {
		return nil
	}
	for _, s := range shares {
		entry := s.Name
		if s.Comment != "" {
			entry += " - " + s.Comment
		}
		out = append(out, entry)
		if len(out) >= 50 {
			break
		}
	}
	return out
}

// ProbeSMB does NEGOTIATE + null-session probe + a separate SMB1 probe.
func ProbeSMB(host string, port int, timeout time.Duration) (*SMBReport, error) {
	rep := &SMBReport{Host: host, Port: port}

	// ── Step 1: SMB2/3 negotiate + null-session attempt ───────────────
	opts := smb.Options{
		Host:        host,
		Port:        port,
		DialTimeout: timeout,
		Initiator: &spnego.NTLMInitiator{
			NullSession: true,
		},
	}
	conn, err := smb.NewConnection(opts)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("smb2_negotiate: %v", err))
	} else {
		defer conn.Close()
		rep.SigningRequired = conn.IsSigningRequired()
		rep.NullSession = conn.IsAuthenticated()
		// best-effort: the library negotiates dialect inside NewConnection
		// but doesn't expose a "negotiated dialect" getter on all versions.
		// We just mark "SMB2/3" since NewConnection succeeded.
		rep.Dialect = "SMB2/3"
		// Windows build + hostname/domain from NTLMSSP CHALLENGE Version and
		// TargetInfo AVPairs. go-smb parses these during SessionSetup.
		if ti := conn.GetTargetInfo(); ti != nil {
			rep.OSVersion = ti.GuessedOSVersion
			if m := smbBuildRe.FindStringSubmatch(ti.GuessedOSVersion); len(m) == 2 {
				if n, err := strconv.Atoi(m[1]); err == nil {
					rep.WindowsBuild = n
				}
			}
			if ti.NBComputerName != "" && rep.NetBIOSName == "" {
				rep.NetBIOSName = ti.NBComputerName
			}
			if ti.DnsComputerName != "" && rep.DNSName == "" {
				rep.DNSName = ti.DnsComputerName
			}
			if ti.DnsDomainName != "" && rep.Domain == "" {
				rep.Domain = ti.DnsDomainName
			}
		}
		// Enumerate shares over the null/guest session so the evidence
		// shows the actual exposed shares (like the smbclient -L output).
		rep.Shares = enumSMBShares(conn, host)
	}

	// ── Step 2: dedicated SMBv1 detection ──────────────────────────────
	v1, v1err := probeSMBv1(host, port, timeout)
	if v1err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("smb1_probe: %v", v1err))
	}
	rep.SMBv1Enabled = v1

	return rep, nil
}

// probeSMBv1 sends an SMB1 NEGOTIATE PROTOCOL request and returns true
// if the server responds positively (any SMB1 dialect accepted).
func probeSMBv1(host string, port int, timeout time.Duration) (bool, error) {
	dialects := []string{
		"PC NETWORK PROGRAM 1.0",
		"LANMAN1.0",
		"LM1.2X002",
		"NT LANMAN 1.0",
		"NT LM 0.12",
	}
	var byteCount int
	var dialectBytes []byte
	for _, d := range dialects {
		dialectBytes = append(dialectBytes, 0x02)
		dialectBytes = append(dialectBytes, []byte(d)...)
		dialectBytes = append(dialectBytes, 0x00)
		byteCount += 2 + len(d)
	}

	smbHeader := []byte{
		0xff, 'S', 'M', 'B',
		0x72,
		0x00, 0x00, 0x00, 0x00,
		0x18,
		0x53, 0xc8,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x2f, 0x4b,
		0x00, 0x00,
		0xc5, 0x5e,
	}
	body := []byte{0x00, byte(byteCount), byte(byteCount >> 8)}
	body = append(body, dialectBytes...)
	smbBody := append(smbHeader, body...)
	totalLen := len(smbBody)
	nbt := []byte{0x00, 0x00, byte(totalLen >> 8), byte(totalLen)}
	pkt := append(nbt, smbBody...)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(pkt); err != nil {
		return false, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, fmt.Errorf("read: %w", err)
	}
	if n < 36 {
		return false, fmt.Errorf("response too short: %d bytes", n)
	}
	if !(buf[4] == 0xff && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B') {
		return false, nil
	}
	if buf[8] != 0x72 {
		return false, nil
	}
	status := uint32(buf[9]) | uint32(buf[10])<<8 |
		uint32(buf[11])<<16 | uint32(buf[12])<<24
	return status == 0, nil
}
