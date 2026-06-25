// rdpprobe.go: phase 3 driver for RDP.
//
// Hand-crafted TPKT + X.224 Connection Request (RFC 1006 + ITU-T X.224 +
// MS-RDPBCGR §2.2.1.1). The grdp library is overkill for a fingerprint
// probe and pulls a lot of code. We send a CR PDU that includes the
// RDP_NEG_REQ block requesting all three security flavors (RDP standard,
// TLS, HYBRID/NLA, HYBRID_EX) and read the CC response.
//
// CC response shape (we care about RDP_NEG_RSP):
//
//   TPKT (4) | X.224 CC header (7) | optional RDP_NEG_RSP (8)
//
// RDP_NEG_RSP = type(1)=0x02 + flags(1) + length(2)=0x0008 + selectedProtocol(4)
//   selectedProtocol bitmask:
//     0x00 RDP standard security (no TLS)
//     0x01 TLS
//     0x02 HYBRID (CredSSP/NLA)
//     0x08 HYBRID_EX
//
// If the server replies with a RDP_NEG_FAILURE (type=0x03) we record the
// failure code instead.
//
// No M2 RDP target. Build is acceptance.
package main

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unicode/utf16"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

// RDPReport is what Phase 3 emits per RDP port.
type RDPReport struct {
	Host                string   `json:"host"`
	Port                int      `json:"port"`
	NLAEnabled          bool     `json:"nla_enabled"`
	TLSOffered          bool     `json:"tls_offered"`
	RDPSecurityOffered  bool     `json:"rdp_security_offered"`
	CredSSPOffered      bool     `json:"credssp_offered"`
	ProtocolFlags       uint32   `json:"protocol_flags"`
	// Deep-content leak from the pre-auth CredSSP/NTLM negotiation
	// (like nmap rdp-ntlm-info). Populated only when the server speaks
	// CredSSP/NLA and returns an NTLMSSP CHALLENGE.
	TargetName          string   `json:"target_name,omitempty"`
	DNSComputerName     string   `json:"dns_computer_name,omitempty"`
	DNSDomainName       string   `json:"dns_domain_name,omitempty"`
	NetbiosComputerName string   `json:"netbios_computer_name,omitempty"`
	NetbiosDomainName   string   `json:"netbios_domain_name,omitempty"`
	OSVersion           string   `json:"os_version,omitempty"`
	ScreenshotPath      string   `json:"screenshot_path,omitempty"`
	ProbeErrors         []string `json:"probe_errors,omitempty"`
}

// RDP_NEG_REQ flag bits per [MS-RDPBCGR] §2.2.1.1.1.
const (
	rdpProtoStandard = 0x00
	rdpProtoSSL      = 0x01
	rdpProtoHybrid   = 0x02 // CredSSP / NLA
	rdpProtoHybridEx = 0x08
)

// ProbeRDP sends an X.224 Connection Request and parses the response.
func ProbeRDP(host string, port int, timeout time.Duration) (*RDPReport, error) {
	rep := &RDPReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Build CR PDU with RDP_NEG_REQ asking for all 3 protocols.
	requested := uint32(rdpProtoSSL | rdpProtoHybrid | rdpProtoHybridEx)
	cr := buildX224CR(requested)
	if _, err := conn.Write(cr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write CR: %v", err))
		return rep, nil
	}

	// Read TPKT header (4 bytes) then the rest.
	tpkt := make([]byte, 4)
	if _, err := io.ReadFull(conn, tpkt); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read TPKT: %v", err))
		return rep, nil
	}
	if tpkt[0] != 0x03 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("not TPKT (got 0x%02x)", tpkt[0]))
		return rep, nil
	}
	totalLen := int(binary.BigEndian.Uint16(tpkt[2:4]))
	if totalLen < 4 || totalLen > 1024 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("absurd TPKT length %d", totalLen))
		return rep, nil
	}
	rest := make([]byte, totalLen-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read CC body: %v", err))
		return rep, nil
	}

	// rest = [length indicator (1)][CR code (1)][dstRef (2)][srcRef (2)][class (1)]
	//        + optional RDP_NEG_RSP (8 bytes) or RDP_NEG_FAILURE (8 bytes).
	if len(rest) < 7 {
		rep.ProbeErrors = append(rep.ProbeErrors, "CC header truncated")
		return rep, nil
	}
	// CC code = 0xD0, we don't strictly need to validate but log if off
	if rest[1] != 0xD0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("not CC (got 0x%02x)", rest[1]))
	}

	negOff := 7
	if len(rest) >= negOff+8 {
		negType := rest[negOff]
		switch negType {
		case 0x02: // RDP_NEG_RSP
			selected := binary.LittleEndian.Uint32(rest[negOff+4 : negOff+8])
			rep.ProtocolFlags = selected
			rep.TLSOffered = selected&rdpProtoSSL != 0
			rep.CredSSPOffered = selected&(rdpProtoHybrid|rdpProtoHybridEx) != 0
			rep.NLAEnabled = rep.CredSSPOffered
			rep.RDPSecurityOffered = selected == rdpProtoStandard
		case 0x03: // RDP_NEG_FAILURE
			code := binary.LittleEndian.Uint32(rest[negOff+4 : negOff+8])
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("RDP_NEG_FAILURE code=%d", code))
			// Failure code 2 = SSL_NOT_ALLOWED_BY_SERVER -> only standard
			// RDP security. Some classic Win2000/XP boxes do this.
			if code == 2 {
				rep.RDPSecurityOffered = true
			}
		default:
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("unknown neg type 0x%02x", negType))
		}
	} else {
		// No RDP_NEG_RSP at all -> server is bare RDP standard security
		rep.RDPSecurityOffered = true
	}

	// Deep-content: if the server selected SSL or CredSSP/HYBRID, upgrade the
	// existing socket to TLS and run the rdp-ntlm-info exchange to leak the
	// hostname/domain/OS build pre-auth. Best-effort: any failure here just
	// leaves the fields empty.
	if rep.TLSOffered || rep.CredSSPOffered {
		grabRDPNTLMInfo(conn, rep, timeout)
	}

	conn.Close()
	captureRDPScreenshot(host, port, rep, timeout)
	return rep, nil
}

// grabRDPNTLMInfo upgrades the negotiated RDP socket to TLS and performs a
// CredSSP TSRequest carrying an NTLMSSP NEGOTIATE (Type 1). It reads back the
// TSRequest, extracts the NTLMSSP CHALLENGE (Type 2) and decodes the target
// info (NetBIOS/DNS computer + domain names) and OS version. This mirrors nmap's
// rdp-ntlm-info. It never panics and never fails the parent probe.
func grabRDPNTLMInfo(conn net.Conn, rep *RDPReport, timeout time.Duration) {
	conn.SetDeadline(time.Now().Add(timeout))

	tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tconn.Handshake(); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("ntlm-info tls: %v", err))
		return
	}

	// Build NTLMSSP NEGOTIATE (Type 1). Reuse go-ntlmssp's exported builder.
	type1, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("ntlm-info type1: %v", err))
		return
	}

	// Wrap in a CredSSP TSRequest and send.
	if _, err := tconn.Write(encodeTSRequest(type1)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("ntlm-info write: %v", err))
		return
	}

	// Read the response TSRequest (one DER SEQUENCE). 4 KiB is ample.
	tconn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, err := tconn.Read(buf)
	if err != nil && n == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("ntlm-info read: %v", err))
		return
	}

	challenge, err := extractNTLMToken(buf[:n])
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("ntlm-info challenge: %v", err))
		return
	}

	parseNTLMChallenge(challenge, rep)
}

// tsRequest is the CredSSP TSRequest structure [MS-CSSP] §2.2.1. We only
// populate version + negoTokens for the initial NTLM NEGOTIATE round-trip.
//
//	TSRequest ::= SEQUENCE {
//	    version    [0] INTEGER,
//	    negoTokens [1] NegoData OPTIONAL,
//	    ...
//	}
//	NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
type tsRequest struct {
	Version    int           `asn1:"explicit,tag:0"`
	NegoTokens []negoDataElem `asn1:"explicit,optional,tag:1"`
}

type negoDataElem struct {
	NegoToken []byte `asn1:"explicit,tag:0"`
}

// encodeTSRequest DER-encodes a TSRequest carrying a single negoToken (the
// NTLMSSP message bytes). CredSSP version 6 is a safe baseline.
func encodeTSRequest(token []byte) []byte {
	req := tsRequest{
		Version:    6,
		NegoTokens: []negoDataElem{{NegoToken: token}},
	}
	b, err := asn1.Marshal(req)
	if err != nil {
		return nil
	}
	return b
}

// extractNTLMToken decodes a TSRequest and returns the first negoToken, which
// for the CHALLENGE round-trip holds the NTLMSSP Type 2 message.
func extractNTLMToken(der []byte) ([]byte, error) {
	var req tsRequest
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		return nil, err
	}
	if len(req.NegoTokens) == 0 || len(req.NegoTokens[0].NegoToken) == 0 {
		return nil, fmt.Errorf("no negoToken in TSRequest")
	}
	return req.NegoTokens[0].NegoToken, nil
}

// NTLMSSP CHALLENGE (Type 2) fixed header offsets [MS-NLMP] §2.2.1.2.
const (
	ntlmChallengeMinLen = 48
	ntlmFlagUnicode     = 0x00000001
	ntlmFlagVersion     = 0x02000000
	// AV_PAIR (MsvAv*) IDs [MS-NLMP] §2.2.2.1.
	avNbComputerName  = 0x0001
	avNbDomainName    = 0x0002
	avDNSComputerName = 0x0003
	avDNSDomainName   = 0x0004
)

// parseNTLMChallenge reads the TargetName, the Target Info AV_PAIR block and the
// optional Version field out of an NTLMSSP CHALLENGE and fills rep. It is
// defensive against truncation: anything malformed is simply skipped.
func parseNTLMChallenge(msg []byte, rep *RDPReport) {
	if len(msg) < ntlmChallengeMinLen {
		return
	}
	if string(msg[0:7]) != "NTLMSSP" || msg[7] != 0x00 {
		return
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 2 { // MessageType == CHALLENGE
		return
	}

	flags := binary.LittleEndian.Uint32(msg[20:24])
	unicode := flags&ntlmFlagUnicode != 0

	// TargetName field: Len(2) MaxLen(2) BufferOffset(4) at offset 12.
	tnLen := binary.LittleEndian.Uint16(msg[12:14])
	tnOff := binary.LittleEndian.Uint32(msg[16:20])
	if tnLen > 0 {
		if s, ok := readField(msg, tnOff, uint32(tnLen), unicode); ok {
			rep.TargetName = s
		}
	}

	// TargetInfo field at offset 40: Len(2) MaxLen(2) BufferOffset(4).
	tiLen := binary.LittleEndian.Uint16(msg[40:42])
	tiOff := binary.LittleEndian.Uint32(msg[44:48])
	if tiLen > 0 {
		parseTargetInfo(msg, tiOff, uint32(tiLen), rep)
	}

	// Version field at offset 48 (8 bytes) when the VERSION flag is set and the
	// header is long enough. major.minor.build -> "Windows x.y build z".
	if flags&ntlmFlagVersion != 0 && len(msg) >= ntlmChallengeMinLen+8 {
		major := msg[48]
		minor := msg[49]
		build := binary.LittleEndian.Uint16(msg[50:52])
		if major != 0 || minor != 0 || build != 0 {
			rep.OSVersion = fmt.Sprintf("Windows %d.%d build %d", major, minor, build)
		}
	}
}

// parseTargetInfo walks the AV_PAIR list and pulls the NetBIOS/DNS names.
func parseTargetInfo(msg []byte, off, length uint32, rep *RDPReport) {
	end := uint64(off) + uint64(length)
	if end > uint64(len(msg)) {
		return
	}
	ti := msg[off:end]
	for len(ti) >= 4 {
		id := binary.LittleEndian.Uint16(ti[0:2])
		l := binary.LittleEndian.Uint16(ti[2:4])
		if id == 0x0000 { // MsvAvEOL
			break
		}
		if int(l)+4 > len(ti) {
			break
		}
		val := ti[4 : 4+l]
		// AV_PAIR string values are always UTF-16LE.
		s := decodeUTF16LE(val)
		switch id {
		case avNbComputerName:
			rep.NetbiosComputerName = s
		case avNbDomainName:
			rep.NetbiosDomainName = s
		case avDNSComputerName:
			rep.DNSComputerName = s
		case avDNSDomainName:
			rep.DNSDomainName = s
		}
		ti = ti[4+l:]
	}
}

// readField slices a CHALLENGE field by offset/length and decodes it.
func readField(msg []byte, off, length uint32, unicode bool) (string, bool) {
	end := uint64(off) + uint64(length)
	if end > uint64(len(msg)) {
		return "", false
	}
	d := msg[off:end]
	if unicode {
		return decodeUTF16LE(d), true
	}
	return string(d), true
}

// decodeUTF16LE converts a UTF-16LE byte slice to a Go string. Odd-length input
// is truncated to the last whole code unit.
func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u))
}

// captureRDPScreenshot is a best-effort grab of the RDP login screen into a
// PNG. It shells out to scrying, the purpose-built pentest screenshotter, which
// drives an RDP/VNC/HTTP session headlessly and writes a PNG. If scrying is not
// installed or the capture fails, rep.ScreenshotPath is left empty and the
// probe is never failed by this step.
//
// scrying is preferred for RDP because a plain xfreerdp +auth-only probe does
// not render a framebuffer to disk. When scrying is absent there is no reliable
// CLI-only RDP screenshot path, so RDP capture is simply skipped.
func captureRDPScreenshot(host string, port int, rep *RDPReport, timeout time.Duration) {
	scry, err := exec.LookPath("scrying")
	if err != nil {
		return
	}

	dir := filepath.Join(os.TempDir(), "fastscan", "screenshots")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	base := fmt.Sprintf("rdp-login_%s_%d", sanitizeForFilename(host), port)
	pngPath := dir + "/" + base + ".png"

	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()

	// scrying --target rdp://host:port --file out.png runs one target headless.
	target := fmt.Sprintf("rdp://%s:%d", host, port)
	args := []string{"--target", target, "--file", pngPath}
	if err := exec.CommandContext(ctx, scry, args...).Run(); err != nil {
		os.Remove(pngPath)
		return
	}

	if fi, err := os.Stat(pngPath); err == nil && fi.Size() > 0 {
		rep.ScreenshotPath = pngPath
	} else {
		os.Remove(pngPath)
	}
}

// buildX224CR constructs a TPKT + X.224 Connection Request with an
// RDP_NEG_REQ asking for the requested protocols.
func buildX224CR(requested uint32) []byte {
	// RDP_NEG_REQ (8 bytes)
	neg := make([]byte, 8)
	neg[0] = 0x01 // type = RDP_NEG_REQ
	neg[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], requested)

	// X.224 CR header (7 bytes) + RDP_NEG_REQ (8)
	// length indicator = total CR length - 1 (X.224 quirk)
	x224 := make([]byte, 7+len(neg))
	x224[0] = byte(6 + len(neg)) // LI
	x224[1] = 0xE0               // CR code
	// dstRef, srcRef = 0; class = 0
	copy(x224[7:], neg)

	// TPKT (4 bytes) + X.224
	totalLen := 4 + len(x224)
	tpkt := make([]byte, 4)
	tpkt[0] = 0x03 // version
	tpkt[1] = 0x00 // reserved
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(totalLen))

	return append(tpkt, x224...)
}
