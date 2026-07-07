// credsauth_ext.go: default-credential auth primitives for protocols
// added beyond the original seven (ssh/ftp/mssql/mysql/postgresql/redis/winrm).
//
// Protocols covered here: smb, telnet, mongodb, ldap, vnc, snmp, couchdb.
package main

import (
	"bytes"
	"context"
	"crypto/des"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	gosnmp "github.com/gosnmp/gosnmp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
	mgodriver "go.mongodb.org/mongo-driver/mongo"
	mgopts "go.mongodb.org/mongo-driver/mongo/options"
)

// ── SMB ──────────────────────────────────────────────────────────────────────

// tryCredsSMB authenticates over SMB2/3 using NTLM with user:pass.
// An empty password is a valid test (null/guest session-style NTLM).
func tryCredsSMB(host string, port int, user, pass string, timeout time.Duration) error {
	opts := smb.Options{
		Host:        host,
		Port:        port,
		DialTimeout: timeout,
		Initiator: &spnego.NTLMInitiator{
			User:     user,
			Password: pass,
			Domain:   "",
		},
	}
	golog.SetLogLevel(golog.LevelNone)
	conn, err := smb.NewConnection(opts)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// ── Telnet ───────────────────────────────────────────────────────────────────

// tryCredsTelnet handles IAC negotiation, waits for a login prompt, sends
// user+pass, then checks the response for success/failure indicators.
func tryCredsTelnet(host string, port int, user, pass string, timeout time.Duration) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Phase 1: negotiate options and collect login prompt.
	var banner strings.Builder
	buf := make([]byte, 2048)
	for round := 0; round < 8; round++ {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			telnetStripAndReply(conn, chunk, &banner)
		}
		if telnetPromptLogin(banner.String()) {
			break
		}
		if err != nil {
			break
		}
	}
	if !telnetPromptLogin(banner.String()) {
		return fmt.Errorf("no login prompt detected")
	}

	// Phase 2: send username, wait for password prompt.
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "%s\r\n", user)

	banner.Reset()
	for round := 0; round < 4; round++ {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			telnetStripAndReply(conn, buf[:n], &banner)
		}
		if strings.Contains(strings.ToLower(banner.String()), "pass") {
			break
		}
		if err != nil {
			break
		}
	}
	if !strings.Contains(strings.ToLower(banner.String()), "pass") {
		return fmt.Errorf("no password prompt")
	}

	// Phase 3: send password, read response, classify.
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "%s\r\n", pass)

	banner.Reset()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)
	if n > 0 {
		telnetStripAndReply(conn, buf[:n], &banner)
	}
	resp := strings.ToLower(banner.String())
	if strings.Contains(resp, "incorrect") || strings.Contains(resp, "failed") ||
		strings.Contains(resp, "denied") || strings.Contains(resp, "invalid") ||
		strings.Contains(resp, "login:") || strings.Contains(resp, "username:") {
		return fmt.Errorf("authentication failed")
	}
	// Shell prompt or welcome message → success.
	if strings.ContainsAny(banner.String(), "$#>") ||
		strings.Contains(resp, "last login") ||
		strings.Contains(resp, "welcome") ||
		n > 0 {
		return nil
	}
	return fmt.Errorf("no response after credentials")
}

// telnetStripAndReply extracts printable text from an IAC stream into dst
// and writes DONT/WONT responses back on conn for every WILL/DO option.
func telnetStripAndReply(conn net.Conn, chunk []byte, dst *strings.Builder) {
	for i := 0; i < len(chunk); {
		if chunk[i] != 0xFF { // not IAC
			b := chunk[i]
			if b >= 0x20 && b < 0x7F || b == '\r' || b == '\n' || b == '\t' {
				dst.WriteByte(b)
			}
			i++
			continue
		}
		if i+1 >= len(chunk) {
			break
		}
		cmd := chunk[i+1]
		switch cmd {
		case 0xFB: // WILL → reply DONT
			if i+2 < len(chunk) {
				conn.Write([]byte{0xFF, 0xFE, chunk[i+2]})
				i += 3
			} else {
				i += 2
			}
		case 0xFD: // DO → reply WONT
			if i+2 < len(chunk) {
				conn.Write([]byte{0xFF, 0xFC, chunk[i+2]})
				i += 3
			} else {
				i += 2
			}
		case 0xFC, 0xFE: // WONT/DONT — no reply needed
			if i+2 < len(chunk) {
				i += 3
			} else {
				i += 2
			}
		case 0xFA: // SB — skip to IAC SE
			j := i + 2
			for j+1 < len(chunk) && !(chunk[j] == 0xFF && chunk[j+1] == 0xF0) {
				j++
			}
			i = j + 2
		default:
			i += 2
		}
	}
}

func telnetPromptLogin(banner string) bool {
	l := strings.ToLower(banner)
	return strings.Contains(l, "login:") || strings.Contains(l, "username:")
}

// ── MongoDB ──────────────────────────────────────────────────────────────────

// tryCredsMongoDB authenticates against admin database using SCRAM (the
// default for MongoDB 3.0+). Uses the official mongo-driver which handles
// SCRAM-SHA-1 and SCRAM-SHA-256 automatically.
func tryCredsMongoDB(host string, port int, user, pass string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	uri := fmt.Sprintf("mongodb://%s:%s@%s:%d/?authSource=admin",
		mongoEscape(user), mongoEscape(pass), host, port)
	client, err := mgodriver.Connect(ctx,
		mgopts.Client().
			ApplyURI(uri).
			SetConnectTimeout(timeout).
			SetServerSelectionTimeout(timeout))
	if err != nil {
		return err
	}
	defer client.Disconnect(context.Background())

	// Run listDatabases — requires authentication; fails with AuthenticationFailed if wrong.
	err = client.Database("admin").RunCommand(ctx,
		map[string]int{"listDatabases": 1}).Err()
	return err
}

// mongoEscape percent-encodes characters that are special in MongoDB URIs.
func mongoEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ':', '/', '?', '#', '[', ']', '@', '!', '$', '&', '\'',
			'(', ')', '*', '+', ',', ';', '=', '%':
			fmt.Fprintf(&b, "%%%02X", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ── LDAP ─────────────────────────────────────────────────────────────────────

// tryCredsLDAP tries a simple bind with the supplied user/pass. If the user
// looks like a plain name (no '=' or '@'), we also try common DN formats so
// the test covers both simple and traditional LDAP servers.
func tryCredsLDAP(host string, port int, user, pass string, timeout time.Duration) error {
	dialURL := fmt.Sprintf("ldap://%s:%d", host, port)
	l, err := ldap.DialURL(dialURL,
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return err
	}
	defer l.Close()
	l.SetTimeout(timeout)

	// Try the user field as-is (works for AD UPN and pre-formatted DNs).
	if err := l.Bind(user, pass); err == nil {
		return nil
	}

	// If it looks like a plain username, also try common DN wrappers.
	if !strings.Contains(user, "=") && !strings.Contains(user, "@") {
		if err := l.Bind("cn="+user+",dc=local", pass); err == nil {
			return nil
		}
		if err := l.Bind("uid="+user+",dc=local", pass); err == nil {
			return nil
		}
	}
	return fmt.Errorf("bind failed for user %q", user)
}

// ── VNC ──────────────────────────────────────────────────────────────────────

// tryCredsVNC performs VNC Authentication (security type 2): DES-ECB with a
// bit-reversed key derived from the password (padded/truncated to 8 bytes).
// The user field is ignored — VNC has no username concept.
func tryCredsVNC(host string, port int, _ /*user*/ string, pass string, timeout time.Duration) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// 1. Read server version (12 bytes: "RFB xxx.yyy\n").
	ver := make([]byte, 12)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return fmt.Errorf("read server version: %w", err)
	}
	if !bytes.HasPrefix(ver, []byte("RFB ")) {
		return fmt.Errorf("not a VNC server")
	}
	// Reply with the same version string.
	if _, err := conn.Write(ver); err != nil {
		return err
	}

	// 2. Security types list (RFB 3.7+): 1-byte count, then type bytes.
	//    RFB 3.3 uses a 4-byte security type directly.
	secHdr := make([]byte, 1)
	if _, err := io.ReadFull(conn, secHdr); err != nil {
		return fmt.Errorf("read security header: %w", err)
	}
	count := int(secHdr[0])
	if count == 0 {
		return fmt.Errorf("server rejected connection")
	}
	types := make([]byte, count)
	if _, err := io.ReadFull(conn, types); err != nil {
		return fmt.Errorf("read security types: %w", err)
	}
	// Find VNC Authentication (type 2).
	hasVNCAuth := false
	for _, t := range types {
		if t == 2 {
			hasVNCAuth = true
			break
		}
	}
	if !hasVNCAuth {
		return fmt.Errorf("VNC auth not offered (types: %v)", types)
	}
	// Select security type 2.
	if _, err := conn.Write([]byte{2}); err != nil {
		return err
	}

	// 3. Server sends 16-byte challenge.
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}

	// 4. Encrypt with bit-reversed DES key.
	key := vncDESKey(pass)
	block, err := des.NewCipher(key)
	if err != nil {
		return fmt.Errorf("DES cipher: %w", err)
	}
	response := make([]byte, 16)
	block.Encrypt(response[:8], challenge[:8])
	block.Encrypt(response[8:], challenge[8:])
	if _, err := conn.Write(response); err != nil {
		return err
	}

	// 5. Server sends 4-byte auth result: 0 = OK.
	result := make([]byte, 4)
	if _, err := io.ReadFull(conn, result); err != nil {
		return fmt.Errorf("read auth result: %w", err)
	}
	if binary.BigEndian.Uint32(result) == 0 {
		return nil
	}
	return fmt.Errorf("VNC authentication failed")
}

// vncDESKey returns an 8-byte DES key with each byte's bits reversed,
// as required by the VNC DES challenge-response protocol.
func vncDESKey(password string) []byte {
	key := make([]byte, 8)
	copy(key, []byte(password))
	for i, b := range key {
		var r byte
		for bit := 0; bit < 8; bit++ {
			if b&(1<<uint(bit)) != 0 {
				r |= 1 << uint(7-bit)
			}
		}
		key[i] = r
	}
	return key
}

// ── SNMP ─────────────────────────────────────────────────────────────────────

// tryCredsSNMP tests an SNMP community string. The user field is ignored —
// SNMPv1/v2c auth is community-string only.
func tryCredsSNMP(host string, port int, _ /*user*/ string, pass string, timeout time.Duration) error {
	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: pass,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   0,
	}
	if err := g.Connect(); err != nil {
		return err
	}
	defer g.Conn.Close()

	// sysDescr.0 — readable on any SNMP agent; auth error → wrong community.
	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"})
	if err != nil {
		return err
	}
	if result.Error == gosnmp.NoError {
		return nil
	}
	return fmt.Errorf("SNMP error %v with community %q", result.Error, pass)
}

// ── CouchDB ──────────────────────────────────────────────────────────────────

// tryCredsCouchDB authenticates against CouchDB's /_session endpoint using
// JSON Basic-style POST (CouchDB native auth). Falls back to HTTP Basic
// against /_up (admin-only endpoint) for older CouchDB deployments.
func tryCredsCouchDB(host string, port int, user, pass string, timeout time.Duration) error {
	scheme := "http"
	if port == 6984 {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	client := &http.Client{Timeout: timeout}

	// Try /_session POST (CouchDB 1.x / 2.x / 3.x).
	body := fmt.Sprintf(`{"name":%q,"password":%q}`, user, pass)
	req, err := http.NewRequest("POST", base+"/_session", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var result struct {
				OK bool `json:"ok"`
			}
			if jerr := json.NewDecoder(resp.Body).Decode(&result); jerr == nil && result.OK {
				return nil
			}
		}
		io.Copy(io.Discard, resp.Body)
	}

	// Fallback: HTTP Basic against /_all_dbs (requires reader perms).
	req2, err := http.NewRequest("GET", base+"/_all_dbs", nil)
	if err != nil {
		return err
	}
	req2.SetBasicAuth(user, pass)
	resp2, err := client.Do(req2)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode == 200 {
		return nil
	}
	return fmt.Errorf("status %d", resp2.StatusCode)
}
