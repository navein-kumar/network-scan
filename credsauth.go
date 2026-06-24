// credsauth.go: per-service authentication primitives used by creds.go.
//
// Each tryCredsXxx attempts a single user:pass against host:port within
// the given timeout. Returns nil on success, an error describing the
// failure otherwise. The functions are hand-rolled where the wire
// format is small (Redis, MySQL, PostgreSQL, FTP, MSSQL pre-login,
// WinRM) and use golang.org/x/crypto/ssh for SSH.
//
// VNC (DES challenge/response) and IPMI (RAKP) are intentionally out of
// scope for v0: their crypto handshakes are too fiddly relative to the
// payoff, and the existing IPMI cipher-zero finding already covers the
// realistic IPMI default-creds exposure path.
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// md5New returns a fresh md5 hash for tryCredsPostgreSQL MD5 auth.
func md5New() hash.Hash { return md5.New() }

// tryCredsSSH dials SSH with password auth, requiring a clean banner
// exchange. Returns nil on accepted login.
func tryCredsSSH(host string, port int, user, pass string, timeout time.Duration) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// tryCredsFTP runs the minimal USER/PASS exchange. 230 = login OK.
// Anything else (530, 421, ...) is treated as a failure.
func tryCredsFTP(host string, port int, user, pass string, timeout time.Duration) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	// Banner
	if _, err := readFTPLine(r); err != nil {
		return fmt.Errorf("banner: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "USER %s\r\n", user); err != nil {
		return err
	}
	line, err := readFTPLine(r)
	if err != nil {
		return err
	}
	// 230 accept w/o pass; 331 need pass; everything else = no.
	if strings.HasPrefix(line, "230") {
		return nil
	}
	if !strings.HasPrefix(line, "331") && !strings.HasPrefix(line, "332") {
		return fmt.Errorf("USER rejected: %s", strings.TrimSpace(line))
	}
	if _, err := fmt.Fprintf(conn, "PASS %s\r\n", pass); err != nil {
		return err
	}
	line, err = readFTPLine(r)
	if err != nil {
		return err
	}
	if strings.HasPrefix(line, "230") {
		return nil
	}
	return fmt.Errorf("PASS rejected: %s", strings.TrimSpace(line))
}

func readFTPLine(r *bufio.Reader) (string, error) {
	// FTP responses can be multi-line; first three chars repeat with a
	// space on the terminator line. For the auth dance, the first line
	// is enough to classify accept/reject.
	return r.ReadString('\n')
}

// tryCredsMSSQL validates a SQL Server credential. It first tries the small
// hand-rolled LOGIN7 path (fast, and enough for servers that allow
// unencrypted login), then falls back to the go-mssqldb driver, which does
// the TLS pre-login handshake that modern SQL Server (2022+) mandates.
func tryCredsMSSQL(host string, port int, user, pass string, timeout time.Duration) error {
	if err := tryCredsMSSQLNative(host, port, user, pass, timeout); err == nil {
		return nil
	}
	return mssqlAuthOK(host, port, user, pass, timeout)
}

// tryCredsMSSQLNative sends a TDS PRELOGIN + LOGIN7 packet containing the
// credentials. Success = LOGINACK token (0xAD) anywhere in the
// response. Failure surface = ERROR token (0xAA) with state explaining
// "Login failed". This is a minimal, hand-rolled login that skips
// TLS/encryption negotiation, so it only works against servers
// configured for unencrypted auth (or with encryption optional).
func tryCredsMSSQLNative(host string, port int, user, pass string, timeout time.Duration) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// PRELOGIN packet. Borrowed from existing mssqlprobe.go pattern.
	prelogin := buildMSSQLPrelogin()
	if _, err := conn.Write(prelogin); err != nil {
		return err
	}
	if _, err := readMSSQLPacket(conn); err != nil {
		return fmt.Errorf("read prelogin: %w", err)
	}

	// LOGIN7 packet with cleartext-ish password (XOR 0xA5A5 + swap nibbles).
	login := buildMSSQLLogin7(user, pass)
	if _, err := conn.Write(login); err != nil {
		return err
	}
	resp, err := readMSSQLPacket(conn)
	if err != nil {
		return fmt.Errorf("read login resp: %w", err)
	}
	// Scan token stream for LOGINACK (0xAD) vs ERROR (0xAA).
	for i := 0; i < len(resp); i++ {
		switch resp[i] {
		case 0xAD:
			return nil
		case 0xAA:
			return fmt.Errorf("login failed")
		}
	}
	return fmt.Errorf("no LOGINACK in response")
}

func readMSSQLPacket(c net.Conn) ([]byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < 8 || length > 65535 {
		return nil, fmt.Errorf("absurd pkt length %d", length)
	}
	body := make([]byte, length-8)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, err
	}
	return body, nil
}

func buildMSSQLPrelogin() []byte {
	// Minimal PRELOGIN: VERSION + TERMINATOR. 13 bytes options block +
	// 6 bytes version data.
	opts := []byte{
		0x00, 0x00, 0x1A, 0x00, 0x06, // VERSION at offset 0x1A, length 6
		0xFF, // TERMINATOR
	}
	versionData := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	body := append(opts, versionData...)
	hdr := []byte{
		0x12, 0x01, // type=prelogin, status=EOM
		0x00, 0x00, // length placeholder
		0x00, 0x00, // SPID
		0x00,       // packet ID
		0x00,       // window
	}
	total := len(hdr) + len(body)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	return append(hdr, body...)
}

// buildMSSQLLogin7 builds a TDS LOGIN7 packet. Layout per [MS-TDS] §2.2.6.4.
func buildMSSQLLogin7(user, pass string) []byte {
	hostname := "fastscan"
	appname := "fastscan"
	servername := ""
	libname := "fastscan"
	language := ""
	database := ""
	clientID := []byte{0, 0, 0, 0, 0, 0}

	// Encode hostname, username, password (obfuscated), appname,
	// servername, libname, language, database as UCS-2 LE.
	hostU := toUCS2(hostname)
	userU := toUCS2(user)
	passU := obfuscateMSSQLPassword(pass)
	appU := toUCS2(appname)
	servU := toUCS2(servername)
	libU := toUCS2(libname)
	langU := toUCS2(language)
	dbU := toUCS2(database)

	const fixedLen = 86 // length of the fixed login header before var-len data
	// offsets are character counts, lengths are character counts.
	offset := uint16(fixedLen)
	var data []byte
	type seg struct {
		bytes []byte
		chars int
	}
	segs := []seg{
		{hostU, len(hostname)},
		{userU, len(user)},
		{passU, len(pass)},
		{appU, len(appname)},
		{servU, len(servername)},
		{nil, 0}, // extension
		{libU, len(libname)},
		{langU, len(language)},
		{dbU, len(database)},
	}
	offsetTable := make([]byte, 0, len(segs)*4)
	for _, s := range segs {
		offsetTable = binary.LittleEndian.AppendUint16(offsetTable, offset)
		offsetTable = binary.LittleEndian.AppendUint16(offsetTable, uint16(s.chars))
		data = append(data, s.bytes...)
		offset += uint16(len(s.bytes))
	}

	totalLen := fixedLen + len(data)

	body := make([]byte, 0, totalLen)
	body = binary.LittleEndian.AppendUint32(body, uint32(totalLen)) // length
	body = append(body, 0x02, 0x00, 0x09, 0x72)                     // TDS 7.1 version
	body = binary.LittleEndian.AppendUint32(body, 0x1000)           // packet size
	body = binary.LittleEndian.AppendUint32(body, 0)                // client prog ver
	body = binary.LittleEndian.AppendUint32(body, 0)                // PID
	body = binary.LittleEndian.AppendUint32(body, 0)                // connection ID
	body = append(body, 0xE0, 0x00, 0x00, 0x00)                     // option flags
	body = binary.LittleEndian.AppendUint32(body, 0)                // client TZ
	body = binary.LittleEndian.AppendUint32(body, 0)                // client LCID

	// offsetTable: 4 bytes per segment × 9 = 36 bytes
	body = append(body, offsetTable...)

	// ClientID
	body = append(body, clientID...)
	// SSPI long
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint16(body, 0)
	// attach DB file
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint16(body, 0)

	body = append(body, data...)

	// Wrap in TDS packet header (type=0x10 LOGIN7)
	pktHdr := []byte{
		0x10, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00,
		0x00,
	}
	total := len(pktHdr) + len(body)
	binary.BigEndian.PutUint16(pktHdr[2:4], uint16(total))
	return append(pktHdr, body...)
}

func toUCS2(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// obfuscateMSSQLPassword XORs each UCS-2 byte with 0xA5 then swaps
// nibbles. Standard TDS password obfuscation per [MS-TDS] §2.2.6.4.
func obfuscateMSSQLPassword(pass string) []byte {
	u := toUCS2(pass)
	for i, b := range u {
		b = (b<<4 | b>>4) & 0xFF
		u[i] = b ^ 0xA5
	}
	return u
}

// tryCredsMySQL validates a MySQL credential. It first tries the hand-rolled
// mysql_native_password handshake (fast, and what MySQL 5.x uses), then falls
// back to the go-sql-driver, which speaks caching_sha2_password, the MySQL 8+
// default that the hand-rolled path does not implement.
func tryCredsMySQL(host string, port int, user, pass string, timeout time.Duration) error {
	if err := tryCredsMySQLNative(host, port, user, pass, timeout); err == nil {
		return nil
	}
	return mysqlAuthOK(host, port, user, pass, timeout)
}

// tryCredsMySQLNative performs the native MySQL handshake response with
// mysql_native_password (SHA1 challenge-response). Returns nil on
// OK_Packet (0x00), error on ERR_Packet (0xFF).
func tryCredsMySQLNative(host string, port int, user, pass string, timeout time.Duration) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Read handshake packet
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	plen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq := hdr[3]
	body := make([]byte, plen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return err
	}
	if len(body) < 1 || body[0] == 0xFF {
		return fmt.Errorf("server rejected pre-auth")
	}
	if body[0] != 0x0A {
		return fmt.Errorf("unexpected protocol version 0x%02x", body[0])
	}

	// Parse handshake to extract challenge salt and auth plugin name.
	pos := 1
	// server version (null-terminated)
	nul := indexByteFrom(body, 0x00, pos)
	if nul < 0 {
		return fmt.Errorf("bad handshake: no server version null")
	}
	pos = nul + 1
	if pos+4 > len(body) {
		return fmt.Errorf("bad handshake: truncated")
	}
	pos += 4 // thread id
	if pos+8 > len(body) {
		return fmt.Errorf("bad handshake: salt1")
	}
	salt1 := body[pos : pos+8]
	pos += 8
	pos++ // filler
	// capability lower
	if pos+2 > len(body) {
		return fmt.Errorf("bad handshake: cap lo")
	}
	capLo := uint16(body[pos]) | uint16(body[pos+1])<<8
	pos += 2
	// charset + status + cap hi + auth plugin data len + 10 byte reserved
	var salt2 []byte
	var pluginName string
	if pos < len(body) {
		pos++ // charset
		pos += 2 // status
		var capHi uint16
		if pos+2 <= len(body) {
			capHi = uint16(body[pos]) | uint16(body[pos+1])<<8
			pos += 2
		}
		caps := uint32(capLo) | uint32(capHi)<<16
		var authDataLen int
		if pos < len(body) {
			authDataLen = int(body[pos])
			pos++
		}
		pos += 10 // reserved
		// salt2: max(13, authDataLen - 8) bytes including trailing null
		salt2Len := 12
		if authDataLen-8 > 12 {
			salt2Len = authDataLen - 8 - 1
		}
		if pos+salt2Len > len(body) {
			salt2Len = len(body) - pos
		}
		if salt2Len > 0 {
			salt2 = body[pos : pos+salt2Len]
			pos += salt2Len
		}
		// Skip the trailing null in salt2 area if any
		if pos < len(body) && body[pos] == 0 {
			pos++
		}
		if (caps & 0x00080000) != 0 { // CLIENT_PLUGIN_AUTH
			if pos < len(body) {
				end := indexByteFrom(body, 0x00, pos)
				if end < 0 {
					end = len(body)
				}
				pluginName = string(body[pos:end])
			}
		}
		_ = pluginName
	}
	salt := append(append([]byte{}, salt1...), salt2...)
	// Trim trailing null bytes from salt
	for len(salt) > 0 && salt[len(salt)-1] == 0 {
		salt = salt[:len(salt)-1]
	}

	// Build client capability flags. CLIENT_PROTOCOL_41 |
	// CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH |
	// CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_TRANSACTIONS
	clientFlags := uint32(0x00000001 | 0x00000004 | 0x00000200 | 0x00000400 |
		0x00008000 | 0x00080000)

	// Build mysql_native_password hash: SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass)))
	var authResp []byte
	if pass != "" {
		h1 := sha1Sum([]byte(pass))
		h2 := sha1Sum(h1)
		h3 := sha1Sum(append(append([]byte{}, salt...), h2...))
		authResp = make([]byte, 20)
		for i := 0; i < 20; i++ {
			authResp[i] = h1[i] ^ h3[i]
		}
	}

	// Build response packet
	resp := make([]byte, 0, 64+len(user)+len(authResp))
	resp = binary.LittleEndian.AppendUint32(resp, clientFlags)
	resp = binary.LittleEndian.AppendUint32(resp, 0x01000000) // max packet
	resp = append(resp, 33)                                   // charset utf8
	resp = append(resp, make([]byte, 23)...)                  // reserved
	resp = append(resp, []byte(user)...)
	resp = append(resp, 0)
	resp = append(resp, byte(len(authResp)))
	resp = append(resp, authResp...)
	resp = append(resp, []byte("mysql_native_password")...)
	resp = append(resp, 0)

	// Wrap with length+seq
	respHdr := []byte{
		byte(len(resp)), byte(len(resp) >> 8), byte(len(resp) >> 16),
		seq + 1,
	}
	if _, err := conn.Write(append(respHdr, resp...)); err != nil {
		return err
	}

	// Read response
	hdr2 := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr2); err != nil {
		return err
	}
	rlen := int(hdr2[0]) | int(hdr2[1])<<8 | int(hdr2[2])<<16
	rbody := make([]byte, rlen)
	if _, err := io.ReadFull(conn, rbody); err != nil {
		return err
	}
	if len(rbody) == 0 {
		return fmt.Errorf("empty response")
	}
	switch rbody[0] {
	case 0x00: // OK
		return nil
	case 0xFF: // ERR
		msg := ""
		if len(rbody) > 9 {
			msg = string(rbody[9:])
		}
		return fmt.Errorf("ERR: %s", msg)
	case 0xFE:
		// Auth switch - we only support native; treat as failure.
		return fmt.Errorf("auth switch requested")
	default:
		return fmt.Errorf("unexpected response 0x%02x", rbody[0])
	}
}

func indexByteFrom(b []byte, c byte, from int) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func sha1Sum(b []byte) []byte {
	h := sha1.New()
	h.Write(b)
	return h.Sum(nil)
}

// tryCredsPostgreSQL sends a StartupMessage followed by PasswordMessage
// (cleartext or MD5). AuthenticationOk = success, ErrorResponse =
// failure. SCRAM-SHA-256 is not implemented; servers that require it
// will surface as an error.
func tryCredsPostgreSQL(host string, port int, user, pass string, timeout time.Duration) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// StartupMessage: int32 length, int32 protocol (196608),
	// key/value pairs, terminator.
	params := []string{"user", user, "database", user, "client_encoding", "UTF8", ""}
	var buf []byte
	for _, s := range params {
		buf = append(buf, []byte(s)...)
		buf = append(buf, 0)
	}
	msg := make([]byte, 0, 8+len(buf))
	msg = binary.BigEndian.AppendUint32(msg, uint32(8+len(buf)))
	msg = binary.BigEndian.AppendUint32(msg, 196608)
	msg = append(msg, buf...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}

	for {
		// Each backend message: 1 byte type, 4 byte length (including self), body.
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return err
		}
		mtype := hdr[0]
		mlen := int(binary.BigEndian.Uint32(hdr[1:5]))
		if mlen < 4 || mlen > 65535 {
			return fmt.Errorf("absurd msg len %d", mlen)
		}
		body := make([]byte, mlen-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return err
		}
		switch mtype {
		case 'R': // Authentication request
			if len(body) < 4 {
				return fmt.Errorf("short auth msg")
			}
			authType := binary.BigEndian.Uint32(body[:4])
			switch authType {
			case 0: // AuthenticationOk
				return nil
			case 3: // CleartextPassword
				if err := sendPGPassword(conn, []byte(pass)); err != nil {
					return err
				}
			case 5: // MD5Password
				if len(body) < 8 {
					return fmt.Errorf("md5 salt missing")
				}
				salt := body[4:8]
				// md5( md5(pass + user) + salt ) prefixed with "md5"
				inner := md5Hex([]byte(pass + user))
				outer := md5Hex(append([]byte(inner), salt...))
				token := "md5" + outer
				if err := sendPGPassword(conn, []byte(token)); err != nil {
					return err
				}
			case 10: // SASL (SCRAM-SHA-256), the PostgreSQL 10+ default.
				// Not hand-rolled here; hand the credential to the lib/pq
				// driver which implements SCRAM, and stop this exchange.
				conn.Close()
				return postgresAuthOK(host, port, user, pass, timeout)
			default:
				return fmt.Errorf("unsupported auth type %d", authType)
			}
		case 'E': // ErrorResponse
			return fmt.Errorf("server error: %s", parsePGError(body))
		default:
			// Ignore other startup messages (S, K, Z) - keep reading.
			if mtype == 'Z' { // ReadyForQuery - we authed
				return nil
			}
		}
	}
}

func sendPGPassword(conn net.Conn, pass []byte) error {
	body := append(append([]byte{}, pass...), 0)
	msg := []byte{'p'}
	msg = binary.BigEndian.AppendUint32(msg, uint32(4+len(body)))
	msg = append(msg, body...)
	_, err := conn.Write(msg)
	return err
}

func parsePGError(body []byte) string {
	var parts []string
	i := 0
	for i < len(body) {
		if body[i] == 0 {
			break
		}
		end := indexByteFrom(body, 0x00, i+1)
		if end < 0 {
			end = len(body)
		}
		if end > i+1 {
			parts = append(parts, string(body[i+1:end]))
		}
		i = end + 1
	}
	return strings.Join(parts, "; ")
}

// md5Hex returns hex(md5(b)) without importing crypto/md5 directly
// twice. Just wraps crypto/md5.
func md5Hex(b []byte) string {
	h := md5New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// tryCredsRedis: send AUTH command, check +OK reply. Empty pass with no
// auth required returns "+PONG" on PING which also counts as success
// (the server has no password set at all - critical finding).
func tryCredsRedis(host string, port int, user, pass string, timeout time.Duration) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// If pass is empty, just send PING.
	if pass == "" && user == "" {
		if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
			return err
		}
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		reply := string(buf[:n])
		if strings.HasPrefix(reply, "+PONG") {
			return nil // no auth required
		}
		return fmt.Errorf("auth required: %s", strings.TrimSpace(reply))
	}

	// Send AUTH. Use RESP array. Redis 6+ supports two-arg AUTH user pass.
	var cmd string
	if user != "" {
		cmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			len(user), user, len(pass), pass)
	} else {
		cmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n",
			len(pass), pass)
	}
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	reply := string(buf[:n])
	if strings.HasPrefix(reply, "+OK") {
		return nil
	}
	return fmt.Errorf("AUTH rejected: %s", strings.TrimSpace(reply))
}

// tryCredsWinRM POSTs an empty SOAP envelope with Basic auth. 200 or
// 500 (WS-Management fault from authenticated session) = creds
// accepted; 401 = rejected.
func tryCredsWinRM(host string, port int, user, pass string, timeout time.Duration) error {
	scheme := "http"
	if port == 5986 || port == 443 {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%d", host, port), Path: "/wsman"}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequest("POST", u.String(), strings.NewReader(""))
	if err != nil {
		return err
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case 401:
		return fmt.Errorf("401 unauthorized")
	case 200, 500:
		// 500 = SOAP fault from authenticated WSMan session ("missing
		// required header" etc.) Still indicates accepted creds.
		return nil
	default:
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}
