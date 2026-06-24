// mysqlprobe.go: phase 3 driver for MySQL / MariaDB.
//
// Hand-rolled handshake parse per [Connection Phase Packets] in the MySQL
// internals manual. We connect, read the initial Handshake V10 packet, and
// extract:
//   - protocol version (1 byte)
//   - server version string (null-terminated)
//   - thread id (4 bytes LE)
//   - auth-plugin-data-part-1 (8 bytes)
//   - filler 0x00 (1 byte)
//   - capability flags low (2 bytes LE)
//   - charset (1 byte)
//   - status flags (2 bytes)
//   - capability flags high (2 bytes LE)
//   - auth-plugin-data-len (1 byte)
//   - reserved (10 bytes 0x00)
//   - auth-plugin-data-part-2 (max(13, auth-plugin-data-len - 8) bytes)
//   - auth-plugin-name (null-terminated, only if CLIENT_PLUGIN_AUTH)
//
// We do NOT authenticate; just parse the greeting then close.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// mysqlAuthOK reports whether the credential authenticates, using the
// go-sql-driver. The driver speaks caching_sha2_password (the MySQL 8+
// default), which the hand-rolled mysql_native_password path cannot do. A
// nil error means the login succeeded.
func mysqlAuthOK(host string, port int, user, pass string, timeout time.Duration) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=%s&readTimeout=%s",
		user, pass, host, port, timeout, timeout)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return db.PingContext(ctx)
}

// MySQLReport is what Phase 3 emits per MySQL port.
type MySQLReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	ProtocolVersion byte     `json:"protocol_version"`
	ServerVersion   string   `json:"server_version"`
	AuthPlugin      string   `json:"auth_plugin,omitempty"`
	SSLSupported    bool          `json:"ssl_supported"`
	CredAttempts    []CredAttempt `json:"cred_attempts,omitempty"`
	Databases       []string      `json:"databases,omitempty"`
	ProbeErrors     []string      `json:"probe_errors,omitempty"`
}

// MySQL capability flag we care about (CLIENT_SSL).
const mysqlClientSSL = 0x0800

// ProbeMySQL reads the initial handshake packet and parses it.
func ProbeMySQL(host string, port int, timeout time.Duration) (*MySQLReport, error) {
	rep := &MySQLReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Packet header: 3-byte LE length + 1-byte sequence id
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read header: %v", err))
		return rep, nil
	}
	pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if pktLen < 1 || pktLen > 16384 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("absurd packet length %d", pktLen))
		return rep, nil
	}
	body := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read body: %v", err))
		return rep, nil
	}

	// If server sends an error packet (first byte 0xff) instead of a
	// handshake, decode the error message.
	if len(body) > 0 && body[0] == 0xff {
		msg := ""
		if len(body) > 3 {
			msg = string(body[3:])
		}
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("server error packet: %s", msg))
		return rep, nil
	}

	// Parse Handshake V10.
	if len(body) < 1 {
		rep.ProbeErrors = append(rep.ProbeErrors, "empty handshake")
		return rep, nil
	}
	rep.ProtocolVersion = body[0]
	off := 1

	// Null-terminated server version
	nul := bytes.IndexByte(body[off:], 0x00)
	if nul < 0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"no terminator for server version")
		return rep, nil
	}
	rep.ServerVersion = string(body[off : off+nul])
	off += nul + 1

	// Thread id (4 bytes LE), auth-plugin-data-part-1 (8 bytes), filler (1 byte),
	// capability flags low (2 bytes LE).
	// Total: 4 + 8 + 1 + 2 = 15 bytes before we can read low caps.
	if len(body) < off+15 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"truncated handshake before capability flags")
		return rep, nil
	}
	off += 4 // thread id
	off += 8 // auth-plugin-data-part-1
	off++    // filler 0x00
	capLow := uint16(body[off]) | uint16(body[off+1])<<8
	off += 2

	// More-data section is present if there's at least one more byte.
	// charset (1) + status (2) + capability flags high (2) + auth-plugin-data-len (1)
	// + reserved (10) = 16 bytes; then auth-plugin-data-part-2 then plugin name.
	capHigh := uint16(0)
	authDataLen := byte(0)
	if len(body) >= off+16 {
		off++ // charset
		off += 2 // status flags
		capHigh = uint16(body[off]) | uint16(body[off+1])<<8
		off += 2
		authDataLen = body[off]
		off++
		off += 10 // reserved
	}
	caps := uint32(capLow) | uint32(capHigh)<<16
	rep.SSLSupported = caps&mysqlClientSSL != 0

	// auth-plugin-data-part-2 (max(13, authDataLen-8) bytes)
	if authDataLen > 0 {
		extra := int(authDataLen) - 8
		if extra < 13 {
			extra = 13
		}
		if off+extra > len(body) {
			return rep, nil
		}
		off += extra
	}

	// auth-plugin-name (null-terminated). Some servers omit the trailing 0.
	if off < len(body) {
		end := bytes.IndexByte(body[off:], 0x00)
		if end < 0 {
			rep.AuthPlugin = string(body[off:])
		} else {
			rep.AuthPlugin = string(body[off : off+end])
		}
	}
	return rep, nil
}

// mysqlListDatabasesWithLogin authenticates with a default credential that
// already succeeded and runs SHOW DATABASES as deep-content evidence.
// Best-effort and bounded: any connect or query error yields an empty slice.
func mysqlListDatabasesWithLogin(host string, port int, user, pass string, timeout time.Duration) []string {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=%s&readTimeout=%s",
		user, pass, host, port, timeout, timeout)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SHOW DATABASES")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var dbs []string
	const maxDBs = 100
	for rows.Next() {
		if len(dbs) >= maxDBs {
			break
		}
		var name string
		if err := rows.Scan(&name); err != nil {
			break
		}
		dbs = append(dbs, name)
	}
	return dbs
}
