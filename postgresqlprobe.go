// postgresqlprobe.go: phase 3 driver for PostgreSQL.
//
// Two-step probe (no auth completed):
//   1. SSLRequest: 8-byte packet 00 00 00 08 04 D2 16 2F. Server replies
//      with one byte: 'S' (SSL ok), 'N' (no SSL), 'E' (error).
//   2. Reconnect, send StartupMessage v3 with user=postgres database=postgres.
//      Server replies with R-type AuthenticationXxx (R + length + auth-type
//      int32: 0 Trust, 3 Cleartext, 5 MD5, 10 SASL/SCRAM) or E (error).
//
// We never send credentials. We just record what auth the server wants.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// postgresAuthOK reports whether the credential authenticates, using the
// lib/pq driver so SCRAM-SHA-256 (the PostgreSQL 10+ default) is handled. A
// nil error means the login succeeded. Called by the credential-test layer
// as the fallback when the hand-rolled startup negotiation gets a SASL
// request.
func postgresAuthOK(host string, port int, user, pass string, timeout time.Duration) error {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=%d",
		user, pass, host, port, int(timeout.Seconds())+1)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return db.PingContext(ctx)
}

// PostgreSQLReport is what Phase 3 emits per PostgreSQL port.
type PostgreSQLReport struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	SSLSupported bool     `json:"ssl_supported"`
	AuthMethod   string   `json:"auth_method,omitempty"` // trust|cleartext|md5|scram-sha-256|sasl|unknown
	ServerError  string        `json:"server_error,omitempty"`
	CredAttempts []CredAttempt `json:"cred_attempts,omitempty"`
	Databases    []string      `json:"databases,omitempty"`
	ProbeErrors  []string      `json:"probe_errors,omitempty"`
}

// ProbePostgreSQL runs the two-step probe.
func ProbePostgreSQL(host string, port int, timeout time.Duration) (*PostgreSQLReport, error) {
	rep := &PostgreSQLReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)

	// ── Step 1: SSLRequest ─────────────────────────────────────────────
	sslConn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial sslrequest: %w", err)
	}
	sslConn.SetDeadline(time.Now().Add(timeout))
	// SSLRequest packet: length=8, magic=80877103 (0x04D2162F)
	sslReq := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
	if _, err := sslConn.Write(sslReq); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write sslrequest: %v", err))
		sslConn.Close()
	} else {
		oneByte := make([]byte, 1)
		if _, err := io.ReadFull(sslConn, oneByte); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("read sslrequest reply: %v", err))
		} else {
			switch oneByte[0] {
			case 'S':
				rep.SSLSupported = true
			case 'N':
				rep.SSLSupported = false
			case 'E':
				rep.ProbeErrors = append(rep.ProbeErrors,
					"server rejected SSLRequest with error")
			default:
				rep.ProbeErrors = append(rep.ProbeErrors,
					fmt.Sprintf("unexpected sslrequest reply byte 0x%02x", oneByte[0]))
			}
		}
		sslConn.Close()
	}

	// ── Step 2: StartupMessage ─────────────────────────────────────────
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial startup: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	startup := buildStartupMessage("postgres", "postgres")
	if _, err := conn.Write(startup); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write startup: %v", err))
		return rep, nil
	}

	// Read one message: type(1) + length(4) + body(length-4).
	mtype := make([]byte, 1)
	if _, err := io.ReadFull(conn, mtype); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read msg type: %v", err))
		return rep, nil
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read msg length: %v", err))
		return rep, nil
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen < 4 || msgLen > 65536 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("absurd msg length %d", msgLen))
		return rep, nil
	}
	body := make([]byte, msgLen-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read msg body: %v", err))
		return rep, nil
	}

	switch mtype[0] {
	case 'R':
		// AuthenticationXxx: first int32 is auth type.
		if len(body) < 4 {
			rep.AuthMethod = "unknown"
			return rep, nil
		}
		authType := binary.BigEndian.Uint32(body[:4])
		switch authType {
		case 0:
			rep.AuthMethod = "trust"
		case 3:
			rep.AuthMethod = "cleartext"
		case 5:
			rep.AuthMethod = "md5"
		case 10:
			// SASL: body has space-separated mechanism list ending in 0x00
			mechs := strings.Trim(string(body[4:]), "\x00 ")
			if strings.Contains(mechs, "SCRAM-SHA-256") {
				rep.AuthMethod = "scram-sha-256"
			} else {
				rep.AuthMethod = "sasl"
			}
		case 12:
			rep.AuthMethod = "sasl-final"
		default:
			rep.AuthMethod = fmt.Sprintf("auth-type-%d", authType)
		}
	case 'E':
		// ErrorResponse: a sequence of "field-type-byte + nul-terminated-string",
		// terminated by a zero byte. We pluck the M (message) and C (sqlstate) fields.
		var msg, code string
		i := 0
		for i < len(body) {
			ft := body[i]
			i++
			if ft == 0 {
				break
			}
			end := bytes.IndexByte(body[i:], 0x00)
			if end < 0 {
				break
			}
			val := string(body[i : i+end])
			i += end + 1
			switch ft {
			case 'M':
				msg = val
			case 'C':
				code = val
			}
		}
		if msg == "" {
			msg = "server error"
		}
		if code != "" {
			rep.ServerError = fmt.Sprintf("%s (%s)", msg, code)
		} else {
			rep.ServerError = msg
		}
	default:
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("unexpected msg type %q", mtype[0]))
	}
	return rep, nil
}

// buildStartupMessage builds the PG StartupMessage v3:
//   length(4) + protocol(4 = 196608) + ("key\0value\0")* + extra \0
func buildStartupMessage(user, db string) []byte {
	var b bytes.Buffer
	// placeholder for length
	b.Write([]byte{0, 0, 0, 0})
	// protocol version 3.0
	binary.Write(&b, binary.BigEndian, uint32(196608))
	for _, kv := range [][2]string{
		{"user", user},
		{"database", db},
	} {
		b.WriteString(kv[0])
		b.WriteByte(0)
		b.WriteString(kv[1])
		b.WriteByte(0)
	}
	b.WriteByte(0)

	out := b.Bytes()
	binary.BigEndian.PutUint32(out[:4], uint32(len(out)))
	return out
}

// postgresListDatabasesWithLogin authenticates with a default credential that
// already succeeded and lists non-template databases as deep-content evidence.
// Best-effort and bounded: any connect or query error yields an empty slice.
func postgresListDatabasesWithLogin(host string, port int, user, pass string, timeout time.Duration) []string {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=%d",
		user, pass, host, port, int(timeout.Seconds()))
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT datname FROM pg_database WHERE datistemplate=false")
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
