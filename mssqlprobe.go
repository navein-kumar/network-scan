// mssqlprobe.go: phase 3 driver for Microsoft SQL Server.
//
// Approach: hand-rolled TDS PRELOGIN packet per [MS-TDS] §2.2.6.5. The
// public surface of github.com/microsoft/go-mssqldb does not expose the
// prelogin step directly (it's inside an internal package), so wrapping
// the library only to throw away the login step adds more code than this.
//
// Wire format we send (one TDS packet):
//   TDS header (8 bytes): type=0x12 PRELOGIN, status=0x01 EOM,
//                         length(2), spid(2)=0, pkt#=1, window=0
//   PRELOGIN options array, each option = id(1) + offset(2) + length(2),
//                          terminated by TERMINATOR (0xff)
//   Option data follows the array.
//
// We advertise the standard 4 options: VERSION (0x00), ENCRYPTION (0x01),
// INSTOPT (0x02), THREADID (0x03). We then read the server's PRELOGIN
// response and decode its VERSION (major.minor.build) and ENCRYPTION byte.
//
// ENCRYPTION byte meanings (MS-TDS §2.2.6.5):
//   0x00 ENCRYPT_OFF    server can encrypt but not configured to
//   0x01 ENCRYPT_ON     server can encrypt and prefers it
//   0x02 ENCRYPT_NOT_SUP server cannot encrypt
//   0x03 ENCRYPT_REQ    server requires encryption
//
// No M2 target for smoke testing. Build is acceptance.
package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

// mssqlAuthOK reports whether the credential authenticates, using the
// go-mssqldb driver. The driver performs the TLS pre-login handshake that
// modern SQL Server (2022+) mandates for the login phase, which the
// hand-rolled LOGIN7 path cannot do. A nil error means login succeeded.
func mssqlAuthOK(host string, port int, user, pass string, timeout time.Duration) error {
	dsn := fmt.Sprintf("sqlserver://%s:%s@%s:%d?connection+timeout=%d",
		user, pass, host, port, int(timeout.Seconds())+1)
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return db.PingContext(ctx)
}

// MSSQLReport is what Phase 3 emits per MSSQL port.
type MSSQLReport struct {
	Host                string   `json:"host"`
	Port                int      `json:"port"`
	Version             string   `json:"version,omitempty"`
	EncryptionSupported bool     `json:"encryption_supported"`
	EncryptionRequired  bool     `json:"encryption_required"`
	Instance            string        `json:"instance,omitempty"`
	CredAttempts        []CredAttempt `json:"cred_attempts,omitempty"`
	Databases           []string      `json:"databases,omitempty"`
	ProbeErrors         []string      `json:"probe_errors,omitempty"`
}

const (
	tdsPktTypePrelogin = 0x12
	tdsStatusEOM       = 0x01

	tdsOptVersion    = 0x00
	tdsOptEncryption = 0x01
	tdsOptInstOpt    = 0x02
	tdsOptThreadID   = 0x03
	tdsOptTerminator = 0xff

	tdsEncryptOff    = 0x00
	tdsEncryptOn     = 0x01
	tdsEncryptNotSup = 0x02
	tdsEncryptReq    = 0x03
)

// ProbeMSSQL sends a TDS PRELOGIN and parses the response.
func ProbeMSSQL(host string, port int, timeout time.Duration) (*MSSQLReport, error) {
	rep := &MSSQLReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	pkt := buildPreloginPacket()
	if _, err := conn.Write(pkt); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write prelogin: %v", err))
		return rep, nil
	}

	// Read TDS response header (8 bytes), then body.
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read tds header: %v", err))
		return rep, nil
	}
	totalLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if totalLen < 8 || totalLen > 8192 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("absurd tds length %d", totalLen))
		return rep, nil
	}
	body := make([]byte, totalLen-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read tds body: %v", err))
		return rep, nil
	}

	parsePreloginResponse(body, rep)
	return rep, nil
}

// buildPreloginPacket constructs the TDS PRELOGIN request.
func buildPreloginPacket() []byte {
	// Option entries: 4 options of 5 bytes each + 1 terminator byte.
	// Options data: VERSION 6 bytes, ENCRYPTION 1 byte, INSTOPT 1 byte (zero
	// terminated empty string), THREADID 4 bytes.
	optTableLen := 4*5 + 1
	optDataOffsets := []struct {
		id     byte
		length uint16
	}{
		{tdsOptVersion, 6},
		{tdsOptEncryption, 1},
		{tdsOptInstOpt, 1},
		{tdsOptThreadID, 4},
	}

	var optTable []byte
	cursor := uint16(optTableLen)
	for _, e := range optDataOffsets {
		optTable = append(optTable, e.id)
		var off [2]byte
		binary.BigEndian.PutUint16(off[:], cursor)
		optTable = append(optTable, off[:]...)
		var ln [2]byte
		binary.BigEndian.PutUint16(ln[:], e.length)
		optTable = append(optTable, ln[:]...)
		cursor += e.length
	}
	optTable = append(optTable, tdsOptTerminator)

	// Option data
	verData := []byte{0, 0, 0, 0, 0, 0} // client version, all zero is fine
	encData := []byte{tdsEncryptOff}    // we advertise we don't encrypt
	instData := []byte{0x00}
	tidData := []byte{0, 0, 0, 0}

	payload := append([]byte(nil), optTable...)
	payload = append(payload, verData...)
	payload = append(payload, encData...)
	payload = append(payload, instData...)
	payload = append(payload, tidData...)

	tdsHdr := make([]byte, 8)
	tdsHdr[0] = tdsPktTypePrelogin
	tdsHdr[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(tdsHdr[2:4], uint16(8+len(payload)))
	// spid, packet#, window already zero
	tdsHdr[6] = 1

	return append(tdsHdr, payload...)
}

// parsePreloginResponse walks the option table and fills the report.
func parsePreloginResponse(body []byte, rep *MSSQLReport) {
	// Walk the option entries until we hit the terminator.
	i := 0
	type optRef struct {
		id     byte
		off    uint16
		length uint16
	}
	var refs []optRef
	for i < len(body) {
		id := body[i]
		if id == tdsOptTerminator {
			i++
			break
		}
		if i+5 > len(body) {
			rep.ProbeErrors = append(rep.ProbeErrors,
				"truncated option table")
			return
		}
		off := binary.BigEndian.Uint16(body[i+1 : i+3])
		ln := binary.BigEndian.Uint16(body[i+3 : i+5])
		refs = append(refs, optRef{id: id, off: off, length: ln})
		i += 5
	}

	for _, r := range refs {
		end := int(r.off) + int(r.length)
		if int(r.off) > len(body) || end > len(body) {
			continue
		}
		data := body[r.off:end]
		switch r.id {
		case tdsOptVersion:
			// VERSION: 4 bytes major.minor.build_hi.build_lo + 2 bytes sub_build
			if len(data) >= 6 {
				major := data[0]
				minor := data[1]
				build := uint16(data[2])<<8 | uint16(data[3])
				rep.Version = fmt.Sprintf(
					"Microsoft SQL Server (build %d.%d.%d)",
					major, minor, build)
				// Friendly mapping for the common majors
				if name := sqlMajorName(major); name != "" {
					rep.Version = fmt.Sprintf(
						"Microsoft SQL Server %s (build %d.%d.%d)",
						name, major, minor, build)
				}
			}
		case tdsOptEncryption:
			if len(data) >= 1 {
				enc := data[0]
				rep.EncryptionSupported = enc != tdsEncryptNotSup
				rep.EncryptionRequired = enc == tdsEncryptReq
			}
		case tdsOptInstOpt:
			if len(data) > 0 {
				// null-terminated ASCII string
				s := string(data)
				if z := indexZero(s); z >= 0 {
					s = s[:z]
				}
				rep.Instance = s
			}
		}
	}
}

// sqlMajorName maps the TDS major-version byte to the SQL Server release.
// Source: https://sqlserverbuilds.blogspot.com/
func sqlMajorName(major byte) string {
	switch major {
	case 7:
		return "7.0"
	case 8:
		return "2000"
	case 9:
		return "2005"
	case 10:
		// 10.0 = 2008, 10.50 = 2008 R2; we don't see minor here to split.
		return "2008"
	case 11:
		return "2012"
	case 12:
		return "2014"
	case 13:
		return "2016"
	case 14:
		return "2017"
	case 15:
		return "2019"
	case 16:
		return "2022"
	}
	return ""
}

func indexZero(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return i
		}
	}
	return -1
}

// mssqlListDatabasesWithLogin authenticates with a default credential that
// already succeeded and lists databases from sys.databases as deep-content
// evidence. Best-effort and bounded: any connect or query error yields an
// empty slice.
func mssqlListDatabasesWithLogin(host string, port int, user, pass string, timeout time.Duration) []string {
	dsn := fmt.Sprintf("sqlserver://%s:%s@%s:%d?connection+timeout=%d",
		user, pass, host, port, int(timeout.Seconds()))
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT name FROM sys.databases")
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
