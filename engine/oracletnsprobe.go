// oracletnsprobe.go: phase 3 driver for Oracle TNS Listener (1521).
//
// Hand-rolled TNS Connect packet (no external lib). The server replies
// with TNS REFUSE (0x04) or REDIRECT (0x05) whose payload often leaks
// the banner "Oracle Database 12c Enterprise Edition Release 12.1.0.2.0".
//
// Packet layout (big-endian, per Oracle Net8/TNS docs):
//   Header (8 bytes):
//     packet length     uint16
//     packet checksum   uint16 (0)
//     type              uint8  (0x01 CONNECT)
//     flags             uint8  (0)
//     header checksum   uint16 (0)
//   Connect data (24 bytes):
//     version           uint16 (0x0139 = 313)
//     version_low       uint16 (0x012c = 300)
//     service_options   uint16
//     sdu               uint16 (0x0800)
//     max_transmit      uint16 (0x7fff)
//     nt_protocol_chars uint16 (0x4f98)
//     line_turnaround   uint16 (0)
//     value_1_hw        uint16 (0x0100)
//     conn_data_length  uint16
//     conn_data_offset  uint16 (0x003a = 58)
//     max_recv_data     uint32
//     connect_flags_0   uint8
//     connect_flags_1   uint8
//   then the connect string (DESCRIPTION=...)
package main

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
)

type OracleTNSReport struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Reachable   bool     `json:"reachable"`
	Version     string   `json:"version,omitempty"`
	Banner      string   `json:"banner,omitempty"`
	SIDs        []string `json:"sids,omitempty"`
	Tables      []string `json:"tables,omitempty"`
	ProbeErrors []string `json:"probe_errors,omitempty"`
}

// commonOracleSIDs are SIDs and service names tried pre-auth to find which
// databases the listener serves.
var commonOracleSIDs = []string{
	"ORCL", "XE", "XEPDB1", "ORACLE", "PROD", "DEV", "TEST",
	"DB1", "PDB1", "ORCLCDB", "ORCLPDB1", "FREE", "FREEPDB1",
}

// oracleDefaultCreds are user/password pairs tried against a discovered SID
// or service to enumerate accessible tables. asDBA flips the connect role.
var oracleDefaultCreds = []struct {
	user, pass string
	asDBA      bool
}{
	{"system", "oracle", false},
	{"system", "manager", false},
	{"system", "oracle123", false},
	{"sys", "oracle", true},
	{"scott", "tiger", false},
}

// ProbeOracleTNS dials and sends a TNS CONNECT for the SERVICE_NAME=<empty>
// description; the listener typically responds with REFUSE that leaks a
// version banner in the data payload.
func ProbeOracleTNS(host string, port int, timeout time.Duration) (*OracleTNSReport, error) {
	rep := &OracleTNSReport{Host: host, Port: port}

	// Banner grab is best-effort: older listeners leak a version in a REFUSE,
	// newer ones (18c+, XE 21c) silently drop the minimal CONNECT. Either way
	// we still run SID/service enumeration below.
	probeTNSBanner(host, port, rep, timeout)

	// Pre-auth SID/service enumeration. Bounded by timeout per attempt.
	rep.SIDs = enumOracleSIDs(host, port, timeout)

	// If a default cred works against a discovered SID/service, sample tables.
	rep.Tables = enumOracleTables(host, port, rep.SIDs, timeout)

	return rep, nil
}

// probeTNSBanner dials, sends a CONNECT for the empty SERVICE_NAME description
// and parses any leaked version banner into rep. All failures are recorded in
// rep.ProbeErrors and swallowed so enumeration can still proceed.
func probeTNSBanner(host string, port int, rep *OracleTNSReport, timeout time.Duration) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("dial: %v", err))
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	connStr := fmt.Sprintf(
		"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=))(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d)))",
		host, port)
	pkt := buildTNSConnect(connStr)
	if _, err := conn.Write(pkt); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return
	}

	// Read response: 8-byte header first.
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read header: %v", err))
		return
	}
	rep.Reachable = true
	pktLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	pktType := hdr[4]
	if pktLen < 8 || pktLen > 1<<16 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("bad pkt len %d", pktLen))
		return
	}
	body := make([]byte, pktLen-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read body: %v", err))
		return
	}
	// Type 0x04 REFUSE or 0x05 REDIRECT often contain a printable string
	// like "(DESCRIPTION=(TMP=)(VSNNUM=...)(ERR=...))" with version info.
	rep.Banner = tnsPrintableASCII(body)

	// Common patterns:
	//   "Oracle Database 12c Enterprise Edition Release 12.1.0.2.0"
	//   "(VSNNUM=185599488)" is an encoded version (12.1.0.2.0 = 0x0B102000)
	versionRe := regexp.MustCompile(`(?i)Oracle Database [^"\n]+ Release [0-9.]+`)
	if m := versionRe.FindString(rep.Banner); m != "" {
		rep.Version = strings.TrimSpace(m)
	} else if vRe := regexp.MustCompile(`(?i)Release\s+([0-9.]+)`); true {
		if m := vRe.FindStringSubmatch(rep.Banner); len(m) > 1 {
			rep.Version = strings.TrimSpace(m[1])
		}
	}
	// VSNNUM decoding: uint32 -> bytes (major, minor1, patch, minor2, junk)
	if rep.Version == "" {
		vsnRe := regexp.MustCompile(`VSNNUM=(\d+)`)
		if m := vsnRe.FindStringSubmatch(rep.Banner); len(m) > 1 {
			var n uint64
			fmt.Sscanf(m[1], "%d", &n)
			if n > 0 {
				major := (n >> 24) & 0xff
				minor1 := (n >> 20) & 0x0f
				patch := (n >> 12) & 0xff
				minor2 := (n >> 8) & 0x0f
				port := n & 0xff
				rep.Version = fmt.Sprintf("%d.%d.%d.%d.%d",
					major, minor1, patch, minor2, port)
			}
		}
	}
	if rep.Banner == "" && pktType == 0x04 {
		rep.Banner = "TNS REFUSE (no payload string)"
	}
}

// enumOracleSIDs probes each candidate SID and service name and records the
// ones the listener serves. It first tries a raw TNS CONNECT (truly pre-auth,
// works on 11g/12c which leak a REFUSE banner); for modern listeners (18c+,
// XE 21c) that drop the minimal CONNECT, it falls back to a go-ora connect
// whose ORA error distinguishes an existing service (ORA-01017 invalid login)
// from an unknown one (ORA-12514/12505). Best-effort, capped, never panics.
func enumOracleSIDs(host string, port int, timeout time.Duration) []string {
	const maxSIDs = 16
	seen := map[string]bool{}
	var found []string
	for _, sid := range commonOracleSIDs {
		if len(found) >= maxSIDs {
			break
		}
		exists := false
		// Try SID then SERVICE_NAME via the raw packet first.
		for _, key := range []string{"SID", "SERVICE_NAME"} {
			cs := fmt.Sprintf(
				"(DESCRIPTION=(CONNECT_DATA=(%s=%s))(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d)))",
				key, sid, host, port)
			if oracleSIDExists(host, port, cs, timeout) {
				exists = true
				break
			}
		}
		// Fallback for listeners that ignore the hand-rolled CONNECT.
		if !exists {
			exists = oracleServiceExistsViaDriver(host, port, sid, timeout)
		}
		if exists && !seen[sid] {
			seen[sid] = true
			found = append(found, sid)
		}
	}
	return found
}

// oracleServiceExistsViaDriver pings the service with a throwaway user. An
// ORA-01017 (invalid login) means the service exists; ORA-12514/12505 mean it
// does not. Best-effort, bounded by timeout, never panics.
func oracleServiceExistsViaDriver(host string, port int, service string, timeout time.Duration) (exists bool) {
	defer func() { _ = recover() }()
	opts := map[string]string{
		"CONNECT TIMEOUT": fmt.Sprintf("%d", int(timeout.Seconds())),
		"TIMEOUT":         fmt.Sprintf("%d", int(timeout.Seconds())),
	}
	url := go_ora.BuildUrl(host, port, service, "fsprobe", "fsprobe_bad_pw", opts)
	db, err := sql.Open("oracle", url)
	if err != nil {
		return false
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		msg := err.Error()
		// Service exists but the throwaway login was rejected.
		if strings.Contains(msg, "ORA-01017") || strings.Contains(msg, "ORA-28000") {
			return true
		}
		return false
	}
	// Unexpected success (blank/anon auth): the service is clearly there.
	return true
}

// oracleSIDExists sends one TNS CONNECT and decides whether the named database
// exists from the response type and any embedded ORA error code.
func oracleSIDExists(host string, port int, connStr string, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildTNSConnect(connStr)); err != nil {
		return false
	}
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false
	}
	pktLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	pktType := hdr[4]
	// ACCEPT (0x02) or REDIRECT (0x05): the listener handed us off, SID exists.
	if pktType == 0x02 || pktType == 0x05 {
		return true
	}
	if pktLen <= 8 || pktLen > 1<<16 {
		return pktType == 0x02 || pktType == 0x05
	}
	body := make([]byte, pktLen-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		return false
	}
	payload := tnsPrintableASCII(body)
	// REFUSE (0x04) leaks an ORA error in the payload. ORA-12505 (SID unknown)
	// and ORA-12514 (service unknown) mean it does NOT exist; any other error
	// (e.g. ORA-12519/12520 resource busy, ORA-28547) means it does.
	if strings.Contains(payload, "12505") || strings.Contains(payload, "12514") {
		return false
	}
	if m := regexp.MustCompile(`ERR=(\d+)`).FindStringSubmatch(payload); len(m) > 1 {
		// ERR=0 with no rejection is unusual on REFUSE; treat any other err as exists.
		return m[1] != "0"
	}
	return false
}

// enumOracleTables tries default creds against each discovered SID/service and,
// on the first success, samples up to 50 accessible table names.
func enumOracleTables(host string, port int, sids []string, timeout time.Duration) []string {
	for _, sid := range sids {
		for _, c := range oracleDefaultCreds {
			tables := oracleListTables(host, port, sid, c.user, c.pass, c.asDBA, timeout)
			if len(tables) > 0 {
				return tables
			}
		}
	}
	return nil
}

// oracleListTables opens a go-ora connection and reads ALL_TABLES. Returns nil
// on any failure (auth or query). Best-effort, bounded by timeout.
func oracleListTables(host string, port int, service, user, pass string, asDBA bool, timeout time.Duration) (out []string) {
	defer func() { _ = recover() }()

	opts := map[string]string{}
	if asDBA {
		opts["DBA PRIVILEGE"] = "SYSDBA"
	}
	url := go_ora.BuildUrl(host, port, service, user, pass, opts)
	db, err := sql.Open("oracle", url)
	if err != nil {
		return nil
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	rows, err := db.Query("SELECT table_name FROM all_tables WHERE rownum <= 50")
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			break
		}
		out = append(out, name)
	}
	return out
}

func buildTNSConnect(connStr string) []byte {
	connBytes := []byte(connStr)
	const headerSize = 8
	const connectDataHeader = 24 // 6*uint16 + uint16 + uint16 + uint32 + 2*uint8
	dataOffset := uint16(headerSize + connectDataHeader)
	pktLen := uint16(int(dataOffset) + len(connBytes))

	var buf bytes.Buffer
	// header
	binary.Write(&buf, binary.BigEndian, pktLen)       // packet length
	binary.Write(&buf, binary.BigEndian, uint16(0))    // packet checksum
	buf.WriteByte(0x01)                                // type = CONNECT
	buf.WriteByte(0x00)                                // flags
	binary.Write(&buf, binary.BigEndian, uint16(0))    // header checksum
	// connect data header
	binary.Write(&buf, binary.BigEndian, uint16(0x0139)) // version (313 = 11g)
	binary.Write(&buf, binary.BigEndian, uint16(0x012c)) // version_low (300 = 10g)
	binary.Write(&buf, binary.BigEndian, uint16(0))      // service options
	binary.Write(&buf, binary.BigEndian, uint16(0x0800)) // SDU
	binary.Write(&buf, binary.BigEndian, uint16(0x7fff)) // max transmit
	binary.Write(&buf, binary.BigEndian, uint16(0x4f98)) // nt protocol chars
	binary.Write(&buf, binary.BigEndian, uint16(0))      // line turnaround
	binary.Write(&buf, binary.BigEndian, uint16(0x0100)) // value of 1 in hw
	binary.Write(&buf, binary.BigEndian, uint16(len(connBytes)))
	binary.Write(&buf, binary.BigEndian, dataOffset)
	binary.Write(&buf, binary.BigEndian, uint32(0))      // max recv data
	buf.WriteByte(0x00)                                  // connect flags 0
	buf.WriteByte(0x00)                                  // connect flags 1
	buf.Write(connBytes)
	return buf.Bytes()
}

// tnsPrintableASCII pulls runs of printable ASCII out of a binary blob so
// the banner is human-readable.
func tnsPrintableASCII(b []byte) string {
	var sb strings.Builder
	run := 0
	start := -1
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			if start < 0 {
				start = i
			}
			run++
			continue
		}
		if run >= 4 {
			sb.Write(b[start : start+run])
			sb.WriteByte(' ')
		}
		run = 0
		start = -1
	}
	if run >= 4 {
		sb.Write(b[start : start+run])
	}
	return strings.TrimSpace(sb.String())
}
