// db2probe.go: phase 3 driver for IBM DB2 (50000) via DRDA EXCSAT.
//
// Hand-rolled DDM/DRDA per [MS-DRDA]. We send a minimal EXCSAT
// (Exchange Server Attributes) packet and parse the EXCSATRD reply for
// SRVCLSNM (server class name), EXTNAM and SRVRLSLV (server release level).
// DB2 servers return their product/release in SRVRLSLV (an IBM product-id
// token such as "SQL11055") and the platform in SRVCLSNM, both PRE-AUTH.
//
// Note: enumerating the actual database (RDB) catalog is NOT possible here.
// DRDA has no pre-auth list-databases verb; opening any RDB requires ACCSEC
// + SECCHK (credentials) followed by ACCRDB, and there is no mature pure-Go
// DRDA client. So this driver is version/instance detection only, by design.
//
// Frame layout:
//
//	DDM header: total length (2 BE), magic 0xD0, format 0x01, correl id (2)
//	            + DSS length (2), code point (2), payload.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type DB2Report struct {
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Reachable     bool     `json:"reachable"`
	ServerClass   string   `json:"server_class,omitempty"`
	ServerName    string   `json:"server_name,omitempty"`
	ServerVersion string   `json:"server_version,omitempty"`
	ServerRel     string   `json:"server_rel,omitempty"`
	ProbeErrors   []string `json:"probe_errors,omitempty"`
}

const (
	cpEXCSAT   = 0x1041
	cpEXTNAM   = 0x115E
	cpSRVCLSNM = 0x1147
	cpSRVNAM   = 0x116D
	cpSRVRLSLV = 0x115A
	cpMGRLVLLS = 0x1404
)

func ProbeDB2(host string, port int, timeout time.Duration) (*DB2Report, error) {
	rep := &DB2Report{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	pkt := buildDB2ExcSat()
	if _, err := conn.Write(pkt); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}

	// Read DDM outer length (2 BE) then the rest of the frame.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("len: %v", err))
		return rep, nil
	}
	total := int(binary.BigEndian.Uint16(lenBuf))
	if total < 6 || total > 4096 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("bad len %d", total))
		return rep, nil
	}
	body := make([]byte, total-2)
	if _, err := io.ReadFull(conn, body); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("body: %v", err))
		return rep, nil
	}
	rep.Reachable = true

	// Skip DDM hdr remainder (4 bytes): magic(1)+format(1)+correlid(2),
	// then walk inner objects. Frame may be: DSS length(2) + code point(2) + payload.
	// We do a simple scan for codepoints of interest.
	r := body[4:]
	parseDB2Objects(r, rep)
	// Derive a release string. SRVRLSLV (the IBM product-id token) is the
	// authoritative source when present; SRVCLSNM is the fallback.
	if rep.ServerVersion != "" {
		rep.ServerRel = decodeDB2PRDID(rep.ServerVersion)
	} else if rep.ServerClass != "" {
		// e.g. "QDB2/LINUXX8664" or "DSN12015 IBM DB2/LINUX"
		rep.ServerRel = guessDB2Release(rep.ServerClass)
	}
	return rep, nil
}

// buildDB2ExcSat creates a minimal EXCSAT packet asking only for SRVCLSNM
// via MGRLVLLS. The Hercules / IBM Toolbox shorthand is fine here: we
// supply EXTNAM/SRVNAM with our client name and ask the server to send
// the server class back.
func buildDB2ExcSat() []byte {
	// Inner objects.
	var inner bytes.Buffer
	// EXTNAM "fastscan"
	writeDB2Object(&inner, cpEXTNAM, []byte("fastscan"))
	// SRVNAM "fastscan"
	writeDB2Object(&inner, cpSRVNAM, []byte("fastscan"))
	// SRVRLSLV "FS01"
	writeDB2Object(&inner, cpSRVRLSLV, []byte("FS01"))
	// MGRLVLLS: list of manager codepoints + levels. Minimal: AGENT 7, SQLAM 7.
	mgrls := []byte{
		0x14, 0x03, 0x00, 0x07, // AGENT manager 0x1403 lvl 7
		0x24, 0x07, 0x00, 0x07, // SQLAM 0x2407 lvl 7
	}
	writeDB2Object(&inner, cpMGRLVLLS, mgrls)

	// EXCSAT wrapper (code point 0x1041).
	var excsat bytes.Buffer
	// DSS length + codepoint
	cpLen := uint16(inner.Len() + 4)
	binary.Write(&excsat, binary.BigEndian, cpLen)
	binary.Write(&excsat, binary.BigEndian, uint16(cpEXCSAT))
	excsat.Write(inner.Bytes())

	// Outer DDM header.
	var out bytes.Buffer
	totalLen := uint16(excsat.Len() + 6)
	binary.Write(&out, binary.BigEndian, totalLen)
	out.WriteByte(0xD0)                             // magic
	out.WriteByte(0x01)                             // format: DSSFMT chained, no same-id chain
	binary.Write(&out, binary.BigEndian, uint16(1)) // correl id
	out.Write(excsat.Bytes())
	return out.Bytes()
}

func writeDB2Object(buf *bytes.Buffer, codepoint uint16, payload []byte) {
	// length includes the length(2) + codepoint(2) + payload.
	binary.Write(buf, binary.BigEndian, uint16(len(payload)+4))
	binary.Write(buf, binary.BigEndian, codepoint)
	buf.Write(payload)
}

// parseDB2Objects walks {len(2) + codepoint(2) + payload} TLV objects and
// records SRVCLSNM and EXTNAM into the report.
func parseDB2Objects(body []byte, rep *DB2Report) {
	for i := 0; i+4 <= len(body); {
		l := int(binary.BigEndian.Uint16(body[i : i+2]))
		if l < 4 || i+l > len(body) {
			return
		}
		cp := binary.BigEndian.Uint16(body[i+2 : i+4])
		payload := body[i+4 : i+l]
		switch cp {
		case cpSRVCLSNM:
			rep.ServerClass = ebcdicOrAscii(payload)
		case cpEXTNAM:
			rep.ServerName = ebcdicOrAscii(payload)
		case cpSRVRLSLV:
			// Server release level, returned PRE-AUTH in EXCSATRD. Carries the
			// IBM product-id token (e.g. "SQL11055" for DB2 LUW v11.5, or
			// "DSN12015" for DB2 for z/OS v12). No credentials are exchanged.
			if v := ebcdicOrAscii(payload); v != "" {
				rep.ServerVersion = v
			}
		case cpEXCSAT, 0x1443, cpMGRLVLLS:
			// Nested: recurse.
			parseDB2Objects(payload, rep)
		}
		i += l
	}
}

// ebcdicOrAscii returns ASCII directly if the bytes look printable, else
// applies a minimal EBCDIC -> ASCII fold for the alphanumeric + space + /
// + . range, which is all DB2 SRVCLSNM strings use in practice.
func ebcdicOrAscii(b []byte) string {
	// Heuristic: any byte < 0x20 and not 0/9 suggests EBCDIC.
	ascii := true
	for _, c := range b {
		if c == 0 {
			continue
		}
		if c < 0x20 || c >= 0x7F {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.TrimSpace(strings.Trim(string(b), "\x00"))
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if r, ok := ebcdicTable[c]; ok {
			out = append(out, r)
		}
	}
	return strings.TrimSpace(string(out))
}

// ebcdicTable maps EBCDIC -> ASCII for the printable subset that DB2 uses
// in EXCSAT replies. Anything else is dropped.
var ebcdicTable = func() map[byte]byte {
	m := map[byte]byte{}
	// digits 0-9 -> 0xF0..0xF9
	for i := byte(0); i < 10; i++ {
		m[0xF0+i] = '0' + i
	}
	// uppercase A-I -> 0xC1..0xC9, J-R -> 0xD1..0xD9, S-Z -> 0xE2..0xE9
	for i := byte(0); i < 9; i++ {
		m[0xC1+i] = 'A' + i
	}
	for i := byte(0); i < 9; i++ {
		m[0xD1+i] = 'J' + i
	}
	for i := byte(0); i < 8; i++ {
		m[0xE2+i] = 'S' + i
	}
	// lowercase a-i -> 0x81..0x89, j-r -> 0x91..0x99, s-z -> 0xA2..0xA9
	for i := byte(0); i < 9; i++ {
		m[0x81+i] = 'a' + i
	}
	for i := byte(0); i < 9; i++ {
		m[0x91+i] = 'j' + i
	}
	for i := byte(0); i < 8; i++ {
		m[0xA2+i] = 's' + i
	}
	m[0x40] = ' '
	m[0x4B] = '.'
	m[0x4E] = '+'
	m[0x4F] = '|'
	m[0x60] = '-'
	m[0x61] = '/'
	m[0x6B] = ','
	m[0x6D] = '_'
	return m
}()

// guessDB2Release extracts version digits from the SRVCLSNM. Examples:
//
//	"QDB2/LINUXX8664" + V11.5  -> 11.5
//	"DSN12015"               -> 12.1.5 z/OS
//
// decodeDB2PRDID decodes the IBM DRDA product-id (SRVRLSLV) token, which has
// the form pppvvrrm: 3-char product code + 2-digit version + 2-digit release
//   - 1-digit modification. Examples:
//     "SQL11055" -> "DB2 LUW 11.5.5"
//     "DSN12015" -> "DB2 z/OS 12.1.5"
//     "IFX..."    -> Informix served over a DRDA alias
//
// Unknown shapes are returned verbatim so nothing is lost.
func decodeDB2PRDID(prdid string) string {
	s := strings.TrimSpace(prdid)
	if len(s) < 8 {
		return s
	}
	code := strings.ToUpper(s[:3])
	digits := s[3:8]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return s // not the expected pppvvrrm shape; keep raw token
		}
	}
	var product string
	switch code {
	case "SQL":
		product = "DB2 LUW"
	case "DSN":
		product = "DB2 z/OS"
	case "QSQ":
		product = "DB2 for i"
	case "IFX", "INF":
		product = "Informix"
	default:
		product = code
	}
	ver := digits[0:2] // vv
	rel := digits[2:4] // rr
	mod := digits[4:5] // m
	// Trim a leading zero from the 2-digit version (e.g. "08" -> "8").
	if ver[0] == '0' {
		ver = ver[1:]
	}
	if rel[0] == '0' {
		rel = rel[1:]
	}
	return fmt.Sprintf("%s %s.%s.%s", product, ver, rel, mod)
}

func guessDB2Release(class string) string {
	var digits strings.Builder
	for _, c := range class {
		if c >= '0' && c <= '9' || c == '.' {
			digits.WriteRune(c)
		}
	}
	return digits.String()
}
