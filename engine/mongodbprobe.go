// mongodbprobe.go: phase 3 driver for MongoDB (27017).
//
// Hand-rolled OP_QUERY isMaster (avoids pulling go.mongodb.org/mongo-driver).
// Wire protocol:
//   MsgHeader (16 bytes) + flags(4) + fullCollectionName "admin.$cmd\x00"
//     + numberToSkip(4) + numberToReturn(4) + BSON {"isMaster":1}
// Reply:
//   MsgHeader (16) + responseFlags(4) + cursorID(8) + startingFrom(4)
//     + numberReturned(4) + documents
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"
)

// MongoDBReport is what Phase 3 emits per MongoDB target.
type MongoDBReport struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Reachable      bool     `json:"reachable"`
	AuthRequired   bool     `json:"auth_required"`
	Version        string   `json:"version,omitempty"`
	MaxWireVersion int      `json:"max_wire_version,omitempty"`
	ReplicaSet     string   `json:"replica_set,omitempty"`
	Primary        string   `json:"primary,omitempty"`
	Databases      []string      `json:"databases,omitempty"`
	CredAttempts   []CredAttempt `json:"cred_attempts,omitempty"`
	ProbeErrors    []string      `json:"probe_errors,omitempty"`
}

const (
	opcodeQuery = 2004
	opcodeReply = 1
)

// ProbeMongoDB sends OP_QUERY isMaster and parses the BSON reply.
func ProbeMongoDB(host string, port int, timeout time.Duration) (*MongoDBReport, error) {
	rep := &MongoDBReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	pkt := buildIsMasterQuery()
	if _, err := conn.Write(pkt); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	// Read reply header (16 bytes), then payload.
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read header: %v", err))
		return rep, nil
	}
	msgLen := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	if msgLen < 16 || msgLen > 1<<20 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("bad msg length %d", msgLen))
		return rep, nil
	}
	opCode := int32(binary.LittleEndian.Uint32(hdr[12:16]))
	if opCode != opcodeReply {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("unexpected opcode %d", opCode))
		return rep, nil
	}
	body := make([]byte, msgLen-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read body: %v", err))
		return rep, nil
	}
	rep.Reachable = true

	// OP_REPLY body: flags(4) + cursorID(8) + startingFrom(4) +
	// numberReturned(4) + documents.
	if len(body) < 20 {
		rep.ProbeErrors = append(rep.ProbeErrors, "reply body too short")
		return rep, nil
	}
	docs := body[20:]
	doc, _, err := readBSONDoc(docs)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("bson parse: %v", err))
		return rep, nil
	}
	// Auth-required signal: ok=0 + errmsg containing "auth" / "Unauthorized".
	okv := bsonAsFloat(doc["ok"])
	if okv == 0 {
		errmsg := bsonAsString(doc["errmsg"])
		if strings.Contains(strings.ToLower(errmsg), "auth") ||
			strings.Contains(strings.ToLower(errmsg), "unauthorized") {
			rep.AuthRequired = true
		}
	}
	rep.Version = bsonAsString(doc["version"])
	if rep.Version == "" {
		rep.Version = mongoBuildInfo(host, port, timeout)
	}
	rep.MaxWireVersion = int(bsonAsFloat(doc["maxWireVersion"]))
	rep.ReplicaSet = bsonAsString(doc["setName"])
	rep.Primary = bsonAsString(doc["primary"])

	// Deep-content: if the server accepts unauthenticated access, list its
	// database names as Nessus-style evidence. Best-effort; never fatal.
	if !rep.AuthRequired && rep.Reachable {
		rep.Databases = mongoListDatabases(host, port, timeout)
	}
	return rep, nil
}

const opcodeMsg = 2013

// mongoListDatabases runs listDatabases via OP_MSG (opcode 2013) on a fresh
// connection. OP_QUERY is removed in MongoDB 5.1+, so listDatabases needs
// OP_MSG. Returns up to 100 database names; any error yields an empty slice.
func mongoListDatabases(host string, port int, timeout time.Duration) []string {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	pkt := buildListDatabasesMsg()
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	// Reply header (16 bytes): msgLen, requestID, responseTo, opcode.
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil
	}
	msgLen := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	if msgLen < 16 || msgLen > 1<<20 {
		return nil
	}
	opCode := int32(binary.LittleEndian.Uint32(hdr[12:16]))
	if opCode != opcodeMsg {
		return nil
	}
	body := make([]byte, msgLen-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil
	}
	// OP_MSG body: flagBits(4) + section kind byte(0x00) + BSON document.
	if len(body) < 5 || body[4] != 0x00 {
		return nil
	}
	return mongoExtractDBNames(body[5:])
}

// buildListDatabasesMsg assembles an OP_MSG packet carrying the command
// { listDatabases: 1, nameOnly: true, $db: "admin" }.
func buildListDatabasesMsg() []byte {
	cmd := buildListDatabasesBSON()

	var section bytes.Buffer
	section.WriteByte(0x00) // section kind 0: single BSON body
	section.Write(cmd)

	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint32(0)) // flagBits
	body.Write(section.Bytes())

	msgLen := 16 + body.Len()
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.LittleEndian, uint32(msgLen))
	binary.Write(&pkt, binary.LittleEndian, uint32(2))         // requestID
	binary.Write(&pkt, binary.LittleEndian, uint32(0))         // responseTo
	binary.Write(&pkt, binary.LittleEndian, uint32(opcodeMsg)) // opcode 2013
	pkt.Write(body.Bytes())
	return pkt.Bytes()
}

// buildListDatabasesBSON serializes
// { listDatabases: int32(1), nameOnly: bool(true), $db: "admin" }.
func buildListDatabasesBSON() []byte {
	var b bytes.Buffer
	// 0x10 int32 "listDatabases" = 1
	b.WriteByte(0x10)
	b.WriteString("listDatabases")
	b.WriteByte(0x00)
	binary.Write(&b, binary.LittleEndian, int32(1))
	// 0x08 bool "nameOnly" = true
	b.WriteByte(0x08)
	b.WriteString("nameOnly")
	b.WriteByte(0x00)
	b.WriteByte(0x01)
	// 0x02 string "$db" = "admin"
	b.WriteByte(0x02)
	b.WriteString("$db")
	b.WriteByte(0x00)
	admin := "admin\x00"
	binary.Write(&b, binary.LittleEndian, int32(len(admin)))
	b.WriteString(admin)
	b.WriteByte(0x00) // doc terminator

	docLen := 4 + b.Len()
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, int32(docLen))
	out.Write(b.Bytes())
	return out.Bytes()
}

// mongoExtractDBNames walks a listDatabases reply document and returns the
// "name" string of each entry in the "databases" array. The array element is
// BSON type 0x04 (encoded like a document with keys "0","1",...); each member
// is type 0x03 (embedded doc) carrying a "name" string (type 0x02). Defensive
// about all lengths so it never panics; caps the result at 100 names.
func mongoExtractDBNames(doc []byte) []string {
	if len(doc) < 5 {
		return nil
	}
	docLen := int(int32(binary.LittleEndian.Uint32(doc[0:4])))
	if docLen < 5 || docLen > len(doc) {
		return nil
	}
	body := doc[4:docLen]
	i := 0
	for i < len(body) {
		t := body[i]
		i++
		if t == 0x00 {
			break // end of document
		}
		end := bytes.IndexByte(body[i:], 0x00)
		if end < 0 {
			return nil
		}
		key := string(body[i : i+end])
		i += end + 1

		if t == 0x04 && key == "databases" {
			// Embedded array document: int32 len + elements + 0x00.
			if i+4 > len(body) {
				return nil
			}
			arrLen := int(int32(binary.LittleEndian.Uint32(body[i : i+4])))
			if arrLen < 5 || i+arrLen > len(body) {
				return nil
			}
			return mongoNamesFromArray(body[i : i+arrLen])
		}

		// Skip any other element using a best-effort length walk.
		n := mongoSkipValue(t, body[i:])
		if n < 0 {
			return nil
		}
		i += n
	}
	return nil
}

// mongoNamesFromArray reads a BSON array document of {name: "..."} entries and
// returns each "name" value, capped at 100.
func mongoNamesFromArray(arr []byte) []string {
	if len(arr) < 5 {
		return nil
	}
	arrLen := int(int32(binary.LittleEndian.Uint32(arr[0:4])))
	if arrLen < 5 || arrLen > len(arr) {
		return nil
	}
	body := arr[4:arrLen]
	var names []string
	i := 0
	for i < len(body) && len(names) < 100 {
		t := body[i]
		i++
		if t == 0x00 {
			break
		}
		end := bytes.IndexByte(body[i:], 0x00)
		if end < 0 {
			break
		}
		i += end + 1

		if t == 0x03 {
			if i+4 > len(body) {
				break
			}
			subLen := int(int32(binary.LittleEndian.Uint32(body[i : i+4])))
			if subLen < 5 || i+subLen > len(body) {
				break
			}
			if name := mongoNameFromDoc(body[i : i+subLen]); name != "" {
				names = append(names, name)
			}
			i += subLen
			continue
		}

		n := mongoSkipValue(t, body[i:])
		if n < 0 {
			break
		}
		i += n
	}
	return names
}

// mongoNameFromDoc returns the "name" string field from a single database
// entry document, or "" if absent or malformed.
func mongoNameFromDoc(doc []byte) string {
	if len(doc) < 5 {
		return ""
	}
	docLen := int(int32(binary.LittleEndian.Uint32(doc[0:4])))
	if docLen < 5 || docLen > len(doc) {
		return ""
	}
	body := doc[4:docLen]
	i := 0
	for i < len(body) {
		t := body[i]
		i++
		if t == 0x00 {
			break
		}
		end := bytes.IndexByte(body[i:], 0x00)
		if end < 0 {
			return ""
		}
		key := string(body[i : i+end])
		i += end + 1

		if t == 0x02 && key == "name" {
			if i+4 > len(body) {
				return ""
			}
			sl := int(binary.LittleEndian.Uint32(body[i : i+4]))
			i += 4
			if sl < 1 || i+sl > len(body) {
				return ""
			}
			return string(body[i : i+sl-1])
		}

		n := mongoSkipValue(t, body[i:])
		if n < 0 {
			return ""
		}
		i += n
	}
	return ""
}

// mongoSkipValue returns how many bytes the value of BSON type t occupies at
// the start of buf, or -1 if it cannot be determined safely.
func mongoSkipValue(t byte, buf []byte) int {
	switch t {
	case 0x01, 0x09, 0x11, 0x12: // double, datetime, timestamp, int64
		if len(buf) < 8 {
			return -1
		}
		return 8
	case 0x10: // int32
		if len(buf) < 4 {
			return -1
		}
		return 4
	case 0x08: // bool
		if len(buf) < 1 {
			return -1
		}
		return 1
	case 0x0A: // null
		return 0
	case 0x07: // ObjectId
		if len(buf) < 12 {
			return -1
		}
		return 12
	case 0x02: // string
		if len(buf) < 4 {
			return -1
		}
		sl := int(binary.LittleEndian.Uint32(buf[0:4]))
		if sl < 1 || 4+sl > len(buf) {
			return -1
		}
		return 4 + sl
	case 0x03, 0x04: // embedded doc / array
		if len(buf) < 4 {
			return -1
		}
		sub := int(int32(binary.LittleEndian.Uint32(buf[0:4])))
		if sub < 5 || sub > len(buf) {
			return -1
		}
		return sub
	default:
		return -1
	}
}

// buildIsMasterQuery assembles the OP_QUERY isMaster packet.
func buildIsMasterQuery() []byte {
	// Document: { isMaster: 1 } encoded as BSON.
	bsonDoc := buildIsMasterBSON()

	collName := []byte("admin.$cmd\x00")
	var body bytes.Buffer
	// flags(4) = 0
	binary.Write(&body, binary.LittleEndian, uint32(0))
	body.Write(collName)
	// numberToSkip(4) = 0
	binary.Write(&body, binary.LittleEndian, uint32(0))
	// numberToReturn(4) = 1
	binary.Write(&body, binary.LittleEndian, uint32(1))
	body.Write(bsonDoc)

	msgLen := 16 + body.Len()
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.LittleEndian, uint32(msgLen))
	binary.Write(&pkt, binary.LittleEndian, uint32(1)) // requestID
	binary.Write(&pkt, binary.LittleEndian, uint32(0)) // responseTo
	binary.Write(&pkt, binary.LittleEndian, uint32(opcodeQuery))
	pkt.Write(body.Bytes())
	return pkt.Bytes()
}

// buildIsMasterBSON manually serializes {"isMaster": 1}.
//   doc-len(4) + 0x10 int32 + "isMaster\x00" + value(4) + 0x00
func buildIsMasterBSON() []byte {
	var b bytes.Buffer
	b.WriteByte(0x10) // int32
	b.WriteString("isMaster")
	b.WriteByte(0x00)
	binary.Write(&b, binary.LittleEndian, int32(1))
	b.WriteByte(0x00) // doc terminator
	docLen := 4 + b.Len()
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, int32(docLen))
	out.Write(b.Bytes())
	return out.Bytes()
}

// readBSONDoc parses one BSON document starting at buf[0]. Returns the
// decoded fields, the number of bytes consumed, or an error.
//
// We only handle the element types we expect from isMaster: 0x01 double,
// 0x02 string, 0x08 bool, 0x10 int32, 0x12 int64. Anything else we skip
// using a best-effort length walk so we don't get stuck.
func readBSONDoc(buf []byte) (map[string]any, int, error) {
	if len(buf) < 5 {
		return nil, 0, fmt.Errorf("doc too short")
	}
	docLen := int(int32(binary.LittleEndian.Uint32(buf[0:4])))
	if docLen < 5 || docLen > len(buf) {
		return nil, 0, fmt.Errorf("bad doc length %d (have %d)", docLen, len(buf))
	}
	body := buf[4:docLen]
	out := map[string]any{}
	i := 0
	for i < len(body) {
		t := body[i]
		i++
		if t == 0x00 {
			break // end of document
		}
		// Read cstring key
		end := bytes.IndexByte(body[i:], 0x00)
		if end < 0 {
			return out, docLen, fmt.Errorf("unterminated key")
		}
		key := string(body[i : i+end])
		i += end + 1
		switch t {
		case 0x01: // double
			if i+8 > len(body) {
				return out, docLen, fmt.Errorf("short double")
			}
			bits := binary.LittleEndian.Uint64(body[i : i+8])
			out[key] = math.Float64frombits(bits)
			i += 8
		case 0x02: // string
			if i+4 > len(body) {
				return out, docLen, fmt.Errorf("short string len")
			}
			sl := int(binary.LittleEndian.Uint32(body[i : i+4]))
			i += 4
			if i+sl > len(body) || sl < 1 {
				return out, docLen, fmt.Errorf("short string body")
			}
			out[key] = string(body[i : i+sl-1])
			i += sl
		case 0x08: // bool
			if i >= len(body) {
				return out, docLen, fmt.Errorf("short bool")
			}
			out[key] = body[i] != 0
			i++
		case 0x10: // int32
			if i+4 > len(body) {
				return out, docLen, fmt.Errorf("short int32")
			}
			out[key] = int32(binary.LittleEndian.Uint32(body[i : i+4]))
			i += 4
		case 0x12: // int64
			if i+8 > len(body) {
				return out, docLen, fmt.Errorf("short int64")
			}
			out[key] = int64(binary.LittleEndian.Uint64(body[i : i+8]))
			i += 8
		case 0x03, 0x04: // embedded doc / array
			if i+4 > len(body) {
				return out, docLen, fmt.Errorf("short subdoc")
			}
			sub := int(int32(binary.LittleEndian.Uint32(body[i : i+4])))
			if sub < 5 || i+sub > len(body) {
				return out, docLen, fmt.Errorf("bad subdoc length")
			}
			i += sub
		case 0x07: // ObjectId
			i += 12
		case 0x09: // datetime
			i += 8
		case 0x11: // timestamp
			i += 8
		case 0x0A: // null
			out[key] = nil
		default:
			// Unknown type: bail rather than guess.
			return out, docLen, fmt.Errorf("unhandled bson type 0x%02X for key %q", t, key)
		}
	}
	return out, docLen, nil
}

func bsonAsString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func bsonAsFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

// mongoBuildInfo sends { buildInfo: 1 } via OP_MSG and returns the version string.
// Fallback for MongoDB 4.4+ where isMaster does not include "version".
func mongoBuildInfo(host string, port int, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildBuildInfoMsg()); err != nil {
		return ""
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return ""
	}
	msgLen := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	if msgLen < 16 || msgLen > 1<<20 {
		return ""
	}
	if int32(binary.LittleEndian.Uint32(hdr[12:16])) != opcodeMsg {
		return ""
	}
	body := make([]byte, msgLen-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		return ""
	}
	// OP_MSG body: flagBits(4) + section kind byte(0x00) + BSON doc
	if len(body) < 5 || body[4] != 0x00 {
		return ""
	}
	doc, _, err := readBSONDoc(body[5:])
	if err != nil {
		return ""
	}
	return bsonAsString(doc["version"])
}

func buildBuildInfoMsg() []byte {
	cmd := buildBuildInfoBSON()

	var section bytes.Buffer
	section.WriteByte(0x00)
	section.Write(cmd)

	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint32(0))
	body.Write(section.Bytes())

	msgLen := 16 + body.Len()
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.LittleEndian, uint32(msgLen))
	binary.Write(&pkt, binary.LittleEndian, uint32(3))
	binary.Write(&pkt, binary.LittleEndian, uint32(0))
	binary.Write(&pkt, binary.LittleEndian, uint32(opcodeMsg))
	pkt.Write(body.Bytes())
	return pkt.Bytes()
}

func buildBuildInfoBSON() []byte {
	var b bytes.Buffer
	b.WriteByte(0x10)
	b.WriteString("buildInfo")
	b.WriteByte(0x00)
	binary.Write(&b, binary.LittleEndian, int32(1))
	b.WriteByte(0x02)
	b.WriteString("$db")
	b.WriteByte(0x00)
	admin := "admin\x00"
	binary.Write(&b, binary.LittleEndian, int32(len(admin)))
	b.WriteString(admin)
	b.WriteByte(0x00)

	docLen := 4 + b.Len()
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, int32(docLen))
	out.Write(b.Bytes())
	return out.Bytes()
}
