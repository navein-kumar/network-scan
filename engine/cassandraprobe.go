// cassandraprobe.go: phase 3 driver for Apache Cassandra CQL native (9042).
//
// Send a v4 OPTIONS frame: version=4, flags=0, stream=1, opcode=0x05,
// length=0. The server replies with a SUPPORTED frame whose body is a
// string-multimap of supported protocol options (PROTOCOL_VERSIONS,
// CQL_VERSION, COMPRESSION).
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/gocql/gocql"
)

type CassandraReport struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	Reachable        bool     `json:"reachable"`
	ProtocolVersions []string `json:"protocol_versions,omitempty"`
	CQLVersions      []string `json:"cql_versions,omitempty"`
	Compressions     []string `json:"compressions,omitempty"`
	Keyspaces        []string `json:"keyspaces,omitempty"`
	ReleaseVersion   string   `json:"release_version,omitempty"`
	Tables           []string `json:"tables,omitempty"`
	ProbeErrors      []string `json:"probe_errors,omitempty"`
}

func ProbeCassandra(host string, port int, timeout time.Duration) (*CassandraReport, error) {
	rep := &CassandraReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// OPTIONS v4: version=0x04, flags=0, stream(2)=1, opcode=0x05, length(4)=0
	frame := []byte{0x04, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(frame); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("hdr: %v", err))
		return rep, nil
	}
	opcode := hdr[4]
	length := binary.BigEndian.Uint32(hdr[5:9])
	if length > 1<<16 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("body too large %d", length))
		return rep, nil
	}
	body := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, body); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("body: %v", err))
			return rep, nil
		}
	}
	rep.Reachable = true
	// SUPPORTED opcode is 0x06. ERROR 0x00; older Cassandra rejects v4.
	if opcode != 0x06 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("opcode 0x%02x", opcode))
		return rep, nil
	}
	mm, err := parseCassandraMultimap(body)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("parse multimap: %v", err))
		return rep, nil
	}
	rep.ProtocolVersions = mm["PROTOCOL_VERSIONS"]
	rep.CQLVersions = mm["CQL_VERSION"]
	rep.Compressions = mm["COMPRESSION"]

	// Deep content: if access is allowed (commonly no-auth), list the schema
	// (keyspaces and tables) Nessus-style. Best-effort, never fatal.
	captureCassandraSchema(rep, host, port, timeout)
	return rep, nil
}

// captureCassandraSchema opens a no-auth gocql session and reads the schema.
// Any connection or query error leaves the slices empty without panicking.
func captureCassandraSchema(rep *CassandraReport, host string, port int, timeout time.Duration) {
	cluster := gocql.NewCluster(host)
	cluster.Port = port
	cluster.Timeout = timeout
	cluster.ConnectTimeout = timeout
	cluster.ProtoVersion = 4
	session, err := cluster.CreateSession()
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("schema session: %v", err))
		return
	}
	defer session.Close()

	// Server release version (e.g. "5.0.3")
	var rv string
	if err2 := session.Query("SELECT release_version FROM system.local").Scan(&rv); err2 == nil {
		rep.ReleaseVersion = rv
	}

	// Keyspaces: modern table first, fall back to Cassandra 2.x layout.
	var ks string
	iter := session.Query("SELECT keyspace_name FROM system_schema.keyspaces").Iter()
	for len(rep.Keyspaces) < 50 && iter.Scan(&ks) {
		rep.Keyspaces = append(rep.Keyspaces, ks)
	}
	if err := iter.Close(); err != nil {
		iter = session.Query("SELECT keyspace_name FROM system.schema_keyspaces").Iter()
		for len(rep.Keyspaces) < 50 && iter.Scan(&ks) {
			rep.Keyspaces = append(rep.Keyspaces, ks)
		}
		iter.Close()
	}

	// Tables as "keyspace.table"; skip system_* keyspaces to reduce noise.
	var tks, tbl string
	iter = session.Query("SELECT keyspace_name, table_name FROM system_schema.tables").Iter()
	for len(rep.Tables) < 50 && iter.Scan(&tks, &tbl) {
		if strings.HasPrefix(tks, "system_") || tks == "system" {
			continue
		}
		rep.Tables = append(rep.Tables, tks+"."+tbl)
	}
	if err := iter.Close(); err != nil {
		iter = session.Query("SELECT keyspace_name, columnfamily_name FROM system.schema_columnfamilies").Iter()
		for len(rep.Tables) < 50 && iter.Scan(&tks, &tbl) {
			if strings.HasPrefix(tks, "system_") || tks == "system" {
				continue
			}
			rep.Tables = append(rep.Tables, tks+"."+tbl)
		}
		iter.Close()
	}
}

// parseCassandraMultimap reads a [string multimap] per CQL binary protocol
// spec: short n followed by n entries of (string -> [string list]).
func parseCassandraMultimap(b []byte) (map[string][]string, error) {
	out := map[string][]string{}
	off := 0
	readShort := func() (uint16, error) {
		if off+2 > len(b) {
			return 0, fmt.Errorf("short read at %d", off)
		}
		v := binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		return v, nil
	}
	readString := func() (string, error) {
		n, err := readShort()
		if err != nil {
			return "", err
		}
		if off+int(n) > len(b) {
			return "", fmt.Errorf("string too long at %d", off)
		}
		s := string(b[off : off+int(n)])
		off += int(n)
		return s, nil
	}
	n, err := readShort()
	if err != nil {
		return nil, err
	}
	for i := uint16(0); i < n; i++ {
		k, err := readString()
		if err != nil {
			return out, err
		}
		listN, err := readShort()
		if err != nil {
			return out, err
		}
		var list []string
		for j := uint16(0); j < listN; j++ {
			v, err := readString()
			if err != nil {
				return out, err
			}
			list = append(list, v)
		}
		out[k] = list
	}
	return out, nil
}
