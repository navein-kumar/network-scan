// kafkaprobe.go: phase 3 driver for Apache Kafka (TCP 9092).
//
// Sends ApiVersionsRequest v3 (KIP-511, Kafka 2.4+) to extract the broker
// software name and version from the tagged fields in the response.
// Falls back gracefully on older brokers: reachability is confirmed but
// version stays empty.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type KafkaReport struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Reachable  bool   `json:"reachable"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

func ProbeKafka(host string, port int, timeout time.Duration) (*KafkaReport, error) {
	rep := &KafkaReport{Host: host, Port: port}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return rep, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildApiVersionsV3()); err != nil {
		rep.ProbeError = "write: " + err.Error()
		return rep, nil
	}
	var respLen uint32
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		rep.ProbeError = "read len: " + err.Error()
		return rep, nil
	}
	if respLen == 0 || respLen > 1<<20 {
		rep.ProbeError = fmt.Sprintf("unexpected resp len %d", respLen)
		return rep, nil
	}
	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		rep.ProbeError = "read body: " + err.Error()
		return rep, nil
	}
	rep.Reachable = true
	rep.Product, rep.Version = parseApiVersionsV3Response(buf)
	if rep.Product == "" {
		rep.Product = "kafka"
	}
	return rep, nil
}

// buildApiVersionsV3 constructs a Kafka ApiVersionsRequest v3 frame.
// Uses flexible (compact) encoding per KIP-482 / KIP-511.
func buildApiVersionsV3() []byte {
	var body []byte
	body = kafkaAppendUint16(body, 18)  // api_key = ApiVersions
	body = kafkaAppendUint16(body, 3)   // api_version = 3
	body = kafkaAppendUint32(body, 1)   // correlation_id
	body = append(body, 0x00)           // null client_id (compact nullable string: 0=null)
	body = kafkaUvarint(body, 0)        // 0 header tagged fields
	body = kafkaCompactStr(body, "fastscan") // client_software_name
	body = kafkaCompactStr(body, "1.0.0")   // client_software_version
	body = kafkaUvarint(body, 0)            // 0 body tagged fields

	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	return frame
}

// parseApiVersionsV3Response extracts software name + version from the
// tagged fields of an ApiVersionsResponse v3.
func parseApiVersionsV3Response(buf []byte) (product, version string) {
	if len(buf) < 8 {
		return "", ""
	}
	off := 4 // skip correlation_id
	// skip header tagged fields count (uvarint)
	_, n := binary.Uvarint(buf[off:])
	off += n
	if off+2 > len(buf) {
		return "", ""
	}
	// error_code
	if int16(binary.BigEndian.Uint16(buf[off:off+2])) != 0 {
		return "", ""
	}
	off += 2
	// skip api_keys compact array
	count, n2 := binary.Uvarint(buf[off:])
	off += n2
	numKeys := int(count) - 1
	if numKeys < 0 || numKeys > 500 {
		return "", ""
	}
	for i := 0; i < numKeys && off < len(buf); i++ {
		off += 6 // api_key(2) + min(2) + max(2)
		_, n3 := binary.Uvarint(buf[off:])
		off += n3
	}
	// throttle_time_ms
	if off+4 > len(buf) {
		return "", ""
	}
	off += 4
	// body tagged fields
	tagCount, n4 := binary.Uvarint(buf[off:])
	off += n4
	for i := uint64(0); i < tagCount && off < len(buf); i++ {
		tag, nt := binary.Uvarint(buf[off:])
		off += nt
		dataLen, nd := binary.Uvarint(buf[off:])
		off += nd
		end := off + int(dataLen)
		if end > len(buf) {
			break
		}
		data := buf[off:end]
		off = end
		s, ok := kafkaReadCompactStr(data)
		if !ok {
			continue
		}
		switch tag {
		case 0:
			product = strings.ToLower(s)
		case 1:
			version = s
		}
	}
	return product, version
}

func kafkaAppendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
func kafkaAppendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func kafkaUvarint(b []byte, v uint64) []byte {
	var tmp [10]byte
	n := binary.PutUvarint(tmp[:], v)
	return append(b, tmp[:n]...)
}
func kafkaCompactStr(b []byte, s string) []byte {
	b = kafkaUvarint(b, uint64(len(s)+1))
	return append(b, s...)
}
func kafkaReadCompactStr(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	length, n := binary.Uvarint(data)
	if length == 0 {
		return "", true
	}
	realLen := int(length - 1)
	if n+realLen > len(data) {
		return "", false
	}
	return string(data[n : n+realLen]), true
}
