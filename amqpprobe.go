// amqpprobe.go: phase 3 driver for AMQP 0-9-1 (5672, e.g. RabbitMQ).
//
// Hand-rolled per the AMQP 0-9-1 specification. We send the protocol
// header `AMQP\x00\x00\x09\x01` and parse the Connection.Start method
// frame the server replies with. That frame's server-properties field
// contains version / platform / product / capabilities, which we
// surface for plugin matching.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

type AMQPReport struct {
	Host             string            `json:"host"`
	Port             int               `json:"port"`
	Reachable        bool              `json:"reachable"`
	Version          string            `json:"version,omitempty"`
	Product          string            `json:"product,omitempty"`
	Platform         string            `json:"platform,omitempty"`
	Mechanisms       string            `json:"mechanisms,omitempty"`
	ServerProperties map[string]string `json:"server_properties,omitempty"`
	GuestAccess      bool              `json:"guest_access,omitempty"`
	Vhosts           []string          `json:"vhosts,omitempty"`
	Queues           []string          `json:"queues,omitempty"`
	ProbeErrors      []string          `json:"probe_errors,omitempty"`
}

func ProbeAMQP(host string, port int, timeout time.Duration) (*AMQPReport, error) {
	rep := &AMQPReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Protocol header
	if _, err := conn.Write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	// Frame header: type(1) channel(2) length(4) payload(length) frame-end(1)
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("frame hdr: %v", err))
		return rep, nil
	}
	if hdr[0] != 1 { // METHOD frame
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("frame type 0x%02x", hdr[0]))
		return rep, nil
	}
	bodyLen := binary.BigEndian.Uint32(hdr[3:7])
	if bodyLen > 1<<16 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("body too large %d", bodyLen))
		return rep, nil
	}
	body := make([]byte, bodyLen+1) // payload + frame-end
	if _, err := io.ReadFull(conn, body); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("body: %v", err))
		return rep, nil
	}
	rep.Reachable = true
	if len(body) < 4 {
		return rep, nil
	}
	classID := binary.BigEndian.Uint16(body[0:2])
	methodID := binary.BigEndian.Uint16(body[2:4])
	if classID != 10 || methodID != 10 { // Connection.Start
		return rep, nil
	}
	// payload: version-major(1) version-minor(1) server-properties(table)
	// peer-properties: field-table = long-uint length + entries
	off := 4
	if off+2 > len(body) {
		return rep, nil
	}
	off += 2 // skip version-major + version-minor

	if off+4 > len(body) {
		return rep, nil
	}
	tableLen := int(binary.BigEndian.Uint32(body[off : off+4]))
	off += 4
	if off+tableLen > len(body) {
		return rep, nil
	}
	props, _ := parseAMQPTable(body[off : off+tableLen])
	rep.ServerProperties = props
	rep.Version = props["version"]
	rep.Product = props["product"]
	rep.Platform = props["platform"]

	// after the table, mechanisms (long-string)
	off += tableLen
	if off+4 <= len(body) {
		ml := int(binary.BigEndian.Uint32(body[off : off+4]))
		off += 4
		if off+ml <= len(body) {
			rep.Mechanisms = string(body[off : off+ml])
		}
	}

	// Deep content: try the default guest:guest credential. A successful
	// AMQP dial proves access; the binary protocol cannot enumerate queues,
	// so we also query the RabbitMQ management HTTP API (conventionally on
	// 15672) for vhosts and queues. Both steps are best-effort.
	amqpGuestAccess(rep, host, port, timeout)

	return rep, nil
}

// amqpGuestAccess attempts the default guest:guest credential over AMQP and,
// if reachable, enumerates vhosts and queues via the management HTTP API.
func amqpGuestAccess(rep *AMQPReport, host string, port int, timeout time.Duration) {
	url := fmt.Sprintf("amqp://guest:guest@%s:%d/", host, port)
	conn, err := amqp091.DialConfig(url, amqp091.Config{Dial: amqp091.DefaultDial(timeout)})
	if err != nil {
		return
	}
	rep.GuestAccess = true
	conn.Close()

	// Management API on 15672 with HTTP Basic guest:guest. May be closed.
	rep.Vhosts = amqpMgmtVhosts(host, timeout)
	rep.Queues = amqpMgmtQueues(host, timeout)
}

func amqpMgmtGet(host, path string, timeout time.Duration) ([]byte, error) {
	url := fmt.Sprintf("http://%s:15672%s", host, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth("guest", "guest")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func amqpMgmtVhosts(host string, timeout time.Duration) []string {
	b, err := amqpMgmtGet(host, "/api/vhosts", timeout)
	if err != nil {
		return nil
	}
	var items []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(b, &items) != nil {
		return nil
	}
	var out []string
	for _, it := range items {
		out = append(out, it.Name)
		if len(out) >= 50 {
			break
		}
	}
	return out
}

func amqpMgmtQueues(host string, timeout time.Duration) []string {
	b, err := amqpMgmtGet(host, "/api/queues", timeout)
	if err != nil {
		return nil
	}
	var items []struct {
		Name     string `json:"name"`
		Vhost    string `json:"vhost"`
		Messages *int   `json:"messages"`
	}
	if json.Unmarshal(b, &items) != nil {
		return nil
	}
	var out []string
	for _, it := range items {
		entry := it.Vhost + "/" + it.Name
		if it.Messages != nil {
			entry = fmt.Sprintf("%s (%d msgs)", entry, *it.Messages)
		}
		out = append(out, entry)
		if len(out) >= 50 {
			break
		}
	}
	return out
}

// parseAMQPTable decodes an AMQP field-table into a flat string map.
// Only the field types we care about (S long-string, s short-string,
// t boolean) are decoded; the rest are skipped over.
func parseAMQPTable(b []byte) (map[string]string, error) {
	out := map[string]string{}
	off := 0
	for off < len(b) {
		if off+1 > len(b) {
			return out, fmt.Errorf("short key len")
		}
		klen := int(b[off])
		off++
		if off+klen > len(b) {
			return out, fmt.Errorf("short key")
		}
		key := string(b[off : off+klen])
		off += klen
		if off+1 > len(b) {
			return out, fmt.Errorf("short type")
		}
		typ := b[off]
		off++
		switch typ {
		case 'S': // long-string
			if off+4 > len(b) {
				return out, fmt.Errorf("short string-len")
			}
			n := int(binary.BigEndian.Uint32(b[off : off+4]))
			off += 4
			if off+n > len(b) {
				return out, fmt.Errorf("short string")
			}
			out[key] = string(b[off : off+n])
			off += n
		case 's': // short-string
			if off+1 > len(b) {
				return out, fmt.Errorf("short s-len")
			}
			n := int(b[off])
			off++
			if off+n > len(b) {
				return out, fmt.Errorf("short s")
			}
			out[key] = string(b[off : off+n])
			off += n
		case 't': // boolean
			if off+1 > len(b) {
				return out, fmt.Errorf("short bool")
			}
			if b[off] != 0 {
				out[key] = "true"
			} else {
				out[key] = "false"
			}
			off++
		case 'F': // nested field-table; record its length and skip
			if off+4 > len(b) {
				return out, fmt.Errorf("short table-len")
			}
			n := int(binary.BigEndian.Uint32(b[off : off+4]))
			off += 4
			if off+n > len(b) {
				return out, fmt.Errorf("short table")
			}
			off += n
		case 'I': // int32
			if off+4 > len(b) {
				return out, fmt.Errorf("short int32")
			}
			off += 4
		case 'l': // int64
			if off+8 > len(b) {
				return out, fmt.Errorf("short int64")
			}
			off += 8
		case 'V':
			// void
		default:
			// unknown type: give up gracefully on the rest of the table
			return out, nil
		}
	}
	return out, nil
}
