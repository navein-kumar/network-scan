// mqttprobe.go: phase 3 driver for MQTT brokers (1883 cleartext, 8883 TLS).
//
// Hand-rolled MQTT v3.1.1 CONNECT packet. Server responds with CONNACK
// whose return code tells us whether the broker requires auth.
//   0 = accepted          (no auth)
//   1 = unacceptable proto version
//   2 = identifier rejected
//   3 = server unavailable
//   4 = bad username/password
//   5 = not authorized
//
// References: MQTT v3.1.1 OASIS spec, §3.1 CONNECT and §3.2 CONNACK.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type MQTTReport struct {
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	Reachable         bool     `json:"reachable"`
	CONNACKReturnCode int      `json:"connack_return_code"`
	AuthRequired      bool     `json:"auth_required"`
	BrokerInfo        []string `json:"broker_info,omitempty"`
	Topics            []string `json:"topics,omitempty"`
	ProbeErrors       []string `json:"probe_errors,omitempty"`
}

func ProbeMQTT(host string, port int, timeout time.Duration) (*MQTTReport, error) {
	rep := &MQTTReport{Host: host, Port: port, CONNACKReturnCode: -1}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	pkt := buildMQTTConnect("fastscan_probe")
	if _, err := conn.Write(pkt); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}

	// CONNACK is fixed 4 bytes: 0x20, 0x02, session_present, return_code.
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read connack: %v", err))
		return rep, nil
	}
	rep.Reachable = true
	if buf[0] != 0x20 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("unexpected reply 0x%02x", buf[0]))
		return rep, nil
	}
	rep.CONNACKReturnCode = int(buf[3])
	// Return codes 4 (bad creds) and 5 (not authorized) indicate auth is
	// being enforced. 0 = anonymous access granted.
	if rep.CONNACKReturnCode == 4 || rep.CONNACKReturnCode == 5 {
		rep.AuthRequired = true
	}
	// Close the raw handshake socket before the deep-capture client opens its
	// own connection (paho manages its own dialing).
	conn.Close()

	// Anonymous access granted: pull broker telemetry ($SYS/#) and live
	// application topics (#) as IoT evidence. Best-effort, fully bounded.
	if rep.CONNACKReturnCode == 0 {
		captureMQTTContent(rep, host, port, timeout)
	}
	return rep, nil
}

// captureMQTTContent connects anonymously with paho and subscribes to $SYS/#
// (broker stats) and # (live topics) under a hard time and message budget.
// It never publishes. Any error leaves the report slices empty.
func captureMQTTContent(rep *MQTTReport, host string, port int, timeout time.Duration) {
	defer func() {
		// Defensive: paho callbacks run on its own goroutines; never let a
		// panic from a malformed message escape the probe.
		_ = recover()
	}()

	const (
		maxMessages = 80 // hard cap across both subscriptions
		maxPerSlice = 50 // cap on each of BrokerInfo / Topics
		previewLen  = 60 // payload preview length for live topics
	)
	// Hard time budget for the whole capture (default ~5s, but never exceed
	// the caller-supplied timeout).
	budget := 5 * time.Second
	if timeout > 0 && timeout < budget {
		budget = timeout
	}

	// Vary the client id by host/port/pid so we never reuse a fixed id and
	// risk kicking a legitimately connected client.
	clientID := fmt.Sprintf("fastscan-%s-%d-%d", sanitizeID(host), port, os.Getpid()&0xffff)

	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s:%d", host, port))
	opts.SetClientID(clientID)
	opts.SetCleanSession(true)
	opts.SetAutoReconnect(false)
	opts.SetConnectTimeout(budget)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetOrderMatters(false)
	// No username, no password: this is the anonymous-access evidence path.

	var (
		mu      sync.Mutex
		sysSeen = map[string]bool{}
		appSeen = map[string]bool{}
		count   int
		done    = make(chan struct{})
		once    sync.Once
	)
	finish := func() { once.Do(func() { close(done) }) }

	handler := func(_ mqtt.Client, m mqtt.Message) {
		topic := m.Topic()
		mu.Lock()
		defer mu.Unlock()
		// Only count messages we actually keep toward the cap. A busy broker
		// floods $SYS load metrics we ignore; counting those would starve the
		// live application topics before they arrive.
		captured := false
		if strings.HasPrefix(topic, "$SYS/broker/") {
			if !sysSeen[topic] && len(rep.BrokerInfo) < maxPerSlice {
				sysSeen[topic] = true
				rep.BrokerInfo = append(rep.BrokerInfo,
					fmt.Sprintf("%s = %s", topic, sanitizePreview(m.Payload(), previewLen)))
				captured = true
			}
		} else if !strings.HasPrefix(topic, "$SYS/") {
			if !appSeen[topic] && len(rep.Topics) < maxPerSlice {
				appSeen[topic] = true
				rep.Topics = append(rep.Topics,
					fmt.Sprintf("%s = %s", topic, sanitizePreview(m.Payload(), previewLen)))
				captured = true
			}
		}
		if captured {
			count++
		}
		// Stop early only when both slices are full or the total kept hits the
		// cap; otherwise let the time budget keep draining for late arrivals.
		if count >= maxMessages ||
			(len(rep.BrokerInfo) >= maxPerSlice && len(rep.Topics) >= maxPerSlice) {
			finish()
		}
	}

	client := mqtt.NewClient(opts)
	tok := client.Connect()
	if !tok.WaitTimeout(budget) || tok.Error() != nil {
		// DisconnectQuiesce(0) is safe even if the connect did not complete.
		client.Disconnect(0)
		return
	}
	defer client.Disconnect(50)

	// $SYS/# for broker stats, # for live application topics. QoS 0 only.
	subs := map[string]byte{"$SYS/#": 0, "#": 0}
	if st := client.SubscribeMultiple(subs, handler); !st.WaitTimeout(budget) || st.Error() != nil {
		return
	}

	// Drain until the message cap trips or the time budget expires.
	select {
	case <-done:
	case <-time.After(budget):
	}

	// Stable output: sort BrokerInfo, keep Topics deterministic too.
	mu.Lock()
	sort.Strings(rep.BrokerInfo)
	sort.Strings(rep.Topics)
	mu.Unlock()
}

// sanitizeID strips characters that would be awkward inside a client id.
func sanitizeID(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
}

// sanitizePreview renders a payload as a short, binary-safe single-line preview.
func sanitizePreview(p []byte, max int) string {
	if len(p) > max {
		p = p[:max]
	}
	var b strings.Builder
	for _, c := range p {
		if c == '\n' || c == '\r' || c == '\t' {
			b.WriteByte(' ')
		} else if c < 0x20 || c == 0x7f {
			b.WriteByte('.')
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func buildMQTTConnect(clientID string) []byte {
	// Variable header: protocol name "MQTT" (len-prefixed), proto level
	// 0x04 (3.1.1), connect flags 0x02 (clean session), keepalive 60.
	var vh bytes.Buffer
	vh.WriteByte(0x00) // proto name length MSB
	vh.WriteByte(0x04) // proto name length LSB
	vh.WriteString("MQTT")
	vh.WriteByte(0x04) // protocol level
	vh.WriteByte(0x02) // connect flags = CleanSession
	binary.Write(&vh, binary.BigEndian, uint16(60)) // keepalive

	// Payload: client identifier (len-prefixed).
	var pl bytes.Buffer
	binary.Write(&pl, binary.BigEndian, uint16(len(clientID)))
	pl.WriteString(clientID)

	body := append(vh.Bytes(), pl.Bytes()...)

	// Fixed header: control packet type 0x10 (CONNECT) + remaining length
	// (variable byte integer).
	var out bytes.Buffer
	out.WriteByte(0x10)
	out.Write(encodeMQTTRemainingLength(len(body)))
	out.Write(body)
	return out.Bytes()
}

func encodeMQTTRemainingLength(n int) []byte {
	var out []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}
