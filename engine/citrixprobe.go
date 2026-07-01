// citrixprobe.go: phase 3 driver for Citrix ICA (1494) and ICA over CGP (2598).
//
// Hand-rolled. We send the Citrix ICA browser hello packet and look for
// any response. The protocol is proprietary and binary; we don't try to
// fully decode it. For v0 we capture the first response bytes as hex
// and try to pull a printable server name / banner out of the reply,
// which Citrix XenApp servers sometimes embed.
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type CitrixReport struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Reachable   bool     `json:"reachable"`
	ServerName  string   `json:"server_name,omitempty"`
	BannerBytes string   `json:"banner_bytes,omitempty"`
	ProbeErrors []string `json:"probe_errors,omitempty"`
}

// citrixHello is the well-known ICA browser hello packet captured from
// the wild. Servers reply with their server name and version block.
var citrixHello = []byte{
	0x1e, 0x00, 0x01, 0x30, 0x02, 0xfd, 0xa8, 0xe3,
	0x02, 0x00, 0x06, 0x44, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func ProbeCitrix(host string, port int, timeout time.Duration) (*CitrixReport, error) {
	rep := &CitrixReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(citrixHello); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("write: %v", err))
		return rep, nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read: %v", err))
		return rep, nil
	}
	rep.Reachable = true
	if n > 64 {
		rep.BannerBytes = hex.EncodeToString(buf[:64])
	} else {
		rep.BannerBytes = hex.EncodeToString(buf[:n])
	}
	rep.ServerName = citrixPrintableRun(buf[:n])
	return rep, nil
}

// citrixPrintableRun extracts the longest contiguous printable ASCII run
// of at least 4 chars from b. Citrix replies often embed the server
// hostname as a plain string surrounded by NULs.
func citrixPrintableRun(b []byte) string {
	var best, cur strings.Builder
	flush := func() {
		if cur.Len() > best.Len() && cur.Len() >= 4 {
			best.Reset()
			best.WriteString(cur.String())
		}
		cur.Reset()
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			cur.WriteByte(c)
		} else {
			flush()
		}
	}
	flush()
	return best.String()
}
