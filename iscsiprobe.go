// iscsiprobe.go: phase 3 driver for iSCSI (3260).
//
// Hand-rolled per RFC 7143. We send a Login PDU (transit=yes, current
// stage=0 SecurityNegotiation, next=1 LoginOperationalNegotiation) with
// SessionType=Discovery + InitiatorName text key. Then a Text Request
// PDU containing SendTargets=All. The Text Response carries Target /
// TargetAddress text-key pairs we enumerate.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type ISCSIReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Reachable       bool     `json:"reachable"`
	Targets         []string `json:"targets,omitempty"`
	TargetAddresses []string `json:"target_addresses,omitempty"`
	ProbeErrors     []string `json:"probe_errors,omitempty"`
}

const (
	iscsiOpLoginReq   = 0x03
	iscsiOpLoginResp  = 0x23
	iscsiOpTextReq    = 0x04
	iscsiOpTextResp   = 0x24
	iscsiOpLogoutReq  = 0x06
)

func ProbeISCSI(host string, port int, timeout time.Duration) (*ISCSIReport, error) {
	rep := &ISCSIReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	var isid [6]byte
	rand.Read(isid[:])

	// Login Request: kick straight to LoginOperationalNegotiation (T=1,
	// CSG=0, NSG=1). Text key data: InitiatorName + SessionType=Discovery.
	loginKeys := iscsiPadKeys(
		"InitiatorName=iqn.2024-01.com.fastscan:probe",
		"SessionType=Discovery",
		"AuthMethod=None",
	)
	loginBHS := buildISCSILoginBHS(isid, uint32(len(loginKeys)))
	if _, err := conn.Write(append(loginBHS, loginKeys...)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("login write: %v", err))
		return rep, nil
	}
	bhs := make([]byte, 48)
	if _, err := io.ReadFull(conn, bhs); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("login read: %v", err))
		return rep, nil
	}
	rep.Reachable = true
	if bhs[0] != iscsiOpLoginResp {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("login opcode 0x%02x", bhs[0]))
		return rep, nil
	}
	dsl := int(binary.BigEndian.Uint32(bhs[4:8]) & 0x00FFFFFF)
	if dsl > 1<<20 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("login dsl too big %d", dsl))
		return rep, nil
	}
	if dsl > 0 {
		buf := make([]byte, iscsiPad4(dsl))
		if _, err := io.ReadFull(conn, buf); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("login data: %v", err))
			return rep, nil
		}
	}
	// status-class at offset 36 (after the 32-byte header it's bhs[36]).
	if bhs[36] != 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("login status-class %d", bhs[36]))
		// Even on auth-required, the listener spoke iSCSI; bail without targets.
		return rep, nil
	}

	// Text Request: SendTargets=All. F=1 (final), I=1 (immediate).
	textKeys := iscsiPadKeys("SendTargets=All")
	textBHS := buildISCSITextBHS(isid, uint32(len(textKeys)))
	if _, err := conn.Write(append(textBHS, textKeys...)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("text write: %v", err))
		return rep, nil
	}
	tbhs := make([]byte, 48)
	if _, err := io.ReadFull(conn, tbhs); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("text read: %v", err))
		return rep, nil
	}
	if tbhs[0] != iscsiOpTextResp {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("text opcode 0x%02x", tbhs[0]))
		return rep, nil
	}
	tdsl := int(binary.BigEndian.Uint32(tbhs[4:8]) & 0x00FFFFFF)
	if tdsl > 1<<20 {
		return rep, nil
	}
	if tdsl > 0 {
		data := make([]byte, iscsiPad4(tdsl))
		if _, err := io.ReadFull(conn, data); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("text data: %v", err))
			return rep, nil
		}
		data = data[:tdsl]
		for _, kv := range bytes.Split(data, []byte{0}) {
			s := string(kv)
			if strings.HasPrefix(s, "TargetName=") {
				rep.Targets = append(rep.Targets, strings.TrimPrefix(s, "TargetName="))
			} else if strings.HasPrefix(s, "TargetAddress=") {
				rep.TargetAddresses = append(rep.TargetAddresses, strings.TrimPrefix(s, "TargetAddress="))
			}
		}
	}
	return rep, nil
}

func buildISCSILoginBHS(isid [6]byte, dsl uint32) []byte {
	b := make([]byte, 48)
	b[0] = iscsiOpLoginReq | 0x40 // I bit (immediate)
	// T=1 (transit), C=0, CSG=1, NSG=3 (FullFeature)
	b[1] = 0x87
	b[2] = 0x00 // version-max
	b[3] = 0x00 // version-min
	// total-AHS-len(1)=0 at b[4]; data-segment-length is 3-byte big-endian
	b[4] = 0
	b[5] = byte(dsl >> 16)
	b[6] = byte(dsl >> 8)
	b[7] = byte(dsl)
	copy(b[8:14], isid[:])
	// TSIH = 0; ITT = 1
	binary.BigEndian.PutUint32(b[16:20], 1)
	return b
}

func buildISCSITextBHS(isid [6]byte, dsl uint32) []byte {
	b := make([]byte, 48)
	b[0] = iscsiOpTextReq | 0x40 // I bit
	b[1] = 0x80                  // F=1
	b[4] = 0
	b[5] = byte(dsl >> 16)
	b[6] = byte(dsl >> 8)
	b[7] = byte(dsl)
	// LUN = 0; ITT = 2; CmdSN/ExpStatSN = 0; TTT = 0xffffffff per RFC
	binary.BigEndian.PutUint32(b[16:20], 2)
	binary.BigEndian.PutUint32(b[20:24], 0xffffffff)
	return b
}

// iscsiPadKeys joins key=value pairs with NUL separators and pads to a
// 4-byte boundary, which iSCSI requires for data segments.
func iscsiPadKeys(keys ...string) []byte {
	var b bytes.Buffer
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
	}
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func iscsiPad4(n int) int {
	if n%4 == 0 {
		return n
	}
	return n + (4 - n%4)
}
