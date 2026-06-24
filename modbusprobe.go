// modbusprobe.go: phase 3 driver for Modbus/TCP (502).
//
// Hand-rolled Modbus/TCP function 0x2B (Encapsulated Interface Transport)
// MEI type 0x0E "Read Device Identification" with category 01 (basic).
// Response carries an object list:
//   0x00 VendorName
//   0x01 ProductCode
//   0x02 MajorMinorRevision
//
// MBAP header (7 bytes):
//   transaction id  uint16
//   protocol id     uint16 (0)
//   length          uint16 (bytes after this field, including unit id)
//   unit id         uint8
// PDU:
//   function code   uint8 (0x2B)
//   MEI type        uint8 (0x0E)
//   read dev id     uint8 (0x01 basic)
//   object id       uint8 (0x00)
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type ModbusReport struct {
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	Reachable          bool     `json:"reachable"`
	VendorName         string   `json:"vendor_name,omitempty"`
	ProductCode        string   `json:"product_code,omitempty"`
	MajorMinorRevision string   `json:"major_minor_revision,omitempty"`
	UnitsResponding    []int    `json:"units_responding,omitempty"`
	HoldingRegisters   []string `json:"holding_registers,omitempty"`
	Coils              []string `json:"coils,omitempty"`
	ProbeErrors        []string `json:"probe_errors,omitempty"`
}

func ProbeModbus(host string, port int, timeout time.Duration) (*ModbusReport, error) {
	rep := &ModbusReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Try unit id 1 first (most common), then 255 (anybody).
	for _, unitID := range []byte{1, 255} {
		req := buildModbusReadDeviceID(0x0001+uint16(unitID), unitID)
		if _, err := conn.Write(req); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("write unit=%d: %v", unitID, err))
			continue
		}
		// Read MBAP header (7 bytes) then PDU.
		hdr := make([]byte, 7)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("read header unit=%d: %v", unitID, err))
			continue
		}
		rep.Reachable = true
		pduLen := int(binary.BigEndian.Uint16(hdr[4:6])) - 1
		if pduLen <= 0 || pduLen > 1<<16 {
			continue
		}
		pdu := make([]byte, pduLen)
		if _, err := io.ReadFull(conn, pdu); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("read pdu unit=%d: %v", unitID, err))
			continue
		}
		if len(pdu) < 1 {
			continue
		}
		// Track that this unit responded at all.
		alreadySeen := false
		for _, u := range rep.UnitsResponding {
			if u == int(unitID) {
				alreadySeen = true
				break
			}
		}
		if !alreadySeen {
			rep.UnitsResponding = append(rep.UnitsResponding, int(unitID))
		}
		fc := pdu[0]
		// Exception response (0xAB)
		if fc == 0xAB || fc&0x80 != 0 {
			continue
		}
		if fc != 0x2B || len(pdu) < 7 {
			continue
		}
		// pdu: [0x2B, 0x0E, read_id_code, conformity, more_follows, next_obj_id, num_objects, ...]
		nObjects := int(pdu[6])
		off := 7
		for i := 0; i < nObjects && off+2 <= len(pdu); i++ {
			objID := pdu[off]
			objLen := int(pdu[off+1])
			off += 2
			if off+objLen > len(pdu) {
				break
			}
			val := string(pdu[off : off+objLen])
			off += objLen
			switch objID {
			case 0x00:
				if rep.VendorName == "" {
					rep.VendorName = val
				}
			case 0x01:
				if rep.ProductCode == "" {
					rep.ProductCode = val
				}
			case 0x02:
				if rep.MajorMinorRevision == "" {
					rep.MajorMinorRevision = val
				}
			}
		}
		if rep.VendorName != "" || rep.ProductCode != "" {
			break // got useful device-id info, stop scanning units
		}
	}

	// Read-only deep content: read holding registers (FC 0x03) and coils
	// (FC 0x01) from responding units. SAFETY: read-only function codes only;
	// this driver never issues any Modbus write. Best-effort and bounded by the
	// connection deadline already set above.
	probeModbusReadData(conn, rep)

	return rep, nil
}

// probeModbusReadData issues read-only Modbus requests against each responding
// unit and appends decoded values to rep. It guards against panics so a
// malformed response can never crash the scan. SAFETY: only read function codes
// 0x03 (Read Holding Registers) and 0x01 (Read Coils) are used; no write
// function code is ever constructed or sent.
func probeModbusReadData(conn net.Conn, rep *ModbusReport) {
	defer func() {
		if r := recover(); r != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("read-data panic recovered: %v", r))
		}
	}()

	units := rep.UnitsResponding
	if len(units) == 0 {
		units = []int{1} // nothing answered the id scan; try the common default
	}

	const maxEntries = 20
	txID := uint16(0x4000)

	for _, u := range units {
		unitID := byte(u)

		// FC 0x03 Read Holding Registers: start 0, quantity 10.
		if len(rep.HoldingRegisters) < maxEntries {
			txID++
			if regs, ok := modbusReadRegisters(conn, txID, unitID, 0x03, 0, 10); ok && len(regs) > 0 {
				parts := make([]string, len(regs))
				for i, v := range regs {
					parts[i] = fmt.Sprintf("%d", v)
				}
				rep.HoldingRegisters = append(rep.HoldingRegisters,
					fmt.Sprintf("unit %d: HR[0-%d] = %s",
						u, len(regs)-1, joinStrings(parts, ", ")))
			}
		}

		// FC 0x01 Read Coils: start 0, quantity 16.
		if len(rep.Coils) < maxEntries {
			txID++
			if bits, ok := modbusReadBits(conn, txID, unitID, 0x01, 0, 16); ok && len(bits) > 0 {
				parts := make([]string, len(bits))
				for i, b := range bits {
					if b {
						parts[i] = "1"
					} else {
						parts[i] = "0"
					}
				}
				rep.Coils = append(rep.Coils,
					fmt.Sprintf("unit %d: coils[0-%d] = %s",
						u, len(bits)-1, joinStrings(parts, ",")))
			}
		}

		if len(rep.HoldingRegisters) >= maxEntries && len(rep.Coils) >= maxEntries {
			break
		}
	}
}

// modbusReadRegisters issues a read-register request (FC 0x03 Read Holding
// Registers or FC 0x04 Read Input Registers, both read-only) and returns the
// decoded big-endian uint16 register values. ok is false on transport error or
// a Modbus exception response (function code | 0x80).
func modbusReadRegisters(conn net.Conn, txID uint16, unitID, fc byte, start, qty uint16) ([]uint16, bool) {
	var pdu bytes.Buffer
	pdu.WriteByte(fc)
	binary.Write(&pdu, binary.BigEndian, start)
	binary.Write(&pdu, binary.BigEndian, qty)

	resp, ok := modbusTransact(conn, txID, unitID, pdu.Bytes())
	if !ok || len(resp) < 2 {
		return nil, false
	}
	if resp[0]&0x80 != 0 { // exception response
		return nil, false
	}
	if resp[0] != fc {
		return nil, false
	}
	byteCount := int(resp[1])
	if byteCount < 2 || 2+byteCount > len(resp) {
		return nil, false
	}
	n := byteCount / 2
	regs := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		off := 2 + i*2
		regs = append(regs, binary.BigEndian.Uint16(resp[off:off+2]))
	}
	return regs, true
}

// modbusReadBits issues a read-bit request (FC 0x01 Read Coils or FC 0x02 Read
// Discrete Inputs, both read-only) and returns the unpacked bit values, least
// significant bit first. ok is false on transport error or a Modbus exception
// response (function code | 0x80).
func modbusReadBits(conn net.Conn, txID uint16, unitID, fc byte, start, qty uint16) ([]bool, bool) {
	var pdu bytes.Buffer
	pdu.WriteByte(fc)
	binary.Write(&pdu, binary.BigEndian, start)
	binary.Write(&pdu, binary.BigEndian, qty)

	resp, ok := modbusTransact(conn, txID, unitID, pdu.Bytes())
	if !ok || len(resp) < 2 {
		return nil, false
	}
	if resp[0]&0x80 != 0 { // exception response
		return nil, false
	}
	if resp[0] != fc {
		return nil, false
	}
	byteCount := int(resp[1])
	if byteCount < 1 || 2+byteCount > len(resp) {
		return nil, false
	}
	bits := make([]bool, 0, int(qty))
	for i := 0; i < int(qty); i++ {
		byteIdx := 2 + i/8
		if byteIdx >= len(resp) {
			break
		}
		bits = append(bits, resp[byteIdx]&(1<<uint(i%8)) != 0)
	}
	return bits, true
}

// modbusTransact sends one MBAP-framed request PDU and returns the response PDU
// (function code first). It reuses the same MBAP framing as the device-id probe
// (transaction id, protocol id 0, length, unit id + PDU).
func modbusTransact(conn net.Conn, txID uint16, unitID byte, pdu []byte) ([]byte, bool) {
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, txID)
	binary.Write(&out, binary.BigEndian, uint16(0))            // protocol id
	binary.Write(&out, binary.BigEndian, uint16(len(pdu)+1))   // length = pdu + unit id
	out.WriteByte(unitID)
	out.Write(pdu)

	if _, err := conn.Write(out.Bytes()); err != nil {
		return nil, false
	}
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, false
	}
	pduLen := int(binary.BigEndian.Uint16(hdr[4:6])) - 1
	if pduLen <= 0 || pduLen > 1<<16 {
		return nil, false
	}
	resp := make([]byte, pduLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, false
	}
	return resp, true
}

// joinStrings joins parts with sep without pulling in the strings package.
func joinStrings(parts []string, sep string) string {
	var b bytes.Buffer
	for i, p := range parts {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(p)
	}
	return b.String()
}

func buildModbusReadDeviceID(txID uint16, unitID byte) []byte {
	var pdu bytes.Buffer
	pdu.WriteByte(0x2B) // function code: encapsulated interface
	pdu.WriteByte(0x0E) // MEI type: read device identification
	pdu.WriteByte(0x01) // read device id code: basic
	pdu.WriteByte(0x00) // object id

	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, txID)
	binary.Write(&out, binary.BigEndian, uint16(0))                  // protocol id
	binary.Write(&out, binary.BigEndian, uint16(pdu.Len()+1))        // length = pdu + unit id
	out.WriteByte(unitID)
	out.Write(pdu.Bytes())
	return out.Bytes()
}
