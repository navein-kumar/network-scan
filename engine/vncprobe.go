// vncprobe.go: phase 3 driver for VNC.
//
// Hand-rolled RFB protocol handshake (RFC 6143):
//   1. server -> "RFB xxx.yyy\n"        (12 bytes)
//   2. client -> "RFB 003.008\n"        (12 bytes)
//   3a. RFB >= 3.7: server -> [n_types][type1][type2]...
//   3b. RFB == 3.3: server -> [u32 security_type]   (single forced type)
//
// We never go past step 3. No auth, no framebuffer, no disconnect noise.
// Library choice: skipped go-vnc (the public Dial API insists on completing
// auth + creating a client session, which is more behavior than a fingerprint
// probe wants). Hand-rolled is ~70 lines and exactly the data we need.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// VNCReport is what Phase 3 emits per VNC port.
type VNCReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	ProtocolVersion string   `json:"protocol_version"` // e.g. "RFB 003.003"
	SecurityTypes   []string `json:"security_types"`   // names per RFC 6143
	NoAuthRequired  bool     `json:"no_auth_required"` // type 1 (None) offered
	ScreenshotPath  string   `json:"screenshot_path,omitempty"`
	ProbeErrors     []string `json:"probe_errors,omitempty"`
}

// rfbSecurityNames maps RFC 6143 §7.2 security type numbers to names.
// Type 0 is the "connection failed" sentinel (RFB >= 3.7).
var rfbSecurityNames = map[uint8]string{
	1:  "None",
	2:  "VNCAuth",
	5:  "RA2",
	6:  "RA2ne",
	16: "Tight",
	17: "Ultra",
	18: "TLS",
	19: "VeNCrypt",
	20: "SASL",
	21: "MD5",
	22: "xvp",
}

// ProbeVNC speaks the RFB handshake just far enough to learn the protocol
// version and the offered security types, then disconnects.
func ProbeVNC(host string, port int, timeout time.Duration) (*VNCReport, error) {
	rep := &VNCReport{Host: host, Port: port}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: read server's ProtocolVersion line (12 bytes, ends \n)
	br := bufio.NewReader(conn)
	verBuf := make([]byte, 12)
	if _, err := io.ReadFull(br, verBuf); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read version: %v", err))
		return rep, nil
	}
	ver := strings.TrimRight(string(verBuf), "\n\x00")
	rep.ProtocolVersion = ver

	// Parse minor digit (positions 8..10 of "RFB xxx.yyy")
	minor := 0
	if len(ver) >= 11 && strings.HasPrefix(ver, "RFB ") {
		fmt.Sscanf(ver[8:11], "%d", &minor)
	}

	// Step 2: agree on 3.8 unless server pinned 3.3 / 3.5.
	clientVer := "RFB 003.008\n"
	if minor < 7 {
		clientVer = "RFB 003.003\n"
	}
	if _, err := conn.Write([]byte(clientVer)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("write version: %v", err))
		return rep, nil
	}

	// Step 3: read security types.
	if minor < 7 {
		// RFB 3.3: server picks one type, sends it as u32.
		var t32 uint32
		if err := binary.Read(br, binary.BigEndian, &t32); err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("read 3.3 sec type: %v", err))
			return rep, nil
		}
		if t32 == 0 {
			// Connection failed; reason string follows but we don't need it.
			rep.ProbeErrors = append(rep.ProbeErrors,
				"server replied security type 0 (failed)")
			return rep, nil
		}
		name := rfbSecurityName(uint8(t32))
		rep.SecurityTypes = []string{name}
		if t32 == 1 {
			rep.NoAuthRequired = true
		}
		conn.Close()
		captureVNCScreenshot(host, port, rep, timeout)
		return rep, nil
	}

	// RFB >= 3.7: [u8 n_types][n_types * u8 types]; n=0 means failure.
	var n uint8
	if err := binary.Read(br, binary.BigEndian, &n); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read sec count: %v", err))
		return rep, nil
	}
	if n == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors,
			"server replied 0 security types (failed)")
		return rep, nil
	}
	types := make([]byte, n)
	if _, err := io.ReadFull(br, types); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("read sec types: %v", err))
		return rep, nil
	}
	for _, t := range types {
		rep.SecurityTypes = append(rep.SecurityTypes, rfbSecurityName(t))
		if t == 1 {
			rep.NoAuthRequired = true
		}
	}
	conn.Close()
	captureVNCScreenshot(host, port, rep, timeout)
	return rep, nil
}

func rfbSecurityName(t uint8) string {
	if n, ok := rfbSecurityNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type-%d", t)
}

// captureVNCScreenshot is a best-effort grab of the remote VNC desktop into a
// PNG via scrying (vnc://host:port). Scrying writes PNG directly — no JPEG
// intermediate or ImageMagick needed. If scrying is absent or the capture
// fails, rep.ScreenshotPath is left empty and the probe continues normally.
func captureVNCScreenshot(host string, port int, rep *VNCReport, timeout time.Duration) {
	scry, err := exec.LookPath("scrying")
	if err != nil {
		return
	}

	dir := screenshotDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	pngPath := fmt.Sprintf("%s/vnc-desktop_%s_%d.png", dir, sanitizeForFilename(host), port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	target := fmt.Sprintf("vnc://%s:%d", host, port)
	if err := exec.CommandContext(ctx, scry, "--target", target, "--file", pngPath).Run(); err != nil {
		os.Remove(pngPath)
		return
	}

	if fi, err := os.Stat(pngPath); err == nil && fi.Size() > 0 {
		// Overlay a label bar (IP:port) on the raw PNG using Pillow so the
		// screenshot is self-identifying in reports.
		addScreenshotLabel(pngPath, fmt.Sprintf("vnc://%s:%d", host, port))
		rep.ScreenshotPath = pngPath
	} else {
		os.Remove(pngPath)
	}
}

// addScreenshotLabel burns a dark header bar with the target address into an
// existing PNG using Python + Pillow (already a required dep). Failure is
// silent — the unlabelled screenshot is kept as-is.
func addScreenshotLabel(pngPath, label string) {
	py, err := exec.LookPath("python3")
	if err != nil {
		if py, err = exec.LookPath("python"); err != nil {
			return
		}
	}
	script := `
import sys, textwrap
try:
    from PIL import Image, ImageDraw, ImageFont
    img = Image.open(sys.argv[1]).convert("RGB")
    bar_h = 38
    new = Image.new("RGB", (img.width, img.height + bar_h), (32, 33, 36))
    new.paste(img, (0, bar_h))
    d = ImageDraw.Draw(new)
    d.rectangle([0, 0, img.width, bar_h - 1], fill=(32, 33, 36))
    label = sys.argv[2]
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
    except Exception:
        font = ImageFont.load_default()
    d.text((14, 12), label, fill=(232, 234, 237), font=font)
    new.save(sys.argv[1])
except Exception as e:
    sys.exit(0)
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, py, "-c", script, pngPath, label).Run()
}

// vncDisplayForPort maps a TCP port to a VNC display number. Ports in the
// 5900..5999 block map to displays 0..99; anything else is passed through as-is
// so non-standard ports still reach the server.
func vncDisplayForPort(port int) int {
	if port >= 5900 && port < 6000 {
		return port - 5900
	}
	return port
}

// sanitizeForFilename strips path separators and other awkward characters from
// a host so it is safe to embed in a screenshot filename.
func sanitizeForFilename(s string) string {
	repl := func(r rune) rune {
		switch r {
		case '/', '\\', ':', ' ', '%', '?', '*', '"', '<', '>', '|':
			return '_'
		}
		return r
	}
	return strings.Map(repl, s)
}
