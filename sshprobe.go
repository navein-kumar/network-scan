// sshprobe.go: phase 3 driver for SSH (replaces nmap ssh-hostkey + ssh2-enum-algos)
//
// Two-step approach, no shell-out, no nmap:
//   1. Parse server's SSH_MSG_KEXINIT directly per RFC 4253 §7.1 to enumerate
//      kex / cipher / mac / compression / host-key algorithm lists.
//   2. Run up to 4 narrow x/crypto/ssh.Dial calls each restricting
//      HostKeyAlgorithms to one type, capture the offered key via a
//      HostKeyCallback that "fails" intentionally. The capture sidesteps
//      having to complete auth.
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHReport is what Phase 3 emits per SSH port.
type SSHReport struct {
	Host             string         `json:"host"`
	Port             int            `json:"port"`
	Banner           string         `json:"banner"`
	Product          string         `json:"product,omitempty"`
	ProductVersion   string         `json:"product_version,omitempty"`
	KexAlgorithms    []string       `json:"kex_algorithms"`
	HostKeyAlgos     []string       `json:"host_key_algorithms"`
	CiphersC2S       []string       `json:"ciphers_c2s"`
	CiphersS2C       []string       `json:"ciphers_s2c"`
	MACsC2S          []string       `json:"macs_c2s"`
	MACsS2C          []string       `json:"macs_s2c"`
	CompressionC2S   []string       `json:"compression_c2s"`
	CompressionS2C   []string       `json:"compression_s2c"`
	HostKeys         []SSHHostKey   `json:"host_keys"`
	WeakAlgos        []string       `json:"weak_algos,omitempty"`
	CredAttempts     []CredAttempt  `json:"cred_attempts,omitempty"`
	CommandOutput    []string       `json:"command_output,omitempty"`
	ProbeErrors      []string       `json:"probe_errors,omitempty"`
}

// SSHHostKey is one offered host key.
type SSHHostKey struct {
	Type             string `json:"type"`              // "ssh-rsa", "ssh-ed25519", ...
	Bits             int    `json:"bits"`              // key size in bits
	FingerprintSHA256 string `json:"fingerprint_sha256"` // OpenSSH style: SHA256:<base64>
	FingerprintMD5    string `json:"fingerprint_md5"`    // legacy nmap style: hex:colon:format
}

// All host-key algorithm names we want to try, grouped so we know which
// "type bucket" each connection is asking for.
var hostKeyBuckets = []struct {
	bucket string
	algos  []string
}{
	{"ssh-rsa",     []string{"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}},
	{"ssh-dss",     []string{"ssh-dss"}},
	{"ecdsa",       []string{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}},
	{"ssh-ed25519", []string{"ssh-ed25519"}},
}

// Weak algos we flag in the report (matches ssh-audit's "fail" / "warn" tiers).
var weakAlgoSet = map[string]bool{
	// KEX
	"diffie-hellman-group1-sha1":             true,
	"diffie-hellman-group-exchange-sha1":     true,
	"diffie-hellman-group14-sha1":            true,
	"rsa1024-sha1":                           true,
	"gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==": true,
	// Host key
	"ssh-dss":     true,
	"ssh-rsa":     true, // SHA-1 signature, deprecated by OpenSSH 8.8
	// Ciphers (CBC = CVE-2008-5161 plaintext recovery surface)
	"3des-cbc":           true,
	"des-cbc":            true,
	"blowfish-cbc":       true,
	"cast128-cbc":        true,
	"aes128-cbc":         true,
	"aes192-cbc":         true,
	"aes256-cbc":         true,
	"arcfour":            true,
	"arcfour128":         true,
	"arcfour256":         true,
	// MACs
	"hmac-md5":        true,
	"hmac-md5-96":     true,
	"hmac-sha1":       true,
	"hmac-sha1-96":    true,
	"hmac-md5-etm@openssh.com":     true,
	"hmac-md5-96-etm@openssh.com":  true,
	"hmac-sha1-96-etm@openssh.com": true,
}

// ProbeSSH does both algo-enum (KEXINIT parse) and host-key extraction.
func ProbeSSH(host string, port int, timeout time.Duration) (*SSHReport, error) {
	rep := &SSHReport{Host: host, Port: port}

	// ── Step 1: raw KEXINIT parse ──────────────────────────────────────
	banner, kex, err := readKexInit(host, port, timeout)
	if err != nil {
		return nil, fmt.Errorf("kex_init: %w", err)
	}
	rep.Banner = banner
	rep.Product, rep.ProductVersion = parseProductVersion(banner)
	rep.KexAlgorithms = kex.KexAlgorithms
	rep.HostKeyAlgos = kex.ServerHostKeyAlgos
	rep.CiphersC2S = kex.EncAlgosC2S
	rep.CiphersS2C = kex.EncAlgosS2C
	rep.MACsC2S = kex.MacAlgosC2S
	rep.MACsS2C = kex.MacAlgosS2C
	rep.CompressionC2S = kex.CompAlgosC2S
	rep.CompressionS2C = kex.CompAlgosS2C

	// ── Step 2: host-key enumeration per bucket ────────────────────────
	for _, b := range hostKeyBuckets {
		hk, herr := grabHostKey(host, port, b.algos, timeout)
		if herr != nil {
			// not all servers offer all key types, only record actual errors
			// that aren't "no mutually supported host key algorithm"
			if !strings.Contains(herr.Error(), "no common algorithm") &&
				!strings.Contains(herr.Error(), "unable to authenticate") &&
				!strings.Contains(herr.Error(), "ssh: handshake failed") {
				rep.ProbeErrors = append(rep.ProbeErrors,
					fmt.Sprintf("%s: %v", b.bucket, herr))
			} else if hk == nil {
				continue
			}
		}
		if hk != nil {
			rep.HostKeys = append(rep.HostKeys, *hk)
		}
	}

	// ── Step 3: flag weak algos in the report ──────────────────────────
	for _, lst := range [][]string{kex.KexAlgorithms, kex.ServerHostKeyAlgos,
		kex.EncAlgosC2S, kex.EncAlgosS2C, kex.MacAlgosC2S, kex.MacAlgosS2C} {
		for _, a := range lst {
			if weakAlgoSet[a] {
				if !contains(rep.WeakAlgos, a) {
					rep.WeakAlgos = append(rep.WeakAlgos, a)
				}
			}
		}
	}
	return rep, nil
}

// ─────────────────────────────────────────────────────────────────────────
// RFC 4253 §7.1 KEXINIT raw parse
// ─────────────────────────────────────────────────────────────────────────

type sshKexInit struct {
	Cookie               [16]byte
	KexAlgorithms        []string
	ServerHostKeyAlgos   []string
	EncAlgosC2S          []string
	EncAlgosS2C          []string
	MacAlgosC2S          []string
	MacAlgosS2C          []string
	CompAlgosC2S         []string
	CompAlgosS2C         []string
	LangC2S              []string
	LangS2C              []string
	FirstKexPacketFollows byte
	Reserved             uint32
}

func readKexInit(host string, port int, timeout time.Duration) (string, *sshKexInit, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// OpenSSH sends banner with just \n; RFC 4253 says \r\n. Accept either.
	br := bufio.NewReader(conn)
	bannerLine, err := br.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("read banner: %w", err)
	}
	banner := strings.TrimRight(bannerLine, "\r\n")

	// Send our client banner
	if _, err := conn.Write([]byte("SSH-2.0-fastscan_probe\r\n")); err != nil {
		return banner, nil, fmt.Errorf("write banner: %w", err)
	}

	// Read first SSH packet from server (should be SSH_MSG_KEXINIT = type 20)
	pkt, err := readSSHPacket(br)
	if err != nil {
		return banner, nil, fmt.Errorf("read kex packet: %w", err)
	}
	if len(pkt) < 1 || pkt[0] != 20 {
		return banner, nil, fmt.Errorf("expected KEXINIT (20), got msg type %d", pkt[0])
	}

	kex, err := parseKexInit(pkt[1:])
	if err != nil {
		return banner, nil, fmt.Errorf("parse kex: %w", err)
	}
	return banner, kex, nil
}

// readSSHPacket reads one SSH binary packet per RFC 4253 §6.
// Format: packet_length(4) + padding_length(1) + payload + random padding + MAC.
// The first KEXINIT happens before crypto is enabled, so MAC length is 0.
func readSSHPacket(br *bufio.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen < 1 || pktLen > 65536 {
		return nil, fmt.Errorf("absurd packet length %d", pktLen)
	}
	body := make([]byte, pktLen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	padLen := int(body[0])
	if int(pktLen)-1-padLen < 0 {
		return nil, fmt.Errorf("invalid pad length %d for packet length %d", padLen, pktLen)
	}
	payload := body[1 : int(pktLen)-padLen]
	return payload, nil
}

func parseKexInit(buf []byte) (*sshKexInit, error) {
	if len(buf) < 16 {
		return nil, errors.New("kex payload too short for cookie")
	}
	kex := &sshKexInit{}
	copy(kex.Cookie[:], buf[:16])
	r := buf[16:]
	for i, dst := range []*[]string{
		&kex.KexAlgorithms,
		&kex.ServerHostKeyAlgos,
		&kex.EncAlgosC2S,
		&kex.EncAlgosS2C,
		&kex.MacAlgosC2S,
		&kex.MacAlgosS2C,
		&kex.CompAlgosC2S,
		&kex.CompAlgosS2C,
		&kex.LangC2S,
		&kex.LangS2C,
	} {
		if len(r) < 4 {
			return nil, fmt.Errorf("short read at namelist %d", i)
		}
		nl := binary.BigEndian.Uint32(r[:4])
		r = r[4:]
		if uint32(len(r)) < nl {
			return nil, fmt.Errorf("namelist %d truncated", i)
		}
		s := string(r[:nl])
		r = r[nl:]
		if s == "" {
			*dst = nil
		} else {
			*dst = strings.Split(s, ",")
		}
	}
	if len(r) < 5 {
		return nil, errors.New("short final fields")
	}
	kex.FirstKexPacketFollows = r[0]
	kex.Reserved = binary.BigEndian.Uint32(r[1:5])
	return kex, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Host-key extraction via x/crypto/ssh.Dial + HostKeyCallback capture
// ─────────────────────────────────────────────────────────────────────────

// stopHandshake is the sentinel error we use to abort the SSH handshake the
// moment we have the host key. Avoids needing a working credential.
var stopHandshake = errors.New("fastscan: stop after host key")

func grabHostKey(host string, port int, algos []string, timeout time.Duration) (*SSHHostKey, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              "fastscan",
		Auth:              []ssh.AuthMethod{ssh.Password("")},
		HostKeyAlgorithms: algos,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return stopHandshake
		},
		Timeout: timeout,
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", addr, cfg)
	if client != nil {
		client.Close()
	}
	if captured == nil {
		return nil, err
	}
	hk := &SSHHostKey{
		Type: captured.Type(),
		Bits: keyBits(captured),
	}
	marshaled := captured.Marshal()
	// SHA-256 fingerprint, OpenSSH format: SHA256:<base64>
	s := sha256.Sum256(marshaled)
	hk.FingerprintSHA256 = "SHA256:" +
		strings.TrimRight(base64.StdEncoding.EncodeToString(s[:]), "=")
	// MD5 fingerprint, classic ssh-keygen -E md5 format: aa:bb:cc:...
	m := md5.Sum(marshaled)
	hex := hex.EncodeToString(m[:])
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	hk.FingerprintMD5 = strings.Join(parts, ":")
	return hk, nil
}

func keyBits(k ssh.PublicKey) int {
	// best-effort: x/crypto/ssh.PublicKey doesn't expose bit length directly.
	// Use type-specific heuristics that are accurate enough for our report.
	switch k.Type() {
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		// RSA pub key wire format: name + e + n. n length minus leading 0x00
		// pad byte equals bits/8. Decode the SSH wire format.
		m := k.Marshal()
		// skip name string (uint32 len + str)
		if len(m) < 4 {
			return 0
		}
		nameLen := binary.BigEndian.Uint32(m[:4])
		off := 4 + int(nameLen)
		// skip e (uint32 len + bytes)
		if off+4 > len(m) {
			return 0
		}
		eLen := binary.BigEndian.Uint32(m[off : off+4])
		off += 4 + int(eLen)
		if off+4 > len(m) {
			return 0
		}
		nLen := binary.BigEndian.Uint32(m[off : off+4])
		off += 4
		// drop leading 0x00 sign byte from mpint encoding
		if int(nLen) > 0 && off < len(m) && m[off] == 0x00 {
			return (int(nLen) - 1) * 8
		}
		return int(nLen) * 8
	case "ssh-dss":
		return 1024 // DSA in SSH is always 1024 per FIPS 186-2
	case "ecdsa-sha2-nistp256":
		return 256
	case "ecdsa-sha2-nistp384":
		return 384
	case "ecdsa-sha2-nistp521":
		return 521
	case "ssh-ed25519":
		return 255
	}
	return 0
}

// ─────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}


// sshRunCommandsWithLogin authenticates with a default credential that already
// succeeded and runs a few harmless evidence commands. Best-effort: any dial,
// auth, or session error yields an empty slice (no panic). Output is bounded.
func sshRunCommandsWithLogin(host string, port int, user, pass string, timeout time.Duration) []string {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
	if err != nil {
		return nil
	}
	defer client.Close()

	cmds := []string{"id", "uname -a", "hostname", "ls -la"}
	var out []string
	const maxLines = 40
	for _, cmd := range cmds {
		if len(out) >= maxLines {
			break
		}
		sess, err := client.NewSession()
		if err != nil {
			continue
		}
		raw, _ := sess.CombinedOutput(cmd)
		sess.Close()
		out = append(out, "$ "+cmd)
		for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			if len(out) >= maxLines {
				break
			}
			out = append(out, line)
		}
	}
	if len(out) > maxLines {
		out = out[:maxLines]
	}
	return out
}
