// kerberosprobe.go: phase 3 driver for Kerberos KDC (88).
//
// We hand-build an AS-REQ for each probe username via gokrb5 messages,
// send to the KDC, and inspect the response:
//   - KRB-ERROR with KDC_ERR_PREAUTH_REQUIRED (25): user EXISTS, secure
//   - KRB-ERROR with KDC_ERR_C_PRINCIPAL_UNKNOWN (6): user does NOT exist
//   - KRB-ERROR with KDC_ERR_CLIENT_REVOKED (18) / NEVER_VALID (11):
//                                                  exists but locked
//   - AS-REP returned without preauth: AS-REP-roastable
package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// KerberosReport is what Phase 3 emits per KDC target.
type KerberosReport struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	Realm            string   `json:"realm,omitempty"`
	ExistingUsers    []string `json:"existing_users,omitempty"`
	NonexistentUsers []string `json:"nonexistent_users,omitempty"`
	AsRepRoastable   []string `json:"as_rep_roastable,omitempty"`
	ProbeErrors      []string `json:"probe_errors,omitempty"`
}

var kerberosProbeUsers = []string{"administrator", "krbtgt", "guest"}

// ProbeKerberos enumerates a small static user list against the KDC.
// Realm is required (no autodiscovery here).
func ProbeKerberos(host string, port int, realm string, timeout time.Duration) (*KerberosReport, error) {
	rep := &KerberosReport{Host: host, Port: port, Realm: realm}
	if realm == "" {
		return rep, fmt.Errorf("realm is required")
	}

	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DNSLookupRealm = false
	cfg.LibDefaults.UDPPreferenceLimit = 1 // force TCP, less truncation drama
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17} // aes256, aes128
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17}
	cfg.Realms = []config.Realm{{
		Realm:         realm,
		KDC:           []string{fmt.Sprintf("%s:%d", host, port)},
		AdminServer:   []string{fmt.Sprintf("%s:749", host)},
		KPasswdServer: []string{fmt.Sprintf("%s:464", host)},
	}}

	for _, user := range kerberosProbeUsers {
		clientPN := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
		req, err := messages.NewASReqForTGT(realm, cfg, clientPN)
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("%s: build AS-REQ: %v", user, err))
			continue
		}
		// Drop pre-auth padata so the KDC has to decide whether to
		// return a krb-error or hand out an AS-REP unauthenticated.
		req.PAData = nil

		raw, err := req.Marshal()
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("%s: marshal: %v", user, err))
			continue
		}
		reply, err := kdcRoundTrip(host, port, raw, timeout)
		if err != nil {
			rep.ProbeErrors = append(rep.ProbeErrors,
				fmt.Sprintf("%s: kdc round-trip: %v", user, err))
			continue
		}
		classify := classifyKDCReply(reply)
		switch classify {
		case "exists":
			rep.ExistingUsers = append(rep.ExistingUsers, user)
		case "missing":
			rep.NonexistentUsers = append(rep.NonexistentUsers, user)
		case "asreproast":
			rep.AsRepRoastable = append(rep.AsRepRoastable, user)
		case "locked":
			rep.ExistingUsers = append(rep.ExistingUsers, user+" (locked)")
		}
	}
	return rep, nil
}

// classifyKDCReply tries to unmarshal as KRB-ERROR first, then as
// AS-REP. Returns one of "exists", "missing", "asreproast", "locked", "unknown".
func classifyKDCReply(reply []byte) string {
	var kerr messages.KRBError
	if err := kerr.Unmarshal(reply); err == nil && kerr.MsgType == 30 {
		switch kerr.ErrorCode {
		case errorcode.KDC_ERR_PREAUTH_REQUIRED:
			return "exists"
		case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
			return "missing"
		case errorcode.KDC_ERR_CLIENT_REVOKED,
			errorcode.KDC_ERR_NEVER_VALID,
			errorcode.KDC_ERR_NAME_EXP:
			return "locked"
		}
		return "unknown"
	}
	var asrep messages.ASRep
	if err := asrep.Unmarshal(reply); err == nil && asrep.MsgType == 11 {
		return "asreproast"
	}
	return "unknown"
}

// kdcRoundTrip sends raw AS-REQ over TCP (4-byte length prefix).
func kdcRoundTrip(host string, port int, payload []byte, timeout time.Duration) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	lenPrefix := []byte{
		byte(len(payload) >> 24),
		byte(len(payload) >> 16),
		byte(len(payload) >> 8),
		byte(len(payload)),
	}
	if _, err := conn.Write(lenPrefix); err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	// Read length-prefixed reply.
	hdr := make([]byte, 4)
	if _, err := readFullKDC(conn, hdr); err != nil {
		return nil, fmt.Errorf("read len: %w", err)
	}
	rl := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if rl <= 0 || rl > 65536 {
		return nil, fmt.Errorf("absurd reply length %d", rl)
	}
	body := make([]byte, rl)
	if _, err := readFullKDC(conn, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

func readFullKDC(c net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		if n > 0 {
			got += n
		}
		if err != nil {
			if got == len(buf) {
				return got, nil
			}
			return got, err
		}
	}
	return got, nil
}

// unused but kept to mirror existing helper style; gokrb5 import surface
// dragged in strings indirectly.
var _ = strings.Contains
