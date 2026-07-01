// ldapprobe.go: phase 3 driver for LDAP.
//
// Sequence: TCP dial -> anonymous BIND -> rootDSE search for the standard
// info-disclosure attributes. If the dial is on the TLS port (636 or 3269)
// we wrap the connection in TLS, otherwise plaintext. We do not attempt
// StartTLS upgrade; the no-tls plugin fires when port == 389 and the
// connection is unencrypted, which is what nmap's ldap-rootdse script
// also flags.
//
// No M2 (Metasploitable2) target for smoke testing: M2 has no LDAP daemon.
// Build is the acceptance criterion.
//
// Library: github.com/go-ldap/ldap/v3.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPReport is what Phase 3 emits per LDAP port.
type LDAPReport struct {
	Host                    string   `json:"host"`
	Port                    int      `json:"port"`
	IsTLS                   bool     `json:"is_tls"`
	AnonymousBindOK         bool     `json:"anonymous_bind_ok"`
	NamingContexts          []string `json:"naming_contexts,omitempty"`
	SupportedSASLMechanisms []string `json:"supported_sasl_mechanisms,omitempty"`
	SupportedLDAPVersions   []string `json:"supported_ldap_versions,omitempty"`
	ServerName              string   `json:"server_name,omitempty"`
	SupportedControls       []string `json:"supported_controls,omitempty"`
	Entries                 []string `json:"entries,omitempty"`
	ProbeErrors             []string `json:"probe_errors,omitempty"`
}

// ProbeLDAP dials, anonymous-binds, reads rootDSE.
func ProbeLDAP(host string, port int, timeout time.Duration) (*LDAPReport, error) {
	rep := &LDAPReport{Host: host, Port: port}

	useTLS := port == 636 || port == 3269
	rep.IsTLS = useTLS

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	var conn *ldap.Conn
	var err error
	if useTLS {
		conn, err = ldap.DialURL("ldaps://"+addr,
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
			ldap.DialWithDialer(dialer),
		)
	} else {
		conn, err = ldap.DialURL("ldap://"+addr,
			ldap.DialWithDialer(dialer),
		)
	}
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("dial: %v", err))
		return rep, nil
	}
	defer conn.Close()
	conn.SetTimeout(timeout)

	// Anonymous BIND.
	if err := conn.UnauthenticatedBind(""); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("anon bind: %v", err))
		return rep, nil
	}
	rep.AnonymousBindOK = true

	// rootDSE search: baseDN="", scope=base, filter=(objectClass=*).
	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, int(timeout.Seconds()), false,
		"(objectClass=*)",
		[]string{
			"namingContexts",
			"defaultNamingContext",
			"supportedSASLMechanisms",
			"supportedLDAPVersion",
			"supportedControl",
			"dnsHostName",
			"rootDomainNamingContext",
		},
		nil,
	)
	res, serr := conn.Search(req)
	if serr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("rootDSE: %v", serr))
		return rep, nil
	}
	for _, entry := range res.Entries {
		for _, attr := range entry.Attributes {
			switch attr.Name {
			case "namingContexts", "defaultNamingContext", "rootDomainNamingContext":
				for _, v := range attr.Values {
					if !contains(rep.NamingContexts, v) {
						rep.NamingContexts = append(rep.NamingContexts, v)
					}
				}
			case "supportedSASLMechanisms":
				rep.SupportedSASLMechanisms = append(rep.SupportedSASLMechanisms, attr.Values...)
			case "supportedLDAPVersion":
				rep.SupportedLDAPVersions = append(rep.SupportedLDAPVersions, attr.Values...)
			case "supportedControl":
				rep.SupportedControls = append(rep.SupportedControls, attr.Values...)
			case "dnsHostName":
				if len(attr.Values) > 0 {
					rep.ServerName = attr.Values[0]
				}
			}
		}
	}

	// Anonymous subtree dump: prove the directory is readable without
	// credentials by listing a bounded sample of entries (DN + identifying
	// attributes). This is the deep-content evidence, matching nmap
	// ldap-search / the Nessus anonymous-LDAP plugin output.
	if rep.AnonymousBindOK && len(rep.NamingContexts) > 0 {
		rep.Entries = ldapDumpEntries(conn, rep.NamingContexts[0], timeout)
	}
	return rep, nil
}

// ldapDumpEntries runs a bounded subtree search under baseDN and returns up
// to 50 entries rendered as "dn | attr=val, ...". Best-effort: if the server
// requires authentication for the subtree the search errors and we return an
// empty slice. A size-limit-exceeded error still carries partial entries,
// which we keep.
func ldapDumpEntries(conn *ldap.Conn, baseDN string, timeout time.Duration) []string {
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		50, int(timeout.Seconds()), false, // sizeLimit=50
		"(objectClass=*)",
		[]string{"cn", "uid", "sn", "givenName", "mail",
			"sAMAccountName", "userPassword", "description", "memberOf"},
		nil,
	)
	res, err := conn.Search(req)
	if res == nil || len(res.Entries) == 0 {
		if err != nil {
			return nil
		}
		return nil
	}
	var out []string
	for _, e := range res.Entries {
		var attrs []string
		for _, a := range e.Attributes {
			if len(a.Values) == 0 {
				continue
			}
			val := strings.Join(a.Values, "|")
			if len(val) > 80 {
				val = val[:80] + "..."
			}
			attrs = append(attrs, a.Name+"="+val)
		}
		linev := e.DN
		if len(attrs) > 0 {
			linev += " | " + strings.Join(attrs, ", ")
		}
		out = append(out, linev)
		if len(out) >= 50 {
			break
		}
	}
	return out
}
