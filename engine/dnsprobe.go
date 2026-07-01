// dnsprobe.go: phase 3 driver for DNS servers.
//
// Three probes against the target resolver:
//   1. version.bind. CHAOS TXT  -> server software version disclosure
//   2. recursion-desired A query for a known internet name -> open resolver
//   3. AXFR for caller-supplied zone hint (default: skip)
// DNSSEC support is inferred from a DNSKEY query for "." with EDNS DO=1.
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSReport struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	VersionBind      string   `json:"version_bind,omitempty"`
	HostnameBind     string   `json:"hostname_bind,omitempty"`
	RecursionAllowed bool     `json:"recursion_allowed"`
	DNSSECCapable    bool     `json:"dnssec_capable"`
	AXFRAttempted    bool     `json:"axfr_attempted,omitempty"`
	AXFRPermitted    bool     `json:"axfr_permitted,omitempty"`
	AXFRRecords      []string `json:"axfr_records,omitempty"`
	ProbeErrors      []string `json:"probe_errors,omitempty"`
}

func ProbeDNS(host string, port int, timeout time.Duration) (*DNSReport, error) {
	rep := &DNSReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	c := &dns.Client{Net: "udp", Timeout: timeout}

	// version.bind. CHAOS TXT
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.Question = []dns.Question{{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}
	m.RecursionDesired = false
	if r, _, err := c.Exchange(m, addr); err == nil && r != nil {
		for _, a := range r.Answer {
			if t, ok := a.(*dns.TXT); ok && len(t.Txt) > 0 {
				rep.VersionBind = strings.Join(t.Txt, " ")
				break
			}
		}
	} else if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("version.bind: %v", err))
	}

	// hostname.bind. CHAOS TXT (BIND-only, informational)
	m = new(dns.Msg)
	m.Id = dns.Id()
	m.Question = []dns.Question{{Name: "hostname.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}
	if r, _, err := c.Exchange(m, addr); err == nil && r != nil {
		for _, a := range r.Answer {
			if t, ok := a.(*dns.TXT); ok && len(t.Txt) > 0 {
				rep.HostnameBind = strings.Join(t.Txt, " ")
				break
			}
		}
	}

	// Recursion check: RD=1 query for google.com A. RA flag set + answer
	// non-empty = open resolver.
	m = new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)
	m.RecursionDesired = true
	if r, _, err := c.Exchange(m, addr); err == nil && r != nil {
		if r.RecursionAvailable && len(r.Answer) > 0 {
			rep.RecursionAllowed = true
		}
	}

	// DNSSEC: query "." DNSKEY with EDNS DO=1. Any DNSKEY in the answer
	// means the resolver returns DNSSEC RRs (so it's at least DNSSEC-aware).
	m = new(dns.Msg)
	m.SetQuestion(".", dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true
	if r, _, err := c.Exchange(m, addr); err == nil && r != nil {
		for _, a := range r.Answer {
			if _, ok := a.(*dns.DNSKEY); ok {
				rep.DNSSECCapable = true
				break
			}
		}
	}

	return rep, nil
}
