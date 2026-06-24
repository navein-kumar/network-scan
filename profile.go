// profile.go: network-latency probe + 4 scan profiles.
//
// At startup we measure the RTT to the first target host with 3 TCP
// connects (port 80 + 443 + 22, taking the best). The detected RTT
// picks one of 4 named profiles. Each profile sets sensible defaults
// for batch / timeout / driver-timeout / max-hosts / HTTP timeouts.
//
// Individual flags override the profile values: any flag set on the
// command line wins over the profile's default.
package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

// Profile bundles the network-tuning defaults for one latency bracket.
type Profile struct {
	Name              string
	Batch             int            // rustscan -b
	Timeout           int            // rustscan -t (per-port discovery, ms)
	DriverTimeout     time.Duration  // Phase 2.5 per-driver timeout
	MaxHosts          int            // concurrent host pipelines
	HTTPConnectTimeout time.Duration // TCP + TLS handshake budget
	HTTPReadTimeout   time.Duration  // body read budget
	HTTPTotalTimeout  time.Duration  // overall request ceiling
	NucleiConcurrency int            // Phase 4 templates in flight per host
	NucleiRateLimit   int            // Phase 4 global request rate (req/sec)
}

var profiles = map[string]Profile{
	"fast": {
		Name: "fast", Batch: 4500, Timeout: 1500,
		DriverTimeout: 8 * time.Second, MaxHosts: 8,
		HTTPConnectTimeout: 5 * time.Second,
		HTTPReadTimeout:    10 * time.Second,
		HTTPTotalTimeout:   30 * time.Second,
		NucleiConcurrency:  25, NucleiRateLimit: 150,
	},
	"medium": {
		Name: "medium", Batch: 1500, Timeout: 3000,
		DriverTimeout: 15 * time.Second, MaxHosts: 4,
		HTTPConnectTimeout: 8 * time.Second,
		HTTPReadTimeout:    20 * time.Second,
		HTTPTotalTimeout:   60 * time.Second,
		NucleiConcurrency:  15, NucleiRateLimit: 100,
	},
	"slow": {
		Name: "slow", Batch: 500, Timeout: 5000,
		DriverTimeout: 30 * time.Second, MaxHosts: 2,
		HTTPConnectTimeout: 15 * time.Second,
		HTTPReadTimeout:    30 * time.Second,
		HTTPTotalTimeout:   90 * time.Second,
		NucleiConcurrency:  8, NucleiRateLimit: 50,
	},
	"crawl": {
		Name: "crawl", Batch: 200, Timeout: 10000,
		DriverTimeout: 60 * time.Second, MaxHosts: 1,
		HTTPConnectTimeout: 30 * time.Second,
		HTTPReadTimeout:    60 * time.Second,
		HTTPTotalTimeout:   180 * time.Second,
		NucleiConcurrency:  3, NucleiRateLimit: 20,
	},
}

// SelectProfileFromRTT picks the profile bracket for a measured RTT.
func SelectProfileFromRTT(rtt time.Duration) Profile {
	ms := rtt.Milliseconds()
	switch {
	case ms < 50:
		return profiles["fast"]
	case ms < 200:
		return profiles["medium"]
	case ms < 500:
		return profiles["slow"]
	default:
		return profiles["crawl"]
	}
}

// ProbeRTT does up to 3 TCP connects to common ports and returns the
// best (lowest) RTT. Returns 0 + error if no port responded.
func ProbeRTT(host string) (time.Duration, error) {
	ports := []int{443, 80, 22, 445, 3389}
	var best time.Duration
	var any bool
	deadline := time.Now().Add(3 * time.Second)
	for _, p := range ports {
		if time.Now().After(deadline) {
			break
		}
		start := time.Now()
		conn, err := net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", host, p), 1500*time.Millisecond)
		if err != nil {
			continue
		}
		rtt := time.Since(start)
		conn.Close()
		if !any || rtt < best {
			best = rtt
			any = true
		}
	}
	if !any {
		return 0, fmt.Errorf("no probe port responded on %s", host)
	}
	return best, nil
}

// firstHostOf takes the -target string (single host or CIDR) and
// returns the first IPv4 in the range. Best-effort.
func firstHostOf(target string) string {
	if ip := net.ParseIP(target); ip != nil {
		return target
	}
	if _, ipNet, err := net.ParseCIDR(target); err == nil {
		ip := ipNet.IP.To4()
		if ip == nil {
			return target
		}
		// rustscan and nmap default to skipping the network address
		// (.0). Bump to .1 for the probe since we just need any host
		// in the range to estimate RTT.
		out := make(net.IP, 4)
		copy(out, ip)
		out[3] = ip[3] + 1
		return out.String()
	}
	return target
}

// AutoSelectProfile probes the target and picks a profile. Falls back
// to "medium" on probe failure (safer than fast for unknown networks).
func AutoSelectProfile(target string) Profile {
	host := firstHostOf(target)
	rtt, err := ProbeRTT(host)
	if err != nil {
		log.Printf("[profile] RTT probe to %s failed (%v), defaulting to medium", host, err)
		return profiles["medium"]
	}
	p := SelectProfileFromRTT(rtt)
	log.Printf("[profile] RTT=%dms -> profile=%s (batch=%d timeout=%dms driver-timeout=%v max-hosts=%d)",
		rtt.Milliseconds(), p.Name, p.Batch, p.Timeout, p.DriverTimeout, p.MaxHosts)
	return p
}
