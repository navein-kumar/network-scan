// ports.go: fast vs deep port-mode resolution + UDP discovery shellout.
//
// fast (default):
//   TCP: 1-1024 plus the curated set of high-value engagement ports
//   UDP: top 50 (hand-curated)
// deep (-deep):
//   TCP: 1-65535
//   UDP: top 100
// custom:
//   TCP: whatever -ports is set to
//   UDP: whatever -udp-ports is set to (empty = no UDP)
package main

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// TCP "fast" = the linux 1-1024 standard range plus the most common
// modern engagement ports above 1024. Keeps the scan tight without
// pulling the full nmap top-2000 list (the long tail is rarely useful
// on internal targets).
const tcpFastPorts = "1-1024," +
	"1099,1433,1521,1723,1883,2049,2181,2222,2375,2376,2483,2484," +
	"3000,3128,3260,3268,3269,3306,3389,3690,4000,4040,4443,4505,4506," +
	"4848,5000,5001,5044,5060,5061,5222,5269,5353,5432,5601,5672,5800," +
	"5900-5910,5984,5985,5986,6000-6010,6379,6443,6446,6667,6697," +
	"7000,7001,7077,7100,7170,7474,7547,7575,7676,7777,7778," +
	"8000-8010,8025,8080-8091,8123,8126,8161,8181,8200,8222,8333," +
	"8400-8403,8443,8500,8530,8531,8761,8765,8786,8787,8880,8888,8889,8983," +
	"9000,9001,9002,9042,9043,9080,9090,9091,9092,9093,9100,9200,9300," +
	"9418,9443,9600,9900,9990,9999,10000,10001,10250,10255,10443," +
	"11211,15672,16080,16992,16993,17500,18080,18091," +
	"19999,20000,20880,21379,22222,23023,24007,25565,27017,27018,27019," +
	"28017,32400,33060,49152,49153,49154,50000,50030,50060,50070,50090," +
	"50095,50111,55553,60001,60010,60020,60030,61613,61616,62078,63791"

const tcpDeepPorts = "1-65535"

// UDP "fast" = the top 50 ports that account for >95% of UDP service
// presence on internal networks: SNMP, NTP, DNS, NetBIOS, IPMI,
// VPN/IKE, syslog, NAT-PMP / UPnP, mDNS, Modbus, TFTP, etc.
const udpFastPorts = "53,67,68,69,88,111,123,135,137,138,139,161,162," +
	"445,500,514,520,623,631,873,1194,1434,1645,1646,1701,1812,1813," +
	"1900,2049,3702,4500,5060,5353,5355,5683,6000,6346,8767,9999," +
	"10000,17185,20031,32768,32815,49152,49153,49154,49156,49181,49182,53413"

const udpDeepPorts = udpFastPorts +
	",7,9,13,17,19,37,49,113,177,213,389,427,464,497,512,513," +
	"593,664,683,800,1029,1058,1080,1719,1720,1812,1813,2002,2123," +
	"3283,3389,3478,3527,4000,4045,4444,5555,5556,7777,9876,10080," +
	"11211,16384,17500,19283,19682,21800,27015,32414,33848,34861,40193"

// ResolveTCPPorts returns the rustscan port spec for TCP.
//   override != "" -> override wins (custom mode)
//   deep == true   -> tcpDeepPorts
//   otherwise      -> tcpFastPorts
func ResolveTCPPorts(override string, deep bool) string {
	if override == "all" {
		return tcpDeepPorts // "all" keyword → 1-65535
	}
	if override != "" {
		return override
	}
	if deep {
		return tcpDeepPorts
	}
	return tcpFastPorts
}

// ResolveUDPPorts returns the UDP port spec the way DiscoverUDP expects.
//   override != "" -> override wins
//   skip == true   -> empty (no UDP scan)
//   deep == true   -> udpDeepPorts
//   otherwise      -> udpFastPorts
func ResolveUDPPorts(override string, deep, skip bool) string {
	if skip {
		return ""
	}
	if override != "" {
		return override
	}
	if deep {
		return udpDeepPorts
	}
	return udpFastPorts
}

// DiscoverUDP runs `nmap -sU -Pn -n -p <ports>` on host and returns
// the open UDP ports. Needs root for raw UDP probes. Returns nil + log
// (not error) on failure so the rest of the pipeline keeps going.
func DiscoverUDP(host, ports string, timeout time.Duration) []int {
	if ports == "" {
		return nil
	}
	args := []string{
		"-sU", "-Pn", "-n",
		"-p", ports,
		"--max-retries", "1",
		"--host-timeout", fmt.Sprintf("%ds", int(timeout.Seconds())),
		"-oX", "-",
		host,
	}
	cmd := exec.Command("nmap", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var run struct {
		Hosts []struct {
			Ports struct {
				Ports []struct {
					Protocol string `xml:"protocol,attr"`
					PortID   int    `xml:"portid,attr"`
					State    struct {
						State string `xml:"state,attr"`
					} `xml:"state"`
				} `xml:"port"`
			} `xml:"ports"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(out, &run); err != nil {
		return nil
	}
	var open []int
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Ports {
			if p.Protocol != "udp" {
				continue
			}
			// nmap UDP states: open, open|filtered, closed. We
			// optimistically include open|filtered because UDP probe
			// returns are often suppressed by firewalls.
			s := strings.ToLower(p.State.State)
			if s == "open" || strings.HasPrefix(s, "open|") {
				open = append(open, p.PortID)
			}
		}
	}
	return open
}

// JoinPortsInt returns "21,22,80" from a slice. Used to feed UDP
// discovery results into the open-ports stream.
func JoinPortsInt(ports []int) string {
	var s []string
	for _, p := range ports {
		s = append(s, strconv.Itoa(p))
	}
	return strings.Join(s, ",")
}

// ExpandPortSpec flattens mixed "1-1024,3306,5900-5910" into
// "1,2,3,...,1024,3306,5900,...,5910". rustscan's -p flag refuses
// ranges so we expand before passing them in. For a single
// start-end spec (no commas), returns the original string unchanged
// so the caller can still pass it through rustscan -r.
func ExpandPortSpec(spec string) string {
	if !strings.Contains(spec, ",") && strings.Contains(spec, "-") {
		// Single range like "1-65535", keep for rustscan -r.
		return spec
	}
	var out []string
	for _, chunk := range strings.Split(spec, ",") {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		if i := strings.Index(chunk, "-"); i > 0 {
			lo, _ := strconv.Atoi(chunk[:i])
			hi, _ := strconv.Atoi(chunk[i+1:])
			if lo > 0 && hi >= lo {
				for p := lo; p <= hi; p++ {
					out = append(out, strconv.Itoa(p))
				}
				continue
			}
		}
		out = append(out, chunk)
	}
	return strings.Join(out, ",")
}
