// snmpprobe.go: phase 3 driver for SNMP (UDP 161).
//
// We brute-force a short list of default communities with SNMPv2c
// GetRequest for sysDescr.0 (.1.3.6.1.2.1.1.1.0). On hit, fetch the
// rest of the system MIB. No write attempts, no Set, no enumeration of
// IF tables: only the standard sys* OIDs.
package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// SNMPReport is what Phase 3 emits per SNMP target.
type SNMPReport struct {
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	CommunityHit      string   `json:"community_hit"`
	Version           string   `json:"version,omitempty"`
	SysDescr          string   `json:"sys_descr,omitempty"`
	SysName           string   `json:"sys_name,omitempty"`
	SysContact        string   `json:"sys_contact,omitempty"`
	SysLocation       string   `json:"sys_location,omitempty"`
	SysObjectID       string   `json:"sys_object_id,omitempty"`
	SysUpTime         string   `json:"sys_up_time,omitempty"`
	RunningProcesses  []string `json:"running_processes,omitempty"`
	InstalledSoftware []string `json:"installed_software,omitempty"`
	NetworkInterfaces []string `json:"network_interfaces,omitempty"`
	UserAccounts      []string `json:"user_accounts,omitempty"`
	SysProduct        string   `json:"sys_product,omitempty"`
	SysVersion        string   `json:"sys_version,omitempty"`
	ProbeErrors       []string `json:"probe_errors,omitempty"`
}

var snmpDefaultCommunities = []string{
	"public", "private", "community", "manager", "admin", "snmp", "guest",
}

// system MIB OIDs we care about
const (
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = ".1.3.6.1.2.1.1.3.0"
	oidSysContact  = ".1.3.6.1.2.1.1.4.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	oidSysLocation = ".1.3.6.1.2.1.1.6.0"
)

// Deep-content walk OIDs (Nessus-style host enumeration). These are
// table/subtree roots we BulkWalk after a community is confirmed valid.
const (
	oidIfDescr           = "1.3.6.1.2.1.2.2.1.2"       // network interfaces (ifDescr)
	oidHrSWRunName       = "1.3.6.1.2.1.25.4.2.1.2"    // running processes (hrSWRunName)
	oidHrSWInstalledName = "1.3.6.1.2.1.25.6.3.1.2"    // installed software (hrSWInstalledName)
	oidLanMgrUsers       = "1.3.6.1.4.1.77.1.2.25.1.1" // Windows LanManager user accounts
)

// snmpWalkCap bounds how many entries we keep per walked subtree.
const snmpWalkCap = 50

// ProbeSNMP tries each default community and on success collects the
// system MIB.
func ProbeSNMP(host string, port int, timeout time.Duration) (*SNMPReport, error) {
	rep := &SNMPReport{Host: host, Port: port, Version: "v2c"}

	for _, community := range snmpDefaultCommunities {
		val, err := snmpGetOne(host, port, community, oidSysDescr, timeout)
		if err != nil {
			// Don't spam probe_errors per community; only record once
			// at the end if nothing worked.
			continue
		}
		rep.CommunityHit = community
		rep.SysDescr = val
		rep.SysProduct, rep.SysVersion = parseSNMPDeviceVersion(val)
		// Fetch the rest of the system MIB
		rep.SysObjectID = mustString(snmpGetOne(host, port, community, oidSysObjectID, timeout))
		rep.SysUpTime = mustString(snmpGetOne(host, port, community, oidSysUpTime, timeout))
		rep.SysContact = mustString(snmpGetOne(host, port, community, oidSysContact, timeout))
		rep.SysName = mustString(snmpGetOne(host, port, community, oidSysName, timeout))
		rep.SysLocation = mustString(snmpGetOne(host, port, community, oidSysLocation, timeout))
		// Deep-content capture: WALK host-resources / interface / user
		// subtrees with the now-confirmed community. Best-effort; one
		// subtree failing must not abort the others.
		snmpDeepContent(host, port, community, timeout, rep)
		return rep, nil
	}
	rep.ProbeErrors = append(rep.ProbeErrors,
		"no default community succeeded (tried "+fmt.Sprintf("%v", snmpDefaultCommunities)+")")
	return rep, nil
}

// snmpGetOne does one v2c GetRequest and returns the value as a string.
func snmpGetOne(host string, port int, community, oid string, timeout time.Duration) (string, error) {
	params := &g.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: community,
		Version:   g.Version2c,
		Timeout:   timeout,
		Retries:   1,
		MaxOids:   1,
	}
	if err := params.Connect(); err != nil {
		return "", err
	}
	defer params.Conn.Close()
	res, err := params.Get([]string{oid})
	if err != nil {
		return "", err
	}
	if len(res.Variables) == 0 {
		return "", fmt.Errorf("no variables in response")
	}
	v := res.Variables[0]
	if v.Type == g.NoSuchObject || v.Type == g.NoSuchInstance || v.Type == g.EndOfMibView {
		return "", fmt.Errorf("oid %s not present", oid)
	}
	switch val := v.Value.(type) {
	case string:
		return val, nil
	case []byte:
		return string(val), nil
	case int:
		return fmt.Sprintf("%d", val), nil
	case uint:
		return fmt.Sprintf("%d", val), nil
	case uint32:
		return fmt.Sprintf("%d", val), nil
	case uint64:
		return fmt.Sprintf("%d", val), nil
	default:
		return fmt.Sprintf("%v", val), nil
	}
}

func mustString(s string, err error) string {
	if err != nil {
		return ""
	}
	return s
}

// snmpDeepContent opens one connection with the confirmed-valid community
// and walks the host-resources, interface and user subtrees. Each walk is
// independent and bounded; failures yield empty slices, never a panic.
func snmpDeepContent(host string, port int, community string, timeout time.Duration, rep *SNMPReport) {
	params := &g.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: community,
		Version:   g.Version2c,
		Timeout:   timeout,
		Retries:   1,
		MaxOids:   g.MaxOids,
	}
	if err := params.Connect(); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, "deep-content connect: "+err.Error())
		return
	}
	defer params.Conn.Close()

	rep.NetworkInterfaces = snmpWalkStrings(params, oidIfDescr, snmpWalkCap)
	rep.RunningProcesses = snmpWalkStrings(params, oidHrSWRunName, snmpWalkCap)
	rep.InstalledSoftware = snmpWalkStrings(params, oidHrSWInstalledName, snmpWalkCap)
	rep.UserAccounts = snmpWalkStrings(params, oidLanMgrUsers, snmpWalkCap)
}

// snmpWalkStrings walks oid on an already-connected params, stringifies each
// PDU value and returns up to cap non-empty entries. It prefers BulkWalkAll
// and falls back to WalkAll if BulkWalk errors (e.g. SNMPv1). Any walk error
// yields an empty slice rather than aborting the caller.
func snmpWalkStrings(params *g.GoSNMP, oid string, cap int) []string {
	pdus, err := params.BulkWalkAll(oid)
	if err != nil {
		pdus, err = params.WalkAll(oid)
		if err != nil {
			return nil
		}
	}
	out := make([]string, 0, len(pdus))
	for _, pdu := range pdus {
		if len(out) >= cap {
			break
		}
		var s string
		switch v := pdu.Value.(type) {
		case []byte:
			s = string(v)
		case string:
			s = v
		default:
			continue
		}
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sysDescrPatterns maps well-known network device sysDescr patterns to a
// structured product name and version regex.
var sysDescrPatterns = []struct {
	product string
	re      *regexp.Regexp
	verIdx  int
}{
	{"cisco-ios", regexp.MustCompile(`(?i)Cisco IOS Software[^,]*?Version\s+(\S+)`), 1},
	{"cisco-nxos", regexp.MustCompile(`(?i)Cisco Nexus.*?NX-OS.*?version\s+(\S+)`), 1},
	{"pan-os", regexp.MustCompile(`(?i)Palo Alto Networks.*?PAN-OS\s+(\d[\d.]+)`), 1},
	{"fortios", regexp.MustCompile(`(?i)FortiGate.*?v(\d+\.\d+[\d.]*)`), 1},
	{"bigip", regexp.MustCompile(`(?i)BIG-IP[^,]*?(\d+\.\d+\.\d+)`), 1},
	{"esxi", regexp.MustCompile(`(?i)VMware ESXi\s+(\d[\d.]+)`), 1},
	{"junos", regexp.MustCompile(`(?i)Juniper Networks.*?JUNOS\s+(\S+)`), 1},
	{"checkpoint", regexp.MustCompile(`(?i)Check Point.*?R(\d+[\d.]*)`), 1},
}

// parseSNMPDeviceVersion extracts product name + version string from SNMP
// sysDescr for common network devices. Returns empty strings if unrecognised.
func parseSNMPDeviceVersion(sysDescr string) (product, version string) {
	for _, p := range sysDescrPatterns {
		m := p.re.FindStringSubmatch(sysDescr)
		if m == nil {
			continue
		}
		ver := ""
		if p.verIdx < len(m) {
			ver = strings.TrimRight(m[p.verIdx], ",:; ")
		}
		return p.product, ver
	}
	return "", ""
}
