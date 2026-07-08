// fastscan: port discover (rustscan) → service detect (nmap -sV via Ullaakut)
//           → HTTP enrich (httpx lib) → nuclei templates per service tag.
//
// Usage:
//   fastscan -target 172.17.0.3 -templates /tmp/all-tpl/ -out /tmp/fastscan_out
//
// Build:
//   cd tools/recon/fastscan && go mod tidy && go build .
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"

	httpxRunner "github.com/projectdiscovery/httpx/runner"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// service → nuclei tag(s). Each tag bucket runs as one nuclei engine.
// Tags must match the `tags:` field in tools/nuclei-templates/*.yaml.
var serviceTagMap = map[string][]string{
	"ftp":         {"ftp"},
	"ssh":         {"ssh"},
	"telnet":      {"telnet"},
	"smtp":        {"smtp"},
	"http":        {"http"},
	"https":       {"http", "ssl", "tls"},
	"ssl/http":    {"http", "ssl", "tls"},
	"rpcbind":     {"rpc"},
	"netbios-ssn": {"smb", "netbios"},
	"microsoft-ds": {"smb"},
	"java-rmi":    {"java", "rmi"},
	"mysql":       {"mysql"},
	"postgresql":  {"postgresql"},
	"vnc":         {"vnc"},
	"irc":         {"irc"},
	"snmp":        {"snmp"},
	"dns":         {"dns"},
	"domain":      {"dns"},
	"ldap":        {"ldap"},
	"rdp":         {"rdp"},
	"ms-wbt-server": {"rdp"},
	"nat-pmp":     {"nat-pmp"},
	"upnp":        {"upnp"},
}

type Finding struct {
	Phase     string                 `json:"phase"`
	Host      string                 `json:"host,omitempty"`
	Port      int                    `json:"port,omitempty"`
	Service   string                 `json:"service,omitempty"`
	Version   string                 `json:"version,omitempty"`
	Product   string                 `json:"product,omitempty"`
	Extra     string                 `json:"extra,omitempty"`
	CPE       []string               `json:"cpe,omitempty"`
	TLS       bool                   `json:"tls,omitempty"`
	Template  string                 `json:"template,omitempty"`
	Severity  string                 `json:"severity,omitempty"`
	Extract   string                 `json:"extract,omitempty"`
	Tech      []string               `json:"tech,omitempty"`
	Title     string                 `json:"title,omitempty"`
	Server    string                 `json:"server,omitempty"`
	URL       string                 `json:"url,omitempty"`
	Meta      map[string]any         `json:"meta,omitempty"`
	Timestamp string                 `json:"ts"`
}

type Port struct {
	Host    string
	Port    int
	Service string
	Product string
	Version string
	Extra   string
	CPE     []string
	TLS     bool
}

// binaryDir returns the directory of the running binary.
func binaryDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Dir(exe)
}

var (
	flagTarget    = flag.String("target", "", "host or CIDR (required)")
	flagTargetFile = flag.String("target-file", "", "file with one target (IP/CIDR) per line")
	flagPorts     = flag.String("ports", "", "TCP ports (overrides fast/deep). Empty = use fast/deep mode")
	flagUDPPorts  = flag.String("udp-ports", "", "UDP ports (overrides fast/deep). Empty = use fast/deep mode")
	flagDeep      = flag.Bool("deep", false, "deep scan mode: TCP 1-65535 + UDP top 100 (default is fast: TCP top ~1700 + UDP top 50)")
	flagSkipUDP   = flag.Bool("skip-udp", false, "skip UDP discovery (Phase 1b)")
	flagProfile   = flag.String("profile", "", "force a network-tuning profile: fast / medium / slow / crawl. Empty = auto-detect from latency")
	flagDriverTimeoutS = flag.String("driver-timeout", "", "per-driver probe timeout (e.g. 8s, 30s). Empty = use profile default")
	flagHTTPConnectS = flag.String("http-connect-timeout", "", "HTTP connect (TCP+TLS) timeout. Empty = use profile default")
	flagHTTPReadS    = flag.String("http-read-timeout", "", "HTTP body read timeout. Empty = use profile default")
	flagHTTPTotalS   = flag.String("http-total-timeout", "", "HTTP total request timeout. Empty = use profile default")
	flagNucleiConcurrency = flag.Int("nuclei-concurrency", 0, "nuclei templates in flight per host (0 = use profile default)")
	flagNucleiRateLimit   = flag.Int("nuclei-rate-limit", 0, "nuclei global request rate, req/sec (0 = use profile default)")
	flagTemplates = flag.String("templates", "/tmp/all-tpl/", "nuclei templates directory")
	flagOut       = flag.String("out", "fastscan_out", "output directory")
	flagBatch     = flag.Int("batch", 0, "rustscan batch size (0 = use profile default)")
	flagTimeout   = flag.Int("timeout", 0, "rustscan timeout ms per port (0 = use profile default)")
	flagSkipNmap   = flag.Bool("skip-nmap", false, "skip nmap -sV (use port-based guesses only)")
	flagSkipNuclei = flag.Bool("skip-nuclei", false, "stop after fingerprint stage")
	flagNmapMode   = flag.String("nmap-mode", "lib", "nmap execution mode: \"lib\" (Ullaakut wrapper) or \"direct\" (exec nmap CLI + XML parse)")
	flagNmapIntensity = flag.Int("nmap-intensity", 7, "nmap --version-intensity (0..9)")
	flagSSHTest    = flag.String("ssh-test", "", "standalone SSH probe: host:port, prints JSON report and exits")
	flagSMBTest    = flag.String("smb-test", "", "standalone SMB probe: host:port, prints JSON report and exits")
	flagVNCTest    = flag.String("vnc-test", "", "standalone VNC probe: host:port, prints JSON report and exits")
	flagLDAPTest   = flag.String("ldap-test", "", "standalone LDAP probe: host:port, prints JSON report and exits")
	flagMSSQLTest  = flag.String("mssql-test", "", "standalone MSSQL probe: host:port, prints JSON report and exits")
	flagRDPTest    = flag.String("rdp-test", "", "standalone RDP probe: host:port, prints JSON report and exits")
	flagMySQLTest      = flag.String("mysql-test", "", "standalone MySQL probe: host:port, prints JSON report and exits")
	flagPostgreSQLTest = flag.String("postgresql-test", "", "standalone PostgreSQL probe: host:port, prints JSON report and exits")
	flagSNMPTest       = flag.String("snmp-test", "", "standalone SNMP probe: host:port, prints JSON report and exits")
	flagNetBIOSTest    = flag.String("netbios-test", "", "standalone NetBIOS-NS probe: host:port, prints JSON report and exits")
	flagSMTPTest       = flag.String("smtp-test", "", "standalone SMTP probe: host:port, prints JSON report and exits")
	flagFTPTest        = flag.String("ftp-test", "", "standalone FTP probe: host:port, prints JSON report and exits")
	flagTelnetTest     = flag.String("telnet-test", "", "standalone Telnet probe: host:port, prints JSON report and exits")
	flagRsyncTest      = flag.String("rsync-test", "", "standalone rsync daemon probe: host:port, prints JSON report and exits")
	flagFingerTest     = flag.String("finger-test", "", "standalone finger probe: host:port, prints JSON report and exits")
	flagKerberosTest   = flag.String("kerberos-test", "", "standalone Kerberos probe: host:port@REALM, prints JSON report and exits")
	flagIPMITest       = flag.String("ipmi-test", "", "standalone IPMI probe: host:port, prints JSON report and exits")
	flagRPCTest        = flag.String("rpc-test", "", "standalone RPC/portmap probe: host:port, prints JSON report and exits")
	flagAJPTest        = flag.String("ajp-test", "", "standalone AJP13 probe: host:port, prints JSON report and exits")
	flagRedisTest      = flag.String("redis-test", "", "standalone Redis probe: host:port, prints JSON report and exits")
	flagMemcachedTest  = flag.String("memcached-test", "", "standalone memcached probe: host:port, prints JSON report and exits")
	flagMongoDBTest    = flag.String("mongodb-test", "", "standalone MongoDB probe: host:port, prints JSON report and exits")
	flagPOP3Test       = flag.String("pop3-test", "", "standalone POP3 probe: host:port, prints JSON report and exits")
	flagIMAPTest       = flag.String("imap-test", "", "standalone IMAP probe: host:port, prints JSON report and exits")
	flagNTPTest        = flag.String("ntp-test", "", "standalone NTP probe: host:port, prints JSON report and exits")
	flagOSTest         = flag.String("os-test", "", "standalone OS detection (nmap -O): host, prints JSON report and exits")
	flagDNSTest        = flag.String("dns-test", "", "standalone DNS probe: host:port, prints JSON report and exits")
	flagWinRMTest      = flag.String("winrm-test", "", "standalone WinRM probe: host:port, prints JSON report and exits")
	flagOracleTest     = flag.String("oracle-test", "", "standalone Oracle TNS probe: host:port, prints JSON report and exits")
	flagMSRPCTest      = flag.String("msrpc-test", "", "standalone MS-RPC probe: host:port, prints JSON report and exits")
	flagMQTTTest       = flag.String("mqtt-test", "", "standalone MQTT probe: host:port, prints JSON report and exits")
	flagSIPTest        = flag.String("sip-test", "", "standalone SIP probe: host:port, prints JSON report and exits")
	flagModbusTest     = flag.String("modbus-test", "", "standalone Modbus probe: host:port, prints JSON report and exits")
	flagTracerouteTest = flag.String("traceroute-test", "", "standalone traceroute probe: host, prints JSON report and exits")
	flagSkipOS         = flag.Bool("skip-os", false, "skip phase 2.6 OS detection (requires root)")
	flagSkipTraceroute = flag.Bool("skip-traceroute", false, "skip phase 2.7 traceroute (requires root)")
	flagPlugins    = flag.String("plugins", filepath.Join(binaryDir(), "plugins"), "directory containing YAML plugin rules")
	flagCheckDeps  = flag.Bool("check-deps", false, "check external CLI dependencies (nmap, rustscan, testssl.sh, nxc) and exit")
	flagSkipDepsWarning = flag.Bool("skip-deps-warning", false, "silence the startup-time dependency check")
	flagSkipDrivers = flag.Bool("skip-drivers", false, "skip phase 3 protocol drivers + plugin evaluation")
	flagMaxHosts   = flag.Int("max-hosts", 0, "max concurrent hosts when -target is a CIDR (0 = use profile default)")
	flagCredsDir   = flag.String("creds-dir", filepath.Join(binaryDir(), "creds"), "directory containing default-credential YAML lists (one per service)")
	flagSkipCreds  = flag.Bool("skip-creds", false, "skip default-credential testing layer")
	flagTLSFPTest  = flag.String("tlsfp-test", "", "standalone TLS fingerprint probe: host:port, prints JSON report and exits")
	flagJDWPTest      = flag.String("jdwp-test", "", "standalone JDWP probe: host:port, prints JSON report and exits")
	flagDockerAPITest = flag.String("dockerapi-test", "", "standalone Docker API probe: host:port, prints JSON report and exits")
	flagCUPSTest      = flag.String("cups-test", "", "standalone CUPS probe: host:port, prints JSON report and exits")
	flagTFTPTest      = flag.String("tftp-test", "", "standalone TFTP probe: host:port, prints JSON report and exits")
	flagWebLogicTest  = flag.String("weblogic-test", "", "standalone WebLogic T3 probe: host:port, prints JSON report and exits")
	flagCouchDBTest   = flag.String("couchdb-test", "", "standalone CouchDB probe: host:port, prints JSON report and exits")
	flagHNAPTest      = flag.String("hnap-test", "", "standalone HNAP1 probe: host:port, prints JSON report and exits")
	flagAFPTest       = flag.String("afp-test", "", "standalone AFP probe: host:port, prints JSON report and exits")
	flagPJLTest       = flag.String("pjl-test", "", "standalone PJL probe: host:port, prints JSON report and exits")
	flagDB2Test       = flag.String("db2-test", "", "standalone DB2 DRDA probe: host:port, prints JSON report and exits")
	flagCassandraTest = flag.String("cassandra-test", "", "standalone Cassandra CQL probe: host:port, prints JSON report and exits")
	flagHBaseTest     = flag.String("hbase-test", "", "standalone HBase web UI probe: host:port, prints JSON report and exits")
	flagCitrixTest    = flag.String("citrix-test", "", "standalone Citrix ICA probe: host:port, prints JSON report and exits")
	flagIKETest       = flag.String("ike-test", "", "standalone IKE/IPsec probe: host:port, prints JSON report and exits")
	flagSSTPTest      = flag.String("sstp-test", "", "standalone SSTP probe: host:port, prints JSON report and exits")
	flagAMQPTest      = flag.String("amqp-test", "", "standalone AMQP probe: host:port, prints JSON report and exits")
	flagISCSITest     = flag.String("iscsi-test", "", "standalone iSCSI probe: host:port, prints JSON report and exits")
	flagISNSTest      = flag.String("isns-test", "", "standalone iSNS probe: host:port, prints JSON report and exits")
	flagXMPPTest      = flag.String("xmpp-test", "", "standalone XMPP probe: host:port, prints JSON report and exits")
	flagTN3270Test    = flag.String("tn3270-test", "", "standalone TN3270 probe: host:port, prints JSON report and exits")
	flagInformixTest  = flag.String("informix-test", "", "standalone Informix probe: host:port, prints JSON report and exits")
	flagSVNTest       = flag.String("svn-test", "", "standalone SVN probe: host:port, prints JSON report and exits")
	flagHadoopTest    = flag.String("hadoop-test", "", "standalone Hadoop web UI probe: host:port, prints JSON report and exits")
	flagHTTPTest      = flag.String("http-test", "", "standalone HTTP probe: host:port, parses Server header, prints JSON report and exits")
	flagTLSVulnTest   = flag.String("tlsvuln-test", "", "standalone testssl.sh wrapper probe: host:port, prints JSON report and exits")
	flagSkipTLSVuln   = flag.Bool("skip-tlsvuln", false, "skip phase 2.95 testssl.sh wrapper")
	flagSMBVulnTest   = flag.String("smbvuln-test", "", "standalone nxc smb vuln probe: host:port, prints JSON report and exits")
	flagSkipSMBVuln   = flag.Bool("skip-smbvuln", false, "skip nxc SMB vuln modules (ms17-010, zerologon, smbghost)")
	flagUpdateTpl     = flag.Bool("update-templates", false, "force nuclei -update-templates and exit")
	flagCVETest       = flag.String("cve-test", "", "standalone cvemap CPE lookup: cpe:/a:vendor:product:version, prints JSON report and exits")
	flagSkipCVE       = flag.Bool("skip-cve", false, "skip phase 2.6b cvemap CPE→CVE lookup")
	flagSaveBaseline  = flag.String("save-baseline", "", "after scan, write a baseline NDJSON of normalized findings to this path")
	flagDiffAgainst   = flag.String("diff-against", "", "load this baseline NDJSON; only emit findings NOT in baseline plus phase=baseline-existing rows for overlap")
	flagWebhook       = flag.String("webhook", "", "POST any critical/high finding to this URL (JSON body, 5s timeout, failures non-fatal)")
	flagSkipAutoFP    = flag.Bool("skip-autofp", false, "skip phase 2.4 auto-fingerprint cascade for unknown / tcpwrapped ports")
	flagForceService  = flag.String("force-service", "", "manual service overrides: PORT=NAME[,PORT=NAME...] (e.g. 8888=ms-wbt-server,55555=http)")
	flagAutoFPTest    = flag.String("autofp-test", "", "standalone auto-fingerprint cascade: host:port, prints JSON {service,method,banner_hex} and exits")
	flagDriversPerHost = flag.Int("drivers-per-host", 4, "max concurrent protocol drivers per host in Phase 2.5 (>=1)")
)

// globalCreds is populated in main() and consulted by per-driver call
// sites. Standalone -xxx-test flag handlers also load it on demand
// through ensureCreds.
var globalCreds *CredStore

// activeProfile is the network-tuning profile chosen at startup (either
// auto-detected from RTT or set via -profile). Individual flags
// override its values when explicitly set.
var activeProfile Profile

// resolveScanTuning fills in profile defaults for any tuning flag the
// user did not pass explicitly. Run once after flag.Parse().
func resolveScanTuning(target string) {
	if *flagProfile != "" {
		p, ok := profiles[*flagProfile]
		if !ok {
			log.Fatalf("[profile] unknown profile %q (valid: fast, medium, slow, crawl)", *flagProfile)
		}
		activeProfile = p
		log.Printf("[profile] forced -profile=%s (batch=%d timeout=%dms driver-timeout=%v max-hosts=%d)",
			p.Name, p.Batch, p.Timeout, p.DriverTimeout, p.MaxHosts)
	} else {
		activeProfile = AutoSelectProfile(target)
	}
	if *flagBatch == 0 {
		*flagBatch = activeProfile.Batch
	}
	if *flagTimeout == 0 {
		*flagTimeout = activeProfile.Timeout
	}
	if *flagMaxHosts == 0 {
		*flagMaxHosts = activeProfile.MaxHosts
	}
}

// resolveDriverTimeout returns the per-driver probe timeout.
// -driver-timeout wins over the profile default.
func resolveDriverTimeout() time.Duration {
	if *flagDriverTimeoutS != "" {
		d, err := time.ParseDuration(*flagDriverTimeoutS)
		if err == nil {
			return d
		}
		log.Printf("[flags] bad -driver-timeout %q: %v (using profile default)", *flagDriverTimeoutS, err)
	}
	return activeProfile.DriverTimeout
}

// resolveHTTPTimeouts returns the (connect, read, total) HTTP timeouts.
func resolveHTTPTimeouts() (connect, read, total time.Duration) {
	connect, read, total = activeProfile.HTTPConnectTimeout, activeProfile.HTTPReadTimeout, activeProfile.HTTPTotalTimeout
	if *flagHTTPConnectS != "" {
		if d, err := time.ParseDuration(*flagHTTPConnectS); err == nil {
			connect = d
		}
	}
	if *flagHTTPReadS != "" {
		if d, err := time.ParseDuration(*flagHTTPReadS); err == nil {
			read = d
		}
	}
	if *flagHTTPTotalS != "" {
		if d, err := time.ParseDuration(*flagHTTPTotalS); err == nil {
			total = d
		}
	}
	return
}

// resolveNucleiConcurrency returns the nuclei concurrency (templates in
// flight per host). -nuclei-concurrency > 0 wins over the profile default.
func resolveNucleiConcurrency() int {
	if *flagNucleiConcurrency > 0 {
		return *flagNucleiConcurrency
	}
	return activeProfile.NucleiConcurrency
}

// resolveNucleiRateLimit returns the nuclei global rate-limit in req/sec.
// -nuclei-rate-limit > 0 wins over the profile default.
func resolveNucleiRateLimit() int {
	if *flagNucleiRateLimit > 0 {
		return *flagNucleiRateLimit
	}
	return activeProfile.NucleiRateLimit
}

// ensureCreds lazily loads the credential store for standalone -xxx-test
// modes. Honors -skip-creds. Safe to call multiple times.
func ensureCreds() *CredStore {
	if *flagSkipCreds {
		return &CredStore{}
	}
	if globalCreds != nil {
		return globalCreds
	}
	store, err := LoadCreds(*flagCredsDir)
	if err != nil {
		log.Printf("[creds] load %s: %v (continuing without creds)", *flagCredsDir, err)
		store = &CredStore{}
	}
	globalCreds = store
	return globalCreds
}

func main() {
	flag.Parse()

	// -check-deps short-circuits everything else.
	if *flagCheckDeps {
		PrintDeps(CheckDeps())
		return
	}

	// Non-fatal startup warning if any optional dep is missing.
	if !*flagSkipDepsWarning {
		WarnMissingAtStartup()
		WarnStaleTemplates(*flagTemplates)
	}

	// Standalone SSH probe mode: --ssh-test host:port
	if *flagSSHTest != "" {
		runSSHTest(*flagSSHTest)
		return
	}
	// Standalone SMB probe mode: --smb-test host:port
	if *flagSMBTest != "" {
		runSMBTest(*flagSMBTest)
		return
	}
	if *flagVNCTest != "" {
		runVNCTest(*flagVNCTest)
		return
	}
	if *flagLDAPTest != "" {
		runLDAPTest(*flagLDAPTest)
		return
	}
	if *flagMSSQLTest != "" {
		runMSSQLTest(*flagMSSQLTest)
		return
	}
	if *flagRDPTest != "" {
		runRDPTest(*flagRDPTest)
		return
	}
	if *flagMySQLTest != "" {
		runMySQLTest(*flagMySQLTest)
		return
	}
	if *flagPostgreSQLTest != "" {
		runPostgreSQLTest(*flagPostgreSQLTest)
		return
	}
	if *flagSNMPTest != "" {
		runSNMPTest(*flagSNMPTest)
		return
	}
	if *flagNetBIOSTest != "" {
		runNetBIOSTest(*flagNetBIOSTest)
		return
	}
	if *flagSMTPTest != "" {
		runSMTPTest(*flagSMTPTest)
		return
	}
	if *flagFTPTest != "" {
		runFTPTest(*flagFTPTest)
		return
	}
	if *flagTelnetTest != "" {
		runTelnetTest(*flagTelnetTest)
		return
	}
	if *flagRsyncTest != "" {
		runRsyncTest(*flagRsyncTest)
		return
	}
	if *flagFingerTest != "" {
		runFingerTest(*flagFingerTest)
		return
	}
	if *flagKerberosTest != "" {
		runKerberosTest(*flagKerberosTest)
		return
	}
	if *flagIPMITest != "" {
		runIPMITest(*flagIPMITest)
		return
	}
	if *flagRPCTest != "" {
		runRPCTest(*flagRPCTest)
		return
	}
	if *flagAJPTest != "" {
		runAJPTest(*flagAJPTest)
		return
	}
	if *flagRedisTest != "" {
		runRedisTest(*flagRedisTest)
		return
	}
	if *flagMemcachedTest != "" {
		runMemcachedTest(*flagMemcachedTest)
		return
	}
	if *flagMongoDBTest != "" {
		runMongoDBTest(*flagMongoDBTest)
		return
	}
	if *flagPOP3Test != "" {
		runPOP3Test(*flagPOP3Test)
		return
	}
	if *flagIMAPTest != "" {
		runIMAPTest(*flagIMAPTest)
		return
	}
	if *flagNTPTest != "" {
		runNTPTest(*flagNTPTest)
		return
	}
	if *flagOSTest != "" {
		runOSTest(*flagOSTest)
		return
	}
	if *flagDNSTest != "" {
		runDNSTest(*flagDNSTest)
		return
	}
	if *flagWinRMTest != "" {
		runWinRMTest(*flagWinRMTest)
		return
	}
	if *flagOracleTest != "" {
		runOracleTest(*flagOracleTest)
		return
	}
	if *flagMSRPCTest != "" {
		runMSRPCTest(*flagMSRPCTest)
		return
	}
	if *flagMQTTTest != "" {
		runMQTTTest(*flagMQTTTest)
		return
	}
	if *flagSIPTest != "" {
		runSIPTest(*flagSIPTest)
		return
	}
	if *flagModbusTest != "" {
		runModbusTest(*flagModbusTest)
		return
	}
	if *flagTracerouteTest != "" {
		runTracerouteTest(*flagTracerouteTest)
		return
	}
	if *flagTLSFPTest != "" {
		runTLSFPTest(*flagTLSFPTest)
		return
	}
	if *flagJDWPTest != "" {
		runJDWPTest(*flagJDWPTest)
		return
	}
	if *flagDockerAPITest != "" {
		runDockerAPITest(*flagDockerAPITest)
		return
	}
	if *flagCUPSTest != "" {
		runCUPSTest(*flagCUPSTest)
		return
	}
	if *flagTFTPTest != "" {
		runTFTPTest(*flagTFTPTest)
		return
	}
	if *flagWebLogicTest != "" {
		runWebLogicTest(*flagWebLogicTest)
		return
	}
	if *flagCouchDBTest != "" {
		runCouchDBTest(*flagCouchDBTest)
		return
	}
	if *flagHNAPTest != "" {
		runHNAPTest(*flagHNAPTest)
		return
	}
	if *flagAFPTest != "" {
		runAFPTest(*flagAFPTest)
		return
	}
	if *flagPJLTest != "" {
		runPJLTest(*flagPJLTest)
		return
	}
	if *flagDB2Test != "" {
		runDB2Test(*flagDB2Test)
		return
	}
	if *flagCassandraTest != "" {
		runCassandraTest(*flagCassandraTest)
		return
	}
	if *flagHBaseTest != "" {
		runHBaseTest(*flagHBaseTest)
		return
	}
	if *flagCitrixTest != "" {
		runCitrixTest(*flagCitrixTest)
		return
	}
	if *flagIKETest != "" {
		runIKETest(*flagIKETest)
		return
	}
	if *flagSSTPTest != "" {
		runSSTPTest(*flagSSTPTest)
		return
	}
	if *flagAMQPTest != "" {
		runAMQPTest(*flagAMQPTest)
		return
	}
	if *flagISCSITest != "" {
		runISCSITest(*flagISCSITest)
		return
	}
	if *flagISNSTest != "" {
		runISNSTest(*flagISNSTest)
		return
	}
	if *flagXMPPTest != "" {
		runXMPPTest(*flagXMPPTest)
		return
	}
	if *flagTN3270Test != "" {
		runTN3270Test(*flagTN3270Test)
		return
	}
	if *flagInformixTest != "" {
		runInformixTest(*flagInformixTest)
		return
	}
	if *flagSVNTest != "" {
		runSVNTest(*flagSVNTest)
		return
	}
	if *flagHadoopTest != "" {
		runHadoopTest(*flagHadoopTest)
		return
	}
	if *flagHTTPTest != "" {
		runHTTPTest(*flagHTTPTest)
		return
	}
	if *flagTLSVulnTest != "" {
		runTLSVulnTest(*flagTLSVulnTest)
		return
	}
	if *flagSMBVulnTest != "" {
		runSMBVulnTest(*flagSMBVulnTest)
		return
	}
	if *flagCVETest != "" {
		runCVETest(*flagCVETest)
		return
	}
	if *flagAutoFPTest != "" {
		runAutoFPTest(*flagAutoFPTest)
		return
	}
	if *flagUpdateTpl {
		if err := UpdateNucleiTemplatesForce(*flagTemplates); err != nil {
			log.Fatalf("update-templates: %v", err)
		}
		return
	}

	var targetList []string
	if *flagTargetFile != "" {
		data, ferr := os.ReadFile(*flagTargetFile)
		if ferr != nil {
			log.Fatalf("read target-file %s: %v", *flagTargetFile, ferr)
		}
		for _, ln := range strings.Split(string(data), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			targetList = append(targetList, ln)
		}
		if len(targetList) == 0 {
			log.Fatalf("target-file %s contained no targets", *flagTargetFile)
		}
	} else if *flagTarget != "" {
		targetList = []string{*flagTarget}
	} else {
		flag.Usage()
		os.Exit(2)
	}
	// Load default-credential store (used by phase 2.5 driver runs).
	ensureCreds()
	if globalCreds != nil {
		log.Printf("[creds] loaded %v", globalCreds.Counts())
	}
	if err := os.MkdirAll(*flagOut, 0o755); err != nil {
		log.Fatalf("mkdir out: %v", err)
	}

	wallStart := time.Now()
	writer := newWriter(filepath.Join(*flagOut, "findings.ndjson"))
	defer writer.Close()

	// Differential + baseline plumbing.
	bl, blErr := LoadBaseline(*flagDiffAgainst)
	if blErr != nil {
		log.Printf("[baseline] load %s: %v (continuing without diff)", *flagDiffAgainst, blErr)
	} else if bl.LoadedCount() > 0 {
		log.Printf("[baseline] loaded %d entries from %s", bl.LoadedCount(), *flagDiffAgainst)
	}
	writer.baseline = bl
	writer.webhook = NewWebhookClient(*flagWebhook)
	if writer.webhook != nil {
		log.Printf("[webhook] critical/high findings will POST to %s", *flagWebhook)
	}
	// Defer the save-baseline write so it runs after the scan loop.
	defer func() {
		if *flagSaveBaseline != "" && writer.baseline != nil {
			if err := writer.baseline.Save(*flagSaveBaseline); err != nil {
				log.Printf("[baseline] save %s: %v", *flagSaveBaseline, err)
			} else {
				log.Printf("[baseline] saved snapshot to %s", *flagSaveBaseline)
			}
		}
	}()

	for _ti, _tgt := range targetList {
		*flagTarget = _tgt
		if len(targetList) > 1 {
			log.Printf("[target-file] === scanning target %s (%d of %d) ===", _tgt, _ti+1, len(targetList))
		}
	// ── Phase 0: network-tuning profile (auto from latency or -profile) ─
	resolveScanTuning(*flagTarget)

	// Resolve TCP and UDP port spec: -ports / -udp-ports win over fast/deep.
	tcpPorts := ExpandPortSpec(ResolveTCPPorts(*flagPorts, *flagDeep))
	udpPorts := ResolveUDPPorts(*flagUDPPorts, *flagDeep, *flagSkipUDP)

	// ── Phase 1: port discovery via rustscan ───────────────────────────
	// rustscan accepts a CIDR natively via -a, so we run it ONCE
	// regardless of single-host vs multi-host target. Results are then
	// grouped by host so Phase 2..4 can iterate per host.
	phaseStart := time.Now()
	log.Printf("[phase 1] rustscan %s ports=%s", *flagTarget, tcpPorts)
	openPorts, err := rustscan(*flagTarget, tcpPorts, *flagBatch, *flagTimeout)
	if err != nil {
		log.Fatalf("rustscan: %v", err)
	}
	log.Printf("[phase 1] %d open ports in %.1fs", len(openPorts), time.Since(phaseStart).Seconds())
	for _, p := range openPorts {
		writer.write(Finding{Phase: "portscan", Host: p.Host, Port: p.Port,
			Timestamp: time.Now().UTC().Format(time.RFC3339)})
	}
	if len(openPorts) == 0 && udpPorts == "" {
		log.Printf("no open ports for %s, skipping", *flagTarget)
		continue
	}

	// ── Phase 1b: UDP discovery (nmap -sU on the top UDP ports) ────────
	// Per-host because nmap -sU has per-host RTT tuning. Findings stream
	// into openPorts so Phase 2.5 drivers (SNMP/NTP/DNS/NetBIOS/IPMI)
	// fire normally. UDP needs raw sockets so this needs root.
	if udpPorts != "" {
		udpStart := time.Now()
		udpHosts := groupPortsByHost(openPorts)
		// If TCP found no hosts but the caller still wants UDP, fall back
		// to running UDP discovery against the original target.
		if len(udpHosts) == 0 {
			udpHosts = []string{firstHostOf(*flagTarget)}
		}
		log.Printf("[phase 1b] UDP discovery (nmap -sU) on %d hosts, ports=%s",
			len(udpHosts), udpPorts)
		udpFound := 0
		for _, h := range udpHosts {
			ports := DiscoverUDP(h, udpPorts, 60*time.Second)
			for _, p := range ports {
				openPorts = append(openPorts, &Port{Host: h, Port: p, Service: ""})
				writer.write(Finding{Phase: "portscan", Host: h, Port: p,
					Meta: map[string]any{"transport": "udp"},
					Timestamp: time.Now().UTC().Format(time.RFC3339)})
				udpFound++
			}
		}
		log.Printf("[phase 1b] %d UDP open in %.1fs", udpFound, time.Since(udpStart).Seconds())
	}

	// Group ports by host. CIDR runs fan out across hosts up to
	// -max-hosts goroutines. Per-host log lines are prefixed with
	// [host=X] so interleaved output stays attributable. The NDJSON
	// writer is already mutex-guarded so we don't need a separate lock.
	hosts := groupPortsByHost(openPorts)
	if len(hosts) > 1 {
		log.Printf("[phase 1] %d hosts have open ports (max-hosts cap=%d)",
			len(hosts), *flagMaxHosts)
	}

	var (
		totalNucleiHits int
		hitsMu          sync.Mutex
		wg              sync.WaitGroup
	)
	maxHosts := *flagMaxHosts
	if maxHosts < 1 {
		maxHosts = 1
	}
	if len(hosts) <= 1 {
		maxHosts = 1
	}
	sem := make(chan struct{}, maxHosts)
	for _, host := range hosts {
		hostPorts := openPorts // default for single-host
		if len(hosts) > 1 {
			hostPorts = filterPortsByHost(openPorts, host)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string, ports []*Port) {
			defer wg.Done()
			defer func() { <-sem }()
			var hlog *log.Logger
			if len(hosts) > 1 {
				hlog = log.New(os.Stderr, fmt.Sprintf("[host=%s] ", h), log.LstdFlags)
				hlog.Printf("--- start (%d ports) ---", len(ports))
			} else {
				hlog = log.Default()
			}
			hits := processHost(h, ports, writer, hlog)
			hitsMu.Lock()
			totalNucleiHits += hits
			hitsMu.Unlock()
		}(host, hostPorts)
	}
	wg.Wait()

	log.Printf("=== TOTAL: %.1fs, %d hosts, %d ports, %d nuclei hits ===",
		time.Since(wallStart).Seconds(), len(hosts), len(openPorts), totalNucleiHits)
	summarize(openPorts)
	} // end per-target loop
}

// processHost runs Phase 2 / 2.5 / 2.6 / 2.7 / 2.8 / 2.9 / 3 / 4
// against one host's open ports. Returns the nuclei hit count.
// `hlog` is a per-host logger so concurrent host output stays
// attributable.
func processHost(host string, openPorts []*Port, writer *writer, hlog *log.Logger) int {
	if hlog == nil {
		hlog = log.Default()
	}
	phaseStart := time.Now()

	// ── Phase 2: service detection via nmap -sV ────────────────────────
	if !*flagSkipNmap {
		phaseStart = time.Now()
		hlog.Printf("[phase 2] nmap -sV (mode=%s, intensity=%d) against %d ports",
			*flagNmapMode, *flagNmapIntensity, len(openPorts))
		var nerr error
		switch *flagNmapMode {
		case "lib":
			nerr = nmapFingerprintLib(openPorts, *flagNmapIntensity)
		case "direct":
			nerr = nmapFingerprintDirect(openPorts, *flagNmapIntensity)
		default:
			hlog.Fatalf("unknown -nmap-mode %q (use lib or direct)", *flagNmapMode)
		}
		if nerr != nil {
			hlog.Printf("nmap: %v (continuing without service info)", nerr)
		}
		hlog.Printf("[phase 2] done in %.1fs", time.Since(phaseStart).Seconds())
	}
	// ── -force-service overrides (manual port→service map) ────────────
	// Applies before auto-fp so the user's override wins over both nmap
	// and the cascade.
	if forceMap := parseForceServiceMap(*flagForceService); len(forceMap) > 0 {
		for _, p := range openPorts {
			if name, ok := forceMap[p.Port]; ok && name != "" {
				hlog.Printf("[force-service] %d -> %s (user override)", p.Port, name)
				p.Service = name
				if p.Extra == "" {
					p.Extra = "force-service"
				} else {
					p.Extra = p.Extra + " | force-service"
				}
			}
		}
	}

	// ── Phase 2.4: auto-fingerprint cascade for unknown ports ─────────
	if !*flagSkipAutoFP {
		afpStart := time.Now()
		nProbed, nClassified := runAutoFingerprint(openPorts)
		if nProbed > 0 {
			hlog.Printf("[phase 2.4] auto-fp probed %d unknown ports, classified %d in %.1fs",
				nProbed, nClassified, time.Since(afpStart).Seconds())
		}
	}

	for _, p := range openPorts {
		writer.write(Finding{Phase: "fingerprint", Host: p.Host, Port: p.Port,
			Service: p.Service, Product: p.Product, Version: p.Version,
			Extra: p.Extra, CPE: p.CPE, TLS: p.TLS,
			Timestamp: time.Now().UTC().Format(time.RFC3339)})
	}

	// driverReports accumulates per-source reports so Phase 2.8 (OS
	// heuristic) can correlate banners. Indexed by source name.
	driverReports := map[string][]any{}

	// ── Phase 2.5: protocol drivers + plugin engine ────────────────────
	if !*flagSkipDrivers {
		phaseStart = time.Now()
		eng, perr := LoadPlugins(*flagPlugins)
		if perr != nil {
			hlog.Printf("[phase 2.5] plugin load: %v (continuing without plugins)", perr)
			eng = &PluginEngine{bySource: map[string][]*PluginRule{}}
		}
		hlog.Printf("[phase 2.5] drivers + plugins: %d rules loaded (per-source: %v)",
			len(eng.rules), eng.RuleCount())
		nDrivers, nFindings := runDriversAndCollect(openPorts, eng, writer, driverReports, hlog)
		hlog.Printf("[phase 2.5] %d drivers ran, %d findings in %.1fs",
			nDrivers, nFindings, time.Since(phaseStart).Seconds())

		// ── Phase 2.6: OS detection (once per unique host) ─────────────
		if !*flagSkipOS {
			osStart := time.Now()
			nOSHits, nOSFindings := runOSDetection(openPorts, eng, writer, hlog)
			hlog.Printf("[phase 2.6] OS detection on %d hosts, %d findings in %.1fs",
				nOSHits, nOSFindings, time.Since(osStart).Seconds())
		}

		// ── Phase 2.7: traceroute (once per unique host) ───────────────
		if !*flagSkipTraceroute {
			trStart := time.Now()
			nTRHits, nTRFindings := runTraceroute(openPorts, eng, writer, hlog)
			hlog.Printf("[phase 2.7] traceroute on %d hosts, %d findings in %.1fs",
				nTRHits, nTRFindings, time.Since(trStart).Seconds())
		}

		// ── Phase 2.8: OS heuristic from banner correlation ────────────
		osHStart := time.Now()
		nOSH, nOSHFindings := runOSHeuristic(openPorts, driverReports, eng, writer, hlog)
		hlog.Printf("[phase 2.8] OS heuristic on %d hosts, %d findings in %.1fs",
			nOSH, nOSHFindings, time.Since(osHStart).Seconds())

		// ── Phase 2.9: TLS fingerprint per TLS-bearing port ────────────
		tlsfpStart := time.Now()
		nTLSFP, nTLSFPFindings := runTLSFingerprint(openPorts, eng, writer, hlog)
		hlog.Printf("[phase 2.9] TLS fingerprint on %d ports, %d findings in %.1fs",
			nTLSFP, nTLSFPFindings, time.Since(tlsfpStart).Seconds())

		// ── Phase 2.95: testssl.sh wrapper per TLS-bearing port ────────
		if !*flagSkipTLSVuln {
			tlsVulnStart := time.Now()
			nTV, nTVFindings := runTLSVuln(openPorts, eng, writer, hlog)
			hlog.Printf("[phase 2.95] TLS vuln (testssl.sh) on %d ports, %d findings in %.1fs",
				nTV, nTVFindings, time.Since(tlsVulnStart).Seconds())
		}

		// ── Phase 2.6b: cvemap CPE → CVE lookup ────────────────────────
		if !*flagSkipCVE {
			cveStart := time.Now()
			nC, nCFindings := runCVELookup(openPorts, driverReports, eng, writer, hlog)
			hlog.Printf("[phase 2.6b] CVE lookup on %d CPEs, %d findings in %.1fs",
				nC, nCFindings, time.Since(cveStart).Seconds())
		}
	}

	// ── Phase 3: httpx enrichment on web ports ─────────────────────────
	webURLs := webURLsFrom(openPorts)
	if len(webURLs) > 0 {
		phaseStart = time.Now()
		hlog.Printf("[phase 3] httpx enriching %d web URLs", len(webURLs))
		// Load the plugin engine so HTTP results run through the YAML
		// rules as source "http". This phase runs even when -skip-drivers
		// is set, so it loads its own engine rather than depending on the
		// Phase 2.5 instance.
		httpEng, perr := LoadPlugins(*flagPlugins)
		if perr != nil {
			hlog.Printf("[phase 3] plugin load: %v (continuing without http rules)", perr)
			httpEng = &PluginEngine{bySource: map[string][]*PluginRule{}}
		}
		webResults, httpFindings, err := httpxEnrich(webURLs, httpEng)
		if err != nil {
			hlog.Printf("httpx: %v", err)
		}
		hlog.Printf("[phase 3] done in %.1fs, %d http findings",
			time.Since(phaseStart).Seconds(), len(httpFindings))
		for _, w := range webResults {
			writer.write(w)
		}
		for _, f := range httpFindings {
			writer.writeFinding(f)
			hlog.Printf("  [FIND] %s %s %s:%d %s",
				f.Severity, f.RuleID, f.Host, f.Port, f.Title)
		}
	}

	if *flagSkipNuclei {
		hlog.Printf("--skip-nuclei set, stopping host %s", host)
		return 0
	}

	// ── Phase 4: nuclei templates, one engine per service tag ──────────
	buckets := bucketByTag(openPorts)
	hlog.Printf("[phase 4] nuclei across %d service buckets", len(buckets))
	phaseStart = time.Now()
	nucleiHits := 0
	for tag, targets := range buckets {
		hlog.Printf("  [%s] %d targets", tag, len(targets))
		hits := runNuclei(tag, targets, *flagTemplates, writer)
		nucleiHits += hits
	}
	hlog.Printf("[phase 4] %d hits in %.1fs", nucleiHits, time.Since(phaseStart).Seconds())
	return nucleiHits
}

// parseForceServiceMap parses "PORT=NAME[,PORT=NAME...]" into a map.
// Malformed entries are skipped with a stderr warning.
func parseForceServiceMap(raw string) map[int]string {
	out := map[int]string{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		eq := strings.IndexByte(item, '=')
		if eq <= 0 || eq == len(item)-1 {
			log.Printf("[force-service] ignoring malformed entry %q (want PORT=NAME)", item)
			continue
		}
		portStr := strings.TrimSpace(item[:eq])
		name := strings.TrimSpace(item[eq+1:])
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			log.Printf("[force-service] ignoring bad port %q", portStr)
			continue
		}
		out[port] = name
	}
	return out
}

// groupPortsByHost returns the unique host list in sorted order.
func groupPortsByHost(ports []*Port) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ports {
		if !seen[p.Host] {
			seen[p.Host] = true
			out = append(out, p.Host)
		}
	}
	sort.Strings(out)
	return out
}

func filterPortsByHost(ports []*Port, host string) []*Port {
	var out []*Port
	for _, p := range ports {
		if p.Host == host {
			out = append(out, p)
		}
	}
	return out
}

// ──────────────────────────────────────────────────────────────────────
// Phase 1: rustscan
// ──────────────────────────────────────────────────────────────────────

var rustscanLineRe = regexp.MustCompile(`^Open\s+([0-9a-fA-F.:\[\]]+):(\d+)`)

func rustscan(target, ports string, batch, timeout int) ([]*Port, error) {
	// rustscan: -r start-end OR -p comma,list. Single port also goes through -p.
	portsFlag := "-r"
	if strings.Contains(ports, ",") || !strings.Contains(ports, "-") {
		portsFlag = "-p"
	}
	args := []string{
		"-a", target,
		portsFlag, ports,
		"-b", strconv.Itoa(batch),
		"-t", strconv.Itoa(timeout),
		"--greppable",
		"--accessible",
		"--no-config",
	}
	cmd := exec.Command("rustscan", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, string(out))
	}
	var openPorts []*Port
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		m := rustscanLineRe.FindStringSubmatch(line)
		if m == nil {
			// "172.17.0.3 -> [21,22,23,...]"
			if i := strings.Index(line, " -> ["); i > 0 {
				host := strings.TrimSpace(line[:i])
				portsRaw := line[i+5:]
				portsRaw = strings.TrimSuffix(portsRaw, "]")
				for _, ps := range strings.Split(portsRaw, ",") {
					if p, err := strconv.Atoi(strings.TrimSpace(ps)); err == nil {
						key := fmt.Sprintf("%s:%d", host, p)
						if !seen[key] {
							seen[key] = true
							openPorts = append(openPorts, &Port{Host: host, Port: p})
						}
					}
				}
			}
			continue
		}
		host := strings.Trim(m[1], "[]")
		p, _ := strconv.Atoi(m[2])
		key := fmt.Sprintf("%s:%d", host, p)
		if !seen[key] {
			seen[key] = true
			openPorts = append(openPorts, &Port{Host: host, Port: p})
		}
	}
	sort.Slice(openPorts, func(i, j int) bool {
		if openPorts[i].Host != openPorts[j].Host {
			return openPorts[i].Host < openPorts[j].Host
		}
		return openPorts[i].Port < openPorts[j].Port
	})
	return openPorts, nil
}

// ──────────────────────────────────────────────────────────────────────
// Phase 2a: nmap -sV via Ullaakut lib (mode=lib)
// ──────────────────────────────────────────────────────────────────────

func nmapFingerprintLib(ports []*Port, intensity int) error {
	if len(ports) == 0 {
		return nil
	}
	// Group ports by host so we can run one nmap per host
	byHost := map[string][]string{}
	for _, p := range ports {
		byHost[p.Host] = append(byHost[p.Host], strconv.Itoa(p.Port))
	}
	for host, pl := range byHost {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		scanner, err := nmap.NewScanner(
			ctx,
			nmap.WithTargets(host),
			nmap.WithPorts(strings.Join(pl, ",")),
			nmap.WithServiceInfo(),
			nmap.WithVersionIntensity(int16(intensity)),
			nmap.WithSkipHostDiscovery(),
			nmap.WithDisabledDNSResolution(),
		)
		if err != nil {
			cancel()
			return fmt.Errorf("nmap NewScanner: %w", err)
		}
		result, warnings, err := scanner.Run()
		cancel()
		if err != nil {
			return fmt.Errorf("nmap Run: %w (warnings=%v)", err, warnings)
		}
		// Index ports by host:port for fast update
		idx := map[string]*Port{}
		for _, p := range ports {
			idx[fmt.Sprintf("%s:%d", p.Host, p.Port)] = p
		}
		for _, h := range result.Hosts {
			var hostKey string
			if len(h.Addresses) > 0 {
				hostKey = h.Addresses[0].Addr
			}
			for _, port := range h.Ports {
				key := fmt.Sprintf("%s:%d", hostKey, port.ID)
				p := idx[key]
				if p == nil {
					continue
				}
				p.Service = port.Service.Name
				p.Product = port.Service.Product
				p.Version = port.Service.Version
				p.Extra = port.Service.ExtraInfo
				p.TLS = port.Service.Tunnel == "ssl"
				for _, c := range port.Service.CPEs {
					p.CPE = append(p.CPE, string(c))
				}
			}
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────
// Phase 2b: nmap -sV via direct exec.Cmd + XML parse (mode=direct)
// ──────────────────────────────────────────────────────────────────────

// Minimal XML schema to parse nmap -oX output. Only fields we use are mapped.
type nmapXMLRun struct {
	XMLName xml.Name       `xml:"nmaprun"`
	Hosts   []nmapXMLHost  `xml:"host"`
}
type nmapXMLHost struct {
	Addresses []nmapXMLAddr `xml:"address"`
	Ports     nmapXMLPorts  `xml:"ports"`
}
type nmapXMLAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
type nmapXMLPorts struct {
	Ports []nmapXMLPort `xml:"port"`
}
type nmapXMLPort struct {
	Protocol string         `xml:"protocol,attr"`
	PortID   int            `xml:"portid,attr"`
	State    nmapXMLState   `xml:"state"`
	Service  nmapXMLService `xml:"service"`
}
type nmapXMLState struct {
	State string `xml:"state,attr"`
}
type nmapXMLService struct {
	Name      string        `xml:"name,attr"`
	Product   string        `xml:"product,attr"`
	Version   string        `xml:"version,attr"`
	ExtraInfo string        `xml:"extrainfo,attr"`
	Tunnel    string        `xml:"tunnel,attr"`
	Method    string        `xml:"method,attr"`
	Conf      int           `xml:"conf,attr"`
	CPEs      []string      `xml:"cpe"`
}

func nmapFingerprintDirect(ports []*Port, intensity int) error {
	if len(ports) == 0 {
		return nil
	}
	byHost := map[string][]string{}
	for _, p := range ports {
		byHost[p.Host] = append(byHost[p.Host], strconv.Itoa(p.Port))
	}
	for host, pl := range byHost {
		args := []string{
			"-sV",
			"--version-intensity", strconv.Itoa(intensity),
			"-Pn",
			"-n",
			"-p", strings.Join(pl, ","),
			"-oX", "-",
			host,
		}
		cmd := exec.Command("nmap", args...)
		stdout, err := cmd.Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return fmt.Errorf("nmap exit: %v stderr=%s", err, string(ee.Stderr))
			}
			return fmt.Errorf("nmap exec: %w", err)
		}
		var run nmapXMLRun
		if err := xml.Unmarshal(stdout, &run); err != nil {
			return fmt.Errorf("nmap xml parse: %w", err)
		}
		idx := map[string]*Port{}
		for _, p := range ports {
			idx[fmt.Sprintf("%s:%d", p.Host, p.Port)] = p
		}
		for _, h := range run.Hosts {
			var hostKey string
			for _, a := range h.Addresses {
				if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
					hostKey = a.Addr
					break
				}
			}
			if hostKey == "" && len(h.Addresses) > 0 {
				hostKey = h.Addresses[0].Addr
			}
			for _, port := range h.Ports.Ports {
				key := fmt.Sprintf("%s:%d", hostKey, port.PortID)
				p := idx[key]
				if p == nil {
					continue
				}
				p.Service = port.Service.Name
				p.Product = port.Service.Product
				p.Version = port.Service.Version
				p.Extra = port.Service.ExtraInfo
				p.TLS = port.Service.Tunnel == "ssl"
				p.CPE = append(p.CPE, port.Service.CPEs...)
			}
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────
// Phase 3: httpx
// ──────────────────────────────────────────────────────────────────────

func webURLsFrom(ports []*Port) []string {
	var urls []string
	for _, p := range ports {
		switch {
		case p.TLS, p.Service == "https", p.Service == "ssl/http":
			urls = append(urls, fmt.Sprintf("https://%s:%d", p.Host, p.Port))
		case p.Service == "http", p.Service == "http-proxy", p.Service == "http-alt":
			urls = append(urls, fmt.Sprintf("http://%s:%d", p.Host, p.Port))
		case p.Service == "" && commonHTTPPort(p.Port):
			// If nmap didn't tell us, guess HTTP on common web ports
			urls = append(urls, fmt.Sprintf("http://%s:%d", p.Host, p.Port))
		case p.Service == "" || p.Service == "unknown" || p.Service == "tcpwrapped":
			// Aggressive fallback: unknown service on any port. Emit BOTH
			// http:// and https:// candidates; httpx filters the dead ones.
			log.Printf("[httpx-fallback] adding http://%s:%d (service was %q)", p.Host, p.Port, p.Service)
			urls = append(urls,
				fmt.Sprintf("http://%s:%d", p.Host, p.Port),
				fmt.Sprintf("https://%s:%d", p.Host, p.Port))
		}
	}
	return urls
}

func commonHTTPPort(port int) bool {
	switch port {
	case 80, 81, 8000, 8008, 8080, 8081, 8088, 8180, 8443, 8888, 9000, 9090:
		return true
	}
	return false
}

func httpxEnrich(urls []string, eng *PluginEngine) ([]Finding, []PluginFinding, error) {
	tmpIn, err := os.CreateTemp("", "fastscan-httpx-in-*.txt")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmpIn.Name())
	for _, u := range urls {
		tmpIn.WriteString(u + "\n")
	}
	tmpIn.Close()

	tmpOut, err := os.CreateTemp("", "fastscan-httpx-out-*.jsonl")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmpOut.Name())
	tmpOut.Close()

	// httpx Timeout is a per-request total budget. Use the resolved
	// total timeout from the profile (or -http-total-timeout override).
	_, _, total := resolveHTTPTimeouts()
	opts := httpxRunner.Options{
		InputFile:          tmpIn.Name(),
		JSONOutput:         true,
		Output:             tmpOut.Name(),
		Silent:             true,
		StatusCode:         true,
		ExtractTitle:       true,
		OutputServerHeader: true,
		TechDetect:         true,
		Timeout:            int(total.Seconds()),
		Threads:            5,
		Retries:            1,
		FollowRedirects:    false,
		NoColor:            true,
		Methods:            "GET",
	}
	if err := opts.ValidateOptions(); err != nil {
		return nil, nil, fmt.Errorf("httpx options: %w", err)
	}
	runner, err := httpxRunner.New(&opts)
	if err != nil {
		return nil, nil, fmt.Errorf("httpx new: %w", err)
	}
	runner.RunEnumeration()
	runner.Close()

	raw, err := os.ReadFile(tmpOut.Name())
	if err != nil {
		return nil, nil, err
	}
	var findings []Finding
	var pluginFindings []PluginFinding
	shot := map[string]bool{} // URLs already screenshotted (dedupe)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		f := Finding{Phase: "httpx", Timestamp: time.Now().UTC().Format(time.RFC3339)}
		if v, ok := rec["url"].(string); ok {
			f.URL = v
		}
		if v, ok := rec["title"].(string); ok {
			f.Title = v
		}
		if v, ok := rec["webserver"].(string); ok {
			f.Server = v
		}
		if v, ok := rec["status_code"].(float64); ok {
			f.Meta = map[string]any{"status_code": int(v)}
		}
		if v, ok := rec["tech"].([]any); ok {
			for _, t := range v {
				if s, ok := t.(string); ok {
					f.Tech = append(f.Tech, s)
				}
			}
		}
		// Best-effort web screenshot. A capture failure (driver/browser
		// missing, dead page, timeout) must never drop the finding or fail the
		// phase. The PNG path is merged into Meta so the existing status_code
		// entry is preserved.
		if f.URL != "" && !shot[f.URL] {
			shot[f.URL] = true
			if out, err := webShotPath(f.URL); err == nil {
				if err := webScreenshot(f.URL, out, 20*time.Second); err == nil {
					if fi, err := os.Stat(out); err == nil && fi.Size() > 0 {
						if f.Meta == nil {
							f.Meta = map[string]any{}
						}
						f.Meta["screenshot_path"] = out
					}
				}
			}
		}
		findings = append(findings, f)

		// Run this HTTP endpoint through the YAML plugin engine as the
		// "http" source, the same way the pipeline evaluates driver
		// reports (runDriversAndCollect). Each endpoint is evaluated once;
		// matching rules emit phase=finding rows with source=http.
		if eng != nil {
			rep := buildHTTPReport(rec)
			hf, ferr := eng.Evaluate("http", rep)
			if ferr != nil {
				log.Printf("  [plugin http] %s eval: %v", rep.URL, ferr)
			}
			pluginFindings = append(pluginFindings, hf...)
		}
	}
	return findings, pluginFindings, nil
}

// ──────────────────────────────────────────────────────────────────────
// Phase 4: nuclei SDK
// ──────────────────────────────────────────────────────────────────────

func bucketByTag(ports []*Port) map[string][]string {
	buckets := map[string]map[string]bool{} // tag → set(target)
	for _, p := range ports {
		tags := append([]string(nil), serviceTagMap[p.Service]...)
		// Any TLS-wrapped service also gets ssl/tls/certificate tags so the
		// cert-details template fires regardless of inner protocol.
		if p.TLS {
			tags = append(tags, "ssl", "tls", "certificate")
		}
		if len(tags) == 0 {
			continue
		}
		var target string
		if p.TLS || p.Service == "https" || p.Service == "ssl/http" {
			target = fmt.Sprintf("https://%s:%d", p.Host, p.Port)
		} else if p.Service == "http" || p.Service == "http-proxy" || p.Service == "http-alt" {
			target = fmt.Sprintf("http://%s:%d", p.Host, p.Port)
		} else {
			target = fmt.Sprintf("%s:%d", p.Host, p.Port)
		}
		for _, t := range tags {
			if buckets[t] == nil {
				buckets[t] = map[string]bool{}
			}
			buckets[t][target] = true
		}
	}
	out := map[string][]string{}
	for tag, set := range buckets {
		var list []string
		for k := range set {
			list = append(list, k)
		}
		sort.Strings(list)
		out[tag] = list
	}
	return out
}

func runNuclei(tag string, targets []string, templatesDir string, writer *writer) int {
	if len(targets) == 0 {
		return 0
	}
	ctx := context.Background()
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{tag}}),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatesDir}}),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           resolveNucleiConcurrency(),
			HostConcurrency:               resolveNucleiConcurrency(),
			HeadlessHostConcurrency:       resolveNucleiConcurrency(),
			HeadlessTemplateConcurrency:   resolveNucleiConcurrency(),
			JavascriptTemplateConcurrency: resolveNucleiConcurrency(),
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
		nuclei.WithGlobalRateLimit(resolveNucleiRateLimit(), time.Second),
		nuclei.DisableUpdateCheck(),
	)
	if err != nil {
		log.Printf("nuclei[%s] init: %v", tag, err)
		return 0
	}
	defer ne.Close()
	ne.LoadTargets(targets, false)

	var (
		mu   sync.Mutex
		hits int
	)
	// Nuclei templates superseded by our own YAML plugins (avoids duplicates).
	nucleiSuperseded := map[string]bool{
		"smb-signing": true, // duplicate of smb-signing-not-required plugin
	}
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		if nucleiSuperseded[event.TemplateID] {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		hits++
		writer.write(Finding{
			Phase:     "nuclei",
			URL:       event.Matched,
			Template:  event.TemplateID,
			Severity:  event.Info.SeverityHolder.Severity.String(),
			Extract:   strings.Join(event.ExtractedResults, " | "),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		log.Printf("    [HIT] %s %s %s",
			event.Info.SeverityHolder.Severity.String(),
			event.TemplateID, event.Matched)
	})
	if err != nil {
		log.Printf("nuclei[%s] exec: %v", tag, err)
	}
	return hits
}

// ──────────────────────────────────────────────────────────────────────
// Output writer
// ──────────────────────────────────────────────────────────────────────

type writer struct {
	mu       sync.Mutex
	f        *os.File
	baseline *Baseline      // optional: -diff-against loaded baseline
	webhook  *WebhookClient // optional: -webhook configured client
}

func newWriter(path string) *writer {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create %s: %v", path, err)
	}
	return &writer{f: f}
}
func (w *writer) write(f Finding) {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, _ := json.Marshal(f)
	w.f.Write(b)
	w.f.Write([]byte("\n"))
}
func (w *writer) writeFinding(f PluginFinding) {
	// Differential routing happens BEFORE the mutex so the helper can
	// run independent work (webhook POST is a network call, must not
	// hold the file mutex).
	if w.baseline != nil && w.baseline.LoadedCount() > 0 {
		isNew, _ := w.baseline.Classify(f)
		if !isNew {
			// Re-tag the finding so the operator sees it as carry-over.
			f.Phase = "baseline-existing"
		}
	}
	// Always record the finding into the live snapshot so -save-baseline
	// can dump it at the end.
	if w.baseline != nil {
		w.baseline.Record(f)
	}
	w.mu.Lock()
	b, _ := json.Marshal(f)
	w.f.Write(b)
	w.f.Write([]byte("\n"))
	w.mu.Unlock()
	// Webhook fires only for NEW findings. Carrying over an existing
	// critical/high every scan would spam the endpoint.
	if w.webhook != nil && f.Phase == "finding" {
		w.webhook.PostFinding(f)
	}
}
func (w *writer) Close() error {
	if w.f == nil {
		return nil
	}
	return w.f.Close()
}

// ──────────────────────────────────────────────────────────────────────
// Standalone SSH probe (Phase 3 single-protocol smoke test)
// ──────────────────────────────────────────────────────────────────────

func runSSHTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("ssh-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeSSH(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeSSH: %v", err)
	}
	if cs := ensureCreds(); cs.HasCreds("ssh") {
		rep.CredAttempts = cs.TryCreds("ssh", host, port)
		attachCredContent(rep, "ssh", host, port, rep.CredAttempts, 8*time.Second)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== SSH probe %s done in %s ===\n", target, dur)

	// Evaluate plugins against this report
	evalPluginsAndPrint("ssh", rep)
}

func runSMBTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("smb-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeSMB(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeSMB: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== SMB probe %s done in %s ===\n", target, dur)

	// Evaluate plugins against this report
	evalPluginsAndPrint("smb", rep)
}

func runVNCTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("vnc-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeVNC(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeVNC: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== VNC probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("vnc", rep)
}

func runLDAPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("ldap-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeLDAP(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeLDAP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== LDAP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("ldap", rep)
}

func runMSSQLTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("mssql-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeMSSQL(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeMSSQL: %v", err)
	}
	if cs := ensureCreds(); cs.HasCreds("mssql") {
		rep.CredAttempts = cs.TryCreds("mssql", host, port)
		attachCredContent(rep, "mssql", host, port, rep.CredAttempts, 8*time.Second)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== MSSQL probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("mssql", rep)
}

func runRDPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("rdp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeRDP(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeRDP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== RDP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("rdp", rep)
}

func runMySQLTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("mysql-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeMySQL(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeMySQL: %v", err)
	}
	if cs := ensureCreds(); cs.HasCreds("mysql") {
		rep.CredAttempts = cs.TryCreds("mysql", host, port)
		attachCredContent(rep, "mysql", host, port, rep.CredAttempts, 8*time.Second)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== MySQL probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("mysql", rep)
}

func runPostgreSQLTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("postgresql-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbePostgreSQL(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbePostgreSQL: %v", err)
	}
	if cs := ensureCreds(); cs.HasCreds("postgresql") {
		rep.CredAttempts = cs.TryCreds("postgresql", host, port)
		attachCredContent(rep, "postgresql", host, port, rep.CredAttempts, 8*time.Second)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== PostgreSQL probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("postgresql", rep)
}

func runSNMPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("snmp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeSNMP(host, port, 3*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeSNMP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== SNMP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("snmp", rep)
}

func runNetBIOSTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("netbios-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeNetBIOS(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeNetBIOS: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== NetBIOS probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("netbios", rep)
}

func runSMTPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("smtp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeSMTP(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeSMTP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== SMTP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("smtp", rep)
}

func runFTPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("ftp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeFTP(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeFTP: %v", err)
	}
	if cs := ensureCreds(); cs.HasCreds("ftp") {
		rep.CredAttempts = cs.TryCreds("ftp", host, port)
		attachCredContent(rep, "ftp", host, port, rep.CredAttempts, 8*time.Second)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== FTP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("ftp", rep)
}

func runTelnetTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("telnet-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeTelnet(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeTelnet: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Telnet probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("telnet", rep)
}

func runRsyncTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("rsync-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeRsync(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeRsync: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== rsync probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("rsync", rep)
}

func runFingerTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("finger-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeFinger(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeFinger: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== finger probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("finger", rep)
}

func runKerberosTest(target string) {
	// target format: host:port@REALM (e.g. dc01.example.com:88@EXAMPLE.COM)
	at := strings.LastIndex(target, "@")
	if at < 0 {
		log.Fatalf("kerberos-test target %q: expected host:port@REALM", target)
	}
	hostPort := target[:at]
	realm := target[at+1:]
	host, port, err := splitHostPort(hostPort)
	if err != nil {
		log.Fatalf("kerberos-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeKerberos(host, port, realm, 6*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeKerberos: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Kerberos probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("kerberos", rep)
}

func runIPMITest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("ipmi-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeIPMI(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeIPMI: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== IPMI probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("ipmi", rep)
}

func runRPCTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("rpc-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeRPC(host, port, 6*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeRPC: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== RPC probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("rpc", rep)
}

func runAJPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("ajp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeAJP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeAJP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== AJP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("ajp", rep)
}

func runRedisTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("redis-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeRedis(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeRedis: %v", err)
	}
	if cs := ensureCreds(); cs.HasCreds("redis") {
		rep.CredAttempts = cs.TryCreds("redis", host, port)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Redis probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("redis", rep)
}

func runMemcachedTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("memcached-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeMemcached(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeMemcached: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== memcached probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("memcached", rep)
}

func runMongoDBTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("mongodb-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeMongoDB(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeMongoDB: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== MongoDB probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("mongodb", rep)
}

func runPOP3Test(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("pop3-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbePOP3(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbePOP3: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== POP3 probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("pop3", rep)
}

func runIMAPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("imap-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeIMAP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeIMAP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== IMAP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("imap", rep)
}

func runNTPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("ntp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeNTP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeNTP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== NTP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("ntp", rep)
}

// runOSTest takes either "host" or "host:port" (port ignored). nmap -O
// requires raw sockets, so this needs root or CAP_NET_RAW on the binary.
func runOSTest(target string) {
	host := target
	if i := strings.LastIndex(target, ":"); i > 0 {
		host = target[:i]
	}
	start := time.Now()
	rep, err := ProbeOS(host, 0, 90*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeOS: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== OS probe %s done in %s ===\n", host, dur)
	evalPluginsAndPrint("os", rep)
}

func runDNSTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("dns-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeDNS(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeDNS: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== DNS probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("dns", rep)
}

func runWinRMTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("winrm-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeWinRM(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeWinRM: %v", err)
	}
	if cs := ensureCreds(); cs.HasCreds("winrm") {
		rep.CredAttempts = cs.TryCreds("winrm", host, port)
		attachCredContent(rep, "winrm", host, port, rep.CredAttempts, 8*time.Second)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== WinRM probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("winrm", rep)
}

func runOracleTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("oracle-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeOracleTNS(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeOracleTNS: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Oracle TNS probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("oracle", rep)
}

func runMSRPCTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("msrpc-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeMSRPC(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeMSRPC: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== MS-RPC probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("msrpc", rep)
}

func runMQTTTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("mqtt-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeMQTT(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeMQTT: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== MQTT probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("mqtt", rep)
}

func runSIPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("sip-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeSIP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeSIP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== SIP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("sip", rep)
}

func runModbusTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("modbus-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeModbus(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeModbus: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Modbus probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("modbus", rep)
}

func runTLSFPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("tlsfp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeTLSFingerprint(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeTLSFingerprint: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== TLS fingerprint probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("tlsfp", rep)
}

func runTLSVulnTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("tlsvuln-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeTLSVuln(host, port, 300*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeTLSVuln: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== TLS vuln probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("tlsvuln", rep)
}

func runSMBVulnTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("smbvuln-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeSMBVuln(host, port, 60*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeSMBVuln: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== SMB vuln probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("smbvuln", rep)
}

func runCVETest(cpe string) {
	start := time.Now()
	rep, err := ProbeCVE("", 0, []string{cpe}, 30*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeCVE: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== CVE probe %s done in %s ===\n", cpe, dur)
	evalPluginsAndPrint("cve", rep)
}

func runTracerouteTest(target string) {
	// target is "host" or "host:ignoredport"
	host := target
	if i := strings.LastIndex(target, ":"); i > 0 {
		host = target[:i]
	}
	start := time.Now()
	rep, err := ProbeTraceroute(host, 0, 60*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeTraceroute: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== traceroute probe %s done in %s ===\n", host, dur)
	evalPluginsAndPrint("traceroute", rep)
}

func runJDWPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("jdwp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeJDWP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeJDWP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== JDWP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("jdwp", rep)
}

func runDockerAPITest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("dockerapi-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeDockerAPI(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeDockerAPI: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Docker API probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("dockerapi", rep)
}

func runCUPSTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("cups-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeCUPS(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeCUPS: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== CUPS probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("cups", rep)
}

func runTFTPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("tftp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeTFTP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeTFTP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== TFTP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("tftp", rep)
}

func runWebLogicTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("weblogic-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeWebLogic(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeWebLogic: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== WebLogic probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("weblogic", rep)
}

func runCouchDBTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("couchdb-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeCouchDB(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeCouchDB: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== CouchDB probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("couchdb", rep)
}

func runHNAPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("hnap-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeHNAP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeHNAP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== HNAP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("hnap", rep)
}

func runAFPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("afp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeAFP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeAFP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== AFP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("afp", rep)
}

func runPJLTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("pjl-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbePJL(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbePJL: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== PJL probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("pjl", rep)
}

func runDB2Test(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("db2-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeDB2(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeDB2: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== DB2 probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("db2", rep)
}

func runCassandraTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("cassandra-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeCassandra(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeCassandra: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Cassandra probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("cassandra", rep)
}

func runHBaseTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("hbase-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeHBase(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeHBase: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== HBase probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("hbase", rep)
}

func runCitrixTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("citrix-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeCitrix(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeCitrix: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Citrix probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("citrix", rep)
}

func runIKETest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("ike-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeIKE(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeIKE: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== IKE probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("ike", rep)
}

func runSSTPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("sstp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeSSTP(host, port, 8*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeSSTP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== SSTP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("sstp", rep)
}

func runAMQPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("amqp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeAMQP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeAMQP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== AMQP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("amqp", rep)
}

func runISCSITest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("iscsi-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeISCSI(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeISCSI: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== iSCSI probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("iscsi", rep)
}

func runISNSTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("isns-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeISNS(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeISNS: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== iSNS probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("isns", rep)
}

func runXMPPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("xmpp-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeXMPP(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeXMPP: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== XMPP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("xmpp", rep)
}

func runTN3270Test(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("tn3270-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeTN3270(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeTN3270: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== TN3270 probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("tn3270", rep)
}

func runInformixTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("informix-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeInformix(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeInformix: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Informix probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("informix", rep)
}

func runSVNTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("svn-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeSVN(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeSVN: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== SVN probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("svn", rep)
}

func runHadoopTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("hadoop-test target %q: %v", target, err)
	}
	start := time.Now()
	rep, err := ProbeHadoop(host, port, 5*time.Second)
	dur := time.Since(start)
	if err != nil {
		log.Fatalf("ProbeHadoop: %v", err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== Hadoop probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("hadoop", rep)
}

// runAutoFPTest runs the auto-fingerprint cascade against a single
// host:port, mirroring the -*-test pattern of the protocol drivers.
// Prints {service, method, banner_hex} JSON and exits.
func runAutoFPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("autofp-test target %q: %v", target, err)
	}
	start := time.Now()
	svc, banner, method := AutoFingerprint(host, port, 8*time.Second)
	dur := time.Since(start)
	out := map[string]any{
		"host":       host,
		"port":       port,
		"service":    svc,
		"method":     method,
		"banner_hex": hex.EncodeToString(banner),
		"banner_len": len(banner),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== AutoFingerprint %s done in %s ===\n", target, dur)
}

// runDrivers iterates open ports, runs the matching protocol driver, writes
// the driver report as phase=driver, evaluates plugins, and writes any
// findings as phase=finding. Returns (driverCount, findingCount).
func runDrivers(ports []*Port, eng *PluginEngine, w *writer) (int, int) {
	return runDriversAndCollect(ports, eng, w, nil, log.Default())
}

// runDriversAndCollect is runDrivers + an optional collector map that
// receives every driver report keyed by source. Phase 2.8 uses it.
// hlog is used for per-host log attribution; pass log.Default() for the
// single-host path.
//
// Concurrency: ports are dispatched through a worker pool bounded by
// -drivers-per-host (default 4). Each driver runs against its own port
// so there is no shared mutable state inside the probe; the writer is
// already mutex-guarded, the collector map and the running counters
// are guarded by a local mutex.
func runDriversAndCollect(ports []*Port, eng *PluginEngine, w *writer,
	collect map[string][]any, hlog *log.Logger) (int, int) {
	if hlog == nil {
		hlog = log.Default()
	}
	driverTimeout := resolveDriverTimeout()
	workers := *flagDriversPerHost
	if workers < 1 {
		workers = 1
	}
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		sem       = make(chan struct{}, workers)
		nDrivers  int
		nFindings int
	)
	runOne := func(p *Port) {
		source := driverSourceFor(p)
		if source == "" {
			return
		}
		report, derr := dispatchDriver(source, p, driverTimeout)
		if derr != nil {
			hlog.Printf("  [driver %s] %s:%d failed: %v", source, p.Host, p.Port, derr)
			return
		}
		// Default-credentials testing layer (item 1). Runs after the
		// passive probe so the original banner/cap reads stay clean.
		if !*flagSkipCreds && globalCreds != nil && globalCreds.HasCreds(source) {
			attempts := globalCreds.TryCreds(source, p.Host, p.Port)
			if len(attempts) > 0 {
				attachCredAttempts(report, attempts)
				// On a successful default-credential login, capture the
				// same deep content we grab on anonymous / no-auth access
				// (file listing, key dump, etc.).
				attachCredContent(report, source, p.Host, p.Port, attempts, driverTimeout)
				hlog.Printf("  [creds %s] %s:%d %d attempts (success=%v)",
					source, p.Host, p.Port, len(attempts), anySuccess(attempts))
			}
		}
		m, _ := toMap(report)
		w.write(Finding{
			Phase:     "driver",
			Host:      p.Host,
			Port:      p.Port,
			Service:   p.Service,
			Meta:      map[string]any{"source": source, "report": m},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		findings, ferr := eng.Evaluate(source, report)
		if ferr != nil {
			hlog.Printf("  [plugin %s] %s:%d eval: %v", source, p.Host, p.Port, ferr)
		}
		// Single critical section: collector + counters + finding writes.
		mu.Lock()
		nDrivers++
		if collect != nil {
			collect[source] = append(collect[source], report)
		}
		for _, f := range findings {
			w.writeFinding(f)
			nFindings++
			hlog.Printf("  [FIND] %s %s %s:%d %s",
				f.Severity, f.RuleID, f.Host, f.Port, f.Title)
		}
		mu.Unlock()
		// SMB vuln piggyback runs single-threaded inside the worker. It
		// only fires after a successful smb probe and itself takes the
		// same locks via runSMBVulnFor.
		if source == "smb" && !*flagSkipSMBVuln {
			mu.Lock()
			runSMBVulnFor(p, eng, w, hlog, collect, &nDrivers, &nFindings)
			mu.Unlock()
		}
	}
	for _, p := range ports {
		if driverSourceFor(p) == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p *Port) {
			defer wg.Done()
			defer func() { <-sem }()
			runOne(p)
		}(p)
	}
	wg.Wait()
	return nDrivers, nFindings
}

// dispatchDriver maps a driver source name to its Probe function and
// runs it. Split out of runDriversAndCollect so the worker-pool path
// stays compact.
func dispatchDriver(source string, p *Port, timeout time.Duration) (any, error) {
	switch source {
	case "ssh":
		return ProbeSSH(p.Host, p.Port, timeout)
	case "smb":
		return ProbeSMB(p.Host, p.Port, timeout)
	case "vnc":
		return ProbeVNC(p.Host, p.Port, timeout)
	case "ldap":
		return ProbeLDAP(p.Host, p.Port, timeout)
	case "mssql":
		return ProbeMSSQL(p.Host, p.Port, timeout)
	case "rdp":
		return ProbeRDP(p.Host, p.Port, timeout)
	case "mysql":
		return ProbeMySQL(p.Host, p.Port, timeout)
	case "postgresql":
		return ProbePostgreSQL(p.Host, p.Port, timeout)
	case "smtp":
		return ProbeSMTP(p.Host, p.Port, timeout)
	case "ftp":
		return ProbeFTP(p.Host, p.Port, timeout)
	case "telnet":
		return ProbeTelnet(p.Host, p.Port, timeout)
	case "rsync":
		return ProbeRsync(p.Host, p.Port, timeout)
	case "finger":
		return ProbeFinger(p.Host, p.Port, timeout)
	case "rpc":
		return ProbeRPC(p.Host, p.Port, timeout)
	case "ajp":
		return ProbeAJP(p.Host, p.Port, timeout)
	case "redis":
		return ProbeRedis(p.Host, p.Port, timeout)
	case "memcached":
		return ProbeMemcached(p.Host, p.Port, timeout)
	case "mongodb":
		return ProbeMongoDB(p.Host, p.Port, timeout)
	case "pop3":
		return ProbePOP3(p.Host, p.Port, timeout)
	case "imap":
		return ProbeIMAP(p.Host, p.Port, timeout)
	case "ntp":
		return ProbeNTP(p.Host, p.Port, timeout)
	case "dns":
		return ProbeDNS(p.Host, p.Port, timeout)
	case "winrm":
		return ProbeWinRM(p.Host, p.Port, timeout)
	case "oracle":
		return ProbeOracleTNS(p.Host, p.Port, timeout)
	case "msrpc":
		return ProbeMSRPC(p.Host, p.Port, timeout)
	case "mqtt":
		return ProbeMQTT(p.Host, p.Port, timeout)
	case "sip":
		return ProbeSIP(p.Host, p.Port, timeout)
	case "modbus":
		return ProbeModbus(p.Host, p.Port, timeout)
	case "jdwp":
		return ProbeJDWP(p.Host, p.Port, timeout)
	case "dockerapi":
		return ProbeDockerAPI(p.Host, p.Port, timeout)
	case "cups":
		return ProbeCUPS(p.Host, p.Port, timeout)
	case "tftp":
		return ProbeTFTP(p.Host, p.Port, timeout)
	case "weblogic":
		return ProbeWebLogic(p.Host, p.Port, timeout)
	case "couchdb":
		return ProbeCouchDB(p.Host, p.Port, timeout)
	case "hnap":
		return ProbeHNAP(p.Host, p.Port, timeout)
	case "afp":
		return ProbeAFP(p.Host, p.Port, timeout)
	case "pjl":
		return ProbePJL(p.Host, p.Port, timeout)
	case "db2":
		return ProbeDB2(p.Host, p.Port, timeout)
	case "cassandra":
		return ProbeCassandra(p.Host, p.Port, timeout)
	case "hbase":
		return ProbeHBase(p.Host, p.Port, timeout)
	case "citrix":
		return ProbeCitrix(p.Host, p.Port, timeout)
	case "ike":
		return ProbeIKE(p.Host, p.Port, timeout)
	case "sstp":
		return ProbeSSTP(p.Host, p.Port, timeout)
	case "amqp":
		return ProbeAMQP(p.Host, p.Port, timeout)
	case "iscsi":
		return ProbeISCSI(p.Host, p.Port, timeout)
	case "isns":
		return ProbeISNS(p.Host, p.Port, timeout)
	case "xmpp":
		return ProbeXMPP(p.Host, p.Port, timeout)
	case "tn3270":
		return ProbeTN3270(p.Host, p.Port, timeout)
	case "informix":
		return ProbeInformix(p.Host, p.Port, timeout)
	case "svn":
		return ProbeSVN(p.Host, p.Port, timeout)
	case "kafka":
		return ProbeKafka(p.Host, p.Port, timeout)
	case "kubernetes":
		return ProbeKubernetes(p.Host, p.Port, timeout)
	case "consul":
		return ProbeConsul(p.Host, p.Port, timeout)
	case "vault":
		return ProbeVault(p.Host, p.Port, timeout)
	case "prometheus":
		return ProbePrometheus(p.Host, p.Port, timeout)
	case "neo4j":
		return ProbeNeo4j(p.Host, p.Port, timeout)
	case "activemq":
		return ProbeActiveMQ(p.Host, p.Port, timeout)
	case "hadoop":
		return ProbeHadoop(p.Host, p.Port, timeout)
	}
	return nil, fmt.Errorf("unknown source %q", source)
}

// attachCredAttempts stuffs cred-attempt results into the driver
// report's CredAttempts field for the protocols that we wired auth for.
// Drivers we did NOT wire (vnc, ipmi, etc.) intentionally do not have
// a CredAttempts field, so this function silently no-ops on them.
func attachCredAttempts(report any, attempts []CredAttempt) {
	switch r := report.(type) {
	case *SSHReport:
		r.CredAttempts = attempts
	case *FTPReport:
		r.CredAttempts = attempts
	case *MSSQLReport:
		r.CredAttempts = attempts
	case *MySQLReport:
		r.CredAttempts = attempts
	case *PostgreSQLReport:
		r.CredAttempts = attempts
	case *RedisReport:
		r.CredAttempts = attempts
	case *WinRMReport:
		r.CredAttempts = attempts
	}
}

// attachCredContent does an authenticated deep-content capture when a default
// credential succeeded, mirroring the listing we grab on anonymous/no-auth
// access. Best-effort and bounded; only fills fields left empty by the
// unauthenticated probe.
func attachCredContent(report any, source, host string, port int, attempts []CredAttempt, timeout time.Duration) {
	var user, pass string
	ok := false
	for _, a := range attempts {
		if a.Success {
			user, pass, ok = a.User, a.Pass, true
			break
		}
	}
	if !ok {
		return
	}
	switch r := report.(type) {
	case *FTPReport:
		if len(r.RootListing) == 0 {
			if listing, err := ftpListRootWithLogin(host, port, user, pass, timeout); err == nil {
				r.RootListing = listing
			}
		}
	case *RedisReport:
		if len(r.Keys) == 0 {
			if keys, n := redisDumpWithAuth(host, port, pass, timeout); len(keys) > 0 {
				r.Keys = keys
				if r.KeyCount == 0 {
					r.KeyCount = n
				}
			}
		}
	case *SSHReport:
		if len(r.CommandOutput) == 0 {
			r.CommandOutput = sshRunCommandsWithLogin(host, port, user, pass, timeout)
		}
	case *MySQLReport:
		if len(r.Databases) == 0 {
			r.Databases = mysqlListDatabasesWithLogin(host, port, user, pass, timeout)
		}
	case *PostgreSQLReport:
		if len(r.Databases) == 0 {
			r.Databases = postgresListDatabasesWithLogin(host, port, user, pass, timeout)
		}
	case *MSSQLReport:
		if len(r.Databases) == 0 {
			r.Databases = mssqlListDatabasesWithLogin(host, port, user, pass, timeout)
		}
	case *WinRMReport:
		if len(r.CommandOutput) == 0 {
			r.CommandOutput = winrmRunCommandsWithLogin(host, port, user, pass, timeout)
		}
	}
}

// anySuccess returns true if any attempt succeeded.
func anySuccess(attempts []CredAttempt) bool {
	for _, a := range attempts {
		if a.Success {
			return true
		}
	}
	return false
}

// driverSourceFor maps a port's fingerprinted service to a driver source
// name. Empty string means no driver available.
func driverSourceFor(p *Port) string {
	switch p.Service {
	case "ssh":
		return "ssh"
	case "netbios-ssn", "microsoft-ds":
		return "smb"
	case "vnc":
		return "vnc"
	case "ldap":
		return "ldap"
	case "ms-sql-s":
		return "mssql"
	case "ms-wbt-server":
		return "rdp"
	case "mysql":
		return "mysql"
	case "postgresql":
		return "postgresql"
	case "smtp", "smtps", "submission":
		return "smtp"
	case "ftp", "ftps":
		return "ftp"
	case "telnet":
		return "telnet"
	case "rsync":
		return "rsync"
	case "finger":
		return "finger"
	case "rpcbind", "nfs":
		return "rpc"
	case "ajp13":
		return "ajp"
	case "redis":
		return "redis"
	case "memcache", "memcached":
		return "memcached"
	case "mongodb":
		return "mongodb"
	case "pop3", "pop3s":
		return "pop3"
	case "imap", "imaps":
		return "imap"
	case "ntp":
		return "ntp"
	case "domain", "dns":
		return "dns"
	case "wsman", "wsmans":
		return "winrm"
	case "oracle-tns", "tns", "oracle":
		return "oracle"
	case "msrpc", "epmap":
		return "msrpc"
	case "mqtt", "mqtts":
		return "mqtt"
	case "sip", "sip-tls":
		return "sip"
	case "modbus", "modbus-tcp":
		return "modbus"
	case "jdwp", "java-debug-wire-protocol":
		return "jdwp"
	case "docker":
		return "dockerapi"
	case "ipp", "cups":
		return "cups"
	case "tftp":
		return "tftp"
	case "afs3-fileserver", "afpovertcp", "afp":
		return "afp"
	case "weblogic", "t3", "afs3-callback":
		return "weblogic"
	case "couchdb":
		return "couchdb"
	case "hnap":
		return "hnap"
	case "hp-pjl", "jetdirect", "pjl":
		return "pjl"
	case "db2", "drda", "ibm-db2":
		return "db2"
	case "cassandra", "cassandra-native":
		return "cassandra"
	case "hbase", "hbase-master":
		return "hbase"
	case "ica", "citrix-ica":
		return "citrix"
	case "isakmp", "ike":
		return "ike"
	case "sstp":
		return "sstp"
	case "amqp", "amqps", "rabbitmq":
		return "amqp"
	case "iscsi", "iscsi-target":
		return "iscsi"
	case "isns":
		return "isns"
	case "xmpp-client", "xmpp-server", "jabber":
		return "xmpp"
	case "tn3270", "tn3270e":
		return "tn3270"
	case "informix", "sqli":
		return "informix"
	case "svn", "svnserve":
		return "svn"
	case "hadoop", "hdfs", "yarn", "hdp-namenode":
		return "hadoop"
	}
	// Service-empty fallback by well-known port (helps when nmap is
	// skipped or returns "?").
	if p.Service == "" {
		switch p.Port {
		case 22:
			return "ssh"
		case 139, 445:
			return "smb"
		case 5900:
			return "vnc"
		case 389:
			return "ldap"
		case 1433:
			return "mssql"
		case 3389:
			return "rdp"
		case 3306:
			return "mysql"
		case 5432:
			return "postgresql"
		case 25, 587:
			return "smtp"
		case 21:
			return "ftp"
		case 23:
			return "telnet"
		case 873:
			return "rsync"
		case 79:
			return "finger"
		case 111:
			return "rpc"
		case 8009:
			return "ajp"
		case 6379:
			return "redis"
		case 11211:
			return "memcached"
		case 27017:
			return "mongodb"
		case 110:
			return "pop3"
		case 143:
			return "imap"
		case 123:
			return "ntp"
		case 53:
			return "dns"
		case 5985, 5986:
			return "winrm"
		case 1521:
			return "oracle"
		case 135:
			return "msrpc"
		case 1883, 8883:
			return "mqtt"
		case 5060:
			return "sip"
		case 502:
			return "modbus"
		case 8000, 5005, 8453:
			return "jdwp"
		case 2375, 2376:
			return "dockerapi"
		case 631:
			return "cups"
		case 69:
			return "tftp"
		case 7001, 7002:
			return "weblogic"
		case 5984:
			return "couchdb"
		case 548:
			return "afp"
		case 9100:
			return "pjl"
		case 50000:
			return "db2"
		case 9042:
			return "cassandra"
		case 60010, 60030, 16010, 16030:
			return "hbase"
		case 1494, 2598:
			return "citrix"
		case 500:
			return "ike"
		case 5672:
			return "amqp"
		case 3260:
			return "iscsi"
		case 3205:
			return "isns"
		case 5222, 5269:
			return "xmpp"
		case 2323:
			return "tn3270"
		case 1526, 9088:
			return "informix"
		case 3690:
			return "svn"
		case 9870, 50070, 8088, 19888:
			return "hadoop"
		case 9092:
			return "kafka"
		case 6443:
			return "kubernetes"
		case 8500:
			return "consul"
		case 8200:
			return "vault"
		case 9090:
			return "prometheus"
		case 7474:
			return "neo4j"
		case 8161:
			return "activemq"
		}
	}
	return ""
}

// runOSDetection runs nmap -O once per unique host present in the
// open-port list. Emits phase=driver source=os and any matching
// phase=finding rows. Returns (hostsProbed, findingCount).
func runOSDetection(ports []*Port, eng *PluginEngine, w *writer, hlog *log.Logger) (int, int) {
	if hlog == nil {
		hlog = log.Default()
	}
	const timeout = 90 * time.Second
	seen := map[string]bool{}
	nHosts, nFindings := 0, 0
	for _, p := range ports {
		if seen[p.Host] {
			continue
		}
		seen[p.Host] = true
		rep, err := ProbeOS(p.Host, 0, timeout)
		if err != nil {
			hlog.Printf("  [os] %s: %v", p.Host, err)
			continue
		}
		nHosts++
		m, _ := toMap(rep)
		w.write(Finding{
			Phase:     "driver",
			Host:      p.Host,
			Meta:      map[string]any{"source": "os", "report": m},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		findings, ferr := eng.Evaluate("os", rep)
		if ferr != nil {
			hlog.Printf("  [plugin os] %s: %v", p.Host, ferr)
			continue
		}
		for _, f := range findings {
			w.writeFinding(f)
			nFindings++
			hlog.Printf("  [FIND] %s %s %s %s",
				f.Severity, f.RuleID, f.Host, f.Title)
		}
	}
	return nHosts, nFindings
}

// runTraceroute runs nmap --traceroute once per unique host present in
// the open-port list. Emits phase=driver source=traceroute and any
// matching phase=finding rows. Returns (hostsProbed, findingCount).
func runTraceroute(ports []*Port, eng *PluginEngine, w *writer, hlog *log.Logger) (int, int) {
	if hlog == nil {
		hlog = log.Default()
	}
	const timeout = 60 * time.Second
	seen := map[string]bool{}
	nHosts, nFindings := 0, 0
	for _, p := range ports {
		if seen[p.Host] {
			continue
		}
		seen[p.Host] = true
		rep, err := ProbeTraceroute(p.Host, 0, timeout)
		if err != nil {
			hlog.Printf("  [traceroute] %s: %v", p.Host, err)
			continue
		}
		nHosts++
		m, _ := toMap(rep)
		w.write(Finding{
			Phase:     "driver",
			Host:      p.Host,
			Meta:      map[string]any{"source": "traceroute", "report": m},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		findings, ferr := eng.Evaluate("traceroute", rep)
		if ferr != nil {
			hlog.Printf("  [plugin traceroute] %s: %v", p.Host, ferr)
			continue
		}
		for _, f := range findings {
			w.writeFinding(f)
			nFindings++
			hlog.Printf("  [FIND] %s %s %s %s",
				f.Severity, f.RuleID, f.Host, f.Title)
		}
	}
	return nHosts, nFindings
}

// runOSHeuristic walks per-host driver reports (collected during
// runDriversAndCollect) and emits an os_heuristic report per host
// inferring an OS family from banner correlations.
func runOSHeuristic(ports []*Port, collect map[string][]any,
	eng *PluginEngine, w *writer, hlog *log.Logger) (int, int) {
	if hlog == nil {
		hlog = log.Default()
	}

	hostBanners := map[string]*HostBanners{}
	getOrInit := func(h string) *HostBanners {
		hb := hostBanners[h]
		if hb == nil {
			hb = &HostBanners{}
			hostBanners[h] = hb
		}
		return hb
	}

	// Extract banner-like fields out of each driver's reports.
	for _, r := range collect["ssh"] {
		if s, ok := r.(*SSHReport); ok && s != nil {
			getOrInit(s.Host).SSHBanner = s.Banner
		}
	}
	for _, r := range collect["smb"] {
		if s, ok := r.(*SMBReport); ok && s != nil {
			b := getOrInit(s.Host)
			b.SMBOSStr = s.OS
			b.SMBVersion = s.Dialect
		}
	}
	for _, r := range collect["ftp"] {
		if s, ok := r.(*FTPReport); ok && s != nil {
			getOrInit(s.Host).FTPBanner = s.Banner
		}
	}
	for _, r := range collect["smtp"] {
		if s, ok := r.(*SMTPReport); ok && s != nil {
			getOrInit(s.Host).SMTPBanner = s.Banner
		}
	}
	for _, r := range collect["mysql"] {
		if s, ok := r.(*MySQLReport); ok && s != nil {
			getOrInit(s.Host).MySQLVer = s.ServerVersion
		}
	}
	// Ensure every host that has open ports gets at least an empty
	// banners record so we still emit an os_heuristic row.
	for _, p := range ports {
		getOrInit(p.Host)
	}

	nHosts, nFindings := 0, 0
	for host, b := range hostBanners {
		rep := ProbeOSHeuristic(host, *b)
		nHosts++
		m, _ := toMap(rep)
		w.write(Finding{
			Phase:     "driver",
			Host:      host,
			Meta:      map[string]any{"source": "os_heuristic", "report": m},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		findings, ferr := eng.Evaluate("os_heuristic", rep)
		if ferr != nil {
			hlog.Printf("  [plugin os_heuristic] %s: %v", host, ferr)
			continue
		}
		for _, f := range findings {
			w.writeFinding(f)
			nFindings++
			hlog.Printf("  [FIND] %s %s %s %s",
				f.Severity, f.RuleID, f.Host, f.Title)
		}
	}
	return nHosts, nFindings
}

// runTLSFingerprint probes any port whose nmap tunnel == ssl or whose
// service is one of https / ssl/http. Per-port (not per-host) because
// the same host can offer different cipher stacks on different ports.
func runTLSFingerprint(ports []*Port, eng *PluginEngine, w *writer, hlog *log.Logger) (int, int) {
	if hlog == nil {
		hlog = log.Default()
	}
	const timeout = 6 * time.Second
	nProbed, nFindings := 0, 0
	for _, p := range ports {
		if !isTLSPort(p) {
			continue
		}
		rep, err := ProbeTLSFingerprint(p.Host, p.Port, timeout)
		if err != nil {
			hlog.Printf("  [tlsfp] %s:%d: %v", p.Host, p.Port, err)
			continue
		}
		nProbed++
		m, _ := toMap(rep)
		w.write(Finding{
			Phase:     "driver",
			Host:      p.Host,
			Port:      p.Port,
			Meta:      map[string]any{"source": "tlsfp", "report": m},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		findings, ferr := eng.Evaluate("tlsfp", rep)
		if ferr != nil {
			hlog.Printf("  [plugin tlsfp] %s:%d: %v", p.Host, p.Port, ferr)
			continue
		}
		for _, f := range findings {
			w.writeFinding(f)
			nFindings++
			hlog.Printf("  [FIND] %s %s %s:%d %s",
				f.Severity, f.RuleID, f.Host, f.Port, f.Title)
		}
	}
	return nProbed, nFindings
}

// runTLSVuln runs testssl.sh against any TLS-bearing port and emits
// driver + finding rows. testssl.sh is heavy (60-120s per port) so we
// only fire it once per TLS port. Missing binary returns silently with
// an in-report ProbeError; we don't spam the log per port for that.
func runTLSVuln(ports []*Port, eng *PluginEngine, w *writer, hlog *log.Logger) (int, int) {
	if hlog == nil {
		hlog = log.Default()
	}
	if !TLSVulnBinaryAvailable() {
		hlog.Printf("  [tlsvuln] testssl.sh not in PATH; skipping (run -check-deps)")
		return 0, 0
	}
	timeout := 300 * time.Second
	nProbed, nFindings := 0, 0
	for _, p := range ports {
		if !isTLSPort(p) && !isSTARTTLSCapable(p) {
			continue
		}
		rep, err := ProbeTLSVulnService(p.Host, p.Port, p.Service, timeout)
		if err != nil {
			hlog.Printf("  [tlsvuln] %s:%d: %v", p.Host, p.Port, err)
			continue
		}
		nProbed++
		m, _ := toMap(rep)
		w.write(Finding{
			Phase:     "driver",
			Host:      p.Host,
			Port:      p.Port,
			Meta:      map[string]any{"source": "tlsvuln", "report": m},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		findings, ferr := eng.Evaluate("tlsvuln", rep)
		if ferr != nil {
			hlog.Printf("  [plugin tlsvuln] %s:%d: %v", p.Host, p.Port, ferr)
			continue
		}
		for _, f := range findings {
			w.writeFinding(f)
			nFindings++
			hlog.Printf("  [FIND] %s %s %s:%d %s",
				f.Severity, f.RuleID, f.Host, f.Port, f.Title)
		}
	}
	return nProbed, nFindings
}

// runCVELookup collects CPEs per unique host and fires cvemap per CPE.
// Emits a phase=driver source=cve row per (host, CPE) plus any plugin
// findings. Skipped (no rows, no log spam) when cvemap is not in PATH.
func runCVELookup(ports []*Port, driverReports map[string][]any, eng *PluginEngine, w *writer, hlog *log.Logger) (int, int) {
	if hlog == nil {
		hlog = log.Default()
	}
	if cvemapBinary() == "" {
		hlog.Printf("  [cve] cvemap not in PATH; skipping")
		return 0, 0
	}
	// Group CPEs by host then iterate one cvemap run per (host, CPE).
	hosts := groupPortsByHost(ports)
	nQueries, nFindings := 0, 0
	for _, host := range hosts {
		cpes := collectCPEsForHost(ports, host, driverReports)
		if len(cpes) == 0 {
			continue
		}
		// Find the first open port on the host so the report has a
		// port to associate with. CVEs are version-based, not
		// per-port, but the NDJSON schema wants a port.
		var portForHost int
		for _, p := range ports {
			if p.Host == host {
				portForHost = p.Port
				break
			}
		}
		for _, cpe := range cpes {
			rep, err := ProbeCVE(host, portForHost, []string{cpe}, 20*time.Second)
			if err != nil {
				hlog.Printf("  [cve] %s %s: %v", host, cpe, err)
				continue
			}
			nQueries++
			m, _ := toMap(rep)
			w.write(Finding{
				Phase:     "driver",
				Host:      host,
				Port:      portForHost,
				Meta:      map[string]any{"source": "cve", "report": m},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			findings, ferr := eng.Evaluate("cve", rep)
			if ferr != nil {
				hlog.Printf("  [plugin cve] %s %s: %v", host, cpe, ferr)
				continue
			}
			for _, f := range findings {
				w.writeFinding(f)
				nFindings++
				hlog.Printf("  [FIND] %s %s %s %s",
					f.Severity, f.RuleID, f.Host, f.Title)
			}
		}
	}
	return nQueries, nFindings
}

// runSMBVulnFor fires the nxc-based MS17-010 / Zerologon / SMBGhost
// modules against one SMB port. Designed to piggyback on a successful
// SMB probe so we don't double-dispatch. Increments counters in place.
func runSMBVulnFor(p *Port, eng *PluginEngine, w *writer, hlog *log.Logger,
	collect map[string][]any, nDrivers, nFindings *int) {
	if nxcBinary() == "" {
		// Only log once per host to keep output sane. We rely on the
		// startup deps warning to surface the missing nxc binary.
		return
	}
	rep, err := ProbeSMBVuln(p.Host, p.Port, 90*time.Second)
	if err != nil {
		hlog.Printf("  [smbvuln] %s:%d: %v", p.Host, p.Port, err)
		return
	}
	if nDrivers != nil {
		*nDrivers++
	}
	if collect != nil {
		collect["smbvuln"] = append(collect["smbvuln"], rep)
	}
	m, _ := toMap(rep)
	w.write(Finding{
		Phase:     "driver",
		Host:      p.Host,
		Port:      p.Port,
		Meta:      map[string]any{"source": "smbvuln", "report": m},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	findings, ferr := eng.Evaluate("smbvuln", rep)
	if ferr != nil {
		hlog.Printf("  [plugin smbvuln] %s:%d: %v", p.Host, p.Port, ferr)
		return
	}
	for _, f := range findings {
		w.writeFinding(f)
		if nFindings != nil {
			*nFindings++
		}
		hlog.Printf("  [FIND] %s %s %s:%d %s",
			f.Severity, f.RuleID, f.Host, f.Port, f.Title)
	}
}

// isTLSPort reports whether a port should get a TLS fingerprint probe.
func isTLSPort(p *Port) bool {
	if p == nil {
		return false
	}
	if p.TLS {
		return true
	}
	switch p.Service {
	case "https", "ssl/http", "ssl/https", "imaps", "pop3s",
		"smtps", "ftps", "ldaps", "ms-wbt-server":
		// ms-wbt-server (RDP) wraps TLS by default since Win Server 2003.
		return true
	}
	return false
}

// isSTARTTLSCapable reports whether a port carries a STARTTLS-capable
// plaintext protocol. testssl.sh wrapper uses this to widen its scope.
// Phase 2.9 (TLS fingerprint, direct TLS only) does NOT use it.
func isSTARTTLSCapable(p *Port) bool {
	if p == nil {
		return false
	}
	switch p.Service {
	case "smtp", "submission", "imap", "pop3", "ftp", "ldap",
		"xmpp-client", "xmpp-server", "xmpp", "nntp",
		"mysql", "postgresql":
		return true
	}
	return false
}

// evalPluginsAndPrint loads YAML plugins from flagPlugins, evaluates the
// ones whose source matches, and prints any matched findings.
func evalPluginsAndPrint(source string, report any) {
	eng, err := LoadPlugins(*flagPlugins)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin load: %v\n", err)
		return
	}
	counts := eng.RuleCount()
	fmt.Fprintf(os.Stderr, "loaded %d rules for source=%s (counts: %v)\n",
		counts[source], source, counts)
	findings, err := eng.Evaluate(source, report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin eval: %v\n", err)
		return
	}
	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "no findings fired.\n")
		return
	}
	fmt.Fprintf(os.Stderr, "\n=== findings (%d) ===\n", len(findings))
	for _, f := range findings {
		b, _ := json.MarshalIndent(f, "", "  ")
		fmt.Println(string(b))
	}
}

func splitHostPort(s string) (string, int, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("expected host:port, got %q", s)
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, err
	}
	return s[:i], p, nil
}

// ──────────────────────────────────────────────────────────────────────
// Console summary
// ──────────────────────────────────────────────────────────────────────

func summarize(ports []*Port) {
	fmt.Println()
	fmt.Println("port    service        product/version")
	fmt.Println("----    -------        ---------------")
	for _, p := range ports {
		svc := p.Service
		if svc == "" {
			svc = "?"
		}
		desc := strings.TrimSpace(strings.Join([]string{p.Product, p.Version, p.Extra}, " "))
		if p.TLS {
			desc = "[TLS] " + desc
		}
		fmt.Printf("%-7d %-14s %s\n", p.Port, svc, desc)
	}
}
