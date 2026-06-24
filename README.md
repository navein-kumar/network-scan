# fastscan

Internal pentest recon scanner. Chains rustscan, nmap, protocol drivers,
httpx, and nuclei into a single NDJSON stream.

## Scan modes and tuning

**Port modes** (UDP is always part of the scan, not an opt-in):

| Mode | Flag | TCP | UDP |
|---|---|---|---|
| fast (default) | (none) | top ~1700 (1-1024 + curated high ports) | top 50 (53, 67, 123, 137, 161, 500, 623, 1900, 5060, ...) |
| deep | `-deep` | 1-65535 | top 100 |
| custom | `-ports "443,8080" -udp-ports "161,500"` | what you set | what you set (empty = no UDP) |

Skip UDP with `-skip-udp`.

**Network-tuning profile.** At startup fastscan probes the RTT to the first target host and picks one of 4 profiles. Each profile sets sensible defaults for batch size, port-discovery timeout, driver probe timeout, concurrent hosts, and HTTP timeouts.

| Profile | RTT bracket | batch | timeout | driver-timeout | max-hosts | http-connect | http-read | http-total |
|---|---|---|---|---|---|---|---|---|
| fast | <50 ms (LAN) | 4500 | 1500 ms | 8 s | 8 | 5 s | 10 s | 30 s |
| medium | 50-200 ms (WAN) | 1500 | 3000 ms | 15 s | 4 | 8 s | 20 s | 60 s |
| slow | 200-500 ms (tunnel/VPN) | 500 | 5000 ms | 30 s | 2 | 15 s | 30 s | 90 s |
| crawl | >500 ms | 200 | 10000 ms | 60 s | 1 | 30 s | 60 s | 180 s |

**Override hierarchy.** Auto-detected profile is the baseline. Then:
- `-profile fast|medium|slow|crawl` forces a named profile.
- Any individual flag (`-batch`, `-timeout`, `-driver-timeout`, `-max-hosts`, `-http-connect-timeout`, `-http-read-timeout`, `-http-total-timeout`) overrides the profile value for that one knob.

```bash
# Auto-detect (most engagements)
./fastscan -target 192.168.100.0/24

# Slow tunnel known up front
./fastscan -target 192.168.100.0/24 -profile slow

# Profile picks medium but raise driver timeout for SMB-heavy hosts
./fastscan -target 192.168.100.0/24 -driver-timeout 45s

# Deep + custom UDP set
./fastscan -target 192.168.100.0/24 -deep -udp-ports "161,500,623"
```

**Ping handling.** fastscan never depends on ICMP echo. Both nmap (via `-Pn`) and rustscan run with host discovery disabled. Targets behind a ping-blocking firewall are scanned normally.

## Intentionally NOT covered

These nmap NSE prefixes are skipped by design. Add a driver only if a specific engagement scope demands the category.

| Category | Prefixes / scripts | Why skip |
|---|---|---|
| **ICS / SCADA / OT** | bacnet, enip, s7, iec-104, omron, stuxnet | Out of scope for IT engagements. Only build if the SOW explicitly covers operational technology / industrial control. |
| **Crypto / P2P** | bitcoin, bitcoinrpc, bittorrent, vuze, deluge | Public crypto / torrent nodes are rarely a finding in enterprise engagements. |
| **Legacy services** | gopher, daytime, finger, netbus, domino, distcc, freelancer, dict, quake1, quake3 | Pre-2010 protocols. nmap version banner via Phase 2 is enough; no dedicated driver needed. |
| **Game / VoIP nostalgia** | teamspeak2, ventrilo, skypev2, iax2 | Not in modern engagement scope. |
| **Anonymity overlays** | tor (5 scripts) | Tor relay enumeration is its own discipline, out of pentest workflow. |
| **OSINT helpers** | address-info, asn-query, fcrdns, ipidseq, ip-geolocation, whois, hostmap, shodan, vulners | Better handled by dedicated OSINT tools (subfinder, dnsx, uncover) before fastscan runs. |
| **L2 broadcast** | broadcast-* (34 scripts) | Need broadcast L2 access. Fastscan is a routed scanner, not a broadcast-discovery tool. |
| **DoS / Exploit / Brute** | `*-brute` (50+ scripts), `*-dos`, `exploit-*` | Out of scope for non-destructive recon. Cred-testing is limited to default-credential list, not brute force. |
| **Discovery noise** | targets-*, sniffer-detect, fingerprint-strings, http-favicon, http-headers | Either we already capture via httpx / nmap -sV, or they are not actionable findings. |

If a future engagement demands any of the above, add a driver following the standard two-file pattern (`<protocol>probe.go` + `plugins/<source>/*.yaml`).

## Pipeline phases

1. `portscan`: rustscan finds open TCP ports.
2. `fingerprint`: nmap `-sV` (via Ullaakut lib or direct CLI) identifies
   the service on each open port.
2.5. Protocol drivers + plugin engine. For ports matching a known
   protocol, run the driver and evaluate YAML plugin rules against the
   driver's report. Includes the default-credential testing layer
   (see "Default credentials" below) so authenticated findings ride the
   same plugin pipeline.
2.6. OS detection (`nmap -O`, once per host, raw-socket privileges).
2.7. Traceroute (`nmap --traceroute -sn -Pn`, once per host, raw-socket
   privileges).
2.8. OS heuristic (banner correlation, no privileges).
2.9. TLS fingerprint (`crypto/tls` handshake per TLS-bearing port).
   Records cipher / version / ALPN / cert subject and a JA4-style tag.
3. `httpx`: enrich web ports with title, tech, server, status.
4. `nuclei`: one nuclei engine per service tag bucket. Hits go out as
   `phase=nuclei`.

Skip flags: `-skip-nmap`, `-skip-drivers`, `-skip-os`,
`-skip-traceroute`, `-skip-nuclei`, `-skip-creds`.

## Drivers

Every driver is one Go file. Function signature is
`Probe<Name>(host string, port int, timeout time.Duration) (*<Name>Report, error)`.

| File             | Service triggers                | Library / protocol             | Extracts                                                  |
|------------------|---------------------------------|--------------------------------|-----------------------------------------------------------|
| `sshprobe.go`    | `ssh` (port 22)                 | `golang.org/x/crypto/ssh` + hand-rolled KEXINIT parse | banner, kex/cipher/mac/compression algos, host keys + fingerprints, weak algo list |
| `smbprobe.go`    | `netbios-ssn`, `microsoft-ds` (139, 445) | `github.com/jfjallid/go-smb` + hand-rolled SMB1 negotiate | dialect, OS/netbios/dns/domain, signing required, null session, SMBv1 enabled |
| `vncprobe.go`    | `vnc` (5900)                    | Hand-rolled RFB 3.x handshake (RFC 6143) | protocol version, security types, no-auth flag |
| `ldapprobe.go`   | `ldap` (389, 636)               | `github.com/go-ldap/ldap/v3`   | TLS state, anonymous bind result, rootDSE attributes (naming contexts, SASL, version, controls, dnsHostName) |
| `mssqlprobe.go`  | `ms-sql-s` (1433)               | Hand-rolled TDS PRELOGIN ([MS-TDS] §2.2.6.5) | version (with release name), encryption supported/required, instance name |
| `rdpprobe.go`    | `ms-wbt-server` (3389)          | Hand-rolled X.224 CR + RDP_NEG_REQ ([MS-RDPBCGR] §2.2.1.1) | NLA enabled, TLS offered, standard RDP security offered, CredSSP offered, raw protocol flags |
| `ftpprobe.go`    | `ftp` (21)                      | Stdlib `net/textproto`         | banner, anonymous login result, SYST, FEAT capabilities, AUTH TLS offered |
| `mysqlprobe.go`  | `mysql` (3306)                  | Hand-rolled MySQL handshake parse | protocol version, server version, auth plugin, SSL/TLS capability flag |
| `postgresqlprobe.go` | `postgresql` (5432)         | Hand-rolled SSLRequest + StartupMessage | SSL supported, auth method (trust/cleartext/md5/scram), server error |
| `snmpprobe.go`   | `snmp` (161/udp)                | `github.com/gosnmp/gosnmp`     | community string that worked, sysDescr / sysName / sysObjectID / sysContact / sysLocation / sysUpTime |
| `netbiosprobe.go`| `netbios-ns` (137/udp)          | Hand-rolled NBSTAT query (RFC 1002) | NetBIOS name table with suffix/role flags, MAC address |
| `smtpprobe.go`   | `smtp` (25, 587)                | Stdlib `net/textproto`         | banner, EHLO capabilities, STARTTLS offered, AUTH methods, open-relay test |
| `telnetprobe.go` | `telnet` (23)                   | Hand-rolled IAC negotiation parse | negotiated options, post-IAC banner, AUTHENTICATION + ENCRYPT option presence |
| `kerberosprobe.go` | `kerberos-sec` (88)           | `github.com/jcmturner/gokrb5/v8` | per-user AS-REQ verdict (existing / nonexistent / AS-REP-roastable) |
| `ipmiprobe.go`   | `ipmi` (623/udp)                | `github.com/bougou/go-ipmi`    | IPMI version, null/anonymous auth, supported auth types, Cipher Suite 0 acceptance |
| `rpcprobe.go`    | `rpcbind` / `nfs` (111, 2049)   | Hand-rolled SunRPC portmap DUMP + mountd EXPORT (RFC 1057, 1813) | RPC program list, NFS enabled, mountd port, exported paths |
| `ajpprobe.go`    | `ajp13` (8009)                  | Hand-rolled AJP13 CPing + Forward-Request | AJP13 responding, Ghostcat probe status |
| `redisprobe.go`  | `redis` (6379)                  | Hand-rolled RESP (PING / INFO / CONFIG GET dir) | reachable, auth required, version, role, data directory |
| `memcachedprobe.go` | `memcached` (11211)          | Stdlib `stats` command         | reachable, version, key stats |
| `mongodbprobe.go`| `mongodb` (27017)               | Hand-rolled OP_QUERY isMaster + BSON parse | reachable, auth required, version, maxWireVersion, replica set, primary |
| `pop3probe.go`   | `pop3` (110)                    | Stdlib `net/textproto`         | banner, CAPA list, STLS offered, SASL mechanisms |
| `imapprobe.go`   | `imap` (143)                    | Stdlib `net/textproto`         | banner, CAPABILITY list, STARTTLS offered, LOGINDISABLED, AUTH mechanisms |
| `ntpprobe.go`    | `ntp` (123/udp)                 | `github.com/beevik/ntp` + hand-rolled mode-7 monlist | version, stratum, reference ID, monlist responding, monitor entry count |
| `osprobe.go`     | per-host (Phase 2.6)            | Shells out to `nmap -O --osscan-guess` + XML parse | OS matches list with accuracy + family/vendor/generation, best match |
| `dnsprobe.go`    | `domain` / `dns` (53)           | `github.com/miekg/dns`         | version.bind CHAOS TXT, hostname.bind, recursion availability, DNSSEC capability |
| `winrmprobe.go`  | `wsman` (5985, 5986)            | Stdlib `net/http` POST /wsman + WWW-Authenticate parse | reachable, TLS state, status code, auth methods offered (Negotiate / Kerberos / NTLM / Basic), server header |
| `oracletnsprobe.go` | `oracle-tns` (1521)          | Hand-rolled TNS CONNECT packet | reachable, version banner from REFUSE/REDIRECT payload (parses VSNNUM hex too) |
| `msrpcprobe.go`  | `msrpc` / `epmap` (135)         | Hand-rolled DCERPC BIND to EPMv4 (UUID e1af8308-...) + single EPT_Lookup call | reachable, BIND_ACK received, endpoint table (UUID, interface version, named pipe, dynamic port, protocol binding) via one Lookup call (no Lookup paging in v0) |
| `tlsfingerprintprobe.go` | per-TLS-port (Phase 2.9)| Stdlib `crypto/tls` handshake  | negotiated TLS version, cipher suite, ALPN, SNI, peer subject / issuer / CN, JA4-style tag (not the official JA4 hash; stdlib hides the raw extension list) |
| `mqttprobe.go`   | `mqtt` (1883, 8883)             | Hand-rolled MQTT v3.1.1 CONNECT / CONNACK | reachable, CONNACK return code, auth required |
| `sipprobe.go`    | `sip` (5060/udp + 5060/tcp)     | Hand-rolled SIP OPTIONS request   | reachable, status code/reason, Server / User-Agent header, Allow methods |
| `modbusprobe.go` | `modbus` (502)                  | Hand-rolled Modbus/TCP function 0x2B Read Device Identification | reachable, vendor name, product code, firmware revision, units responding |
| `tracerouteprobe.go` | per-host (Phase 2.7)       | Shells out to `nmap --traceroute -sn -Pn` + XML parse | hop list (ttl, address, rtt, hostname) |
| `tcposscan.go`   | per-host (Phase 2.8)            | Banner correlation across SSH / SMB / HTTP / FTP / SMTP / MySQL reports | OS family, OS guess, confidence (0..100), matched signals. No raw sockets needed. |
| `jdwpprobe.go`   | `jdwp` (8000 / 5005 / 8453)     | Hand-rolled JDWP handshake + VirtualMachine.Version | reachable, JDWP wire version, VM name, VM version, description |
| `dockerapiprobe.go` | `docker` (2375 / 2376)       | Stdlib HTTP GET /version and /containers/json | reachable, TLS flag, API version, daemon version, OS / arch / kernel, containers accessible flag and count |
| `cupsprobe.go`   | `cups` / `ipp` (631)            | Stdlib HTTP GET / and /printers/ | reachable, Server header, version, printer count, accessible printer names |
| `tftpprobe.go`   | `tftp` (69/udp)                 | Hand-rolled RRQ packet (RFC 1350) | reachable, accepts-requests flag, error code/message |
| `weblogicprobe.go` | `weblogic` / `t3` (7001 / 7002) | Hand-rolled T3 handshake | reachable, T3 version advertised, WebLogic version parsed from HELO |
| `couchdbprobe.go` | `couchdb` (5984)               | Stdlib HTTP GET / and /_all_dbs | reachable, version, database list, admin-party flag |
| `hnapprobe.go`   | `hnap` (80 / 8080)              | Stdlib HTTP POST /HNAP1/ GetDeviceSettings SOAP | reachable, model name, firmware version, device name, vendor name |
| `afpprobe.go`    | `afp` (548)                     | Hand-rolled DSI GetStatus (Apple Filing Protocol) | reachable, server name, machine type, AFP versions, UAM list, server signature |
| `pjlprobe.go`    | `pjl` / `hp-pjl` (9100)         | PJL INFO ID + INFO STATUS framed by UEL | reachable, model id, status, firmware |
| `db2probe.go`    | `db2` / `drda` (50000)          | Hand-rolled DRDA EXCSAT ([MS-DRDA]) | reachable, server class (SRVCLSNM), server name (EXTNAM), release |
| `cassandraprobe.go` | `cassandra` (9042)           | Hand-rolled CQL v4 OPTIONS frame | reachable, protocol versions, CQL versions, compression options |
| `hbaseprobe.go`  | `hbase` (60010 / 60030 / 16010) | Stdlib HTTP /jmx + / | reachable, role (master / regionserver), version, region/live/dead server counts |
| `citrixprobe.go` | `citrix` (1494 / 2598)          | Hand-rolled ICA browser hello | reachable, server name (printable run), banner hex |
| `ikeprobe.go`    | `ike` (500/udp)                 | Hand-rolled IKEv1 SA proposal, Main + Aggressive Mode | reachable, IKE version, main / aggressive accepted, vendor IDs |
| `sstpprobe.go`   | `sstp` (443 / SSTP path)        | Stdlib HTTPS SSTP_DUPLEX_POST | reachable, sstp_responding, status code, server header |
| `amqpprobe.go`   | `amqp` (5672)                   | Hand-rolled AMQP 0-9-1 protocol header + Connection.Start parse | reachable, product, version, platform, server-properties map |
| `iscsiprobe.go`  | `iscsi` (3260)                  | Hand-rolled iSCSI Login + SendTargets=All Text Request | reachable, target IQN list, target portal addresses |
| `isnsprobe.go`   | `isns` (3205)                   | Hand-rolled iSNS DevAttrQry | reachable, function id, device tag count |
| `xmppprobe.go`   | `xmpp` (5222 / 5269)            | Stream:stream open + stream:features parse | reachable, stream id, server name, starttls offered, SASL mechanisms |
| `tn3270probe.go` | `tn3270` (23 / 2323)            | Telnet IAC option negotiation (TN3270E / TERMINAL-TYPE) | reachable, TN3270E offered, terminal-type offered, LU name |
| `informixprobe.go` | `informix` (1526 / 9088)      | Hand-rolled SQLI handshake hint + banner sniff | reachable, banner text, product_match flag |
| `svnprobe.go`    | `svn` (3690)                    | svnserve protocol greeting parse | reachable, min/max protocol versions, capabilities, realm |
| `hadoopprobe.go` | `hadoop` (9870 / 50070 / 8088 / 19888) | Stdlib HTTP GET /jmx + bean parse | reachable, component (NameNode / ResourceManager / JobHistory), version, cluster id, live / dead data node counts |

Service-to-driver mapping lives in `driverSourceFor` in `main.go`.
Fallback by well-known port when nmap returns an empty service.

OS detection (Phase 2.6) is special: it runs once per unique host after
the per-port Phase 2.5 loop, and requires raw-socket privileges
(CAP_NET_RAW or root). Disable with `-skip-os` if running unprivileged.

Traceroute (Phase 2.7) also runs once per unique host and shells out to
`nmap --traceroute -sn -Pn`. Same raw-socket requirement as OS
detection. Disable with `-skip-traceroute`.

OS heuristic (Phase 2.8) runs after the per-port drivers and reuses
the banners those drivers already captured (SSH, SMB, HTTP, FTP, SMTP,
MySQL) to infer a Linux / Windows / BSD family guess with a confidence
score. It needs no privileges. We chose banner correlation over raw
TCP/IP fingerprinting because Go's `net.Conn` does not expose the
remote SYN/ACK TTL or window size; doing that properly would need
`AF_PACKET` and CAP_NET_RAW, which would break the unprivileged
guarantee.

TLS fingerprint (Phase 2.9) runs once per port flagged as TLS (the
nmap Tunnel attribute is `ssl`, or the service is one of `https`,
`ssl/http`, `imaps`, `pop3s`, `smtps`, `ftps`, `ldaps`,
`ms-wbt-server`). We use stdlib `crypto/tls` instead of
projectdiscovery/tlsx so we don't pull in the heavy tlsx dependency
graph. The trade-off: stdlib hides the raw ClientHello extension list,
so the JA4 / JA4S fields we emit are JA4-style tags
(`t<ver>_<alpn>_<cipher-hex>` and `s<ver>_<cipher-hex>`), not the
official FoxIO JA4 hash. They are still sufficient for "same TLS stack
across multiple ports / hosts" correlation, which is the engagement
use case (e.g. flagging when Acunetix-default ports get mislabeled as
Ajenti or vice-versa).

## Default credentials

Phase 2.5 includes a default-credential testing layer. Credential lists
live in `creds/<service>.yaml` (editable without rebuild). Supported
services in v0: ssh, ftp, mssql, mysql, postgresql, redis, winrm. VNC
(DES challenge / response VNCAuth) and IPMI (RAKP cipher-zero) are out
of scope: the existing `ipmi-cipher-zero` plugin already catches the
realistic IPMI default-creds exposure, and VNC challenge / response is
fiddly relative to the payoff.

Schema:

```yaml
service: mysql
attempts:
  - { user: root,  pass: "" }
  - { user: root,  pass: root }
  - { user: admin, pass: admin }
```

After each driver run, fastscan walks the loaded attempts for that
service, stops on the first success, and appends the results to the
driver report's `cred_attempts` field. The `<service>-default-creds`
plugin then fires `critical` if any attempt succeeded.

Flags:
- `-creds-dir DIR`: directory of credential YAML files (default
  `creds`). Set to a non-existent path to disable list loading.
- `-skip-creds`: turn the entire layer off (e.g. for safe-mode recon).

Per-service implementation:
- SSH: `golang.org/x/crypto/ssh.Dial` with password auth.
- FTP: stdlib USER / PASS, accept on `230`.
- MSSQL: hand-rolled TDS PRELOGIN + LOGIN7 with obfuscated password.
  Skips TLS negotiation, so it only works against servers configured
  for unencrypted auth or encryption-optional. Servers that require
  encryption will surface as a connection error in the attempt record.
- MySQL: hand-rolled native handshake response with `mysql_native_password`
  (SHA-1 challenge / response). Auth-switch and SCRAM-SHA-256 are not
  implemented and surface as errors.
- PostgreSQL: StartupMessage + PasswordMessage (cleartext and MD5).
  SCRAM-SHA-256 is not implemented.
- Redis: `*1\r\n$4\r\nPING\r\n` first for empty-password tests; AUTH
  command otherwise (supports both single-arg and Redis 6+ two-arg ACL
  syntax).
- WinRM: HTTP POST `/wsman` with `Authorization: Basic`. 200 or 500 =
  accepted, 401 = rejected.

The store auto-loads from `-creds-dir` at startup for both full
pipeline mode and the standalone `-xxx-test` modes, so single-protocol
smoke tests also exercise the cred path.

## Multi-host parallelism

When `-target` is a CIDR, fastscan runs Phase 2..4 for each live host
in parallel goroutines, bounded by `-max-hosts` (default 8). The
NDJSON writer is already mutex-guarded so output stays well-formed.
Per-host log lines are prefixed with `[host=<ip>] ` so concurrent
output stays attributable.

```
./fastscan -target 192.168.1.0/24 -max-hosts 4 -ports '22,80,443' \
           -plugins plugins/ -out /tmp/sweep
```

Lower `-max-hosts` if you see nmap or nuclei CPU contention; raise it
on bigger sweeps where most subprocess time is network I/O.

## Evidence .txt bridge

`scripts/fastscan_to_evidence.py` converts `findings.ndjson` into one
.txt per fired finding, in the nxc terminal-output style that the
existing `tools/scripts/txt_to_img.py` colouriser renders into 1600x830
PNGs ready for the engagement report.

```bash
python scripts/fastscan_to_evidence.py -i out/findings.ndjson -o evidence/fastscan/
find evidence/fastscan -name "*.txt" -print0 \
  | xargs -0 -n1 python tools/scripts/txt_to_img.py
```

Each .txt is `# fastscan -...-test` at the top, followed by
`PROTO  host  Port: N  [*/+]  ...` lines pulled from the driver's
report fields plus any cred successes plus the plugin's evidence
string. Output layout: `evidence/fastscan/<rule_id>/<host>_<port>.txt`.
The engagement lead later moves each into the right `evidence/vul-NN/`
folder per the report's vulnerability numbering.

Pure scanner output, no commentary, no plugin names: matches the
project rule for evidence files going into `deliverables/images/`.

## xlsx report bridge

`scripts/fastscan_to_xlsx.py` converts the `findings.ndjson` produced by
a fastscan run into a 13-column workbook that matches the engagement
xlsx schema (No. / Vulnerability Name / Severity / CVSS / CVE_Type /
MITRE ATT&CK / Vulnerable IP / Group / Description / POC / Fix / Status
/ Pages Need).

```bash
python scripts/fastscan_to_xlsx.py -i out/findings.ndjson -o out/findings.xlsx
```

What it does automatically:
- Groups findings by rule_id so the same plugin firing across N hosts
  becomes a single row with all hosts in the Vulnerable IP column.
- Derives CVSS heuristically from severity. Engagement lead overrides
  with the real CVE record.
- Sets Group to "Private IP" if every affected host is RFC1918, else
  "Public IP".
- Skips `info` severity rows. Use `--include-info` to keep them.

What stays manual:
- MITRE ATT&CK column (left blank).
- Pages Need column (screenshot mapping is manual).
- The 80-word description prose (the bridge produces a short summary
  that the lead rewrites).

## Plugins

YAML rules under `plugins/<source>/<rule>.yaml`. The engine is
expr-lang/expr; evidence templates are Go `text/template` with the
driver report exposed as the dot context (keys = JSON tags).

Current rules:

| Source | Rule ID                          | Severity | Catches                                              |
|--------|----------------------------------|----------|------------------------------------------------------|
| ssh    | `openssh-eol`                    | medium   | OpenSSH <= 7.3 banners                              |
| ssh    | `ssh-cbc-ciphers`                | medium   | CBC cipher in offered list                          |
| ssh    | `ssh-dh-group1`                  | high     | `diffie-hellman-group1-sha1` kex                    |
| ssh    | `ssh-dss-host-key`               | high     | DSA host key offered                                |
| ssh    | `ssh-weak-mac`                   | medium   | hmac-md5 / hmac-sha1 family                         |
| smb    | `smb-null-session`               | medium   | Anonymous SMB authentication accepted               |
| smb    | `smb-signing-not-required`       | medium   | SMB signing optional                                |
| smb    | `smb-v1-enabled`                 | high     | SMBv1 NEGOTIATE accepted                            |
| vnc    | `vnc-no-auth-required`           | critical | Security type None (1) offered                      |
| vnc    | `vnc-protocol-3.3`               | medium   | RFB 3.3 only                                        |
| vnc    | `vnc-weak-vncauth`               | low      | VNCAuth (DES, 8-char) offered                       |
| ldap   | `ldap-anonymous-bind`            | medium   | Anonymous BIND accepted                             |
| ldap   | `ldap-no-tls`                    | medium   | Port 389 plaintext                                  |
| ldap   | `ldap-rootdse-leak`              | info     | Naming contexts via anonymous rootDSE               |
| mssql  | `mssql-encryption-not-required`  | medium   | TDS encryption not required                         |
| mssql  | `mssql-eol-version`              | medium   | SQL Server 2008 / 2012 / 2014                       |
| rdp    | `rdp-no-nla`                     | medium   | No CredSSP/Hybrid offered                           |
| rdp    | `rdp-standard-security`          | high     | Standard RDP security and TLS not offered           |
| ftp    | `ftp-anonymous-login`            | medium   | Anonymous login accepted                            |
| ftp    | `ftp-no-tls`                     | medium   | AUTH TLS not advertised in FEAT                     |
| ftp    | `ftp-vsftpd-234-backdoor`        | critical | vsftpd 2.3.4 banner (CVE-2011-2523)                 |
| mysql  | `mysql-version-disclosure`       | info     | Handshake leaks server version                      |
| mysql  | `mysql-eol-version`              | medium   | MySQL 3.x / 4.x / 5.0..5.6 EOL                      |
| mysql  | `mysql-no-ssl`                   | medium   | CLIENT_SSL capability not advertised                |
| postgresql | `postgresql-no-ssl`          | medium   | SSLRequest returns N (no SSL)                       |
| postgresql | `postgresql-trust-auth`      | critical | postgres role bound via trust auth                  |
| postgresql | `postgresql-cleartext-auth`  | high     | AuthenticationCleartextPassword returned            |
| postgresql | `postgresql-md5-auth`        | low      | MD5 auth (deprecated since PG14)                    |
| snmp   | `snmp-default-community`         | high     | public/private community accepted                   |
| snmp   | `snmp-weak-community`            | medium   | Guessable non-default community accepted            |
| snmp   | `snmp-eol-os`                    | medium   | sysDescr matches Windows XP/2003/2008 or Linux 2.x  |
| netbios| `netbios-name-disclosure`        | info     | NBSTAT returns name table                           |
| netbios| `netbios-dc-exposed`             | medium   | Suffix 0x1C (domain controllers group) present      |
| netbios| `netbios-master-browser`         | low      | Suffix 0x1D (master browser) present                |
| smtp   | `smtp-banner-disclosure`         | info     | Banner identifies Postfix/Sendmail/Exim/Microsoft   |
| smtp   | `smtp-no-starttls`               | medium   | STARTTLS not in EHLO capability list                |
| smtp   | `smtp-open-relay`                | high     | RCPT TO accepts external recipient                  |
| telnet | `telnet-cleartext`               | high     | Telnet listener reachable                           |
| telnet | `telnet-no-encryption`           | medium   | ENCRYPT option not offered in IAC                   |
| telnet | `telnet-banner-disclosure`       | info     | Banner identifies Cisco/HP/Juniper/Linux/Windows    |
| kerberos | `kerberos-asrep-roastable`     | high     | AS-REP returned without preauth                     |
| kerberos | `kerberos-user-enumeration`    | low      | KDC distinguishes existing vs nonexistent users     |
| ipmi   | `ipmi-cipher-zero`               | critical | Cipher Suite 0 accepted (CVE-2013-4786)             |
| ipmi   | `ipmi-null-auth`                 | high     | Null username login allowed                         |
| ipmi   | `ipmi-anonymous-auth`            | medium   | Anonymous auth advertised                           |
| rpc    | `rpc-portmap-exposed`            | info     | portmap DUMP returns program list                   |
| rpc    | `rpc-nfs-enabled`                | medium   | NFS (program 100003) registered                     |
| rpc    | `rpc-nfs-exports-readable`       | high     | mountd EXPORT returns paths                         |
| ajp    | `ajp-exposed`                    | medium   | AJP13 connector reachable                           |
| ajp    | `ajp-ghostcat-possible`          | high     | Forward-Request answered (manual verify Ghostcat)   |
| redis  | `redis-no-auth`                  | high     | PING accepted without AUTH                          |
| redis  | `redis-version-disclosure`       | info     | INFO leaks redis_version                            |
| redis  | `redis-info-leak`                | medium   | CONFIG GET dir reveals on-disk path                 |
| memcached | `memcached-no-auth`           | high     | TCP stats command reachable (protocol has no auth)  |
| memcached | `memcached-version-disclosure`| info    | stats discloses version                             |
| memcached | `memcached-udp-amplification` | medium   | UDP 11211 surface (CVE-2018-1000115 hint)           |
| mongodb | `mongodb-no-auth`               | critical | isMaster succeeds anonymously                       |
| mongodb | `mongodb-version-disclosure`    | info     | isMaster returns version                            |
| mongodb | `mongodb-replica-set-exposure`  | medium   | setName disclosed                                   |
| pop3   | `pop3-no-stls`                   | medium   | STLS missing from CAPA                              |
| pop3   | `pop3-banner-disclosure`         | info     | Banner identifies Dovecot/Courier/Cyrus/Exchange    |
| pop3   | `pop3-plaintext-auth-only`       | medium   | USER or SASL but no STLS                            |
| imap   | `imap-no-starttls`               | medium   | STARTTLS missing from CAPABILITY                    |
| imap   | `imap-banner-disclosure`         | info     | Banner identifies Dovecot/Courier/Cyrus/Exchange    |
| imap   | `imap-plaintext-auth`            | medium   | No STARTTLS and LOGIN not disabled                  |
| ntp    | `ntp-monlist-amplification`      | high     | mode-7 monlist returns entries (CVE-2013-5211)      |
| ntp    | `ntp-version-disclosure`         | info     | SNTP reachable, version reported                    |
| os     | `os-eol-windows`                 | critical | XP / 2003 / Vista / 7 / 8 / 2008 / 2008 R2          |
| os     | `os-eol-linux`                   | medium   | Linux kernel 2.x / 3.x                              |
| os     | `os-fingerprint`                 | info     | OS detection result (correlates with banners/SNMP)  |
| dns    | `dns-version-bind`               | info     | version.bind CHAOS TXT returned                     |
| dns    | `dns-open-resolver`              | medium   | RA + answer returned for off-domain query           |
| dns    | `dns-no-dnssec`                  | low      | Resolver answers RD=1 but returns no DNSKEY for "." |
| winrm  | `winrm-reachable`                | info     | /wsman responded                                    |
| winrm  | `winrm-plaintext`                | high     | Reachable on port 5985 (HTTP without TLS)           |
| winrm  | `winrm-basic-auth`               | medium   | WWW-Authenticate includes Basic                     |
| oracle | `oracle-version-disclosure`      | info     | TNS REFUSE/REDIRECT leaks version banner            |
| oracle | `oracle-eol-version`             | medium   | Oracle 11g or earlier (8 / 9i / 10g / 11g)          |
| msrpc  | `msrpc-endpoint-mapper-exposed`  | medium   | DCERPC BIND_ACK on 135/tcp                          |
| msrpc  | `msrpc-endpoint-disclosure`      | info     | EPM Lookup returns registered endpoints             |
| mqtt   | `mqtt-no-auth`                   | high     | CONNACK rc=0 (anonymous connect accepted)           |
| mqtt   | `mqtt-reachable`                 | info     | MQTT broker responded to CONNECT                    |
| sip    | `sip-banner-disclosure`          | info     | Server / User-Agent header in OPTIONS reply         |
| sip    | `sip-allow-methods`              | info     | Allow header lists supported methods                |
| modbus | `modbus-exposed`                 | high     | ICS device reachable on routable network            |
| modbus | `modbus-device-disclosure`       | info     | Read Device Identification returns vendor/product   |
| traceroute | `traceroute-hops`            | info     | nmap --traceroute enumerated the path               |
| os_heuristic | `os-heuristic-fingerprint` | info    | OS family inferred from service banners             |
| jdwp   | `jdwp-exposed`                   | critical | JDWP handshake accepted (remote code execution)     |
| jdwp   | `jdwp-version`                   | info     | JDWP discloses JVM vendor / version                 |
| dockerapi | `docker-api-exposed`          | critical | Docker daemon answers /containers/json anonymously  |
| dockerapi | `docker-api-version`          | info     | Docker /version leaks API / version / host info    |
| cups   | `cups-exposed`                   | medium   | CUPS reachable on the network                       |
| cups   | `cups-version-disclosure`        | info     | CUPS Server header leaks version                    |
| cups   | `cups-printer-enum`              | medium   | Anonymous /printers/ enumeration                    |
| tftp   | `tftp-exposed`                   | medium   | TFTP listener responds (DATA or ERROR)              |
| tftp   | `tftp-anonymous-read`            | high     | TFTP returns DATA to anonymous RRQ                  |
| weblogic | `weblogic-exposed`             | medium   | WebLogic T3 HELO accepted                           |
| weblogic | `weblogic-eol-version`         | high     | WebLogic 10.x / 11.x / 12.1 / 12.2 (out of support) |
| couchdb | `couchdb-no-auth`               | critical | /_all_dbs returns DB list anonymously               |
| couchdb | `couchdb-version-disclosure`    | info     | Welcome banner leaks CouchDB version                |
| couchdb | `couchdb-admin-party`           | critical | Admin party mode (no admin defined)                 |
| hnap   | `hnap-exposed`                   | medium   | HNAP1 GetDeviceSettings response received           |
| hnap   | `hnap-info-disclosure`           | medium   | HNAP discloses router model / firmware              |
| afp    | `afp-exposed`                    | info     | AFP server responds to DSI GetStatus                |
| afp    | `afp-uam-cleartext`              | high     | AFP advertises Cleartxt Passwrd UAM                 |
| pjl    | `pjl-exposed`                    | medium   | PJL listener (9100) replied                         |
| pjl    | `pjl-info-disclosure`            | info     | PJL INFO ID leaks model and firmware                |
| db2    | `db2-exposed`                    | medium   | DB2 DRDA EXCSAT reply received                      |
| cassandra | `cassandra-exposed`           | medium   | CQL native OPTIONS SUPPORTED accepted               |
| cassandra | `cassandra-version-disclosure`| info    | SUPPORTED frame leaks CQL / protocol versions       |
| hbase  | `hbase-exposed`                  | high     | HBase Master / Region Server web UI reachable       |
| citrix | `citrix-exposed`                 | medium   | Citrix ICA listener (1494 / 2598) replied           |
| citrix | `citrix-info-disclosure`         | info     | ICA reply contains printable server name            |
| ike    | `ike-exposed`                    | medium   | ISAKMP / IKE responded to SA proposal               |
| ike    | `ike-aggressive-mode`            | high     | IKEv1 Aggressive Mode accepted (PSK hash leak)      |
| sstp   | `sstp-exposed`                   | medium   | Microsoft SSTP duplex POST accepted on 443          |
| amqp   | `amqp-exposed`                   | medium   | AMQP 0-9-1 broker responded with Connection.Start   |
| amqp   | `amqp-version-disclosure`        | info     | server-properties leaks product / version           |
| iscsi  | `iscsi-anonymous-discovery`      | high     | SendTargets=All returned target list without CHAP   |
| isns   | `isns-exposed`                   | medium   | iSNS server returned DevAttrQry response            |
| xmpp   | `xmpp-no-starttls`               | medium   | stream:features omits STARTTLS                      |
| xmpp   | `xmpp-plain-auth`                | medium   | SASL PLAIN advertised                               |
| tn3270 | `tn3270-mainframe-exposed`       | medium   | TN3270E option negotiated (likely mainframe)        |
| informix | `informix-exposed`             | medium   | Informix SQLI listener banner matches               |
| svn    | `svn-exposed`                    | medium   | svnserve protocol greeting received                 |
| svn    | `svn-anonymous-read`             | high     | svnserve advertises ANONYMOUS / EXTERNAL caps       |
| hadoop | `hadoop-exposed`                 | high     | Hadoop admin web UI (HDFS / YARN / JobHistory) open |
| hadoop | `hadoop-version-disclosure`      | info     | /jmx leaks Hadoop version + cluster id              |

## Usage

```
# Single-protocol smoke test (no orchestration)
./fastscan -ssh-test 172.17.0.3:22 -plugins plugins/
./fastscan -smb-test 172.17.0.3:445 -plugins plugins/
./fastscan -vnc-test 172.17.0.3:5900 -plugins plugins/
./fastscan -ldap-test dc01.example.com:389 -plugins plugins/
./fastscan -mssql-test sql01.example.com:1433 -plugins plugins/
./fastscan -rdp-test ws01.example.com:3389 -plugins plugins/

# Full pipeline
./fastscan -target 172.17.0.3 -ports '22,139,445,5900' \
           -templates /tmp/all-tpl/ -out /tmp/fastscan_final \
           -plugins plugins/
```

Output is `<out>/findings.ndjson` (one JSON record per line).

## Multi-host scanning (CIDR)

`-target` accepts either a single host / hostname or a CIDR range.
rustscan handles CIDR natively, so one rustscan invocation covers the
whole range; the results are then grouped by host and Phase 2..4 runs
serially per host. `-max-hosts N` is reserved for a future parallel
implementation; in v0 the loop is serial to keep NDJSON output
ordered and avoid nmap / nuclei CPU contention.

```
./fastscan -target 192.168.1.0/24 -ports '22,80,443' \
           -templates /tmp/all-tpl/ -out /tmp/fastscan_sweep \
           -plugins plugins/
```

Only hosts with at least one open port go through the deep-driver
pipeline. The findings file `<out>/findings.ndjson` carries the union
of all hosts in one stream, with the host field per record.

## Adding a new driver

Two files. (1) `xxxprobe.go`:

```go
type XXXReport struct {
    Host string `json:"host"`
    Port int    `json:"port"`
    // protocol-specific fields with json tags
    ProbeErrors []string `json:"probe_errors,omitempty"`
}

func ProbeXXX(host string, port int, timeout time.Duration) (*XXXReport, error) {
    rep := &XXXReport{Host: host, Port: port}
    // dial, probe, fill rep
    return rep, nil
}
```

(2) Wire it into `main.go` in `driverSourceFor` (map service name to
`"xxx"`) and `runDrivers` (add a case calling `ProbeXXX`). Add a
`-xxx-test` flag and a `runXXXTest` helper mirroring the existing ones.

## Adding a new plugin

Create `plugins/<source>/<rule-id>.yaml`:

```yaml
id: example-rule
title: Example: server admits to running EOL widget
severity: medium                # critical|high|medium|low|info
source: xxx                     # must match a driver source name
when: version matches "(?i)widget 1\\."
evidence: '{{ .host }}:{{ .port }} runs {{ .version }}'
references:
  - https://example.com/advisory
remediation: |
  Free-text remediation guidance, multi-line.
tags: [widget, eol]
```

The `when` expression runs against the driver report keyed by JSON tag.
Supports `==`, `!=`, `in`, `contains()`, `matches`, `any`, `all`, `len`,
plus arithmetic and boolean operators. See expr-lang.org/docs for the
full reference. Compiled at startup; bad expressions abort the load.
