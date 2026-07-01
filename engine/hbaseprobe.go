// hbaseprobe.go: phase 3 driver for HBase web UIs (60010 master, 60030 region
// server, 16010 newer master).
//
// stdlib HTTP. We probe a small set of common endpoints:
//   - /status/cluster (Stargate REST) -> HBase XML cluster summary.
//   - /jmx?qry=Hadoop:service=HBase,name=Master,sub=Server -> JMX bean.
//   - / -> HTML title contains "HBase Master" or "HBase Region Server".
// The first hit wins for Version / RegionCount / LiveServers / DeadServers.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type HBaseReport struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Reachable    bool     `json:"reachable"`
	Role         string   `json:"role,omitempty"`
	Version      string   `json:"version,omitempty"`
	RegionCount  int      `json:"region_count,omitempty"`
	LiveServers  int      `json:"live_servers,omitempty"`
	DeadServers  int      `json:"dead_servers,omitempty"`
	ProbeErrors  []string `json:"probe_errors,omitempty"`
}

var (
	hbaseTitleRE   = regexp.MustCompile(`(?is)<title>([^<]+)</title>`)
	hbaseVerHTMLRE = regexp.MustCompile(`(?i)HBase\s+Version[^>]*>\s*([\d.]+)`)
)

func ProbeHBase(host string, port int, timeout time.Duration) (*HBaseReport, error) {
	rep := &HBaseReport{Host: host, Port: port}
	cli := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
	base := fmt.Sprintf("http://%s:%d", host, port)

	// /jmx first; cheapest JSON read.
	if jmxErr := hbaseFromJMX(cli, base, rep); jmxErr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("jmx: %v", jmxErr))
	}
	// HTML root for Role + version banner.
	if rootErr := hbaseFromRoot(cli, base, rep); rootErr != nil && !rep.Reachable {
		return rep, fmt.Errorf("root: %w", rootErr)
	}
	if !rep.Reachable && len(rep.ProbeErrors) == 0 {
		rep.ProbeErrors = append(rep.ProbeErrors, "no HBase signature")
	}
	return rep, nil
}

func hbaseFromJMX(cli *http.Client, base string, rep *HBaseReport) error {
	resp, err := cli.Get(base + "/jmx")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var doc struct {
		Beans []map[string]any `json:"beans"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	for _, bean := range doc.Beans {
		name, _ := bean["name"].(string)
		if !strings.Contains(name, "HBase") {
			continue
		}
		rep.Reachable = true
		if v, ok := bean["HBaseVersion"].(string); ok && v != "" {
			rep.Version = v
		}
		if v, ok := bean["Version"].(string); ok && v != "" && rep.Version == "" {
			rep.Version = v
		}
		if strings.Contains(name, "Master") {
			rep.Role = "master"
		}
		if strings.Contains(name, "RegionServer") {
			rep.Role = "regionserver"
		}
		// Cluster status info on Master,sub=Server bean.
		if n, ok := bean["numRegionServers"].(float64); ok {
			rep.LiveServers = int(n)
		}
		if n, ok := bean["numDeadRegionServers"].(float64); ok {
			rep.DeadServers = int(n)
		}
		if n, ok := bean["averageLoad"].(float64); ok && rep.RegionCount == 0 && rep.LiveServers > 0 {
			rep.RegionCount = int(n * float64(rep.LiveServers))
		}
	}
	return nil
}

func hbaseFromRoot(cli *http.Client, base string, rep *HBaseReport) error {
	resp, err := cli.Get(base + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	s := string(body)
	if !strings.Contains(s, "HBase") {
		return fmt.Errorf("no HBase in / body")
	}
	rep.Reachable = true
	if rep.Role == "" {
		if strings.Contains(s, "HBase Master") {
			rep.Role = "master"
		} else if strings.Contains(s, "Region Server") {
			rep.Role = "regionserver"
		}
	}
	if m := hbaseTitleRE.FindStringSubmatch(s); len(m) > 1 && rep.Role == "" {
		t := strings.ToLower(m[1])
		if strings.Contains(t, "master") {
			rep.Role = "master"
		} else if strings.Contains(t, "region") {
			rep.Role = "regionserver"
		}
	}
	if rep.Version == "" {
		if m := hbaseVerHTMLRE.FindStringSubmatch(s); len(m) > 1 {
			rep.Version = m[1]
		}
	}
	return nil
}
