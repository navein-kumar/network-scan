// hadoopprobe.go: phase 3 driver for Hadoop admin web UIs.
//
// Covers HDFS NameNode (9870, older 50070), YARN ResourceManager (8088),
// JobHistory (19888). Stdlib HTTP. GET /jmx returns JSON with a beans
// array; ServiceState bean exposes Version + ClusterId. NameNodeInfo
// bean exposes LiveNodes / DeadNodes counts. The whole UI is unauth'd
// by default, which is the finding.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HadoopReport struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Reachable      bool     `json:"reachable"`
	Component      string   `json:"component,omitempty"`
	Version        string   `json:"version,omitempty"`
	ClusterID      string   `json:"cluster_id,omitempty"`
	LiveDataNodes  int      `json:"live_data_nodes,omitempty"`
	DeadDataNodes  int      `json:"dead_data_nodes,omitempty"`
	ProbeErrors    []string `json:"probe_errors,omitempty"`
}

func ProbeHadoop(host string, port int, timeout time.Duration) (*HadoopReport, error) {
	rep := &HadoopReport{Host: host, Port: port}
	cli := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
	base := fmt.Sprintf("http://%s:%d", host, port)

	resp, err := cli.Get(base + "/jmx")
	if err != nil {
		return rep, fmt.Errorf("get /jmx: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("/jmx status=%d", resp.StatusCode))
		return rep, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var doc struct {
		Beans []map[string]any `json:"beans"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("json: %v", err))
		return rep, nil
	}
	for _, bean := range doc.Beans {
		name, _ := bean["name"].(string)
		if !strings.Contains(name, "Hadoop:") && !strings.Contains(name, "hadoop") {
			continue
		}
		rep.Reachable = true
		// FSNamesystem NameNode info bean
		if strings.Contains(name, "NameNode") {
			rep.Component = "HDFS NameNode"
		}
		if strings.Contains(name, "ResourceManager") {
			rep.Component = "YARN ResourceManager"
		}
		if strings.Contains(name, "JobHistoryServer") {
			rep.Component = "JobHistory Server"
		}
		if v, ok := bean["Version"].(string); ok && v != "" && rep.Version == "" {
			rep.Version = v
		}
		if v, ok := bean["HadoopVersion"].(string); ok && v != "" && rep.Version == "" {
			rep.Version = v
		}
		if v, ok := bean["ClusterId"].(string); ok && v != "" {
			rep.ClusterID = v
		}
		if v, ok := bean["NumLiveDataNodes"].(float64); ok {
			rep.LiveDataNodes = int(v)
		}
		if v, ok := bean["NumDeadDataNodes"].(float64); ok {
			rep.DeadDataNodes = int(v)
		}
	}
	if !rep.Reachable {
		rep.ProbeErrors = append(rep.ProbeErrors, "no Hadoop bean in /jmx")
	}
	return rep, nil
}
