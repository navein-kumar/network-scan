package main

import (
	"os/exec"
	"sync"
)

type Config struct {
	Name          string `json:"name"`
	Targets       string `json:"targets"`
	Template      string `json:"template"`
	Ports         string `json:"ports"`
	UDPPorts      string `json:"udp_ports"`
	SkipUDP       bool   `json:"skip_udp"`
	SkipNuclei    bool   `json:"skip_nuclei"`
	DeepTLS       bool   `json:"deep_tls"`
	MaxHosts      int    `json:"max_hosts"`
	NmapIntensity int    `json:"nmap_intensity"`
	ForceService  string `json:"force_service"`
	FolderID      string `json:"folder_id"`
}

type Severity struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// HostStat is the per-host progress snapshot emitted in SSE progress events.
type HostStat struct {
	Host    string `json:"host"`
	Phase   string `json:"phase"`
	Percent int    `json:"percent"`
	Status  string `json:"status"` // "running" | "done"
}

type Status struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	State        string     `json:"status"`
	Progress     int        `json:"progress"`
	Started      string     `json:"started"`
	Finished     string     `json:"finished,omitempty"`
	HostCount    int        `json:"host_count"`
	FindingCount int        `json:"finding_count"`
	RulesFired   int        `json:"rules_fired"`
	Severity     Severity   `json:"severity"`
	HostsDone    int        `json:"hosts_done"`
	HostsTotal   int        `json:"hosts_total"`
	HostsScanned int        `json:"hosts_scanned"`
	HostsNoPorts int        `json:"hosts_no_ports"`
	HostsSkipped int        `json:"hosts_skipped"`
	HostStats    []HostStat `json:"host_stats,omitempty"`
	Config       Config     `json:"config"`
}

type Scan struct {
	mu     sync.Mutex
	dir    string
	Status Status
	cmd    *exec.Cmd
}

type Finding struct {
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Source   string `json:"source"`
	Evidence string `json:"evidence"`
}

type listItem struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	State        string   `json:"status"`
	Progress     int      `json:"progress"`
	Started      string   `json:"started"`
	Finished     string   `json:"finished,omitempty"`
	HostCount    int      `json:"host_count"`
	FindingCount int      `json:"finding_count"`
	Severity     Severity `json:"severity"`
	FolderID     string   `json:"folder_id"`
}

func (st Status) toListItem() listItem {
	return listItem{
		ID:           st.ID,
		Name:         st.Name,
		State:        st.State,
		Progress:     st.Progress,
		Started:      st.Started,
		Finished:     st.Finished,
		HostCount:    st.HostCount,
		FindingCount: st.FindingCount,
		Severity:     st.Severity,
		FolderID:     st.Config.FolderID,
	}
}
