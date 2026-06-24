// consulprobe.go: phase 3 driver for HashiCorp Consul (TCP 8500).
//
// GET /v1/agent/self exposes version and datacenter without auth (default).
// Also lists registered services for deep-content reporting.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

type ConsulReport struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	Datacenter string   `json:"datacenter,omitempty"`
	NodeName   string   `json:"node_name,omitempty"`
	Services   []string `json:"services,omitempty"`
	ProbeError string   `json:"probe_error,omitempty"`
}

func ProbeConsul(host string, port int, timeout time.Duration) (*ConsulReport, error) {
	rep := &ConsulReport{Host: host, Port: port}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s:%d/v1/agent/self", scheme, host, port)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		var data struct {
			Config struct {
				Version    string `json:"Version"`
				Datacenter string `json:"Datacenter"`
				NodeName   string `json:"NodeName"`
			} `json:"Config"`
		}
		if err := json.Unmarshal(body, &data); err != nil || data.Config.Version == "" {
			continue
		}
		rep.Product = "consul"
		rep.Version = data.Config.Version
		rep.Datacenter = data.Config.Datacenter
		rep.NodeName = data.Config.NodeName
		// List registered services (deep content)
		svcURL := fmt.Sprintf("%s://%s:%d/v1/catalog/services", scheme, host, port)
		if sr, err2 := client.Get(svcURL); err2 == nil {
			defer sr.Body.Close()
			var svcs map[string][]string
			if b2, _ := io.ReadAll(io.LimitReader(sr.Body, 32*1024)); json.Unmarshal(b2, &svcs) == nil {
				for name := range svcs {
					if len(rep.Services) >= 50 {
						break
					}
					rep.Services = append(rep.Services, name)
				}
				sort.Strings(rep.Services)
			}
		}
		return rep, nil
	}
	rep.ProbeError = "no valid consul /v1/agent/self response"
	return rep, nil
}
