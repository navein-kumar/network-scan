// prometheusprobe.go: phase 3 driver for Prometheus (TCP 9090).
//
// GET /api/v1/status/buildinfo returns version, goVersion, etc. No auth needed.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type PrometheusReport struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	GoVersion  string `json:"go_version,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

func ProbePrometheus(host string, port int, timeout time.Duration) (*PrometheusReport, error) {
	rep := &PrometheusReport{Host: host, Port: port}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s:%d/api/v1/status/buildinfo", scheme, host, port)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		var result struct {
			Status string `json:"status"`
			Data   struct {
				Version   string `json:"version"`
				GoVersion string `json:"goVersion"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &result); err != nil || result.Data.Version == "" {
			continue
		}
		rep.Product = "prometheus"
		rep.Version = result.Data.Version
		rep.GoVersion = result.Data.GoVersion
		return rep, nil
	}
	rep.ProbeError = "no valid prometheus /api/v1/status/buildinfo response"
	return rep, nil
}
