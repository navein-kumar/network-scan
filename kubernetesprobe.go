// kubernetesprobe.go: phase 3 driver for Kubernetes API server (TCP 6443).
//
// GET /version returns JSON with gitVersion, platform, etc. Runs HTTPS only.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type KubernetesReport struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	GitVersion string `json:"git_version,omitempty"`
	Platform   string `json:"platform,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

func ProbeKubernetes(host string, port int, timeout time.Duration) (*KubernetesReport, error) {
	rep := &KubernetesReport{Host: host, Port: port}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s:%d/version", scheme, host, port)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		var data struct {
			GitVersion string `json:"gitVersion"`
			Platform   string `json:"platform"`
		}
		if err := json.Unmarshal(body, &data); err != nil || data.GitVersion == "" {
			continue
		}
		rep.Product = "kubernetes"
		rep.GitVersion = data.GitVersion
		rep.Platform = data.Platform
		rep.Version = strings.TrimPrefix(data.GitVersion, "v")
		return rep, nil
	}
	rep.ProbeError = "no valid kubernetes /version response"
	return rep, nil
}
