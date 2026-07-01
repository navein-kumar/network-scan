// vaultprobe.go: phase 3 driver for HashiCorp Vault (TCP 8200).
//
// GET /v1/sys/seal-status exposes version, init and seal state without auth.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type VaultReport struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	ProbeError  string `json:"probe_error,omitempty"`
}

func ProbeVault(host string, port int, timeout time.Duration) (*VaultReport, error) {
	rep := &VaultReport{Host: host, Port: port}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s:%d/v1/sys/seal-status", scheme, host, port)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		var data struct {
			Version     string `json:"version"`
			Initialized bool   `json:"initialized"`
			Sealed      bool   `json:"sealed"`
		}
		if err := json.Unmarshal(body, &data); err != nil || data.Version == "" {
			continue
		}
		rep.Product = "vault"
		rep.Version = data.Version
		rep.Initialized = data.Initialized
		rep.Sealed = data.Sealed
		return rep, nil
	}
	rep.ProbeError = "no valid vault /v1/sys/seal-status response"
	return rep, nil
}
