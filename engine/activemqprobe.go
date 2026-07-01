// activemqprobe.go: phase 3 driver for Apache ActiveMQ (TCP 8161 HTTP console).
//
// GET /api/jolokia/version returns product + version via the embedded Jolokia
// agent. Works with ActiveMQ Classic 5.x/6.x and ActiveMQ Artemis 2.x.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type ActiveMQReport struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

func ProbeActiveMQ(host string, port int, timeout time.Duration) (*ActiveMQReport, error) {
	rep := &ActiveMQReport{Host: host, Port: port}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s:%d/api/jolokia/version", scheme, host, port)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		var data struct {
			Value struct {
				Info struct {
					Version string `json:"version"`
					Product string `json:"product"`
				} `json:"info"`
			} `json:"value"`
			Status int `json:"status"`
		}
		if err := json.Unmarshal(body, &data); err != nil || data.Value.Info.Version == "" {
			continue
		}
		rep.Product = "activemq"
		if data.Value.Info.Product != "" {
			rep.Product = data.Value.Info.Product
		}
		rep.Version = data.Value.Info.Version
		return rep, nil
	}
	rep.ProbeError = "no valid activemq jolokia response"
	return rep, nil
}
