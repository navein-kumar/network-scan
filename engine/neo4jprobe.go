// neo4jprobe.go: phase 3 driver for Neo4j graph database (TCP 7474 HTTP).
//
// GET / returns JSON with neo4j_version and neo4j_edition without auth.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Neo4jReport struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	Edition    string `json:"edition,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

func ProbeNeo4j(host string, port int, timeout time.Duration) (*Neo4jReport, error) {
	rep := &Neo4jReport{Host: host, Port: port}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		var data struct {
			Neo4jVersion string `json:"neo4j_version"`
			Neo4jEdition string `json:"neo4j_edition"`
		}
		if err := json.Unmarshal(body, &data); err != nil || data.Neo4jVersion == "" {
			continue
		}
		rep.Product = "neo4j"
		rep.Version = data.Neo4jVersion
		rep.Edition = data.Neo4jEdition
		return rep, nil
	}
	rep.ProbeError = "no valid neo4j response"
	return rep, nil
}
