// couchdbprobe.go: phase 3 driver for Apache CouchDB (5984).
//
// stdlib HTTP. GET / returns {"couchdb":"Welcome","version":"X.Y.Z"}.
// GET /_all_dbs returns the database list if no auth is required.
// "Admin party" mode = anonymous + read of /_all_dbs returns the list.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type CouchDBReport struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Reachable      bool     `json:"reachable"`
	Version        string   `json:"version,omitempty"`
	AllDBs         []string `json:"all_dbs,omitempty"`
	AdminPartyMode bool     `json:"admin_party_mode"`
	ProbeErrors    []string `json:"probe_errors,omitempty"`
}

func ProbeCouchDB(host string, port int, timeout time.Duration) (*CouchDBReport, error) {
	rep := &CouchDBReport{Host: host, Port: port}
	cli := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
	base := fmt.Sprintf("http://%s:%d", host, port)

	resp, err := cli.Get(base + "/")
	if err != nil {
		return rep, fmt.Errorf("get /: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var welcome struct {
		Couchdb string `json:"couchdb"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &welcome); err == nil && welcome.Couchdb == "Welcome" {
		rep.Reachable = true
		rep.Version = welcome.Version
	}
	if !rep.Reachable {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("/ status=%d", resp.StatusCode))
		return rep, nil
	}

	// /_all_dbs : if 200 + JSON array, no-auth read.
	aresp, aerr := cli.Get(base + "/_all_dbs")
	if aerr != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("get /_all_dbs: %v", aerr))
		return rep, nil
	}
	defer aresp.Body.Close()
	abody, _ := io.ReadAll(io.LimitReader(aresp.Body, 1<<20))
	if aresp.StatusCode == 200 {
		var dbs []string
		if err := json.Unmarshal(abody, &dbs); err == nil {
			rep.AllDBs = dbs
			rep.AdminPartyMode = true
		}
	}
	return rep, nil
}
