// creds.go: default-credential testing layer.
//
// Loads YAML credential lists from a directory (one file per service) at
// startup. For each port whose driver source matches a loaded service,
// fastscan walks the attempt list and records pass/fail per attempt as a
// CredAttempt. The list is appended to the driver report as the
// `cred_attempts` field, and plugin YAML rules can then fire on it via
// the standard expr engine.
//
// Per-protocol authentication primitives live in credsauth.go. This file
// just owns the loader + dispatcher.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CredAttempt is one user:pass attempt against one host:port.
// Embedded into each driver report as cred_attempts.
type CredAttempt struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// credAttempt is the on-disk YAML schema (lowercase keys).
type credAttempt struct {
	User string `yaml:"user"`
	Pass string `yaml:"pass"`
}

// credFile is one creds/<service>.yaml file.
type credFile struct {
	Service  string        `yaml:"service"`
	Attempts []credAttempt `yaml:"attempts"`
}

// CredStore holds loaded credential lists keyed by service name. Match
// these against driver source names (ssh, ftp, mssql, mysql,
// postgresql, redis, winrm).
type CredStore struct {
	byService map[string][]credAttempt
}

// LoadCreds walks dir for *.yaml files and parses each one. Empty dir
// returns an empty store. Errors on individual files are logged but do
// not fail the whole load.
func LoadCreds(dir string) (*CredStore, error) {
	store := &CredStore{byService: map[string][]credAttempt{}}
	if dir == "" {
		return store, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		// missing dir = empty store, not an error
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("creds dir %q is not a directory", dir)
	}
	err = filepath.Walk(dir, func(path string, fi os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if fi.IsDir() {
			return nil
		}
		low := strings.ToLower(path)
		if !strings.HasSuffix(low, ".yaml") && !strings.HasSuffix(low, ".yml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[creds] read %s: %v", path, err)
			return nil
		}
		var f credFile
		if err := yaml.Unmarshal(raw, &f); err != nil {
			log.Printf("[creds] parse %s: %v", path, err)
			return nil
		}
		if f.Service == "" || len(f.Attempts) == 0 {
			return nil
		}
		store.byService[f.Service] = append(store.byService[f.Service], f.Attempts...)
		return nil
	})
	return store, err
}

// HasCreds reports whether any attempts are loaded for service.
func (s *CredStore) HasCreds(service string) bool {
	return s != nil && len(s.byService[service]) > 0
}

// Counts returns attempt-count by service for startup logging.
func (s *CredStore) Counts() map[string]int {
	out := map[string]int{}
	if s == nil {
		return out
	}
	for svc, attempts := range s.byService {
		out[svc] = len(attempts)
	}
	return out
}

// TryCreds dispatches to the per-service auth function. Returns one
// CredAttempt per loaded attempt for that service. Empty result means no
// creds loaded or service unsupported.
//
// The per-attempt timeout is short so a large list does not blow the
// scan budget. We also stop after the first successful authentication:
// no point hammering further once we have a working set.
func (s *CredStore) TryCreds(service, host string, port int) []CredAttempt {
	if !s.HasCreds(service) {
		return nil
	}
	attempts := s.byService[service]
	const perTry = 5 * time.Second
	var out []CredAttempt
	for _, a := range attempts {
		ca := CredAttempt{Host: host, Port: port, User: a.User, Pass: a.Pass}
		var err error
		switch service {
		case "ssh":
			err = tryCredsSSH(host, port, a.User, a.Pass, perTry)
		case "ftp":
			err = tryCredsFTP(host, port, a.User, a.Pass, perTry)
		case "mssql":
			err = tryCredsMSSQL(host, port, a.User, a.Pass, perTry)
		case "mysql":
			err = tryCredsMySQL(host, port, a.User, a.Pass, perTry)
		case "postgresql":
			err = tryCredsPostgreSQL(host, port, a.User, a.Pass, perTry)
		case "redis":
			err = tryCredsRedis(host, port, a.User, a.Pass, perTry)
		case "winrm":
			err = tryCredsWinRM(host, port, a.User, a.Pass, perTry)
		default:
			// Unsupported service - skip silently.
			return out
		}
		if err == nil {
			ca.Success = true
		} else {
			ca.Error = err.Error()
		}
		out = append(out, ca)
		if ca.Success {
			// First success is enough; don't waste cycles.
			break
		}
	}
	return out
}
