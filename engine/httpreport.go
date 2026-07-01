// httpreport.go: HTTP result -> plugin-engine source.
//
// The httpx phase (main.go) produces Finding rows but never runs HTTP
// results through the YAML plugin engine, so version-based HTTP rules
// (source: http) could never fire. This file defines the HTTPReport
// struct that the engine evaluates, a server-header parser that splits
// the raw Server/webserver string into product + version, and a minimal
// standalone probe wired to the -http-test flag (mirroring the other
// -X-test handlers).
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// HTTPReport is the "http" source report fed to PluginEngine.Evaluate.
// Field names (json tags) are the contract referenced by http plugin
// rules' when: / evidence: expressions. host + port populate the
// PluginFinding Host/Port (Evaluate reads env["host"]/env["port"]).
type HTTPReport struct {
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Server        string   `json:"server"`         // raw Server/webserver header
	ServerProduct string   `json:"server_product"` // parsed product, e.g. "Apache"
	ServerVersion string   `json:"server_version"` // parsed version, e.g. "2.4.52"
	OpenSSL       string   `json:"openssl,omitempty"`
	Tech          []string `json:"tech,omitempty"`
}

// parseServerHeader splits a raw Server header into a primary product and
// version. Typical forms: "Apache/2.4.52 (Ubuntu)", "nginx/1.18.0",
// "Microsoft-IIS/10.0", "lighttpd/1.4.55 OpenSSL/1.1.1f". The primary
// product/version come from the first "name/version" token. If an
// OpenSSL/x token appears anywhere it is captured separately.
func parseServerHeader(server string) (product, version, openssl string) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", "", ""
	}
	for _, tok := range strings.Fields(server) {
		name, ver, ok := splitNameVersion(tok)
		if !ok {
			continue
		}
		if product == "" {
			product, version = name, ver
		}
		if openssl == "" && strings.EqualFold(name, "OpenSSL") {
			openssl = ver
		}
	}
	return product, version, openssl
}

// splitNameVersion splits a single "name/version" token. Returns ok=false
// when the token has no '/' or an empty name/version.
func splitNameVersion(tok string) (name, version string, ok bool) {
	i := strings.IndexByte(tok, '/')
	if i <= 0 || i >= len(tok)-1 {
		return "", "", false
	}
	return tok[:i], tok[i+1:], true
}

// hostPortFromURL derives host + port from an httpx URL, defaulting to
// the scheme's standard port when the URL omits one.
func hostPortFromURL(raw string) (host string, port int) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0
	}
	host = u.Hostname()
	if ps := u.Port(); ps != "" {
		port, _ = strconv.Atoi(ps)
		return host, port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return host, 443
	}
	return host, 80
}

// techProductPriority lists products we want to surface from httpx tech
// fingerprints when the Server: header doesn't identify the product.
// Order matters: first match wins.
var techProductPriority = []string{
	"php", "wordpress", "drupal", "joomla",
	"jenkins", "grafana", "elasticsearch", "kibana",
	"jira", "confluence", "gitlab", "django",
	"rails", "spring", "struts",
}

// parseTechProduct scans httpx Wappalyzer tech entries (format "Product"
// or "Product:version") and returns the first product+version that matches
// the priority list. Used as fallback when the Server: header is absent.
func parseTechProduct(tech []string) (product, version string) {
	for _, t := range tech {
		// normalise "Product:version" → "Product/version" for splitNameVersion
		norm := strings.Replace(t, ":", "/", 1)
		name, ver, ok := splitNameVersion(norm)
		if !ok {
			name = t
		}
		lower := strings.ToLower(name)
		for _, p := range techProductPriority {
			if lower == p || strings.HasPrefix(lower, p) {
				display := strings.ToUpper(name[:1]) + name[1:]
				return display, ver
			}
		}
	}
	return "", ""
}

// buildHTTPReport assembles an HTTPReport from a parsed httpx NDJSON
// record. It mirrors the field reads used to build the Finding in the
// httpx phase, then parses the Server header into product/version.
// If the Server header is absent it falls back to Wappalyzer tech fingerprints.
func buildHTTPReport(rec map[string]any) HTTPReport {
	var rep HTTPReport
	if v, ok := rec["url"].(string); ok {
		rep.URL = v
		rep.Host, rep.Port = hostPortFromURL(v)
	}
	if v, ok := rec["title"].(string); ok {
		rep.Title = v
	}
	if v, ok := rec["webserver"].(string); ok {
		rep.Server = v
	}
	if v, ok := rec["status_code"].(float64); ok {
		rep.StatusCode = int(v)
	}
	if v, ok := rec["tech"].([]any); ok {
		for _, t := range v {
			if s, ok := t.(string); ok {
				rep.Tech = append(rep.Tech, s)
			}
		}
	}
	rep.ServerProduct, rep.ServerVersion, rep.OpenSSL = parseServerHeader(rep.Server)
	// Fallback: if Server: header gave no product, try tech fingerprints.
	if rep.ServerProduct == "" {
		rep.ServerProduct, rep.ServerVersion = parseTechProduct(rep.Tech)
	}
	// Also try X-Powered-By / response_header map from httpx JSON.
	if rep.ServerProduct == "" {
		if hdr, ok := rec["response_header"].(map[string]any); ok {
			rep.ServerProduct, rep.ServerVersion = parseExtraHeaders(hdr)
		}
	}
	return rep
}

// parseExtraHeaders extracts product/version from non-standard response
// headers that identify the application platform.
func parseExtraHeaders(hdr map[string]any) (product, version string) {
	get := func(key string) string {
		if v, ok := hdr[strings.ToLower(key)].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	// X-Jenkins: 2.504 (Jenkins CI)
	if v := get("x-jenkins"); v != "" {
		return "Jenkins", v
	}
	// X-Grafana-Version: 11.6.1
	if v := get("x-grafana-version"); v != "" {
		return "Grafana", v
	}
	// X-Influxdb-Version: 2.7.10  (InfluxDB /ping endpoint)
	if v := get("x-influxdb-version"); v != "" {
		return "InfluxDB", v
	}
	// X-Powered-By: PHP/8.3.2  or  ASP.NET
	if v := get("x-powered-by"); v != "" {
		name, ver, ok := splitNameVersion(strings.Fields(v)[0])
		if ok {
			return name, ver
		}
	}
	// X-Generator: Drupal 10 (https://www.drupal.org)
	if v := get("x-generator"); v != "" {
		fields := strings.Fields(v)
		if len(fields) >= 2 {
			return fields[0], fields[1]
		}
	}
	return "", ""
}

// probeHTTPReport is a minimal best-effort HTTP probe for the standalone
// -http-test path. It issues a single GET (https first on 443, else http),
// reading the Server header and key product-identifying response headers.
// Failures are non-fatal: an empty/partial report is returned.
func probeHTTPReport(host string, port int, timeout time.Duration) HTTPReport {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	target := scheme + "://" + host + ":" + strconv.Itoa(port) + "/"
	rep := HTTPReport{Host: host, Port: port, URL: target}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(target)
	if err != nil {
		if scheme == "http" {
			alt := "https://" + host + ":" + strconv.Itoa(port) + "/"
			if resp2, err2 := client.Get(alt); err2 == nil {
				rep.URL = alt
				resp = resp2
			}
		}
		if resp == nil {
			return rep
		}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	rep.StatusCode = resp.StatusCode
	rep.Server = strings.TrimSpace(resp.Header.Get("Server"))
	rep.ServerProduct, rep.ServerVersion, rep.OpenSSL = parseServerHeader(rep.Server)
	// Fallback: check product-identifying response headers.
	if rep.ServerProduct == "" {
		hdrMap := map[string]any{}
		for k, vv := range resp.Header {
			if len(vv) > 0 {
				hdrMap[strings.ToLower(k)] = vv[0]
			}
		}
		rep.ServerProduct, rep.ServerVersion = parseExtraHeaders(hdrMap)
	}
	return rep
}

// runHTTPTest is the standalone -http-test handler, mirroring the other
// -X-test drivers: probe host:port, print the HTTPReport JSON, then run
// it through the plugin engine for source "http".
func runHTTPTest(target string) {
	host, port, err := splitHostPort(target)
	if err != nil {
		log.Fatalf("http-test target %q: %v", target, err)
	}
	start := time.Now()
	rep := probeHTTPReport(host, port, 8*time.Second)
	dur := time.Since(start)
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "\n=== HTTP probe %s done in %s ===\n", target, dur)
	evalPluginsAndPrint("http", rep)
}
