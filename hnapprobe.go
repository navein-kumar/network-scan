// hnapprobe.go: phase 3 driver for HNAP1 (D-Link / Cisco home routers, /HNAP1/).
//
// stdlib HTTP POST /HNAP1/ with a GetDeviceSettings SOAP envelope and parse
// the response for ModelName, FirmwareVersion, DeviceName.
package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type HNAPReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Reachable       bool     `json:"reachable"`
	ModelName       string   `json:"model_name,omitempty"`
	FirmwareVersion string   `json:"firmware_version,omitempty"`
	DeviceName      string   `json:"device_name,omitempty"`
	VendorName      string   `json:"vendor_name,omitempty"`
	ProbeErrors     []string `json:"probe_errors,omitempty"`
}

const hnapBody = `<?xml version="1.0" encoding="utf-8"?>` +
	`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
	`<soap:Body><GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/"/>` +
	`</soap:Body></soap:Envelope>`

var (
	hnapModelRE    = regexp.MustCompile(`(?is)<ModelName>([^<]+)</ModelName>`)
	hnapFirmwareRE = regexp.MustCompile(`(?is)<FirmwareVersion>([^<]+)</FirmwareVersion>`)
	hnapDeviceRE   = regexp.MustCompile(`(?is)<DeviceName>([^<]+)</DeviceName>`)
	hnapVendorRE   = regexp.MustCompile(`(?is)<VendorName>([^<]+)</VendorName>`)
)

func ProbeHNAP(host string, port int, timeout time.Duration) (*HNAPReport, error) {
	rep := &HNAPReport{Host: host, Port: port}
	cli := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
	url := fmt.Sprintf("http://%s:%d/HNAP1/", host, port)
	req, err := http.NewRequest("POST", url, strings.NewReader(hnapBody))
	if err != nil {
		return rep, err
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("SOAPAction", `"http://purenetworks.com/HNAP1/GetDeviceSettings"`)
	resp, err := cli.Do(req)
	if err != nil {
		return rep, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	s := string(body)
	// Require a concrete HNAP response element, not just an echo of the
	// request path or namespace. Routers that actually speak HNAP wrap
	// the body in <GetDeviceSettingsResponse>, <ModelName>, etc.
	isHNAP := resp.StatusCode == 200 &&
		(strings.Contains(s, "GetDeviceSettingsResponse") ||
			strings.Contains(s, "<ModelName>") ||
			strings.Contains(s, "<FirmwareVersion>") ||
			strings.Contains(s, "<DeviceName>"))
	if !isHNAP {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("status=%d (no HNAP elements)", resp.StatusCode))
		return rep, nil
	}
	rep.Reachable = true
	if m := hnapModelRE.FindStringSubmatch(s); len(m) > 1 {
		rep.ModelName = strings.TrimSpace(m[1])
	}
	if m := hnapFirmwareRE.FindStringSubmatch(s); len(m) > 1 {
		rep.FirmwareVersion = strings.TrimSpace(m[1])
	}
	if m := hnapDeviceRE.FindStringSubmatch(s); len(m) > 1 {
		rep.DeviceName = strings.TrimSpace(m[1])
	}
	if m := hnapVendorRE.FindStringSubmatch(s); len(m) > 1 {
		rep.VendorName = strings.TrimSpace(m[1])
	}
	return rep, nil
}
