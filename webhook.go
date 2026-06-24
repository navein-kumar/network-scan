// webhook.go: POST high/critical findings to a configured URL.
//
// Enabled via -webhook URL. The writer hands every finding that fires
// to PostFinding(); we filter to severity in {critical, high} and POST a
// compact JSON body. Failures log and continue: the scan never blocks
// on a slow webhook endpoint.
//
// Timeout is 5s per request. No retry. No backpressure. The intent is
// "wire it to PagerDuty / Slack / webhook.site for a quick demo," not
// "guaranteed delivery."
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// WebhookClient wraps an http.Client with the destination URL.
type WebhookClient struct {
	URL    string
	client *http.Client
}

// NewWebhookClient returns a client (or nil if url is empty).
func NewWebhookClient(url string) *WebhookClient {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil
	}
	return &WebhookClient{
		URL:    url,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// webhookPayload is the JSON body for one finding.
type webhookPayload struct {
	RuleID     string   `json:"rule_id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Evidence   string   `json:"evidence,omitempty"`
	References []string `json:"references,omitempty"`
	Source     string   `json:"source,omitempty"`
	Timestamp  string   `json:"ts"`
}

// PostFinding fires the webhook if severity is critical or high. Errors
// are logged but never returned: the scan never blocks on this.
func (w *WebhookClient) PostFinding(f PluginFinding) {
	if w == nil {
		return
	}
	sev := strings.ToLower(f.Severity)
	if sev != "critical" && sev != "high" {
		return
	}
	body := webhookPayload{
		RuleID:     f.RuleID,
		Title:      f.Title,
		Severity:   f.Severity,
		Host:       f.Host,
		Port:       f.Port,
		Evidence:   f.Evidence,
		References: f.References,
		Source:     f.Source,
		Timestamp:  f.Timestamp,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		log.Printf("[webhook] marshal: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(raw))
	if err != nil {
		log.Printf("[webhook] new request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fastscan-webhook/1.0")
	resp, err := w.client.Do(req)
	if err != nil {
		log.Printf("[webhook] post %s %s: %v", f.Severity, f.RuleID, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("[webhook] post %s %s: HTTP %d", f.Severity, f.RuleID, resp.StatusCode)
		return
	}
	// Optional: log a quiet success line. Keep it compact so the
	// scan log stays readable.
	log.Printf("[webhook] posted %s %s (%s)", f.Severity, f.RuleID, fmt.Sprintf("HTTP %d", resp.StatusCode))
}
