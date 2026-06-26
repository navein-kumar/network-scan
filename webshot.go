package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/playwright-community/playwright-go"
)

// webShotPath derives a safe screenshot output path for a web URL. It parses the
// host and port and returns /tmp/fastscan/screenshots/web_<host>_<port>.png,
// inferring port 80 for http and 443 for https when none is given. The directory
// is created (mkdir -p) and the host is sanitized so it carries no path
// separators.
func webShotPath(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("webshot: no host in %q", rawurl)
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	dir := filepath.Join(os.TempDir(), "fastscan", "screenshots")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme) // "http" or "https"
	if scheme != "http" && scheme != "https" {
		scheme = "http"
	}
	base := fmt.Sprintf("%s_%s_%s", scheme, sanitizeForFilename(host), sanitizeForFilename(port))
	return dir + "/" + base + ".png", nil
}

// tlsCertError returns true when the HTTPS endpoint's certificate fails
// standard validation (self-signed, expired, hostname mismatch, etc.).
func tlsCertError(rawurl string) bool {
	u, err := url.Parse(rawurl)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 4 * time.Second},
		"tcp", u.Hostname()+":"+port,
		&tls.Config{InsecureSkipVerify: false},
	)
	if err != nil {
		return true // cert error (self-signed, expired, etc.)
	}
	conn.Close()
	return false
}

// webScreenshot is a best-effort grab of a web page into a PNG via playwright-go
// (headless Chromium). It launches and closes the browser per call so no node or
// browser process is left orphaned. Insecure HTTP and bad-cert HTTPS are handled
// (IgnoreHttpsErrors). Navigation errors and timeouts are tolerated: the page is
// still screenshotted on a best-effort basis. If the playwright driver or
// browser is not installed, the launch error is returned and nothing is captured
// (the caller ignores it). The whole capture is bounded by the Goto timeout plus
// the per-call browser close.
func webScreenshot(rawurl, outPath string, timeout time.Duration) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("webshot panic: %v", r)
		}
	}()

	pw, err := playwright.Run()
	if err != nil {
		return fmt.Errorf("webshot run: %w", err)
	}
	defer pw.Stop()

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args:     []string{"--no-sandbox", "--disable-dev-shm-usage"},
	})
	if err != nil {
		return fmt.Errorf("webshot launch: %w", err)
	}
	defer browser.Close()

	page, err := browser.NewPage(playwright.BrowserNewPageOptions{
		IgnoreHttpsErrors: playwright.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("webshot newpage: %w", err)
	}
	defer page.Close()

	// Cap navigation so a hung page cannot block past ~timeout. Goto errors
	// (timeout, TLS, connection reset) are intentionally ignored: we still try
	// to screenshot whatever rendered.
	gotoMS := float64(timeout.Milliseconds())
	if gotoMS <= 0 {
		gotoMS = 15000
	}
	_, _ = page.Goto(rawurl, playwright.PageGotoOptions{
		Timeout:   playwright.Float(gotoMS),
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
	})

	// Determine URL bar icon + label based on scheme and cert validity.
	isHTTPS := strings.HasPrefix(strings.ToLower(rawurl), "https://")
	certErr := isHTTPS && tlsCertError(rawurl)

	var iconHTML, labelHTML string
	switch {
	case !isHTTPS:
		// Plain HTTP — open padlock + "Not Secure" in red
		iconHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f28b82" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`
		labelHTML = `<span style="font:12px/1 Arial,sans-serif;color:#f28b82;margin-right:4px;">Not Secure</span>`
	case certErr:
		// HTTPS with self-signed / invalid cert — warning triangle
		iconHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#fdd663" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
		labelHTML = `<span style="font:12px/1 Arial,sans-serif;color:#fdd663;margin-right:4px;">Certificate Warning</span>`
	default:
		// HTTPS with valid cert — closed green padlock
		iconHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#81c995" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`
		labelHTML = ``
	}

	js := `([url, icon, label]) => {
		const bar = document.createElement('div');
		bar.id = '__fastscan_urlbar__';
		bar.style.cssText = [
			'position:fixed','top:0','left:0','right:0','height:38px',
			'background:#202124','display:flex','align-items:center',
			'padding:0 12px','z-index:2147483647','box-sizing:border-box',
			'box-shadow:0 1px 4px rgba(0,0,0,.5)',
		].join(';');
		const pill = document.createElement('div');
		pill.style.cssText = [
			'flex:1','background:#303134','border-radius:20px',
			'padding:5px 14px','display:flex','align-items:center','gap:6px',
			'overflow:hidden','white-space:nowrap',
		].join(';');
		pill.innerHTML = icon + label +
			'<span style="font:13px/1 Arial,sans-serif;color:#e8eaed;overflow:hidden;text-overflow:ellipsis;">' +
			url.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</span>';
		bar.appendChild(pill);
		const old = document.getElementById('__fastscan_urlbar__');
		if (old) old.remove();
		document.documentElement.prepend(bar);
		const spacer = document.createElement('div');
		spacer.style.cssText = 'height:38px;display:block;';
		if (document.body) document.body.insertAdjacentElement('afterbegin', spacer);
	}`
	_, _ = page.Evaluate(js, []string{rawurl, iconHTML, labelHTML})

	if _, err := page.Screenshot(playwright.PageScreenshotOptions{
		Path: playwright.String(outPath),
	}); err != nil {
		return fmt.Errorf("webshot capture: %w", err)
	}
	return nil
}
