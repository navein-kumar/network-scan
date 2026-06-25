package main

import (
	"fmt"
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

	// Inject a Chrome-style address bar so the URL is visible in the screenshot.
	js := `(url) => {
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
			'padding:5px 14px','display:flex','align-items:center','gap:7px',
			'overflow:hidden','white-space:nowrap','text-overflow:ellipsis',
		].join(';');
		pill.innerHTML = '<span style="font:13px/1 Arial,sans-serif;color:#bdc1c6;">&#128274;</span>' +
			'<span style="font:13px/1 Arial,sans-serif;color:#e8eaed;overflow:hidden;text-overflow:ellipsis;">' +
			url.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</span>';
		bar.appendChild(pill);
		// Remove any previous injection (re-used page safety).
		const old = document.getElementById('__fastscan_urlbar__');
		if (old) old.remove();
		document.documentElement.prepend(bar);
		// Shift page body down so bar does not overlap real content.
		const spacer = document.createElement('div');
		spacer.style.cssText = 'height:38px;display:block;';
		if (document.body) document.body.insertAdjacentElement('afterbegin', spacer);
	}`
	_, _ = page.Evaluate(js, rawurl)

	if _, err := page.Screenshot(playwright.PageScreenshotOptions{
		Path: playwright.String(outPath),
	}); err != nil {
		return fmt.Errorf("webshot capture: %w", err)
	}
	return nil
}
