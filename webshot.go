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
	base := fmt.Sprintf("web_%s_%s", sanitizeForFilename(host), sanitizeForFilename(port))
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

	if _, err := page.Screenshot(playwright.PageScreenshotOptions{
		Path: playwright.String(outPath),
	}); err != nil {
		return fmt.Errorf("webshot capture: %w", err)
	}
	return nil
}
