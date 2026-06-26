package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
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

// addWebURLBar composites a URL bar (badge + URL text) onto an existing web
// screenshot PNG using Pillow. The bar is prepended above the page content so
// it is always visible regardless of the page's CSS or DOM structure.
func addWebURLBar(pngPath, rawurl, badgeText, badgeBg, badgeFg string) {
	py, err := exec.LookPath("python3")
	if err != nil {
		if py, err = exec.LookPath("python"); err != nil {
			return
		}
	}
	script := `
import sys
try:
    from PIL import Image, ImageDraw, ImageFont

    png, url, btxt, bbg, bfg = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]

    def hex2rgb(h):
        h = h.lstrip('#')
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    img = Image.open(png).convert("RGB")
    bar_h = 40
    new = Image.new("RGB", (img.width, img.height + bar_h), (32, 33, 36))
    new.paste(img, (0, bar_h))
    d = ImageDraw.Draw(new)
    d.rectangle([0, 0, img.width, bar_h - 1], fill=(32, 33, 36))

    try:
        font_b = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 11)
        font   = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
    except Exception:
        font_b = font = ImageFont.load_default()

    # Draw badge
    pad_x, pad_y = 8, 4
    bbox = d.textbbox((0, 0), btxt, font=font_b)
    bw = bbox[2] - bbox[0] + pad_x * 2
    bh = bbox[3] - bbox[1] + pad_y * 2
    bx, by = 12, (bar_h - bh) // 2
    d.rounded_rectangle([bx, by, bx + bw, by + bh], radius=4, fill=hex2rgb(bbg))
    d.text((bx + pad_x, by + pad_y), btxt, fill=hex2rgb(bfg), font=font_b)

    # Draw URL
    url_x = bx + bw + 10
    d.text((url_x, (bar_h - 13) // 2), url, fill=(232, 234, 237), font=font)

    new.save(png)
except Exception:
    sys.exit(0)
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, py, "-c", script, pngPath, rawurl, badgeText, badgeBg, badgeFg).Run()
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
		Viewport: &playwright.Size{Width: 1280, Height: 720},
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

	// Capture the page as-is — no JS injection (fragile on pages that use
	// CSS transforms, full-viewport overlays, or post-DOMContentLoaded redirects).
	if _, err := page.Screenshot(playwright.PageScreenshotOptions{
		Path:     playwright.String(outPath),
		FullPage: playwright.Bool(false),
	}); err != nil {
		return fmt.Errorf("webshot capture: %w", err)
	}

	// Burn URL bar onto the PNG with Pillow after capture — always visible
	// regardless of the page's DOM/CSS, same approach as RDP/VNC labels.
	isHTTPS := strings.HasPrefix(strings.ToLower(rawurl), "https://")
	certErr := isHTTPS && tlsCertError(rawurl)

	var badgeText, badgeBg, badgeFg string
	switch {
	case !isHTTPS:
		badgeText, badgeBg, badgeFg = "NOT SECURE", "#c62828", "#ffffff"
	case certErr:
		badgeText, badgeBg, badgeFg = "CERT WARNING", "#f57f17", "#ffffff"
	default:
		badgeText, badgeBg, badgeFg = "HTTPS", "#1b5e20", "#ffffff"
	}
	addWebURLBar(outPath, rawurl, badgeText, badgeBg, badgeFg)
	return nil
}
