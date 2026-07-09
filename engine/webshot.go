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
)

// screenshotDir returns the directory where webshot PNGs are written.
// Preference order:
//  1. <scan output dir>/screenshots  — persistent, lives on the /data volume in Docker
//  2. $TMPDIR/fastscan/screenshots   — legacy fallback for standalone engine runs
func screenshotDir() string {
	if flagOut != nil && *flagOut != "" {
		return filepath.Join(*flagOut, "screenshots")
	}
	return filepath.Join(os.TempDir(), "fastscan", "screenshots")
}

// webShotPath derives a safe screenshot output path for a web URL.
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
	dir := screenshotDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		scheme = "http"
	}
	base := fmt.Sprintf("%s_%s_%s", scheme, sanitizeForFilename(host), sanitizeForFilename(port))
	return dir + "/" + base + ".png", nil
}

// addWebURLBar composites a URL bar onto an existing web screenshot PNG using Pillow.
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

    pad_x, pad_y = 8, 4
    bbox = d.textbbox((0, 0), btxt, font=font_b)
    bw = bbox[2] - bbox[0] + pad_x * 2
    bh = bbox[3] - bbox[1] + pad_y * 2
    bx, by = 12, (bar_h - bh) // 2
    d.rounded_rectangle([bx, by, bx + bw, by + bh], radius=4, fill=hex2rgb(bbg))
    d.text((bx + pad_x, by + pad_y), btxt, fill=hex2rgb(bfg), font=font_b)

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

// tlsCertError returns true when the HTTPS endpoint's certificate fails validation.
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
		return true
	}
	conn.Close()
	return false
}

// chromiumBin finds the system chromium binary.
//
// Preference order:
//  1. google-chrome-stable / google-chrome  — deb-installed by our
//     install-prereqs.sh, headless-safe, writes screenshots to arbitrary
//     paths.
//  2. chromium-browser  — Debian/Ubuntu apt package (not snap).
//  3. chromium  — last resort. On Ubuntu this often resolves to
//     /snap/bin/chromium which sandboxes filesystem writes and quietly
//     drops --screenshot to a snap-local dir; if google-chrome or the
//     apt chromium-browser exists we always prefer those.
func chromiumBin() string {
	for _, name := range []string{"google-chrome-stable", "google-chrome", "chromium-browser", "chromium"} {
		if p, err := exec.LookPath(name); err == nil {
			// Skip snap-wrapped binaries when a non-snap alternative
			// might still show up later in the list.
			if strings.HasPrefix(p, "/snap/") && name != "chromium" {
				continue
			}
			return p
		}
	}
	// Fallback: allow snap chromium only if nothing else exists.
	if p, err := exec.LookPath("chromium"); err == nil {
		return p
	}
	return ""
}

// webScreenshot captures a web page as PNG using headless Chromium via exec.
// No playwright/CDN dependency — uses the system chromium package.
func webScreenshot(rawurl, outPath string, timeout time.Duration) error {
	bin := chromiumBin()
	if bin == "" {
		return fmt.Errorf("webshot: chromium not found in PATH")
	}

	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	// chromium --headless writes screenshot.png to the working directory.
	// We use a temp dir so the output path is predictable.
	tmpDir, err := os.MkdirTemp("", "fastscan-webshot-*")
	if err != nil {
		return fmt.Errorf("webshot tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	args := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-setuid-sandbox",
		"--no-zygote",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-software-rasterizer",
		"--ignore-certificate-errors",
		"--window-size=1280,720",
		fmt.Sprintf("--screenshot=%s", outPath),
		fmt.Sprintf("--virtual-time-budget=%d", timeout.Milliseconds()),
		rawurl,
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		// Check if the screenshot was still written despite an error exit
		if _, statErr := os.Stat(outPath); statErr != nil {
			return fmt.Errorf("webshot exec: %w", err)
		}
	}

	if _, err := os.Stat(outPath); err != nil {
		return fmt.Errorf("webshot: screenshot not created at %s", outPath)
	}

	// Burn URL bar onto the PNG with Pillow
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
