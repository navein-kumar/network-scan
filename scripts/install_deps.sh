#!/usr/bin/env bash
# install_deps.sh: install every CLI dependency fastscan shells out to.
# Re-runnable. Idempotent. Targets Debian / Ubuntu / Kali. Adjust the
# package manager for other distros.
#
# Usage:
#   sudo bash install_deps.sh
set -u

cyan()  { printf '\033[36m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        red "[!] re-run with sudo (apt + symlink steps need root)"
        exit 1
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

cyan "=== fastscan dependency installer ==="
need_root

# --- nmap -------------------------------------------------------------
if have nmap; then
    green "[+] nmap already installed: $(nmap --version | head -1)"
else
    cyan "[*] installing nmap..."
    apt-get update -qq
    apt-get install -y nmap
fi

# --- rustscan ---------------------------------------------------------
if have rustscan; then
    green "[+] rustscan already installed: $(rustscan --version 2>&1 | head -1)"
else
    cyan "[*] installing rustscan via snap (fastest path)..."
    if have snap; then
        snap install rustscan
    else
        red "[!] snap not available. Install rustscan manually:"
        red "    https://github.com/RustScan/RustScan/releases (cargo install rustscan also works)"
    fi
fi

# --- httpx (optional, also linked in the Go binary) -------------------
if have httpx-pd || have httpx; then
    green "[+] httpx CLI already installed"
else
    cyan "[*] httpx CLI (optional, linked as Go library too): skip or run:"
    echo  "    go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
fi

# --- nuclei CLI (for -update-templates) -------------------------------
if have nuclei; then
    green "[+] nuclei already installed: $(nuclei -version 2>&1 | tail -1)"
else
    cyan "[*] installing nuclei (also runs as linked Go lib, CLI used for -update-templates)..."
    if have go; then
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    else
        red "[!] go toolchain not present. Skipping nuclei CLI install."
    fi
fi

# --- testssl.sh -------------------------------------------------------
if have testssl.sh; then
    green "[+] testssl.sh already installed: $(testssl.sh --version 2>&1 | head -1)"
else
    cyan "[*] installing testssl.sh from upstream..."
    git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh 2>&1 | tail -3
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
    if have testssl.sh; then
        green "[+] testssl.sh installed at /usr/local/bin/testssl.sh"
    else
        red "[!] testssl.sh install failed -- check /opt/testssl.sh"
    fi
fi

# --- nxc / netexec ---------------------------------------------------
if have nxc; then
    green "[+] nxc already installed: $(nxc --version 2>&1 | head -1)"
else
    cyan "[*] installing nxc via pipx..."
    if have pipx; then
        pipx install netexec
    elif have pip3; then
        cyan "    pipx not present, falling back to pip3 --user (consider apt install pipx)"
        pip3 install --user netexec
    else
        red "[!] no pipx / pip3 found. Install manually:"
        red "    apt install pipx && pipx install netexec"
    fi
fi

cyan
cyan "=== done. Verify with: fastscan -check-deps ==="
