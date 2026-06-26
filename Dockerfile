# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS builder

# Install Node.js 20 for the React frontend build
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Download Go modules first (cache layer — only re-runs when go.mod/go.sum change)
COPY go.mod go.sum ./
RUN go mod download

# Install frontend deps (cache layer — only re-runs when package-lock.json changes)
COPY ui/web/package*.json ui/web/
RUN cd ui/web && npm ci --silent

# Copy all source
COPY . .

# Build the engine binary
RUN go build -buildvcs=false -o /out/fastscan .

# Write driver count so the UI can report it without source files present
RUN ls *probe.go | grep -v _test | wc -l > /out/drivers.count

# Build the frontend, embed into the Go UI server, build UI binary
RUN cd ui/web && npm run build --silent \
 && rm -rf /src/ui/server/static \
 && cp -r /src/ui/web/dist /src/ui/server/static \
 && cd /src/ui/server \
 && go build -buildvcs=false -o /out/fastscan-ui .

# Install Go-based scanning tools into /out so we can copy them to runtime
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && cp /go/bin/httpx  /out/httpx \
 && cp /go/bin/nuclei /out/nuclei

# Install playwright chromium driver into /out (used by webshot.go)
RUN cd /src && go run github.com/playwright-community/playwright-go/cmd/playwright install chromium \
 && mkdir -p /out/playwright-cache \
 && cp -r /root/.cache/ms-playwright /out/playwright-cache/

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Core runtime packages
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      curl \
      ca-certificates \
      git \
      tmux \
      python3 \
      python3-pip \
      pipx \
      libpcap-dev \
      imagemagick \
      ike-scan \
      vncsnapshot \
    && pip3 install --no-cache-dir openpyxl Pillow \
    && ( apt-get install -y netexec 2>/dev/null \
         || PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install netexec --system-site-packages 2>/dev/null \
         || PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install git+https://github.com/Pennyw0rth/NetExec 2>/dev/null \
         || true ) \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh — needed for TLS vulnerability scans
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
 && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# rustscan — fast port scanner (engine falls back to nmap if absent)
# Try apt first, then GitHub release, then skip (nmap fallback covers it)
RUN apt-get update && \
    ( apt-get install -y --no-install-recommends rustscan 2>/dev/null || \
      ( ARCH="$(dpkg --print-architecture)" && \
        for VER in 2.4.1 2.3.0 2.2.3 2.1.1; do \
          URL="https://github.com/RustScan/RustScan/releases/download/${VER}/rustscan_${VER}_${ARCH}.deb" && \
          curl -sfL --max-time 30 "$URL" -o /tmp/rustscan.deb 2>/dev/null && \
          dpkg -i /tmp/rustscan.deb 2>/dev/null && \
          rm -f /tmp/rustscan.deb && break || rm -f /tmp/rustscan.deb; \
        done ) || true ) && \
    rm -rf /var/lib/apt/lists/*

# scrying — RDP login screen screenshots (optional; best-effort install)
RUN ARCH="$(dpkg --print-architecture)" && \
    for VER in 0.9.1 0.9.0 0.8.0; do \
      URL="https://github.com/nccgroup/scrying/releases/download/v${VER}/scrying_${VER}-1_${ARCH}.deb" && \
      curl -sfL --max-time 30 "$URL" -o /tmp/scrying.deb 2>/dev/null && \
      dpkg -i /tmp/scrying.deb 2>/dev/null && rm -f /tmp/scrying.deb && break || rm -f /tmp/scrying.deb; \
    done; true

# Copy binaries from builder
COPY --from=builder /out/fastscan        /opt/fastscan/fastscan
COPY --from=builder /out/fastscan-ui     /opt/fastscan/ui/fastscan-ui
COPY --from=builder /out/httpx           /usr/local/bin/httpx
COPY --from=builder /out/nuclei          /usr/local/bin/nuclei

COPY --from=builder /out/drivers.count              /opt/fastscan/drivers.count
COPY --from=builder /out/playwright-cache/ms-playwright /root/.cache/ms-playwright

# Copy support files baked into the image
COPY scripts/  /opt/fastscan/scripts/
COPY plugins/  /opt/fastscan/plugins/
COPY creds/    /opt/fastscan/creds/

RUN chmod +x /opt/fastscan/scripts/*.py

# Pull nuclei templates at image build time so first scan doesn't need internet
RUN nuclei -update-templates 2>/dev/null || true

# Entrypoint
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# /data is the scan data volume — mount a host directory here to persist results
VOLUME ["/data"]

EXPOSE 8888

ENTRYPOINT ["docker-entrypoint.sh"]
