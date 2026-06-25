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

# Build the frontend, embed into the Go UI server, build UI binary
RUN cd ui/web && npm run build --silent \
 && rm -rf /src/ui/server/static \
 && cp -r /src/ui/web/dist /src/ui/server/static \
 && cd /src/ui/server \
 && go build -buildvcs=false -o /out/fastscan-ui .

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Core runtime: nmap (required), python3 + deps (export scripts)
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      curl \
      ca-certificates \
      git \
      python3 \
      python3-pip \
      imagemagick \
    && pip3 install --no-cache-dir openpyxl Pillow xlsxwriter \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh — needed for TLS vulnerability scans
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
 && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# rustscan — fast port scanner (engine falls back to nmap if absent)
RUN ARCH="$(dpkg --print-architecture)" \
 && curl -sfL "https://github.com/RustScan/RustScan/releases/download/2.4.1/rustscan_2.4.1_${ARCH}.deb" \
      -o /tmp/rustscan.deb \
 && dpkg -i /tmp/rustscan.deb 2>/dev/null || true \
 && rm -f /tmp/rustscan.deb

# Copy binaries from builder
COPY --from=builder /out/fastscan     /opt/fastscan/fastscan
COPY --from=builder /out/fastscan-ui  /opt/fastscan/ui/fastscan-ui

# Copy support files baked into the image
COPY scripts/  /opt/fastscan/scripts/
COPY plugins/  /opt/fastscan/plugins/
COPY creds/    /opt/fastscan/creds/

RUN chmod +x /opt/fastscan/scripts/*.py

# Entrypoint
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# /data is the scan data volume — mount a host directory here to persist results
VOLUME ["/data"]

EXPOSE 8888

ENTRYPOINT ["docker-entrypoint.sh"]
