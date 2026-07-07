# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS builder

# Install Node.js 20 for the React frontend build
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Go module cache (only re-runs when go.mod/go.sum change)
COPY engine/go.mod engine/go.sum engine/
RUN cd engine && go mod download

# Engine source only — cached independently from UI/scripts/README changes
COPY engine/ engine/
RUN cd engine && go build -buildvcs=false -o /out/fastscan .

# Frontend dep cache (only re-runs when package-lock.json changes)
COPY ui/web/package*.json ui/web/
RUN cd ui/web && npm ci --silent

# UI source + remaining files
COPY . .

# Write driver count so the UI can report it without source files present
RUN ls engine/*probe.go | grep -v _test | wc -l > /out/drivers.count

# Build the frontend, embed into the Go UI server, build UI binary
RUN cd ui/web && npm run build --silent \
 && rm -rf /src/ui/server/static \
 && cp -r /src/ui/web/dist /src/ui/server/static \
 && cd /src/ui/server \
 && go build -buildvcs=false -o /out/fastscan-ui .

# Install Go-based scanning tools into /out so we can copy them to runtime
RUN cd engine && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest \
 && cp /go/bin/httpx   /out/httpx \
 && cp /go/bin/nuclei  /out/nuclei \
 && cp /go/bin/cvemap  /out/cvemap

# Install playwright chromium driver into /out (used by webshot.go) — optional
RUN cd /src/engine && go run github.com/playwright-community/playwright-go/cmd/playwright install chromium \
 && cp -r /root/.cache/ms-playwright /out/playwright-cache/ \
 || mkdir -p /out/playwright-cache/ms-playwright

# ── Stage 2: nxc builder (Ubuntu 22.04 = same Python 3.10 as runtime) ───────
# NetExec (nxc) requires Rust (aardwolf dep) and poetry build system.
# We build it here in an isolated venv then copy only /opt/nxc-env to runtime.
FROM ubuntu:22.04 AS nxc-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv git \
      rustc cargo libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/nxc-env \
 && /opt/nxc-env/bin/pip install --quiet --upgrade pip wheel \
 && git clone --depth 1 https://github.com/Pennyw0rth/NfsClient /tmp/nfsclient \
 && /opt/nxc-env/bin/pip install --quiet /tmp/nfsclient \
 && git clone --depth 1 https://github.com/Pennyw0rth/NetExec /tmp/netexec \
 && cd /tmp/netexec \
 && /opt/nxc-env/bin/pip install --quiet . \
 && test -f /opt/nxc-env/bin/nxc \
 && rm -rf /tmp/nfsclient /tmp/netexec

# ── Stage 3: runtime ────────────────────────────────────────────────────────
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
      libpcap-dev \
      ike-scan \
      bsdmainutils \
      fonts-dejavu-core \
    && pip3 install --no-cache-dir openpyxl Pillow \
    && rm -rf /var/lib/apt/lists/*

# nxc/netexec — copied from nxc-builder stage (avoids Rust toolchain in runtime)
COPY --from=nxc-builder /opt/nxc-env /opt/nxc-env
RUN ln -sf /opt/nxc-env/bin/nxc /usr/local/bin/nxc \
 && ln -sf /opt/nxc-env/bin/nxc /usr/local/bin/netexec

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

# scrying — RDP/VNC screenshots. v0.9.2 needs libssl1.1 (Ubuntu 22.04 ships libssl3).
RUN ARCH="$(dpkg --print-architecture)" && \
    curl -fsSL "http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_${ARCH}.deb" \
      -o /tmp/libssl1.1.deb && dpkg -i /tmp/libssl1.1.deb && rm -f /tmp/libssl1.1.deb || true
RUN ARCH="$(dpkg --print-architecture)" && \
    URL="https://github.com/nccgroup/scrying/releases/download/v0.9.2/scrying_0.9.2_${ARCH}.deb" && \
    curl -fsSL --max-time 60 "$URL" -o /tmp/scrying.deb && \
    dpkg -i /tmp/scrying.deb && rm -f /tmp/scrying.deb || true

# Default runtime credentials — override with -e UI_PASS=... at docker run time
ENV UI_USER=admin \
    UI_PASS=NetworkScan@2026 \
    UI_ADDR=0.0.0.0:8888 \
    UI_DATA_DIR=/data

# Copy binaries from builder
COPY --from=builder /out/fastscan        /opt/fastscan/fastscan
COPY --from=builder /out/fastscan-ui     /opt/fastscan/ui/fastscan-ui
COPY --from=builder /out/httpx           /usr/local/bin/httpx
COPY --from=builder /out/nuclei          /usr/local/bin/nuclei
COPY --from=builder /out/cvemap          /usr/local/bin/cvemap

COPY --from=builder /out/drivers.count              /opt/fastscan/drivers.count
COPY --from=builder /out/playwright-cache/ /root/.cache/ms-playwright/

# Copy support files baked into the image (dev-only scripts excluded via .dockerignore)
ARG CACHEBUST=1
COPY scripts/          /opt/fastscan/scripts/
COPY engine/plugins/   /opt/fastscan/engine/plugins/
COPY engine/creds/     /opt/fastscan/creds/

RUN chmod +x /opt/fastscan/scripts/*.py \
 && pip3 install --no-cache-dir PyYAML \
 && rm -f /opt/fastscan/scripts/nasl_to_rules.py \
           /opt/fastscan/scripts/audit.sh \
           /opt/fastscan/scripts/install_deps.sh \
           /opt/fastscan/scripts/smoke_tls_test.sh \
           /opt/fastscan/scripts/requirements.txt

# Pull nuclei templates to /tmp/all-tpl/ — the engine's default templates path
RUN nuclei -update-templates 2>/dev/null; \
    mkdir -p /tmp/all-tpl && \
    cp -rn /root/nuclei-templates/. /tmp/all-tpl/ 2>/dev/null; \
    touch /tmp/all-tpl/.nuclei-last-update || true

# Entrypoint
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# /data is the scan data volume — mount a host directory here to persist results
VOLUME ["/data"]

EXPOSE 8888

ENTRYPOINT ["docker-entrypoint.sh"]
