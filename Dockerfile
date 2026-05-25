# syntax=docker/dockerfile:1
# KHEPRA MCP Server — OCI image for registry.modelcontextprotocol.io
#
# Build:  docker build -t ghcr.io/nouchix/pqc-khepra-mcp:1.0.0 .
# Run:    docker run --rm -i -e KHEPRA_LICENSE_KEY ghcr.io/nouchix/pqc-khepra-mcp:1.0.0

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Build tools
RUN apk add --no-cache git make

# Fetch dependencies before copying source (layer-cache optimisation)
COPY go.mod go.sum ./
RUN GONOSUMCHECK="*" go mod download && go mod verify

# Copy source
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/

ARG VERSION=1.0.0
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown

# Build the MCP binary — single static binary, no CGO
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w \
      -X main.Version=${VERSION} \
      -X main.BuildDate=${BUILD_DATE} \
      -X main.Commit=${VCS_REF}" \
    -o /out/khepra-mcp \
    ./cmd/khepra-mcp

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata curl \
 && addgroup -g 10001 -S khepra \
 && adduser  -u 10001 -S -G khepra -h /var/lib/khepra khepra

WORKDIR /app

COPY --from=builder /out/khepra-mcp /usr/local/bin/khepra-mcp
COPY manifest.json /app/manifest.json

# Data directories (empty at build time; populated via volume or init container)
RUN mkdir -p /var/lib/khepra /var/log/khepra \
 && chown -R khepra:khepra /var/lib/khepra /var/log/khepra

ENV KHEPRA_MANIFEST_PATH=/app/manifest.json
ENV KHEPRA_MODE=sovereign
ENV KHEPRA_HOME=/var/lib/khepra
ENV KHEPRA_LOG_DIR=/var/log/khepra

LABEL org.opencontainers.image.title="KHEPRA MCP Server" \
      org.opencontainers.image.description="Sovereign compliance engine with 36,195 STIG/CCI/NIST/CMMC mappings. Air-gappable. Zero token costs." \
      org.opencontainers.image.url="https://nouchix.com" \
      org.opencontainers.image.source="https://github.com/nouchix/PQC-Khepra-MCP" \
      org.opencontainers.image.licenses="Proprietary" \
      org.opencontainers.image.vendor="NouchiX / SecRed Knowledge Inc." \
      io.modelcontextprotocol.server.name="io.github.nouchix/pqc-khepra-mcp"

USER khepra

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD khepra-mcp --health-check || exit 1

ENTRYPOINT ["/usr/local/bin/khepra-mcp"]
