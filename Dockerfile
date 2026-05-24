# Stage 1: Build Go binaries
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies in a single layer
RUN apk add --no-cache git=2.47.2-r0 make=4.4.1-r2

# Copy module files first for layer caching
COPY go.mod go.sum ./

# Copy source code
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/
COPY vendor/ ./vendor/

# Build all binaries in a single RUN layer to minimise image layers
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-sonar ./cmd/sonar/ && \
    CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-gateway ./cmd/gateway/ && \
    CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-pentest ./cmd/khepra-pentest/ && \
    CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-motherboard ./cmd/apiserver/ && \
    CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-phantom ./cmd/phantom-node/ && \
    CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-adinkhepra ./cmd/adinkhepra/ && \
    CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-agent ./cmd/agent/ && \
    CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-stig ./cmd/stig-test/

# Stage 2: Minimal runtime image
FROM alpine:3.21 AS runtime

# OCI label required by registry.modelcontextprotocol.io
LABEL io.modelcontextprotocol.server.name="pqc-khepra-mcp"
LABEL io.modelcontextprotocol.server.version="1.0.0"
LABEL org.opencontainers.image.title="KHEPRA MCP Server"
LABEL org.opencontainers.image.description="Sovereign compliance engine: 36195 STIG/CCI/NIST/CMMC mappings. Air-gappable. Zero token costs."
LABEL org.opencontainers.image.source="https://github.com/nouchix/PQC-Khepra-MCP"
LABEL org.opencontainers.image.licenses="LicenseRef-Proprietary"

RUN apk add --no-cache --no-install-recommends ca-certificates=20241121-r1

COPY --from=builder /usr/local/bin/nouchix-* /usr/local/bin/

WORKDIR /var/lib/khepra

ENV KHEPRA_MODE=sovereign
ENV KHEPRA_HOME=/var/lib/khepra
ENV KHEPRA_LOG_DIR=/var/log/khepra

ENTRYPOINT ["/usr/local/bin/nouchix-adinkhepra"]
