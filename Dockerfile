# Stage 1: Build NouchiX Tactical Arsenal (Go)
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy Go module files
COPY go.mod go.sum ./

# Copy source code with internal packages
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/
COPY vendor/ ./vendor/ 

# Build the Full Tactical Suite
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-sonar ./cmd/sonar/
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-gateway ./cmd/gateway/
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-pentest ./cmd/khepra-pentest/
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-motherboard ./cmd/apiserver/
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-phantom ./cmd/phantom-node/
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-adinkhepra ./cmd/adinkhepra/
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-agent ./cmd/agent/
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-stig ./cmd/stig-test/
RUN CGO_ENABLED=0 go build -mod=vendor -o /usr/local/bin/nouchix-client ./cmd/khepra-client/

# Stage 2: Runtime Environment (Python + Khepra)
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
# curl: for healthcheck
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python requirements
COPY services/ml_anomaly/requirements.txt /app/requirements.txt

# Install PyTorch CPU from dedicated index and other dependencies
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir \
    -r requirements.txt \
    reportlab \
    websockets \
    pydantic-settings && \
    mkdir -p /app/data/cyber_brain /app/models /app/top_secret_intel

# Copy NouchiX Tactical Suite from builder
COPY --from=builder /usr/local/bin/nouchix-* /usr/local/bin/
# Symlink for backward compatibility if needed
RUN ln -s /usr/local/bin/nouchix-sonar /usr/local/bin/khepra && \
    ln -s /usr/local/bin/nouchix-gateway /usr/local/bin/khepra-gateway

# Copy entrypoint script, set permissions, and create non-root user
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && \
    useradd -m -u 1000 khepra && \
    mkdir -p models && touch models/.keep && \
    mkdir -p top_secret_intel && touch top_secret_intel/.keep && \
    chown -R khepra:khepra /app

# Copy application code
COPY services/ml_anomaly /app/services/ml_anomaly
COPY models /app/models
COPY top_secret_intel /app/top_secret_intel

# Switch to non-root user
USER khepra

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Run the application
CMD ["/app/entrypoint.sh"]
