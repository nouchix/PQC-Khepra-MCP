APP?=adinkhepra
AGENT?=adinkhepra-agent
GATEWAY?=khepra-gateway
HUB?=asaf-hub

# UI source and embed target
STARGATE_DIR?=../Adinkhepra-ASAF
HUB_DIST?=cmd/asaf-hub/dist

all: build

# ── ASAF Stargate Hub ──────────────────────────────────────────────────────────
# Full build: Next.js static export → go:embed → asaf-hub binary
.PHONY: build-hub
build-hub:
	@echo "[STARGATE] Building Next.js UI..."
	cd $(STARGATE_DIR) && npm ci && npm run build
	@echo "[STARGATE] Copying static export to embed target..."
	@if exist $(HUB_DIST) rmdir /s /q $(HUB_DIST)
	xcopy /E /I /Q "$(STARGATE_DIR)\out" "$(HUB_DIST)"
	@echo "[STARGATE] Building asaf-hub binary..."
	go build -o bin/$(HUB).exe ./cmd/asaf-hub
	@echo "[STARGATE] bin/$(HUB).exe ready"
	@echo "[STARGATE]   Hub UI:   http://localhost:8443/"
	@echo "[STARGATE]   MCP:      http://localhost:8444/mcp"
	@echo "[STARGATE]   Fleet:    http://localhost:8443/api/v1/fleet/*"

# Quick Go-only build (no UI rebuild — uses existing dist/)
.PHONY: build-hub-go
build-hub-go:
	go build -o bin/$(HUB).exe ./cmd/asaf-hub
	@echo "[STARGATE] bin/$(HUB).exe built (no UI rebuild)"

# Run the hub in development mode (no UI embed, dev placeholder shown)
.PHONY: run-hub
run-hub: build-hub-go
	KHEPRA_MODE=sovereign \
	KHEPRA_HUB_PORT=8443 \
	KHEPRA_MCP_PORT=8444 \
	PHANTOM_SYMBOL=Eban \
	./bin/$(HUB).exe

# Secure (stripped) production build
.PHONY: build-hub-secure
build-hub-secure:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(HUB).exe ./cmd/asaf-hub

# ── ASAF Stargate Reporter (endpoint agent) ────────────────────────────────────
REPORTER?=khepra-reporter

.PHONY: build-reporter
build-reporter:
	go build -o bin/$(REPORTER).exe ./cmd/khepra-reporter
	@echo "[REPORTER] bin/$(REPORTER).exe ready"
	@echo "[REPORTER] Usage:"
	@echo "[REPORTER]   ASAF_HUB_URL=https://asaf.corp.mil:8443 ./bin/$(REPORTER).exe"

.PHONY: build-reporter-secure
build-reporter-secure:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(REPORTER).exe ./cmd/khepra-reporter

# Cross-compile reporter for Linux (for deployment to RHEL/Ubuntu endpoints)
.PHONY: build-reporter-linux
build-reporter-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
		-o bin/$(REPORTER)-linux-amd64 ./cmd/khepra-reporter
	@echo "[REPORTER] Linux binary: bin/$(REPORTER)-linux-amd64"


build:
	go mod tidy
	go build -o bin/$(APP) ./cmd/adinkhepra
	go build -o bin/$(AGENT) ./cmd/agent
	go build -o bin/$(GATEWAY) ./cmd/gateway

run-agent: build
	ADINKHEPRA_AGENT_PORT=45444 ./bin/$(AGENT)

run-gateway: build
	./bin/$(GATEWAY) -addr=:8443 -debug

run-gateway-learning: build
	./bin/$(GATEWAY) -addr=:8443 -debug -learning


secure-build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -mod=vendor -o bin/$(APP).exe ./cmd/adinkhepra
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -mod=vendor -o bin/$(AGENT).exe ./cmd/agent
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -mod=vendor -o bin/$(GATEWAY).exe ./cmd/gateway

# ECR-02: FIPS 140-3 Compliance Build (DoD Iron Bank)
# This builds with BoringCrypto (FIPS-validated cryptography module)
# Required for DoD Platform One deployments
#
# Prerequisites:
#   - gcc installed (for CGO)
#   - Go 1.19+ (BoringCrypto experiment)
#
# Note: BoringCrypto requires CGO_ENABLED=1 and Linux/amd64 target
fips-boring-build:
	@echo "[ADINKHEPRA] Building with BoringCrypto (FIPS 140-3 validated)"
	@echo "[ADINKHEPRA] Target: Linux/amd64 (DoD Platform One)"
	GOOS=linux GOARCH=amd64 GOEXPERIMENT=boringcrypto CGO_ENABLED=1 \
		go build -tags=fips -trimpath \
		-ldflags="-s -w -X main.FIPSMode=required" \
		-o bin/$(APP)-fips ./cmd/adinkhepra
	@echo "[ADINKHEPRA] FIPS build complete: bin/$(APP)-fips"
	@echo "[ADINKHEPRA] Verify with: ADINKHEPRA_FIPS_MODE=true ./bin/$(APP)-fips version"

# Go 1.24+ Native FIPS 140-3 Compliance (GODEBUG method)
# This is the newer approach that doesn't require CGO
# Usage: Set GODEBUG=fips140=on at runtime
fips-build: secure-build
	@echo "[ADINKHEPRA] FIPS-Ready Binaries Built (Go 1.24+ GODEBUG method)"
	@echo "[ADINKHEPRA] To run in FIPS mode: GODEBUG=fips140=on ./bin/$(APP)"
	@echo "[ADINKHEPRA] For DoD Iron Bank, use 'make fips-boring-build' instead"

clean:
	rm -rf bin

test:
	# Run Go tests without using the cache to ensure deterministic runs
	go test -count=1 ./...

ci-test:
	# CI-friendly test runner: vendor-aware and no-cache
	CGO_ENABLED=0 go test -count=1 -mod=vendor ./...

# ============================================================
# CVE Database Management
# ============================================================

CVE_DATA_DIR=data/cve-database/cve-data

# Check if CVE data exists
.PHONY: check-cve
check-cve:
	@if [ ! -d "$(CVE_DATA_DIR)/mitre" ] || [ ! -f "$(CVE_DATA_DIR)/cisa-kev/known_exploited_vulnerabilities.json" ]; then \
		echo "[ADINKHEPRA] CVE data not found. Run 'make fetch-cve' to download."; \
		exit 1; \
	else \
		echo "[ADINKHEPRA] CVE data present."; \
	fi

# Fetch CVE data from all sources
.PHONY: fetch-cve
fetch-cve:
	@echo "[ADINKHEPRA] Fetching CVE data from multiple sources..."
	@cd data/cve-database && bash fetch-cve-data.sh
	@echo "[ADINKHEPRA] CVE data fetch complete."

# Quick CVE update (CISA KEV only - fastest, most critical)
# SOVEREIGN/IRONBANK MODE: This target is BLOCKED. Use 'make bundle-cve' on a
# connected system, transfer the bundle, then extract on the sovereign system.
.PHONY: fetch-cve-quick
fetch-cve-quick:
	@if [ "$(KHEPRA_MODE)" = "sovereign" ] || [ "$(KHEPRA_MODE)" = "ironbank" ]; then \
		echo "[ERROR] fetch-cve-quick blocked: KHEPRA_MODE=$(KHEPRA_MODE) — no outbound network permitted."; \
		echo "[ERROR] To update CVE data for a sovereign system:"; \
		echo "[ERROR]   1. On a connected system: make bundle-cve"; \
		echo "[ERROR]   2. Transfer dist/cve-bundle-*.tar.gz to the sovereign system"; \
		echo "[ERROR]   3. On sovereign system: tar -xzf cve-bundle-*.tar.gz -C data/"; \
		exit 1; \
	fi
	@echo "[ADINKHEPRA] Quick fetch: CISA Known Exploited Vulnerabilities..."
	@mkdir -p $(CVE_DATA_DIR)/cisa-kev
	@curl -sf -o $(CVE_DATA_DIR)/cisa-kev/known_exploited_vulnerabilities.json \
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
		|| (echo "[ERROR] CVE fetch failed — check network connectivity"; exit 1)
	@echo "Last updated: $$(date -u +%Y-%m-%dT%H:%M:%SZ)" > $(CVE_DATA_DIR)/cisa-kev/last-updated.txt
	@echo "[ADINKHEPRA] CISA KEV updated."

# Bundle CVE data for offline / sovereign transfer
# Run on a connected system, then transfer the .tar.gz to sovereign bare metal.
.PHONY: bundle-cve
bundle-cve: check-cve
	@mkdir -p dist
	$(eval BUNDLE_DATE := $(shell date +%Y%m%d))
	@tar -czf dist/cve-bundle-$(BUNDLE_DATE).tar.gz -C data cve-database/
	@sha256sum dist/cve-bundle-$(BUNDLE_DATE).tar.gz > dist/cve-bundle-$(BUNDLE_DATE).tar.gz.sha256
	@echo "[ADINKHEPRA] CVE bundle: dist/cve-bundle-$(BUNDLE_DATE).tar.gz"
	@echo "[ADINKHEPRA] SHA256:     dist/cve-bundle-$(BUNDLE_DATE).tar.gz.sha256"
	@echo "[ADINKHEPRA] Transfer to sovereign system, then:"
	@echo "[ADINKHEPRA]   tar -xzf cve-bundle-$(BUNDLE_DATE).tar.gz -C data/"

# Prepare Docker image + Ollama model bundle for true air-gap transfer.
# Run on a connected system with Docker + Ollama installed.
# Transfer dist/airgap-images-*.tar.gz and dist/airgap-models-*.tar.gz to sovereign system.
.PHONY: airgap-prepare
airgap-prepare:
	@echo "[AIRGAP] Pulling images for offline bundling..."
	@mkdir -p dist
	$(eval BUNDLE_DATE := $(shell date +%Y%m%d))
	docker pull ollama/ollama:latest
	docker pull postgres:16-alpine
	docker pull redis:7-alpine
	docker pull nginx:1.25-alpine
	@echo "[AIRGAP] Saving Docker images to dist/airgap-images-$(BUNDLE_DATE).tar.gz..."
	docker save ollama/ollama:latest postgres:16-alpine redis:7-alpine nginx:1.25-alpine \
		| gzip > dist/airgap-images-$(BUNDLE_DATE).tar.gz
	@echo "[AIRGAP] Pulling Ollama model deepseek-r1 for bundling..."
	ollama pull deepseek-r1
	@echo "[AIRGAP] Bundling Ollama model files..."
	tar -czf dist/airgap-models-$(BUNDLE_DATE).tar.gz -C ~/.ollama models/
	sha256sum dist/airgap-images-$(BUNDLE_DATE).tar.gz dist/airgap-models-$(BUNDLE_DATE).tar.gz \
		> dist/airgap-bundle-$(BUNDLE_DATE).sha256
	@echo "[AIRGAP] Done. Transfer to sovereign system:"
	@echo "[AIRGAP]   docker load < dist/airgap-images-$(BUNDLE_DATE).tar.gz"
	@echo "[AIRGAP]   tar -xzf dist/airgap-models-$(BUNDLE_DATE).tar.gz -C ~/.ollama/"


# Build with CVE data validation
.PHONY: build-with-cve
build-with-cve: fetch-cve-quick build
	@echo "[ADINKHEPRA] Build complete with fresh CVE data."

# Validate build (includes CVE check)
.PHONY: validate
validate: check-cve test
	@echo "[ADINKHEPRA] Validation complete."

# Full CI pipeline with CVE data
.PHONY: ci
ci: fetch-cve-quick ci-test secure-build
	@echo "[ADINKHEPRA] CI pipeline complete."
# Iron Bank Automation (hardening_manifest.yaml)
# Auto-generates the manifest required for DoD container hardening
.PHONY: ironbank
ironbank: fips-boring-build
	@echo "[ADINKHEPRA] Generating Iron Bank Hardening Manifest..."
	@go run tools/gen_manifest.go "v2.0.0" "bin/$(APP)-fips"
	@echo "[ADINKHEPRA] Manifest generated: hardening_manifest.yaml"

# Cross-compilation for khepra-mcp across modular targets (windows, mac, linux, embedded)
.PHONY: cross-compile
cross-compile:
	@echo "[KHEPRA-MCP] Cross-compiling for all target platforms..."
	@mkdir -p bin/release
	# Windows (AMD64)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/release/khepra-mcp-windows-amd64.exe ./cmd/khepra-mcp
	# macOS (Apple Silicon ARM64)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/release/khepra-mcp-darwin-arm64 ./cmd/khepra-mcp
	# macOS (Intel AMD64)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/release/khepra-mcp-darwin-amd64 ./cmd/khepra-mcp
	# Linux (AMD64)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/release/khepra-mcp-linux-amd64 ./cmd/khepra-mcp
	# Linux (ARM64)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/release/khepra-mcp-linux-arm64 ./cmd/khepra-mcp
	# Embedded / IoT (ARMv7)
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/release/khepra-mcp-linux-armv7 ./cmd/khepra-mcp
	# Embedded (RISC-V)
	GOOS=linux GOARCH=riscv64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/release/khepra-mcp-linux-riscv64 ./cmd/khepra-mcp
	@echo "[KHEPRA-MCP] Cross-compilation complete. Binaries saved to bin/release/"

