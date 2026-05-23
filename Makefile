APP?=adinkhepra
AGENT?=adinkhepra-agent
GATEWAY?=khepra-gateway

all: build

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
.PHONY: fetch-cve-quick
fetch-cve-quick:
	@echo "[ADINKHEPRA] Quick fetch: CISA Known Exploited Vulnerabilities..."
	@mkdir -p $(CVE_DATA_DIR)/cisa-kev
	@curl -s -o $(CVE_DATA_DIR)/cisa-kev/known_exploited_vulnerabilities.json \
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	@echo "Last updated: $$(date)" > $(CVE_DATA_DIR)/cisa-kev/last-updated.txt
	@echo "[ADINKHEPRA] CISA KEV updated."

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
	@go run tools/gen_manifest.go "v1.0.0" "bin/$(APP)-fips"
	@echo "[ADINKHEPRA] Manifest generated: hardening_manifest.yaml"
