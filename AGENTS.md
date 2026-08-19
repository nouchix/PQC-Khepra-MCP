# PQC-Khepra-MCP — Agent Trajectory & Architectural Boundary

You are working in **`PQC-Khepra-MCP`**: the open-source, public Model Context Protocol (MCP) server kernel carrying post-quantum cryptographic (PQC) primitives and DoD compliance tools.

## Architectural Boundaries & Rules

1. **Public Open-Source Scope**:
   - Contains open-source PQC algorithms (`pkg/adinkra`), DoD PQC STIG (`pqc_stig`), OWASP Agent Assessment, NIST SP 800-53 mapping, and basic asset discovery tools.
   - Licensed under Apache 2.0.

2. **Strict Dependency Boundary**:
   - **This repo NEVER imports `khepra-trust-os`**.
   - `khepra-trust-os` is the private commercial monorepo and landing zone that imports this public kernel as a Go module.
   - Do not add dependencies pointing to private repositories.

3. **Licensing & Tool Tiers**:
   - Community Tier tools (`pqc_stig`, `nist_map`, `owasp_agent_assess`, `agent_record`) require no key ($0/mo).
   - Sovereign Tier tools (`scan_shadow_ai`, `attest_ai_policy`, `khepra_get_compliance_score`) require a Sovereign key ($299/mo).
   - Pharaoh Tier tools (`cmmc_assess`, `nhi_revoke`, `ert_scan`) require an Enterprise key ($2,999/mo).

4. **Offline Build & Verification**:
   - Keep builds offline and self-contained: `go test ./...`.
   - Never remove or compromise ML-DSA-65 signature verification routines.
