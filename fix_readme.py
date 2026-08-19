
with open("README.md", "r") as f:
    content = f.read()

# Add new badges
old_badges = """[![smithery badge](https://smithery.ai/badge/skone/pqc-khepra-mcp)](https://smithery.ai/servers/skone/pqc-khepra-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.nouchix%2Fpqc--khepra--mcp-blue?style=for-the-badge)](https://registry.modelcontextprotocol.io/?q=khepra)
[![mcpservers.org](https://img.shields.io/badge/mcpservers.org-nouchix%2Fpqc--khepra--mcp-orange?style=for-the-badge)](https://mcpservers.org/servers/nouchix/pqc-khepra-mcp)
[![Cline Marketplace](https://img.shields.io/badge/Cline_Marketplace-Issue_%231824-blueviolet?style=for-the-badge)](https://github.com/cline/mcp-marketplace/issues/1824)
[![License](https://img.shields.io/badge/License-Community%20%2F%20Commercial-green?style=for-the-badge)](https://nouchix.com)
[![Container](https://img.shields.io/badge/Container-ghcr.io-green?style=for-the-badge&logo=docker)](https://ghcr.io/nouchix/pqc-khepra-mcp)
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--65%20%2F%20FIPS%20204-purple?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/204/final)
[![Live](https://img.shields.io/badge/Live-mcp.souhimbou.ai-brightgreen?style=for-the-badge)](https://mcp.souhimbou.ai/mcp/v1/health)"""

new_badges = """[![Release](https://img.shields.io/badge/Release-v2.0.0-blue?style=for-the-badge)](https://github.com/nouchix/PQC-Khepra-MCP/releases)
[![Downloads](https://img.shields.io/badge/Downloads-424%2B_Verified-blue?style=for-the-badge&logo=docker)](https://github.com/nouchix/PQC-Khepra-MCP/pkgs/container/pqc-khepra-mcp)
[![smithery badge](https://smithery.ai/badge/skone/pqc-khepra-mcp)](https://smithery.ai/servers/skone/pqc-khepra-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.nouchix%2Fpqc--khepra--mcp-blue?style=for-the-badge)](https://registry.modelcontextprotocol.io/?q=khepra)
[![mcpservers.org](https://img.shields.io/badge/mcpservers.org-nouchix%2Fpqc--khepra--mcp-orange?style=for-the-badge)](https://mcpservers.org/servers/nouchix/pqc-khepra-mcp)
[![Cline Marketplace](https://img.shields.io/badge/Cline_Marketplace-Issue_%231824-blueviolet?style=for-the-badge)](https://github.com/cline/mcp-marketplace/issues/1824)
[![License](https://img.shields.io/badge/License-Apache_2.0-green?style=for-the-badge)](LICENSE)
[![Container](https://img.shields.io/badge/Container-ghcr.io-green?style=for-the-badge&logo=docker)](https://ghcr.io/nouchix/pqc-khepra-mcp)
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--65%20%2F%20FIPS%20204-purple?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/204/final)
[![Live](https://img.shields.io/badge/Live-mcp.souhimbou.ai-brightgreen?style=for-the-badge)](https://mcp.souhimbou.ai/mcp/v1/health)"""

content = content.replace(old_badges, new_badges)

old_boundary = """> [!NOTE]
> **Public Kernel vs. Sovereign Landing Zone Boundary**:
> - **`PQC-Khepra-MCP` (This Public Repository)**: The open-source post-quantum MCP kernel (Apache 2.0). Contains PQC primitives, the DoD PQC STIG (`pqc_stig`), OWASP Agentic Top 10 assessment (`owasp_agent_assess`), basic AI asset discovery (`scan_shadow_ai`), and NIST SP 800-53 baseline lookups.
> - **`khepra-trust-os` (Private Repository)**: The commercial landing zone & trust OS containing the AI Evidence Object fabric (`core/aeo`), Agent Passports (`core/citizenship`), Privileged Enforcement Daemon (`core/enforce`), automated CMMC SSP generator (`core/compliance`), and commercial key management (`core/commercial`).
> - **Dependency Direction**: Strictly **one-way**. `khepra-trust-os` imports this public kernel as a Go module; this public repo never imports private repositories."""

new_boundary = """> [!NOTE]
> **v2.0.0 Public Kernel Extraction Complete**:
> - **`PQC-Khepra-MCP` (This Public Repository)**: The newly extracted, open-source post-quantum MCP kernel (Apache 2.0). Contains PQC primitives, the DoD PQC STIG (`pqc_stig`), OWASP Agentic Top 10 assessment (`owasp_agent_assess`), basic AI asset discovery (`scan_shadow_ai`), and NIST SP 800-53 baseline lookups. Built in complete isolation via `kernelports`.
> - **`khepra-trust-os` (Private Repository)**: The commercial landing zone & trust OS containing the AI Evidence Object fabric (`core/aeo`), Agent Passports (`core/citizenship`), Privileged Enforcement Daemon (`core/enforce`), automated CMMC SSP generator (`core/compliance`), and commercial key management (`core/commercial`).
> - **Dependency Direction**: Strictly **one-way**. `khepra-trust-os` and all internal tools import this public kernel as a Go module; this public repo never imports private repositories."""

content = content.replace(old_boundary, new_boundary)

# Remove the blurb at the bottom since we integrated it above
blurb = """---
### 🚀 System Architecture Update: Public Kernel Extraction Complete
**Status:** ✅ Condition 3 (Kernel Standalone) Met

The core Khepra MCP (`PQC-Khepra-MCP`) has been successfully decoupled from all proprietary orchestration and security planes (Adinkra, Sekhem, Giza). Through the introduction of the `kernelports` dependency injection boundary, the `khepra-kernel` now builds and operates in complete isolation. All legacy internal tools continue to compile seamlessly against the original repository. 

*This paves the way for the formal Apache-2.0 open-source release of the standalone PQC-Khepra-MCP kernel!*"""
content = content.replace(blurb, "")

with open("README.md", "w") as f:
    f.write(content)

