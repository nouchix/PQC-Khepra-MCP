# Commercial Architecture & Licensing Alignment

The Giza/Khepra API server architecture is designed to be highly modular, supporting both Cloud/SaaS deployments (SouHimBou AI / Enterprise) and Standalone/Embedded deployments (STARGATE Desktop / Air-gapped).

To achieve this, several core subsystems are injected optionally via a builder pattern (e.g. `WithSekhemTriad()`, `WithASAFRecorder()`). This ensures the server does not crash when offline or in air-gapped environments.

## Component Licensing & Stripe Alignment

### 1. `mcpStore` (Supabase MCP Persistence)
* **Use Case**: Saves Model Context Protocol (MCP) tool executions and Natural Language chat histories to Supabase.
* **Licensing**: Available to all SaaS tiers, but entirely disabled (left `nil`) in the STARGATE desktop app (which uses local SQLite/Memory stores instead to remain vendor-free).

### 2. `nlProcessor` (Natural Language Engine)
* **Use Case**: The AI engine that translates user text into executable DAG nodes and CLI tool chains.
* **Licensing**: Community users rely on local Ollama. Starter/Enterprise tiers unlock the ability to route queries through hosted Anthropic/Claude infrastructure.

### 3. `pqcGateway` (Post-Quantum Auth)
* **Use Case**: Validates enterprise Single Sign-On (SAML 2.0 / WorkOS) and Supabase JWTs, exchanging them for Quantum-Safe tokens. 
* **Licensing**: SAML 2.0 / WorkOS integrations are gated behind **Enterprise ($499/mo)** and **Professional ($999/mo)** Stripe tiers. Community/Starter users use standard JWTs or local Go-native Auth.

### 4. `sekhemTriad` (WAF & Autonomous Healing)
* **Use Case**: Runs the Ouroboros cycle—monitoring the system, detecting vulnerabilities (Isfet), and automatically remediating them (Maat). Includes the L7 WAF.
* **Licensing**: Basic scanning is available to all. Automated remediation (healing) and active WAF blocking are premium features for the **Enterprise** or **Sovereign** tiers.

### 5. `recorder` (ASAF Flight Recorder)
* **Use Case**: Records every action, tool execution, and prompt, creating a cryptographically verifiable "flight recorder" log for compliance audits.
* **Licensing**: Maps directly to the **Professional** or **Sovereign ($2,999/mo)** tiers for defense contractors requiring extreme auditability (CMMC/DoD).

### 6. `autopilot` (Continuous Compliance)
* **Use Case**: Schedules continuous, invisible scans and auto-generates compliance artifacts (Set it and forget it).
* **Licensing**: Explicitly gated behind the `autopilot` Stripe purchase tier. If not purchased, the continuous scheduler is never spun up.
