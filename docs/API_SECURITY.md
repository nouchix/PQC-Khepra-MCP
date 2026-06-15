# OWASP API Security Top 10 — Compliance Mapping
### PQC-Khepra-MCP / AdinKhepra ASAF Engine

> OWASP SDLC Phase: Implementation + Verification  
> Reference: [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)

---

## API Inventory

| Endpoint Group | Protocol | Auth | Rate Limit | Zone |
|---|---|---|---|---|
| `/api/stigs/*` | HTTPS/mTLS | mTLS cert | Token bucket (100/hr) | Zone 1 DMZ |
| `/mcp/*` (tool calls) | HTTPS | DEMARC JWT | Per-identity limiter | Zone 2 |
| `/api/scada/*` | HTTPS | JWT | Not implemented ❌ | Zone 2 |
| `/api/agents/*` | HTTPS | JWT | Not implemented ❌ | Zone 2 |
| `/webhook/*` | HTTPS | HMAC-SHA256 sig | Not implemented ❌ | Zone 1 |
| `/health` | HTTP | None | N/A | Internal |

---

## API1:2023 — Broken Object Level Authorization (BOLA)

**Risk**: User A can access User B's resources by changing an ID in the request.

| Control | Implementation | Status |
|---|---|---|
| Identity attached to all MCP calls | `call.Identity = id` in router.go after DEMARC | ✅ |
| Agent ID scoped to agent's own resources | MCPToolCall carries Identity throughout | ✅ |
| SCADA handler has no per-user scoping | `/api/scada/*` no auth check | ❌ |
| Webhook lacks per-org resource checks | Webhook uses HMAC global signature only | 🟡 |

**Action Required**: Add per-organization resource scoping to SCADA and webhook handlers.

---

## API2:2023 — Broken Authentication

**Risk**: Weak or missing authentication allows impersonation.

| Control | Implementation | Status |
|---|---|---|
| mTLS for Zone 1 STIGConnector | `tls.Config` with client cert verification | ✅ |
| JWT/DEMARC for MCP tool calls | DEMARC.Authenticate() in router | ✅ |
| HMAC-SHA256 webhook signatures | `validateWebhookSignature()` in main.go | ✅ |
| MCP transport integrity guard | `MCPTransportGuard.ts` | ✅ |
| SCADA handler authentication | None — no auth on `/api/scada/*` | ❌ |
| Token expiry enforcement | Not verified in DEMARC handler | 🟡 |

**Action Required**: Add auth to SCADA endpoints; verify JWT expiry in DEMARC.

---

## API3:2023 — Broken Object Property Level Authorization

**Risk**: Mass assignment or over-exposed fields allow users to modify unauthorized properties.

| Control | Implementation | Status |
|---|---|---|
| STIGRule struct has validated fields only | `validateResponse()` sanitizes all fields | ✅ |
| MCP tool parameters schema-validated | Tool spec validation in executor | ✅ |
| Webhook payload limited via `json.Decoder` | `io.LimitReader` + strict parsing | ✅ |
| SCADA telemetry exposes all sensor data | No field-level filtering | 🟡 |

---

## API4:2023 — Unrestricted Resource Consumption

**Risk**: No limits on request size, rate, or compute — enables DoS.

| Control | Implementation | Status |
|---|---|---|
| STIGConnector rate limit (100/hr) | Token bucket in `stig_connector.go` | ✅ |
| API payload size limit (10MB) | `io.LimitReader(resp.Body, MaxPayloadBytes)` | ✅ |
| MCP CIDR rate limiting | `CheckCIDR` + backoff in layer4_control.go | ✅ |
| SCADA no rate limit | No limiter on `/api/scada/*` | ❌ |
| Webhook no rate limit | HMAC validation only | ❌ |
| nist_map_tool topK bounded to 50 | `if topK > 50 { topK = 50 }` (pre-fix) | ✅ |

**Action Required**: Add rate limiting to SCADA and webhook endpoints.

---

## API5:2023 — Broken Function Level Authorization

**Risk**: Regular users can invoke admin/privileged functions.

| Control | Implementation | Status |
|---|---|---|
| MCP tool classification (read-only/sandboxed/destructive) | `ToolSpec.Classification` in executor | ✅ |
| Destructive tools require ConfirmationGate | `executeDestructive()` enforces confirm | ✅ |
| Admin endpoints restricted to admin role | Not verified — no explicit admin check | 🟡 |

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**Risk**: No protection against business logic abuse (e.g., scraping, automated attacks).

| Control | Implementation | Status |
|---|---|---|
| WAF layer blocks automated attacks | Layer1 firewall with WAF patterns | ✅ |
| CIDR allowlisting for DoD networks | `CheckCIDR` in DEMARC | ✅ |
| Tor exit node blocking | `BlockTorExitNodes` in firewall config | ✅ |
| Geo-blocking | `GeoBlockCountries` configurable | ✅ |

---

## API7:2023 — Server-Side Request Forgery (SSRF)

**Risk**: API accepts URLs from users and fetches them server-side.

| Control | Implementation | Status |
|---|---|---|
| STIGConnector BaseURL is config-only (not user input) | Fixed in `STIGConnectorConfig.BaseURL` | ✅ |
| CloudProviderDetector uses endsWith() | Fixed this session (hostnameMatchesDomain) | ✅ |
| No user-supplied URL fetch endpoints found | Reviewed cmd/ and pkg/api/ | ✅ |

---

## API8:2023 — Security Misconfiguration

**Risk**: Exposed debug endpoints, verbose errors, default credentials, missing TLS.

| Control | Implementation | Status |
|---|---|---|
| `/health` returns no sensitive data | Returns circuit state + connector name | ✅ |
| Error messages don't expose stack traces | `fmt.Errorf("%w", err)` wrapping | ✅ |
| Server header removed | `middleware.SecureHeaders()` deletes it | ✅ (new) |
| Secure headers applied globally | `pkg/middleware/secure_headers.go` | ✅ (new) |
| SCADA debug endpoints open | `/api/scada/live` has no auth | ❌ |

---

## API9:2023 — Improper Inventory Management

**Risk**: Exposed deprecated API versions, undocumented endpoints.

| Control | Implementation | Status |
|---|---|---|
| API version in response headers | `X-API-Version` from STIGConnector | ✅ |
| `server.json` documents all MCP tools | Yes — validated in CI | ✅ |
| No `/api/v0` or legacy endpoint detected | Code review | ✅ |

---

## API10:2023 — Unsafe Consumption of APIs

**Risk**: Trusting data from third-party APIs without validation.

| Control | Implementation | Status |
|---|---|---|
| STIGViewer response fully validated | `validateResponse()` in stig_connector.go | ✅ |
| Field length limits enforced | `sanitizeTextField(field, maxLen)` | ✅ |
| Array size limits enforced | `OwnerRoles[:10]`, `Controls[:50]` | ✅ |
| JSON decoded strictly | `json.NewDecoder` with Decode | ✅ |
| Response size limited | `io.LimitReader` (10MB) | ✅ |

---

## Outstanding Actions

| Priority | Item | Owner |
|----------|------|-------|
| 🔴 Critical | Add auth to `/api/scada/*` endpoints | Dev |
| 🔴 Critical | Add rate limiting to webhook and SCADA | Dev |
| 🟡 High | Verify JWT expiry in DEMARC authenticate | Dev |
| 🟡 High | Per-org resource scoping in webhook | Dev |
| 🟢 Med | Apply `SecureHeaders` middleware at all entrypoints | Dev |
| 🟢 Med | Document full endpoint inventory with auth requirements | Docs |

---

*Last Updated: 2026-06-15 | Standard: OWASP API Security Top 10 (2023)*
