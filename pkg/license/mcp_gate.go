// Package license — mcp_gate.go: MCP tool gating layer over the sovereign license stack.
//
// Three public tiers:
//
//	TierCommunity  (free, Apache 2.0 OSS)   — crypto discovery + Dark Crypto + local audit
//	TierPilot      (Sovereign, $299/mo)      — compliance reporting, ACP, NHI inventory
//	TierEnterprise (Pharaoh, custom pricing) — STIG/CMMC/NHI-full/ert-full/PQC STIG
//
// Tools NOT in mcpToolTier are accessible at Community tier with no license key.
// A nil license → Community tier (non-fatal — server starts and runs core tools).
//
// Display names map internal constants to customer-facing names:
//
//	"community"  → "Community"
//	"pilot"      → "Sovereign"
//	"enterprise" → "Pharaoh"
//	"master"     → "NouchiX Internal"
package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// ─── External Display Names ────────────────────────────────────────────────────

// TierDisplayNames maps internal tier constants to customer-facing names.
var TierDisplayNames = map[string]string{
	TierCommunity:  "Community",
	TierPilot:      "Sovereign",
	TierEnterprise: "Pharaoh",
	TierMaster:     "NouchiX Internal",
}

// RequiredTierDisplayName returns the customer-facing tier name for a given internal constant.
func RequiredTierDisplayName(tierConst string) string {
	if name, ok := TierDisplayNames[tierConst]; ok {
		return name
	}
	return tierConst
}

// ─── MCP Tool Gate ────────────────────────────────────────────────────────────

// ErrMCPTierInsufficient is returned when a tool requires a higher license tier.
type ErrMCPTierInsufficient struct {
	Tool     string
	Have     string
	Required string
}

func (e *ErrMCPTierInsufficient) Error() string {
	return fmt.Sprintf(
		"license: tool %q requires %s tier (current: %s) — upgrade at khepra.nouchix.com",
		e.Tool, RequiredTierDisplayName(e.Required), RequiredTierDisplayName(e.Have),
	)
}

// mcpToolTier maps each MCP tool name to the minimum tier constant.
// Tools NOT present are accessible at Community tier (no license key required).
//
// ── Community tier tools (no key needed) ───────────────────────────────────────
//
//	nist_map, khepra_query_stig, khepra_query_threat_intel,
//	discover_assets, owasp_agent_assess, ert_crypto,
//	agent_record, dag_attestation, khepra_get_dag_chain,
//	flight_export, dark_crypto_contribute
//
// ── Sovereign tier tools (TierPilot key) ──────────────────────────────────────
//
//	khepra_get_compliance_score, khepra_export_attestation, khepra_export_poam,
//	godfather_report, godfather_approve, ert_godfather, khepra_watch,
//	acp_issue, acp_revoke, acp_status, nhi_inventory
//
// ── Pharaoh tier tools (TierEnterprise key) ──────────────────────────────────
//
//	nhi_revoke, nhi_orphans, nhi_excessive, nhi_expired,
//	ert_scan, ert_readiness, ert_architect, stig_check, cmmc_assess
var mcpToolTier = map[string]string{

	"nist_map":                  TierCommunity,
	"khepra_query_stig":         TierCommunity,
	"khepra_query_threat_intel": TierCommunity,
	"discover_assets":           TierCommunity,
	"owasp_agent_assess":        TierCommunity,
	"ert_crypto":                TierCommunity,
	"agent_record":              TierCommunity,
	"dag_attestation":           TierCommunity,
	"khepra_get_dag_chain":      TierCommunity,
	"flight_export":             TierCommunity,
	"dark_crypto_contribute":    TierCommunity,
	"pqc_stig":                  TierCommunity, // World's First DoD PQC STIG — free for all, drives adoption

	// ── Sovereign / Pilot ─────────────────────────────────────────────────────
	// Compliance reporting, evidence packaging, human approval gates,
	// ACP credential management, and NHI inventory.
	"khepra_get_compliance_score": TierPilot,
	"khepra_export_attestation":   TierPilot,
	"khepra_export_poam":          TierPilot,
	"godfather_report":            TierPilot,
	"godfather_approve":           TierPilot,
	"ert_godfather":               TierPilot,
	"khepra_watch":                TierPilot,
	"acp_issue":                   TierPilot,
	"acp_revoke":                  TierPilot,
	"acp_status":                  TierPilot,
	"nhi_inventory":               TierPilot,

	// ── Pharaoh / Enterprise ──────────────────────────────────────────────────
	// Full NHI lifecycle, deep scanning, STIG/CMMC full assessments,
	// Docker-sandboxed code execution, air-gap licensing.
	"nhi_revoke":    TierEnterprise,
	"nhi_orphans":   TierEnterprise,
	"nhi_excessive": TierEnterprise,
	"nhi_expired":   TierEnterprise,
	"ert_scan":      TierEnterprise,
	"ert_readiness": TierEnterprise,
	"ert_architect": TierEnterprise,
	"stig_check":    TierEnterprise,
	"cmmc_assess":   TierEnterprise,
	// pqc_stig is Community tier — see above
}

// tierRank maps tier strings to numeric rank for AtLeast comparison.
var tierRank = map[string]int{
	TierCommunity:  0,
	TierPilot:      1,
	TierEnterprise: 2,
	TierMaster:     3,
}

// tierAtLeast returns true if have >= required in the tier hierarchy.
func tierAtLeast(have, required string) bool {
	return tierRank[have] >= tierRank[required]
}

// CheckToolAccess returns nil if lic permits toolName, or ErrMCPTierInsufficient.
// A nil license is treated as Community tier (non-fatal — server still starts).
func CheckToolAccess(lic *KhepraLicense, toolName string) error {
	currentTier := TierCommunity
	if lic != nil {
		currentTier = lic.Tier
	}

	required, gated := mcpToolTier[toolName]
	if !gated {
		return nil // Community-accessible tool
	}

	if !tierAtLeast(currentTier, required) {
		return &ErrMCPTierInsufficient{
			Tool:     toolName,
			Have:     currentTier,
			Required: required,
		}
	}
	return nil
}

// RequiredTier returns the minimum tier constant for a tool,
// or TierCommunity if the tool is ungated.
func RequiredTier(toolName string) string {
	if tier, gated := mcpToolTier[toolName]; gated {
		return tier
	}
	return TierCommunity
}

// ─── Per-Tool Behavior Helpers ────────────────────────────────────────────────

// NistMapLimit returns the maximum BM25 result count for the tier.
//   - Community:  25  (sufficient for Dark Crypto intelligence lookups)
//   - Sovereign+: 616 (full NIST 800-53 / 800-171 index)
func NistMapLimit(lic *KhepraLicense) int {
	if lic == nil || lic.Tier == TierCommunity {
		return 25
	}
	return 616
}

// ERTFullScan returns true if the tier permits all ERT scan lanes (secrets, sbom, pqc).
// Community: crypto-only lane (ert_crypto tool).
// Sovereign: sast + sca + pqc lanes.
// Enterprise: all lanes including Docker-sandboxed ert_scan.
func ERTFullScan(lic *KhepraLicense) bool {
	if lic == nil {
		return false
	}
	return tierAtLeast(lic.Tier, TierPilot)
}

// SignedAuditLogEnabled returns true if cloud relay (SouHimBou AI) is permitted.
// Community builds use local-only DAG (air-gap mode, zero cloud dependency).
// Sovereign+ can set SOUHIMBOU_ENDPOINT for cloud relay.
func SignedAuditLogEnabled(lic *KhepraLicense) bool {
	if lic == nil {
		return false
	}
	return tierAtLeast(lic.Tier, TierPilot)
}

// DarkCryptoContributeEnabled always returns true.
// Dark Crypto contribution is a Community feature — the primary value exchange:
// users contribute anonymous crypto inventory; in return they receive global
// quantum exposure intelligence. Available at all tiers.
func DarkCryptoContributeEnabled(_ *KhepraLicense) bool {
	return true
}

// ─── MCP License Loading ──────────────────────────────────────────────────────

// ErrNoLicenseKey is returned (non-fatal) when KHEPRA_LICENSE_KEY is empty.
var ErrNoLicenseKey = errors.New("license: KHEPRA_LICENSE_KEY not set — Community tier active")

// ParseMCPLicense loads the license from KHEPRA_LICENSE_KEY env var and verifies
// it offline using VerifySovereignLicense against the embedded master public key.
//
// Returns:
//   - (nil, ErrNoLicenseKey) — no key set, Community tier, non-fatal
//   - (*KhepraLicense, nil) — valid license
//   - (nil, err) — key present but invalid (tampered/expired), FATAL at startup
func ParseMCPLicense() (*KhepraLicense, error) {
	raw := os.Getenv("KHEPRA_LICENSE_KEY")
	if raw == "" {
		return nil, ErrNoLicenseKey
	}

	var lic KhepraLicense
	if err := json.Unmarshal([]byte(raw), &lic); err != nil {
		return nil, fmt.Errorf("license: KHEPRA_LICENSE_KEY parse failed: %w", err)
	}

	// Offline ML-DSA-65 verification pinned to the compiled-in master public key
	// (pkg/license/master_pubkey.go). Without pinning, VerifySovereignLicense
	// would fall back to lic.SignerPublicKey — i.e. trust whatever key the
	// license itself carries, which any self-signed license satisfies trivially.
	if err := VerifySovereignLicense(&lic, MasterPublicKey); err != nil {
		return nil, fmt.Errorf("license: sovereign verification failed: %w", err)
	}

	return &lic, nil
}
