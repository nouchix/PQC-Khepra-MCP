// Package tools — tier gating for KHEPRA MCP tool handlers.
//
// Each tool handler calls RequireTier() or RequireCapability() at entry.
// Community tier users see the problem (scan results) for free,
// but solution-generating tools (evidence export, POA&M, SOAR) are gated.
//
// Copyright © 2024-2026 SOUHIMBOU DOH KONE LLC. Exclusively licensed to SecRed Knowledge Inc.
package tools

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
)

// ─── Tier Hierarchy ────────────────────────────────────────────────────────────

const (
	TierCommunity  = "community"
	TierPilot      = "pilot"      // $99/mo via Smithery/Stripe
	TierEnterprise = "enterprise" // $499/mo via Smithery/Stripe
	TierMaster     = "master"     // Internal — Cyber-only
)

// tierRank maps tier names to numeric rank for >= comparison.
var tierRank = map[string]int{
	TierCommunity:  0,
	TierPilot:      1,
	TierEnterprise: 2,
	TierMaster:     3,
}

// ClassifiedTools are hidden from the public server-card.json and tools/list
// response. They remain functional for authenticated Enterprise/Master tier
// users via stdio transport or licensed HTTP calls.
// Ref: AGENTS.md Non-Negotiable #3 — Phantom Network, NSOHIA are classified.
var ClassifiedTools = map[string]bool{
	"phantom_stealth":  true,
	"identity_shroud":  true,
	"identity_epiphany": true,
}

// IsClassified returns true if the tool must be hidden from public discovery.
func IsClassified(toolName string) bool {
	return ClassifiedTools[toolName]
}

// ─── Cached License (loaded once at first gate check) ──────────────────────────

var (
	cachedTier string
	cachedCaps []string
	tierOnce   sync.Once
)

// loadTier resolves the active tier from the license system.
// Called once, result is cached for the process lifetime.
func loadTier() {
	tierOnce.Do(func() {
		lic, err := license.ParseMCPLicense()
		if err != nil || lic == nil {
			cachedTier = TierCommunity
			cachedCaps = license.AllTierCapabilities[license.TierCommunity]
			return
		}
		cachedTier = lic.Tier
		if caps, ok := license.AllTierCapabilities[lic.Tier]; ok {
			cachedCaps = caps
		} else {
			cachedCaps = license.AllTierCapabilities[license.TierCommunity]
		}
	})
}

// ActiveTier returns the current tier name.
func ActiveTier() string {
	loadTier()
	return cachedTier
}

// ─── Gate Results ──────────────────────────────────────────────────────────────

// GatedResponse is the standard response when a tool is tier-gated.
// It tells the AI agent (and ultimately the user) exactly what to do.
type GatedResponse struct {
	Error       string `json:"error"`
	Tier        string `json:"current_tier"`
	RequiredMin string `json:"required_tier"`
	UpgradeURL  string `json:"upgrade_url"`
	Reason      string `json:"gated_reason"`
}

// ─── Gate Functions ────────────────────────────────────────────────────────────

// RequireTier checks if the active license meets the minimum tier.
// Returns nil if authorized, or a GatedResponse if blocked.
//
// Usage in a handler:
//
//	func HandleFlightExport(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
//	    if gate := RequireTier(TierPilot, "Evidence export with CMMC control mapping"); gate != nil {
//	        return gate, nil, nil
//	    }
//	    // ... actual implementation
//	}
func RequireTier(minTier, reason string) *GatedResponse {
	loadTier()
	currentRank := tierRank[cachedTier]
	requiredRank := tierRank[minTier]

	if currentRank >= requiredRank {
		return nil // Authorized
	}

	pricing := tierPricing(minTier)
	return &GatedResponse{
		Error:       fmt.Sprintf("This tool requires %s tier (%s)", minTier, pricing),
		Tier:        cachedTier,
		RequiredMin: minTier,
		UpgradeURL:  upgradeURL(),
		Reason:      reason,
	}
}

// RequireCapability checks if the active license includes a specific capability.
// Uses the AllTierCapabilities map from pkg/license/sovereign.go.
func RequireCapability(capability, reason string) *GatedResponse {
	loadTier()
	for _, c := range cachedCaps {
		if c == capability {
			return nil // Authorized
		}
	}

	// Find the minimum tier that has this capability
	minTier := TierMaster
	for _, tier := range []string{TierCommunity, TierPilot, TierEnterprise, TierMaster} {
		caps := license.AllTierCapabilities[tier]
		for _, c := range caps {
			if c == capability {
				minTier = tier
				goto found
			}
		}
	}
found:

	pricing := tierPricing(minTier)
	return &GatedResponse{
		Error:       fmt.Sprintf("Capability %q requires %s tier (%s)", capability, minTier, pricing),
		Tier:        cachedTier,
		RequiredMin: minTier,
		UpgradeURL:  upgradeURL(),
		Reason:      reason,
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

func tierPricing(tier string) string {
	switch tier {
	case TierPilot:
		return "$99/mo or $25K/yr ASAF pilot"
	case TierEnterprise:
		return "$499/mo or $75K+/yr ASAF program"
	case TierMaster:
		return "Internal only"
	default:
		return "Free"
	}
}

func upgradeURL() string {
	if u := os.Getenv("KHEPRA_UPGRADE_URL"); u != "" {
		return u
	}
	return "https://souhimbou.ai/pricing"
}

// ─── Tool → Tier Mapping (reference table) ─────────────────────────────────────
//
// Community (free):
//   stig_check (summary score only)
//   cmmc_assess (summary score only)
//   ert_scan, ert_readiness, ert_architect
//   pqc_stig (summary only)
//   discover_assets
//   agent_record
//   kasa_status
//   ea_threat_score (1 run)
//   threat_model (summary)
//   pqc_keygen, pqc_sign, pqc_verify
//   dag_query
//   enumerate_host, fingerprint_device
//   ouroboros_*_eye (status only)
//
// Pilot ($99/mo):
//   stig_check (full findings + remediation)
//   cmmc_assess (full findings)
//   ert_crypto, ert_godfather
//   pqc_stig (full 12 controls)
//   flight_export (evidence packet)
//   khepra_export_attestation
//   forensic_snapshot
//   fim_baseline
//   audit_dag_integrity
//   ea_evolve (unlimited generations)
//   ea_risk_summary
//   threat_lookup, drift_detect
//   sbom_generate
//
// Enterprise ($499/mo):
//   khepra_export_poam
//   ir_incident, ir_add_ioc
//   attack_graph
//   port_scan, vuln_scan, secret_scan, container_scan, compliance_scan, packet_analyze
//   drbc_backup, drbc_restore
//   phantom_stealth, identity_shroud, identity_epiphany
//   dag_write, dag_audit
//   quantum_optimize
//   kasa_start
//   flight_record (SIEM integration)

// ToolTierMap returns the minimum tier required for a given tool name.
// Used by the executor to enforce gating before dispatch.
var ToolTierMap = map[string]string{
	// ── Community (free) ─────────────────────────────────────
	"stig_check":              TierCommunity,
	"cmmc_assess":             TierCommunity,
	"ert_scan":                TierCommunity,
	"ert_readiness":           TierCommunity,
	"ert_architect":           TierCommunity,
	"pqc_stig":                TierCommunity,
	"discover_assets":         TierCommunity,
	"agent_record":            TierCommunity,
	"kasa_status":             TierCommunity,
	"ea_threat_score":         TierCommunity,
	"threat_model":            TierCommunity,
	"pqc_keygen":              TierCommunity,
	"pqc_sign":                TierCommunity,
	"pqc_verify":              TierCommunity,
	"dag_query":               TierCommunity,
	"enumerate_host":          TierCommunity,
	"fingerprint_device":      TierCommunity,
	"ouroboros_waf_eye":       TierCommunity,
	"ouroboros_stig_eye":      TierCommunity,
	"ouroboros_vuln_eye":      TierCommunity,
	"ouroboros_fim_eye":       TierCommunity,
	"nhi_inventory":           TierCommunity,
	"nhi_orphans":             TierCommunity,
	"nhi_excessive":           TierCommunity,
	"nhi_expired":             TierCommunity,
	"acp_status":              TierCommunity,
	"khepra_query_stig":       TierCommunity,
	"khepra_query_threat_intel": TierCommunity,
	"khepra_get_compliance_score": TierCommunity,
	"nist_map":                TierCommunity,
	"khepra_watch":            TierCommunity,
	"khepra_get_dag_chain":    TierCommunity,

	// ── Pilot ($99/mo) ───────────────────────────────────────
	"ert_crypto":              TierPilot,
	"ert_godfather":           TierPilot,
	"flight_export":           TierPilot,
	"attest_export":           TierPilot, // C3PAO 13-artifact evidence ZIP (ML-DSA-65 signed)
	"khepra_export_attestation": TierPilot,
	"forensic_snapshot":       TierPilot,
	"fim_baseline":            TierPilot,
	"ir_incident":             TierPilot,
	"ir_add_ioc":              TierPilot,
	"attack_graph":            TierPilot,
	"drbc_backup":             TierPilot,
	"drbc_restore":            TierPilot,
	"audit_dag_integrity":     TierPilot,
	"ea_evolve":               TierPilot,
	"ea_risk_summary":         TierPilot,
	"threat_lookup":           TierPilot,
	"drift_detect":            TierPilot,
	"sbom_generate":           TierPilot,

	// ── Enterprise ($499/mo) ─────────────────────────────────
	"khepra_export_poam":      TierEnterprise,
	"port_scan":               TierEnterprise,
	"vuln_scan":               TierEnterprise,
	"secret_scan":             TierEnterprise,
	"container_scan":          TierEnterprise,
	"compliance_scan":         TierEnterprise,
	"packet_analyze":          TierEnterprise,
	"phantom_stealth":         TierEnterprise,
	"identity_shroud":         TierEnterprise,
	"identity_epiphany":       TierEnterprise,
	"dag_write":               TierEnterprise,
	"dag_audit":               TierEnterprise,
	"quantum_optimize":        TierEnterprise,
	"kasa_start":              TierEnterprise,
	"flight_record":           TierEnterprise,
	"acp_issue":               TierEnterprise,
	"acp_revoke":              TierEnterprise,
	"nhi_revoke":              TierEnterprise,
}

// GateForTool checks the tier map and returns a GatedResponse if blocked.
// Returns nil if the tool is allowed under the current tier.
func GateForTool(toolName string) *GatedResponse {
	minTier, exists := ToolTierMap[toolName]
	if !exists {
		// Unknown tool — default to enterprise gate
		minTier = TierEnterprise
	}

	reason := fmt.Sprintf("%s requires %s tier", toolName, minTier)
	// Build a more helpful reason based on the tool category
	switch {
	case strings.HasPrefix(toolName, "ir_"):
		reason = "Incident Response tools require Enterprise tier for SOC-grade IR workflows"
	case strings.HasPrefix(toolName, "drbc_"):
		reason = "Disaster Recovery/Business Continuity requires Enterprise tier"
	case strings.HasPrefix(toolName, "phantom_") || strings.HasPrefix(toolName, "identity_"):
		reason = "OPSEC tools require Enterprise tier for operational security"
	case strings.Contains(toolName, "export") || strings.Contains(toolName, "attestation"):
		reason = "Evidence export and attestation require Pilot tier for C3PAO-ready packages"
	case strings.Contains(toolName, "scan") && minTier == TierEnterprise:
		reason = "Active scanning tools require Enterprise tier for authorized penetration testing"
	case strings.HasPrefix(toolName, "ea_") && minTier == TierPilot:
		reason = "Full EA evolution and risk synthesis require Pilot tier for continuous threat modeling"
	}

	return RequireTier(minTier, reason)
}
