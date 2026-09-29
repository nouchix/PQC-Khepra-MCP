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
	Error       string   `json:"error"`
	Tier        string   `json:"current_tier"`
	RequiredMin string   `json:"required_tier"`
	Pricing     string   `json:"pricing"`
	UpgradeURL  string   `json:"upgrade_url"`
	CheckoutURL string   `json:"checkout_url,omitempty"`
	Reason      string   `json:"gated_reason"`
	Unlocks     []string `json:"unlocks,omitempty"`
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
		Pricing:     pricing,
		UpgradeURL:  upgradeURLFor("tier_gate", minTier),
		CheckoutURL: checkoutURLFor(minTier),
		Reason:      reason,
		Unlocks:     tierUnlocks(minTier),
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
		Pricing:     pricing,
		UpgradeURL:  upgradeURLFor(capability, minTier),
		CheckoutURL: checkoutURLFor(minTier),
		Reason:      reason,
		Unlocks:     tierUnlocks(minTier),
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

func tierPricing(tier string) string {
	switch tier {
	case TierPilot, license.TierPro:
		return "$99/mo (Pro Security Engineer / Agentic SOC)"
	case TierEnterprise:
		return "$499/mo (Enterprise Agentic SOC / SOAR / Compliance)"
	case license.TierSovereign:
		return "$2,999/mo (Sovereign SCIF / Air-Gap)"
	case TierMaster:
		return "Internal only"
	default:
		return "Free"
	}
}

func checkoutURLFor(tier string) string {
	switch tier {
	case TierPilot, license.TierPro:
		return "https://buy.stripe.com/3cI3cv8AaaNk6BdevV9ws05"
	case TierEnterprise:
		return "https://buy.stripe.com/aFa7sLaIi6x4cZBevV9ws04"
	case license.TierSovereign:
		return "https://buy.stripe.com/7sY6oH2bM8Fc5x90F59ws03"
	default:
		return ""
	}
}

func tierUnlocks(tier string) []string {
	switch tier {
	case TierPilot, license.TierPro:
		return []string{
			"Live compliance scoring & continuous DAG attestation",
			"ACP credential issuance & NHI discovery",
			"Automated email notifications via Resend",
			"500 STIGViewer API credits/mo",
		}
	case TierEnterprise:
		return []string{
			"Full STIG and CMMC Level 1/2/3 assessments",
			"Live DISA STIGViewer API v2 batch crosswalks (15,000 credits/mo)",
			"SOAR autonomous incident remediation playbooks",
			"C3PAO-ready POA&M / OSCAL evidence packaging",
		}
	case license.TierSovereign:
		return []string{
			"100% sovereign air-gapped deployment posture",
			"QKD Kyber-1024 post-quantum capsules",
			"Hardware Security Module (HSM) attestation",
			"Unlimited fleet governance nodes",
		}
	default:
		return nil
	}
}

func upgradeURLFor(targetName, minTier string) string {
	u := os.Getenv("KHEPRA_UPGRADE_URL")
	if u == "" {
		u = "https://souhimbou.ai/pricing"
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%supgrade_target=%s&tier=%s&utm_source=pqc-khepra-mcp", u, sep, targetName, minTier)
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
	// ── Community (free — discovery & basic status) ───────────
	"pqc_keygen":              TierCommunity,
	"pqc_sign":                TierCommunity,
	"pqc_verify":              TierCommunity,
	"flight_record":           TierCommunity,
	"flight_export":           TierCommunity,
	"agent_record":            TierCommunity,
	"dag_attestation":         TierCommunity,
	"khepra_get_dag_chain":    TierCommunity,
	"enumerate_host":          TierCommunity,
	"fingerprint_device":      TierCommunity,
	"discover_assets":         TierCommunity,
	"kasa_status":             TierCommunity,
	"threat_lookup":           TierCommunity,
	"nist_map":                TierCommunity,

	// ── Pilot / Pro ($99/mo) ─────────────────────────────────
	"khepra_get_compliance_score": TierPilot,
	"pqc_stig":                    TierPilot,
	"dag_query":                   TierPilot,
	"threat_model":                TierPilot,
	"ea_threat_score":             TierPilot,
	"ouroboros_waf_eye":           TierPilot,
	"ouroboros_stig_eye":          TierPilot,
	"ouroboros_vuln_eye":          TierPilot,
	"ouroboros_fim_eye":           TierPilot,
	"khepra_query_threat_intel":   TierPilot,
	"nhi_inventory":               TierPilot,
	"acp_status":                  TierPilot,
	"scan_shadow_ai":              TierPilot,
	"attest_ai_policy":            TierPilot,
	"ert_crypto":                  TierPilot,
	"ert_godfather":               TierPilot,
	"attest_export":               TierPilot, // C3PAO 13-artifact evidence ZIP (ML-DSA-65 signed)
	"khepra_export_attestation":   TierPilot,
	"forensic_snapshot":           TierPilot,
	"fim_baseline":                TierPilot,
	"ir_incident":                 TierPilot,
	"ir_add_ioc":                  TierPilot,
	"attack_graph":                TierPilot,
	"drbc_backup":                 TierPilot,
	"drbc_restore":                TierPilot,
	"audit_dag_integrity":         TierPilot,
	"ea_evolve":                   TierPilot,
	"ea_risk_summary":             TierPilot,
	"drift_detect":                TierPilot,
	"sbom_generate":               TierPilot,
	"khepra_watch":                TierPilot,

	// ── Enterprise / Sovereign ($499/mo - $2,999/mo) ────────
	"cmmc_assess":             TierEnterprise,
	"stig_check":              TierEnterprise,
	"khepra_query_stig":       TierEnterprise, // Live STIG crosswalk / DISA STIGViewer query
	"ert_scan":                TierEnterprise,
	"ert_readiness":           TierEnterprise,
	"ert_architect":           TierEnterprise,
	"nhi_orphans":             TierEnterprise,
	"nhi_excessive":           TierEnterprise,
	"nhi_expired":             TierEnterprise,
	"nhi_revoke":              TierEnterprise,
	"acp_issue":               TierEnterprise,
	"acp_revoke":              TierEnterprise,
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
