// Package tools — dark_crypto_contribute.go: MCP handler for the Dark Crypto
// Intelligence Network community contribution tool.
//
// This is a COMMUNITY TIER tool (no license key required). It is the primary
// value exchange in the Khepra Community model:
//
//	User contributes → anonymized crypto inventory → Nouchix Dark Crypto DB
//	User receives    ← global quantum exposure rank ← community intelligence
//
// Privacy is the product guarantee. No file paths, no IPs, no hostnames,
// no credentials, no code contents leave the machine.
//
// Tool registration in main.go: executor.RegisterFunc("dark_crypto_contribute", HandleDarkCryptoContribute)
package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/telemetry"
)

// HandleDarkCryptoContribute is the MCP handler for dark_crypto_contribute.
// It accepts a list of crypto findings (from discover_assets or ert_crypto output),
// strips all sensitive data, and submits the anonymized inventory to the
// Nouchix Dark Crypto Intelligence Network.
//
// Returns: ContributionReceipt with global exposure rank and community stats.
func HandleDarkCryptoContribute(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	args := call.Args
	var warnings []string

	// ── Parse findings input ──────────────────────────────────────────────────
	// Accept findings as either:
	//   (a) "findings" array of objects (from ert_crypto/discover_assets output)
	//   (b) "algorithms" string list (simple comma-separated algorithm names)
	findings, warn := parseContributeFindings(args)
	warnings = append(warnings, warn...)

	if len(findings) == 0 {
		// No explicit findings — run a basic self-assessment of the server's crypto
		findings = builtinKhepraFindings()
		warnings = append(warnings, "No findings provided — using KHEPRA server's own crypto inventory as contribution. For full environment scan, run discover_assets or ert_crypto first, then pass results to dark_crypto_contribute.")
	}

	// ── Submit to Dark Crypto Network ─────────────────────────────────────────
	receipt, err := telemetry.ContributeFindings(findings)
	if err != nil {
		return nil, warnings, fmt.Errorf("dark_crypto_contribute: contribution failed: %w", err)
	}

	// ── Build response ────────────────────────────────────────────────────────
	result := &DarkCryptoContributeResult{
		ContributionID:       receipt.ContributionID,
		AlgorithmsCatalogued: receipt.AlgorithmsCatalogued,
		GlobalExposureRank:   receipt.GlobalExposureRank,
		QuantumRiskLevel:     receipt.QuantumRiskLevel,
		CommunityStat:        receipt.CommunityStat,
		Recommendation:       receipt.Recommendation,
		AcceptedAt:           receipt.AcceptedAt,
		Offline:              receipt.Offline,
		PrivacyGuarantees: []string{
			"No file paths, IPs, hostnames, or credentials collected",
			"Only algorithm identifiers, library names, and versions transmitted",
			"All system identifiers SHA-256 hashed before transmission",
			"Ephemeral signing key — no persistent identity",
			"GDPR compliant | NIST SP 800-188 de-identification compliant",
			"Opt-in only — you explicitly invoked this tool",
		},
		NetworkLink:  "https://nouchix.ai/dark-crypto",
		TierRequired: "Community (free) — no license key needed",
	}

	if receipt.Offline {
		result.StatusMessage = "Contribution queued for offline sync. Results will appear when nouchix.ai is reachable."
	} else {
		result.StatusMessage = fmt.Sprintf(
			"Contribution accepted. %d algorithms catalogued. Your environment ranks %s globally.",
			receipt.AlgorithmsCatalogued, receipt.GlobalExposureRank,
		)
	}

	return result, warnings, nil
}

// DarkCryptoContributeResult is the structured response from dark_crypto_contribute.
type DarkCryptoContributeResult struct {
	ContributionID       string    `json:"contribution_id"`
	AlgorithmsCatalogued int       `json:"algorithms_catalogued"`
	GlobalExposureRank   string    `json:"global_exposure_rank"`
	QuantumRiskLevel     string    `json:"quantum_risk_level"`
	CommunityStat        string    `json:"community_stat"`
	Recommendation       string    `json:"recommendation"`
	StatusMessage        string    `json:"status_message"`
	AcceptedAt           time.Time `json:"accepted_at"`
	Offline              bool      `json:"offline"`
	PrivacyGuarantees    []string  `json:"privacy_guarantees"`
	NetworkLink          string    `json:"network_link"`
	TierRequired         string    `json:"tier_required"`
}

// ─── Findings Parsing ─────────────────────────────────────────────────────────

// parseContributeFindings extracts CryptoFinding list from tool call arguments.
func parseContributeFindings(args map[string]any) ([]telemetry.CryptoFinding, []string) {
	var findings []telemetry.CryptoFinding
	var warnings []string

	// Try "findings" array of objects
	if raw, ok := args["findings"].([]any); ok && len(raw) > 0 {
		for _, item := range raw {
			f, err := parseFindingObject(item)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("skipped malformed finding: %v", err))
				continue
			}
			findings = append(findings, f)
		}
		return findings, warnings
	}

	// Try "algorithms" as comma-separated string (simple mode)
	if algStr, ok := args["algorithms"].(string); ok && algStr != "" {
		algs := strings.Split(algStr, ",")
		for _, alg := range algs {
			alg = strings.TrimSpace(alg)
			if alg == "" {
				continue
			}
			findings = append(findings, telemetry.CryptoFinding{
				Algorithm:         alg,
				UsagePattern:      "unknown",
				QuantumVulnerable: isQuantumVulnerable(alg),
			})
		}
		return findings, warnings
	}

	return nil, warnings
}

// parseFindingObject converts a raw map[string]any to a CryptoFinding.
func parseFindingObject(raw any) (telemetry.CryptoFinding, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return telemetry.CryptoFinding{}, fmt.Errorf("finding must be an object")
	}

	alg, _ := m["algorithm"].(string)
	if alg == "" {
		return telemetry.CryptoFinding{}, fmt.Errorf("finding missing 'algorithm' field")
	}

	f := telemetry.CryptoFinding{
		Algorithm:         alg,
		QuantumVulnerable: isQuantumVulnerable(alg),
	}
	if lib, ok := m["library_name"].(string); ok {
		f.LibraryName = lib
	}
	if ver, ok := m["library_version"].(string); ok {
		f.LibraryVersion = ver
	}
	if usage, ok := m["usage_pattern"].(string); ok {
		f.UsagePattern = usage
	}
	if qv, ok := m["quantum_vulnerable"].(bool); ok {
		f.QuantumVulnerable = qv // caller override
	}
	return f, nil
}

// isQuantumVulnerable returns true if the algorithm is known to be quantum-vulnerable
// based on NIST / CNSA 2.0 migration guidance.
func isQuantumVulnerable(alg string) bool {
	upper := strings.ToUpper(alg)
	quantumVulnerable := []string{
		"RSA", "DSA", "ECDSA", "ECDH", "DH", "DIFFIE-HELLMAN",
		"ECC", "ELGAMAL",
		"SHA-1", "SHA1", "MD5", "MD4", "RC4",
		"DES", "3DES", "TRIPLE-DES",
		"AES-128", // AES-256 is quantum-safe; AES-128 provides only 64-bit quantum security
		"TLS-1.0", "TLS-1.1", "TLS-1.2", // TLS 1.3 with PQC KEM is safe
		"NTLM", "LANMAN",
	}
	for _, vuln := range quantumVulnerable {
		if strings.Contains(upper, vuln) {
			return true
		}
	}
	return false
}

// builtinKhepraFindings returns the crypto inventory of the KHEPRA server itself.
// Used when no external findings are provided — contributes KHEPRA's own crypto
// posture to the Dark Crypto Network (self-attestation).
func builtinKhepraFindings() []telemetry.CryptoFinding {
	return []telemetry.CryptoFinding{
		{
			Algorithm:             "ML-DSA-65",
			LibraryName:           "CRYSTALS-Dilithium",
			LibraryVersion:        "FIPS-204",
			UsagePattern:          "digital-signature",
			QuantumVulnerable:     false,
			NISTMigrationPriority: 0, // Already PQC-safe
		},
		{
			Algorithm:             "ML-KEM-768",
			LibraryName:           "CRYSTALS-Kyber",
			LibraryVersion:        "FIPS-203",
			UsagePattern:          "key-exchange",
			QuantumVulnerable:     false,
			NISTMigrationPriority: 0,
		},
		{
			Algorithm:             "AES-256-GCM",
			LibraryName:           "go-stdlib",
			LibraryVersion:        "crypto/aes",
			UsagePattern:          "encryption",
			QuantumVulnerable:     false,
			NISTMigrationPriority: 0,
		},
		{
			Algorithm:             "SHA-256",
			LibraryName:           "go-stdlib",
			LibraryVersion:        "crypto/sha256",
			UsagePattern:          "hashing",
			QuantumVulnerable:     false,
			NISTMigrationPriority: 0,
		},
		{
			Algorithm:             "SHA-3-256",
			LibraryName:           "go-stdlib",
			LibraryVersion:        "golang.org/x/crypto",
			UsagePattern:          "hashing",
			QuantumVulnerable:     false,
			NISTMigrationPriority: 0,
		},
	}
}
