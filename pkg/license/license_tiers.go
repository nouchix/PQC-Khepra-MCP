package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// License represents a Khepra license bound to an account/organization.
// This is the node-quota licensing model used by cmd/agent (distinct from the
// per-tool MCP gate in mcp_gate.go, which reads KhepraLicense directly).
type License struct {
	ID                string      `json:"id"`
	Tier              LicenseTier `json:"tier"`
	NodeQuota         int         `json:"node_quota"` // Max nodes allowed (-1 = unlimited)
	NodeCount         int         `json:"node_count"` // Current nodes created
	CreatedAt         time.Time   `json:"created_at"`
	ExpiresAt         time.Time   `json:"expires_at"`
	Features          []string    `json:"features"`
	MaxAccessLevel    int         `json:"max_access_level"`              // Highest DAG node-type access level this license permits
	IsAirGapped       bool        `json:"is_air_gapped"`                 // Sovereign tier only
	OfflineLicenseSig string      `json:"offline_license_sig,omitempty"` // Base64 ShuBreathSignature (see pqc_signing.go)
}

// TierInfo holds configuration for each tier.
type TierInfo struct {
	Tier              LicenseTier
	Name              string
	Price             float64 // 0 for Community (free) and Sovereign (custom/contact sales)
	NodeQuota         int     // -1 = unlimited
	Features          []string
	MaxAccessLevel    int // Highest DAG node-type access level (see accessLevelForNodeType)
	MonthlyRetention  int // Days to retain DAG
	ConcurrentScans   int // -1 = unlimited
	AIQueriesPerMonth int // -1 = unlimited
	AssetCriticality  int // Tenable-inspired ACR (1-10)
}

// TierConfigurations is the single source of truth for tier pricing/limits.
// Keys are the canonical LicenseTier constants from sovereign.go — there is
// no separate tier taxonomy anywhere else in this repo.
var TierConfigurations = map[LicenseTier]TierInfo{
	TierCommunity: {
		Tier:             TierCommunity,
		Name:             "Community",
		Price:            0,
		NodeQuota:        1,
		MonthlyRetention: 1,
		AssetCriticality: 2, // Low impact
		MaxAccessLevel:   2,
		Features: []string{
			"basic-scan",
			"community-pqc",
			"limited-dashboard",
		},
	},
	TierPro: {
		Tier:              TierPro,
		Name:              "Pro",
		Price:             19,
		NodeQuota:         3,
		MonthlyRetention:  7,
		ConcurrentScans:   3,
		AIQueriesPerMonth: 100,
		AssetCriticality:  5, // Medium impact
		MaxAccessLevel:    5,
		Features: []string{
			"advanced-scan",
			"premium-pqc",
			"stig-nist",
			"threat-detection",
			"full-dashboard",
			"autopilot", // Continuous CMMC compliance scanning — every paid tier gets this
		},
	},
	TierEnterprise: {
		Tier:              TierEnterprise,
		Name:              "Enterprise",
		Price:             499,
		NodeQuota:         10,
		MonthlyRetention:  30,
		ConcurrentScans:   10,
		AIQueriesPerMonth: 1000,
		AssetCriticality:  8, // High impact
		MaxAccessLevel:    7,
		Features: []string{
			"all-pro-features",
			"auto-remediation",
			"sso-rbac",
			"multi-framework",
			"advanced-threat-hunting",
			"autopilot",
		},
	},
	TierSovereign: {
		Tier:              TierSovereign,
		Name:              "Sovereign",
		Price:             0,  // Custom — Contact Sales
		NodeQuota:         -1, // Unlimited
		MonthlyRetention:  365,
		ConcurrentScans:   -1, // Unlimited
		AIQueriesPerMonth: -1, // Unlimited
		AssetCriticality:  10, // Critical Infrastructure
		MaxAccessLevel:    10,
		Features: []string{
			"all-enterprise-features",
			"red-team-mode",
			"air-gap-licensing",
			"hsm-integration",
			"autopilot",
			"custom-pricing",
		},
	},
}

// LicenseManager handles license enforcement and node quota tracking.
type LicenseManager struct {
	mu                sync.RWMutex
	licenses          map[string]*License
	nodeToLicense     map[string]string  // nodeID -> licenseID mapping
	complianceWeights map[string]float64 // nodeID -> compliance debt
	storePath         string             // Path for persistence
}

// NewLicenseManager creates a new license manager with optional persistence.
func NewLicenseManager(storePath string) *LicenseManager {
	lm := &LicenseManager{
		licenses:          make(map[string]*License),
		nodeToLicense:     make(map[string]string),
		complianceWeights: make(map[string]float64),
		storePath:         storePath,
	}

	if storePath != "" {
		_ = lm.LoadFromDisk()
	}

	return lm
}

// SaveToDisk persists the current state to disk.
func (lm *LicenseManager) SaveToDisk() error {
	if lm.storePath == "" {
		return nil
	}

	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(lm.storePath), 0755); err != nil {
		return err
	}

	data := struct {
		Licenses          map[string]*License `json:"licenses"`
		NodeToLicense     map[string]string   `json:"node_to_license"`
		ComplianceWeights map[string]float64  `json:"compliance_weights"`
	}{
		Licenses:          lm.licenses,
		NodeToLicense:     lm.nodeToLicense,
		ComplianceWeights: lm.complianceWeights,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(lm.storePath, jsonData, 0644)
}

// LoadFromDisk restores the state from disk.
func (lm *LicenseManager) LoadFromDisk() error {
	if lm.storePath == "" {
		return nil
	}

	data, err := os.ReadFile(lm.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state struct {
		Licenses          map[string]*License `json:"licenses"`
		NodeToLicense     map[string]string   `json:"node_to_license"`
		ComplianceWeights map[string]float64  `json:"compliance_weights"`
	}

	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	lm.mu.Lock()
	lm.licenses = state.Licenses
	lm.nodeToLicense = state.NodeToLicense
	lm.complianceWeights = state.ComplianceWeights
	lm.mu.Unlock()

	return nil
}

// CreateLicense creates a new license for an organization/account.
func (lm *LicenseManager) CreateLicense(licenseID string, tier LicenseTier, durationDays int) (*License, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	tierInfo, exists := TierConfigurations[tier]
	if !exists {
		return nil, fmt.Errorf("invalid tier: %s", tier)
	}

	lic := &License{
		ID:             licenseID,
		Tier:           tier,
		NodeQuota:      tierInfo.NodeQuota,
		NodeCount:      0,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().AddDate(0, 0, durationDays),
		Features:       tierInfo.Features,
		MaxAccessLevel: tierInfo.MaxAccessLevel,
	}

	lm.licenses[licenseID] = lic
	_ = lm.SaveToDisk()
	return lic, nil
}

// CanCreateNode checks if a node creation is allowed under the current license.
// accessLevel is a 1-10 scale (see accessLevelForNodeType) gating which DAG
// node types the tier may create — higher tiers unlock deeper node types.
func (lm *LicenseManager) CanCreateNode(licenseID string, nodeType string, accessLevel int) error {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	lic, exists := lm.licenses[licenseID]
	if !exists {
		return ErrLicenseNotFound
	}

	if time.Now().After(lic.ExpiresAt) {
		return fmt.Errorf("license expired at %s", lic.ExpiresAt)
	}

	if lic.NodeQuota > 0 && lic.NodeCount >= lic.NodeQuota {
		return fmt.Errorf("node quota exceeded: %d/%d nodes used. Upgrade to %s tier for more capacity",
			lic.NodeCount, lic.NodeQuota, GetNextTier(lic.Tier))
	}

	if accessLevel > lic.MaxAccessLevel {
		return fmt.Errorf("node type %q (access level %d) requires a higher tier than %s (max level %d)",
			nodeType, accessLevel, RequiredTierDisplayName(lic.Tier), lic.MaxAccessLevel)
	}

	return nil
}

// RegisterNodeCreation records a node creation under a license.
func (lm *LicenseManager) RegisterNodeCreation(licenseID string, nodeID string, accessLevel int) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lic, exists := lm.licenses[licenseID]
	if !exists {
		return ErrLicenseNotFound
	}

	lic.NodeCount++
	lm.nodeToLicense[nodeID] = licenseID
	_ = lm.SaveToDisk()

	return nil
}

// ErrLicenseNotFound is returned when a license ID does not exist.
var ErrLicenseNotFound = errors.New("license not found")

// WeighHeart checks whether a node's accumulated compliance debt is acceptable.
func (lm *LicenseManager) WeighHeart(nodeID string) (bool, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	weight, exists := lm.complianceWeights[nodeID]
	if !exists {
		return true, nil // No compliance debt recorded
	}

	if weight > 0 {
		return false, fmt.Errorf("node %s has outstanding compliance debt: %.2f — remediate findings immediately",
			nodeID, weight)
	}

	return true, nil
}

// RecordComplianceDebt sets the compliance weight for a node.
func (lm *LicenseManager) RecordComplianceDebt(nodeID string, weight float64) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lm.complianceWeights[nodeID] = weight
}

// UpgradeLicense upgrades a license to a higher tier.
func (lm *LicenseManager) UpgradeLicense(licenseID string, newTier LicenseTier) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lic, exists := lm.licenses[licenseID]
	if !exists {
		return ErrLicenseNotFound
	}

	tierInfo, exists := TierConfigurations[newTier]
	if !exists {
		return fmt.Errorf("invalid tier: %s", newTier)
	}

	if !isValidUpgrade(lic.Tier, newTier) {
		return fmt.Errorf("cannot downgrade from %s to %s — use SetTier for revocations/cancellations", lic.Tier, newTier)
	}

	lic.Tier = newTier
	lic.NodeQuota = tierInfo.NodeQuota
	lic.Features = tierInfo.Features
	lic.MaxAccessLevel = tierInfo.MaxAccessLevel
	_ = lm.SaveToDisk()

	return nil
}

// SetTier changes a license's tier in either direction — used for
// cancellations/revocations (e.g. a Stripe subscription ending), where
// UpgradeLicense's upgrade-only guard would otherwise reject the change.
func (lm *LicenseManager) SetTier(licenseID string, newTier LicenseTier) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lic, exists := lm.licenses[licenseID]
	if !exists {
		return ErrLicenseNotFound
	}

	tierInfo, exists := TierConfigurations[newTier]
	if !exists {
		return fmt.Errorf("invalid tier: %s", newTier)
	}

	lic.Tier = newTier
	lic.NodeQuota = tierInfo.NodeQuota
	lic.Features = tierInfo.Features
	lic.MaxAccessLevel = tierInfo.MaxAccessLevel
	_ = lm.SaveToDisk()

	return nil
}

// isValidUpgrade validates the upgrade path (Community → Pro → Enterprise → Sovereign).
func isValidUpgrade(currentTier, newTier LicenseTier) bool {
	tierOrder := map[LicenseTier]int{
		TierCommunity:  0,
		TierPro:        1,
		TierEnterprise: 2,
		TierSovereign:  3,
	}

	return tierOrder[newTier] >= tierOrder[currentTier]
}

// GetLicenseCount returns the total number of licenses.
func (lm *LicenseManager) GetLicenseCount() int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return len(lm.licenses)
}

// CountByTier returns the number of licenses for a given tier.
func (lm *LicenseManager) CountByTier(tier LicenseTier) int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	count := 0
	for _, l := range lm.licenses {
		if l.Tier == tier {
			count++
		}
	}
	return count
}

// GetLicense retrieves a license by ID.
func (lm *LicenseManager) GetLicense(licenseID string) (*License, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	lic, exists := lm.licenses[licenseID]
	if !exists {
		return nil, ErrLicenseNotFound
	}

	return lic, nil
}

// GetAllLicenses returns all managed licenses.
func (lm *LicenseManager) GetAllLicenses() []*License {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	all := make([]*License, 0, len(lm.licenses))
	for _, l := range lm.licenses {
		all = append(all, l)
	}
	return all
}

// GetLicenseByNodeID retrieves the license associated with a node.
func (lm *LicenseManager) GetLicenseByNodeID(nodeID string) (*License, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	licenseID, exists := lm.nodeToLicense[nodeID]
	if !exists {
		return nil, fmt.Errorf("no license associated with node %s", nodeID)
	}

	lic, exists := lm.licenses[licenseID]
	if !exists {
		return nil, ErrLicenseNotFound
	}

	return lic, nil
}

// GenerateOfflineLicense creates a signed offline-license artifact for air-gapped
// Sovereign-tier deployments. Delegates to the real ML-DSA-65 signing pipeline
// in pqc_signing.go (GenerateSignedOfflineLicense) — this wrapper only exists
// to keep the LicenseManager-facing API stable for existing callers.
func (lm *LicenseManager) GenerateOfflineLicense(licenseID string, durationDays int, authority *SigningAuthority) (string, error) {
	lm.mu.Lock()
	lic, exists := lm.licenses[licenseID]
	if !exists {
		lm.mu.Unlock()
		return "", ErrLicenseNotFound
	}
	if lic.Tier != TierSovereign {
		lm.mu.Unlock()
		return "", fmt.Errorf("offline licensing only available for Sovereign tier (current: %s)", lic.Tier)
	}
	lic.ExpiresAt = time.Now().AddDate(0, 0, durationDays)
	lm.mu.Unlock()

	return lm.GenerateSignedOfflineLicense(licenseID, authority, nil)
}

// ValidateOfflineLicense verifies a signed offline-license artifact against the
// trusted root public key. Delegates to the real ML-DSA-65 verification in
// pqc_signing.go (VerifyLicense) — no code path accepts an unsigned artifact.
func ValidateOfflineLicense(artifact string, trustedRootPublicKey []byte) (bool, error) {
	shuBreath, err := decodeShuBreath(artifact)
	if err != nil {
		return false, err
	}
	return VerifyLicense(shuBreath, trustedRootPublicKey)
}

// ============================================================================
// Helper Functions for Tier Management
// ============================================================================

// GetNextTier returns the next tier up in the hierarchy.
func GetNextTier(currentTier LicenseTier) LicenseTier {
	switch currentTier {
	case TierCommunity:
		return TierPro
	case TierPro:
		return TierEnterprise
	case TierEnterprise:
		return TierSovereign
	default:
		return TierSovereign
	}
}

// accessLevelForNodeType returns the DAG node-type access level (1-10) used by
// CanCreateNode. Replaces the old per-deity node-type mapping with a plain
// numeric scale — the tier gate itself is unchanged, only the naming.
func accessLevelForNodeType(nodeType string) int {
	switch nodeType {
	case "raw_event":
		return 1
	case "agent_action":
		return 2
	case "attestation":
		return 3
	case "remediation":
		return 4
	case "finding":
		return 5
	case "threat":
		return 6
	case "asset":
		return 7
	case "tactical_control":
		return 8
	case "strategic_control":
		return 9
	case "meta_governance":
		return 10
	default:
		return 0
	}
}

// GetSephirotLevel is a deprecated alias for accessLevelForNodeType, kept for
// any external caller still using the old name.
//
// Deprecated: use accessLevelForNodeType.
func GetSephirotLevel(nodeType string) int {
	return accessLevelForNodeType(nodeType)
}

// TierSummary returns a human-readable summary of a license tier.
func TierSummary(tier LicenseTier) string {
	tierInfo, exists := TierConfigurations[tier]
	if !exists {
		return "Unknown tier"
	}

	if tierInfo.Price == 0 && tier != TierCommunity {
		return fmt.Sprintf("%s Tier: Custom pricing — contact sales, %d-day retention", tierInfo.Name, tierInfo.MonthlyRetention)
	}
	return fmt.Sprintf("%s Tier: $%.0f/mo, %d nodes, %d-day retention",
		tierInfo.Name, tierInfo.Price, tierInfo.NodeQuota, tierInfo.MonthlyRetention)
}
