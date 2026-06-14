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

// EgyptianTier represents the four Egyptian solar phases and license tiers.
type EgyptianTier string

const (
	TierKhepri EgyptianTier = "khepri" // Morning Sun / Scout - $50/mo, 1 node
	TierRa     EgyptianTier = "ra"     // Midday Sun / Hunter - $500/mo, 3 nodes
	TierAtum   EgyptianTier = "atum"   // Evening Sun / Hive - $2000/mo, 10 nodes
	TierOsiris EgyptianTier = "osiris" // Night / Pharaoh - Custom, ∞ nodes
)

// Deity represents Egyptian deities governing Sephirot access.
type Deity string

const (
	// Raw Event / Malkuth
	DeityKhepri Deity = "Khepri" // Scarab - Birth/transformation

	// Agent Action / Yesod
	DeityPtah Deity = "Ptah" // Builder - Foundation

	// Attestation / Hod
	DeityAnubis Deity = "Anubis" // Jackal - Guardian/proof

	// Remediation / Netzach
	DeityIsis Deity = "Isis" // Healer - Magic/restoration

	// Finding / Tiphereth
	DeityMaat Deity = "Ma'at" // Feather - Truth/balance

	// Threat / Geburah
	DeityHorus Deity = "Horus" // Falcon/Eye - Protection/severity

	// Asset / Chesed
	DeityRa Deity = "Ra" // Sun - Power/abundance

	// Tactical Control / Binah
	DeityThoth Deity = "Thoth" // Ibis - Wisdom/understanding

	// Strategic Control / Chokmah
	DeityOsiris Deity = "Osiris" // Pharaoh - Resurrection/eternal

	// Meta-Governance / Keter
	DeityAtum Deity = "Atum" // Creator - Crown/completion
)

// License represents a Khepra license bound to an account/organization.
type License struct {
	ID                string       `json:"id"`
	Tier              EgyptianTier `json:"tier"`
	NodeQuota         int          `json:"node_quota"` // Max nodes allowed
	NodeCount         int          `json:"node_count"` // Current nodes created
	CreatedAt         time.Time    `json:"created_at"`
	ExpiresAt         time.Time    `json:"expires_at"`
	Features          []string     `json:"features"`                      // Feature flags
	DeityAuthorities  []Deity      `json:"deity_authorities"`             // Deities accessible
	SephirotAccess    []int        `json:"sephirot_access"`               // Sephirot levels allowed
	IsAirGapped       bool         `json:"is_air_gapped"`                 // Pharaoh only
	OfflineLicenseSig string       `json:"offline_license_sig,omitempty"` // Shu Breath
}

// TierInfo holds configuration for each tier.
type TierInfo struct {
	Tier              EgyptianTier
	Name              string
	Price             float64
	NodeQuota         int
	Features          []string
	DeityAuthorities  []Deity
	SephirotAccess    []int // Max Sephirot level
	MonthlyRetention  int   // Days to retain DAG
	ConcurrentScans   int
	AIQueriesPerMonth int
	AssetCriticality  int // Tenable-inspired ACR (1-10)
}

var TierConfigurations = map[EgyptianTier]TierInfo{
	TierKhepri: {
		Tier:             TierKhepri,
		Name:             "Scout",
		Price:            50,
		NodeQuota:        1,
		MonthlyRetention: 1,
		AssetCriticality: 2, // Low impact
		Features: []string{
			"basic-scan",
			"community-pqc",
			"limited-dashboard",
		},
		DeityAuthorities: []Deity{DeityKhepri, DeityPtah, DeityAnubis},
		SephirotAccess:   []int{1, 2}, // Malkuth, Yesod
	},
	TierRa: {
		Tier:              TierRa,
		Name:              "Hunter",
		Price:             500,
		NodeQuota:         3,
		MonthlyRetention:  7,
		ConcurrentScans:   3,
		AIQueriesPerMonth: 100,
		AssetCriticality:  5, // Medium impact
		Features: []string{
			"advanced-scan",
			"premium-pqc",
			"stig-nist",
			"threat-detection",
			"full-dashboard",
		},
		DeityAuthorities: []Deity{
			DeityKhepri, DeityPtah, DeityAnubis,
			DeityIsis, DeityMaat, DeityHorus, DeityThoth,
		},
		SephirotAccess: []int{1, 2, 3, 4, 5}, // Malkuth through Tiphereth
	},
	TierAtum: {
		Tier:              TierAtum,
		Name:              "Hive",
		Price:             2000,
		NodeQuota:         10,
		MonthlyRetention:  30,
		ConcurrentScans:   10,
		AIQueriesPerMonth: 1000,
		AssetCriticality:  8, // High impact
		Features: []string{
			"all-hunter-features",
			"auto-remediation",
			"sso-rbac",
			"multi-framework",
			"advanced-threat-hunting",
		},
		DeityAuthorities: []Deity{
			DeityKhepri, DeityPtah, DeityAnubis, DeityIsis,
			DeityMaat, DeityHorus, DeityRa, DeityThoth,
		},
		SephirotAccess: []int{1, 2, 3, 4, 5, 6, 7}, // through Chesed
	},
	TierOsiris: {
		Tier:              TierOsiris,
		Name:              "Pharaoh",
		Price:             0,  // Custom pricing
		NodeQuota:         -1, // Unlimited
		MonthlyRetention:  365,
		ConcurrentScans:   -1, // Unlimited
		AIQueriesPerMonth: -1, // Unlimited
		AssetCriticality:  10, // Critical Infrastructure
		Features: []string{
			"all-hive-features",
			"red-team-mode",
			"commando-mode",
			"air-gap-licensing",
			"hsm-integration",
			"eternal-license",
		},
		DeityAuthorities: []Deity{
			DeityKhepri, DeityPtah, DeityAnubis, DeityIsis,
			DeityMaat, DeityHorus, DeityRa, DeityThoth, DeityOsiris, DeityAtum,
		},
		SephirotAccess: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, // Full tree access
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

	// Ensure directory exists
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
func (lm *LicenseManager) CreateLicense(licenseID string, tier EgyptianTier, durationDays int) (*License, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	tierInfo, exists := TierConfigurations[tier]
	if !exists {
		return nil, fmt.Errorf("invalid tier: %s", tier)
	}

	license := &License{
		ID:               licenseID,
		Tier:             tier,
		NodeQuota:        tierInfo.NodeQuota,
		NodeCount:        0,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().AddDate(0, 0, durationDays),
		Features:         tierInfo.Features,
		DeityAuthorities: tierInfo.DeityAuthorities,
		SephirotAccess:   tierInfo.SephirotAccess,
	}

	lm.licenses[licenseID] = license
	_ = lm.SaveToDisk()
	return license, nil
}

// CanCreateNode checks if a node creation is allowed under the current license.
func (lm *LicenseManager) CanCreateNode(licenseID string, nodeType string, sephirotLevel int) error {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	license, exists := lm.licenses[licenseID]
	if !exists {
		return ErrLicenseNotFound
	}

	// Check expiration
	if time.Now().After(license.ExpiresAt) {
		return fmt.Errorf("license expired at %s", license.ExpiresAt)
	}

	// Check node quota (except for Pharaoh tier which is unlimited)
	if license.NodeQuota > 0 && license.NodeCount >= license.NodeQuota {
		return fmt.Errorf("node quota exceeded: %d/%d nodes used. Upgrade to %s tier for more capacity",
			license.NodeCount, license.NodeQuota, GetNextTier(license.Tier))
	}

	// Check Sephirot access (node type corresponds to Sephirot level)
	if !lm.hasSephirotAccess(license, sephirotLevel) {
		return fmt.Errorf("sephirot level %d not accessible in %s tier. Egyptian deity required: %s",
			sephirotLevel, license.Tier, GetRequiredDeity(sephirotLevel))
	}

	return nil
}

// hasSephirotAccess checks if license allows access to a Sephirot level.
func (lm *LicenseManager) hasSephirotAccess(license *License, sephirotLevel int) bool {
	for _, allowed := range license.SephirotAccess {
		if allowed >= sephirotLevel {
			return true
		}
	}
	return false
}

// RegisterNodeCreation records a node creation under a license.
func (lm *LicenseManager) RegisterNodeCreation(licenseID string, nodeID string, sephirotLevel int) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	license, exists := lm.licenses[licenseID]
	if !exists {
		return ErrLicenseNotFound
	}

	license.NodeCount++
	lm.nodeToLicense[nodeID] = licenseID
	_ = lm.SaveToDisk()

	return nil
}

// ErrLicenseNotFound is returned when a license ID does not exist.
var ErrLicenseNotFound = errors.New("license not found")

// WeighHeart implements the "Weighing of the Heart" compliance check.
// Returns true if node's compliance weight is acceptable (heart lighter than Ma'at's feather).
func (lm *LicenseManager) WeighHeart(nodeID string) (bool, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	weight, exists := lm.complianceWeights[nodeID]
	if !exists {
		// No compliance debt recorded = pure heart
		return true, nil
	}

	// Ma'at's feather weight = 0 (perfect compliance)
	// If weight > 0, heart is heavier (sins/violations present)
	if weight > 0 {
		return false, fmt.Errorf("node %s has compliance debt: %.2f. "+
			"Ammit the Devourer awaits. Remediate findings immediately.",
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
func (lm *LicenseManager) UpgradeLicense(licenseID string, newTier EgyptianTier) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	license, exists := lm.licenses[licenseID]
	if !exists {
		return ErrLicenseNotFound
	}

	tierInfo, exists := TierConfigurations[newTier]
	if !exists {
		return fmt.Errorf("invalid tier: %s", newTier)
	}

	// Validate upgrade path (can only upgrade, not downgrade)
	if !isValidUpgrade(license.Tier, newTier) {
		return fmt.Errorf("cannot downgrade from %s to %s", license.Tier, newTier)
	}

	// Upgrade the license
	license.Tier = newTier
	license.NodeQuota = tierInfo.NodeQuota
	license.Features = tierInfo.Features
	license.DeityAuthorities = tierInfo.DeityAuthorities
	license.SephirotAccess = tierInfo.SephirotAccess
	_ = lm.SaveToDisk()

	return nil
}

// isValidUpgrade validates the upgrade path (Khepri → Ra → Atum → Osiris).
func isValidUpgrade(currentTier, newTier EgyptianTier) bool {
	tierOrder := map[EgyptianTier]int{
		TierKhepri: 0,
		TierRa:     1,
		TierAtum:   2,
		TierOsiris: 3,
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
func (lm *LicenseManager) CountByTier(tier EgyptianTier) int {
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

	license, exists := lm.licenses[licenseID]
	if !exists {
		return nil, ErrLicenseNotFound
	}

	return license, nil
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

	license, exists := lm.licenses[licenseID]
	if !exists {
		return nil, ErrLicenseNotFound
	}

	return license, nil
}

// GenerateOfflineLicense creates a "Shu Breath" offline license signature for air-gapped Pharaoh deployments.
func (lm *LicenseManager) GenerateOfflineLicense(licenseID string, durationDays int) (string, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	license, exists := lm.licenses[licenseID]
	if !exists {
		return "", ErrLicenseNotFound
	}

	if license.Tier != TierOsiris {
		return "", fmt.Errorf("offline licensing only available for Pharaoh tier (current: %s)", license.Tier)
	}

	// Create Shu Breath signature (in production, would use proper cryptographic signing)
	offlineSig := map[string]interface{}{
		"license_id":  licenseID,
		"tier":        license.Tier,
		"valid_until": time.Now().AddDate(0, 0, durationDays),
		"issued_at":   time.Now(),
		"node_quota":  license.NodeQuota,
		"features":    license.Features,
		"breath_type": "shu", // Breath of the wind god Shu
	}

	sigJSON, err := json.Marshal(offlineSig)
	if err != nil {
		return "", err
	}

	// In production: sign with Dilithium private key
	license.OfflineLicenseSig = string(sigJSON)
	license.IsAirGapped = true

	return string(sigJSON), nil
}

// ValidateOfflineLicense validates a Shu Breath signature in air-gapped environment.
func ValidateOfflineLicense(shuBreathSig string) (bool, error) {
	var sig map[string]interface{}
	if err := json.Unmarshal([]byte(shuBreathSig), &sig); err != nil {
		return false, fmt.Errorf("invalid Shu Breath signature: %w", err)
	}

	// Check expiration
	validUntilStr, ok := sig["valid_until"].(string)
	if !ok {
		return false, errors.New("missing valid_until in Shu Breath")
	}

	validUntil, err := time.Parse(time.RFC3339, validUntilStr)
	if err != nil {
		// Try parsing as timestamp
		return false, fmt.Errorf("invalid date format in Shu Breath: %w", err)
	}

	if time.Now().After(validUntil) {
		return false, fmt.Errorf("Shu Breath expired at %s. Re-emerge from Duat to renew.", validUntil)
	}

	// In production: verify Dilithium signature against root CA

	return true, nil
}

// ============================================================================
// Helper Functions for Egyptian Tier Management
// ============================================================================

// GetNextTier returns the next tier up in the hierarchy.
func GetNextTier(currentTier EgyptianTier) EgyptianTier {
	switch currentTier {
	case TierKhepri:
		return TierRa
	case TierRa:
		return TierAtum
	case TierAtum:
		return TierOsiris
	default:
		return TierOsiris
	}
}

// GetRequiredDeity returns the deity required to access a Sephirot level.
func GetRequiredDeity(sephirotLevel int) Deity {
	switch sephirotLevel {
	case 1:
		return DeityKhepri // Malkuth
	case 2:
		return DeityPtah // Yesod
	case 3:
		return DeityAnubis // Hod
	case 4:
		return DeityIsis // Netzach
	case 5:
		return DeityMaat // Tiphereth
	case 6:
		return DeityHorus // Geburah
	case 7:
		return DeityRa // Chesed
	case 8:
		return DeityThoth // Binah
	case 9:
		return DeityOsiris // Chokmah
	case 10:
		return DeityAtum // Keter
	default:
		return Deity("Unknown")
	}
}

// GetSephirotLevel returns the Sephirot level for a node type.
func GetSephirotLevel(nodeType string) int {
	switch nodeType {
	case "raw_event":
		return 1 // Malkuth
	case "agent_action":
		return 2 // Yesod
	case "attestation":
		return 3 // Hod
	case "remediation":
		return 4 // Netzach
	case "finding":
		return 5 // Tiphereth
	case "threat":
		return 6 // Geburah
	case "asset":
		return 7 // Chesed
	case "tactical_control":
		return 8 // Binah
	case "strategic_control":
		return 9 // Chokmah
	case "meta_governance":
		return 10 // Keter
	default:
		return 0
	}
}

// TierSummary returns a human-readable summary of a license tier.
func TierSummary(tier EgyptianTier) string {
	tierInfo, exists := TierConfigurations[tier]
	if !exists {
		return "Unknown tier"
	}

	return fmt.Sprintf("%s Tier: $%.0f/mo, %d nodes, %d-day retention",
		tierInfo.Name, tierInfo.Price, tierInfo.NodeQuota, tierInfo.MonthlyRetention)
}
