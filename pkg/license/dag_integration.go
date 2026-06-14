package license

import (
	"fmt"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

// NodeLicenseBinding tracks which license authorizes which nodes
type NodeLicenseBinding struct {
	NodeID         string
	LicenseID      string
	SephirotLevel  int
	CreatedAt      time.Time
	ComplianceDebt float64 // "Heart weight" for judgment
}

// DAGLicenseEnforcer provides license enforcement hooks for DAG operations
type DAGLicenseEnforcer struct {
	manager           *LicenseManager
	nodeBindings      map[string]*NodeLicenseBinding
	mu                sync.RWMutex
	complianceWeights map[string]float64 // Node ID -> weight
}

// NewDAGLicenseEnforcer creates a new enforcer linked to LicenseManager
func NewDAGLicenseEnforcer(mgr *LicenseManager) *DAGLicenseEnforcer {
	return &DAGLicenseEnforcer{
		manager:           mgr,
		nodeBindings:      make(map[string]*NodeLicenseBinding),
		complianceWeights: make(map[string]float64),
	}
}

// CanCreateNode enforces license constraints before node creation
// Called by: pkg/dag/dag.go Store.Add()
func (dle *DAGLicenseEnforcer) CanCreateNode(licenseID string, nodeID string, nodeType string, sephirotLevel int) error {
	dle.mu.Lock()
	defer dle.mu.Unlock()

	// Check if node already bound
	if _, exists := dle.nodeBindings[nodeID]; exists {
		return fmt.Errorf("node %s already licensed", nodeID)
	}

	// Delegate to LicenseManager for quota/access checks
	return dle.manager.CanCreateNode(licenseID, nodeType, sephirotLevel)
}

// ErrLicenseNotFoundFmt is the format string for license not found errors
const ErrLicenseNotFoundFmt = "license %s not found"

// RegisterNodeCreation binds node to license and updates quota
// Called by: pkg/dag/dag.go Store.Add() after successful node creation
func (dle *DAGLicenseEnforcer) RegisterNodeCreation(licenseID string, nodeID string, sephirotLevel int) error {
	dle.mu.Lock()
	defer dle.mu.Unlock()

	// Validate license exists
	lic, exists := dle.manager.licenses[licenseID]
	if !exists {
		return fmt.Errorf(ErrLicenseNotFoundFmt, licenseID)
	}

	// Check node quota
	if lic.NodeQuota > 0 && lic.NodeCount >= lic.NodeQuota {
		return fmt.Errorf("license quota exceeded: %d/%d nodes", lic.NodeCount, lic.NodeQuota)
	}

	// Create binding
	binding := &NodeLicenseBinding{
		NodeID:        nodeID,
		LicenseID:     licenseID,
		SephirotLevel: sephirotLevel,
		CreatedAt:     time.Now(),
	}

	dle.nodeBindings[nodeID] = binding

	// Update license node count
	dle.manager.mu.Lock()
	lic.NodeCount++
	dle.manager.mu.Unlock()

	return dle.manager.RegisterNodeCreation(licenseID, nodeID, sephirotLevel)
}

// EvaluateNodeFate maps node to Egyptian fate based on state code
// Called by: pkg/attest/attest.go when creating attestation
func (dle *DAGLicenseEnforcer) EvaluateNodeFate(nodeID string, stateCode int, complianceDebt float64) (string, error) {
	dle.mu.Lock()
	_, exists := dle.nodeBindings[nodeID]
	dle.mu.Unlock()

	if !exists {
		return "", fmt.Errorf("node %s has no license binding", nodeID)
	}

	// Record compliance weight
	dle.mu.Lock()
	dle.complianceWeights[nodeID] = complianceDebt
	dle.mu.Unlock()

	// Map state code to Egyptian fate using hypercube judgment
	fate := dag.StateCodeToFate(stateCode)

	// If Ammit (state 15 = 0b1111, all bits set), escalate to Pharaoh
	if stateCode == 15 {
		return "", fmt.Errorf("Ammit the Devourer awaits node %s: state=%d (CRITICAL), fate=%s",
			nodeID, stateCode, fate)
	}

	return string(fate), nil
}

// CanRemoveNode checks if node can be deleted (compliance cleared)
// Called by: pkg/dag/dag.go Store.Delete()
func (dle *DAGLicenseEnforcer) CanRemoveNode(nodeID string) error {
	dle.mu.Lock()
	defer dle.mu.Unlock()

	_, exists := dle.nodeBindings[nodeID]
	if !exists {
		return fmt.Errorf("node %s not tracked by license system", nodeID)
	}

	// Check compliance weight (must be ≤ 0 for removal)
	weight := dle.complianceWeights[nodeID]
	if weight > 0 {
		return fmt.Errorf("node %s has outstanding compliance debt: %.2f", nodeID, weight)
	}

	// Mark node as removed
	delete(dle.nodeBindings, nodeID)
	delete(dle.complianceWeights, nodeID)

	return nil
}

// GetNodeLicense returns the license binding for a node
func (dle *DAGLicenseEnforcer) GetNodeLicense(nodeID string) (*NodeLicenseBinding, error) {
	dle.mu.RLock()
	defer dle.mu.RUnlock()

	binding, exists := dle.nodeBindings[nodeID]
	if !exists {
		return nil, fmt.Errorf("node %s not found", nodeID)
	}

	return binding, nil
}

// GetNodeCount returns the total number of licensed nodes.
func (dle *DAGLicenseEnforcer) GetNodeCount() int {
	dle.mu.RLock()
	defer dle.mu.RUnlock()
	return len(dle.nodeBindings)
}

// ListNodesByLicense returns all nodes authorized by a license
func (dle *DAGLicenseEnforcer) ListNodesByLicense(licenseID string) []*NodeLicenseBinding {
	dle.mu.RLock()
	defer dle.mu.RUnlock()

	var nodes []*NodeLicenseBinding
	for _, binding := range dle.nodeBindings {
		if binding.LicenseID == licenseID {
			nodes = append(nodes, binding)
		}
	}

	return nodes
}

// UpdateComplianceDebt records compliance weight for a node
// Called by: pkg/attest/attest.go when findings are recorded
func (dle *DAGLicenseEnforcer) UpdateComplianceDebt(nodeID string, debt float64) error {
	dle.mu.Lock()
	defer dle.mu.Unlock()

	binding, exists := dle.nodeBindings[nodeID]
	if !exists {
		return fmt.Errorf("node %s not found", nodeID)
	}

	binding.ComplianceDebt = debt
	dle.complianceWeights[nodeID] = debt

	return nil
}

// VerifyWeighingOfHeart performs "Heart" judgment for license compliance
// Called by: pkg/attest/attest.go before sealing attestation
func (dle *DAGLicenseEnforcer) VerifyWeighingOfHeart(licenseID string) (bool, error) {
	dle.mu.Lock()
	defer dle.mu.Unlock()

	// Get all nodes under this license
	var totalDebt float64
	for _, binding := range dle.nodeBindings {
		if binding.LicenseID == licenseID {
			totalDebt += binding.ComplianceDebt
		}
	}

	// Ma'at's feather (balance point) is at 0.0
	// Positive debt = heart heavier than feather = ⚖️ UNBALANCED
	if totalDebt > 0 {
		return false, fmt.Errorf("weighing of heart failed: license %s has debt %.2f", licenseID, totalDebt)
	}

	return true, nil
}

// GetLicenseUsageStats returns quota and compliance info
func (dle *DAGLicenseEnforcer) GetLicenseUsageStats(licenseID string) map[string]interface{} {
	dle.mu.RLock()
	defer dle.mu.RUnlock()

	lic, exists := dle.manager.licenses[licenseID]
	if !exists {
		return nil
	}

	// Count nodes under this license
	var nodes []*NodeLicenseBinding
	totalDebt := 0.0
	criticalNodes := 0

	for _, binding := range dle.nodeBindings {
		if binding.LicenseID == licenseID {
			nodes = append(nodes, binding)
			debt := dle.complianceWeights[binding.NodeID]
			totalDebt += debt
			if debt > 5.0 { // Arbitrary critical threshold
				criticalNodes++
			}
		}
	}

	return map[string]interface{}{
		"license_tier":    lic.Tier,
		"node_quota":      lic.NodeQuota,
		"nodes_used":      len(nodes),
		"nodes_available": lic.NodeQuota - lic.NodeCount,
		"total_debt":      totalDebt,
		"critical_nodes":  criticalNodes,
		"average_debt":    totalDebt / float64(len(nodes)+1),
		"is_balanced":     totalDebt <= 0,
		"expires_at":      lic.ExpiresAt,
	}
}

// EnforceAirGapIfNeeded validates Pharaoh tier offline licenses
// Called by: cmd/agent/main.go on startup
func (dle *DAGLicenseEnforcer) EnforceAirGapIfNeeded(licenseID string, systemIsAirGapped bool) error {
	dle.mu.Lock()
	defer dle.mu.Unlock()

	lic, exists := dle.manager.licenses[licenseID]
	if !exists {
		return fmt.Errorf(ErrLicenseNotFoundFmt, licenseID)
	}

	// Only Pharaoh tier can use air-gap
	if systemIsAirGapped && lic.Tier != TierOsiris {
		return fmt.Errorf("air-gap deployment requires Pharaoh tier, got %s", lic.Tier)
	}

	// If Pharaoh tier and air-gapped, validate offline signature
	if lic.Tier == TierOsiris && systemIsAirGapped {
		if lic.OfflineLicenseSig == "" {
			return fmt.Errorf("Pharaoh tier requires offline license signature (Shu Breath)")
		}

		// Cryptographic validation: parse JSON payload, verify expiry, and confirm license ID.
		valid, err := ValidateOfflineLicense(lic.OfflineLicenseSig)
		if err != nil {
			return fmt.Errorf("offline license validation failed for %s: %w", licenseID, err)
		}
		if !valid {
			return fmt.Errorf("offline license rejected for %s: signature not valid", licenseID)
		}
	}

	return nil
}

// RekeyOfflineLicense renews air-gap license (annual)
// Called by: CLI command "adinkhepra renew-offline-license"
func (dle *DAGLicenseEnforcer) RekeyOfflineLicense(licenseID string) (string, error) {
	dle.mu.Lock()
	defer dle.mu.Unlock()

	lic, exists := dle.manager.licenses[licenseID]
	if !exists {
		return "", fmt.Errorf(ErrLicenseNotFoundFmt, licenseID)
	}

	if lic.Tier != TierOsiris {
		return "", fmt.Errorf("only Pharaoh tier supports offline licensing")
	}

	// Generate new offline license (valid 365 days)
	newSig, err := dle.manager.GenerateOfflineLicense(licenseID, 365)
	if err != nil {
		return "", err
	}

	lic.OfflineLicenseSig = newSig
	lic.ExpiresAt = time.Now().AddDate(0, 0, 365)

	return newSig, nil
}

// GetAmmitAlertStatus checks for critical nodes across all licenses
// Called by: Dashboard endpoint GET /admin/ammit-alerts
func (dle *DAGLicenseEnforcer) GetAmmitAlertStatus() []map[string]interface{} {
	dle.mu.RLock()
	defer dle.mu.RUnlock()

	var alerts []map[string]interface{}

	for nodeID, binding := range dle.nodeBindings {
		debt := dle.complianceWeights[nodeID]

		// State code 15 (0b1111) = Ammit alert
		// Map debt to hypothetical state code
		if debt > 10.0 { // Critical threshold
			alerts = append(alerts, map[string]interface{}{
				"node_id":    nodeID,
				"license_id": binding.LicenseID,
				"debt":       debt,
				"state_code": 15,
				"alert_type": "ammit",
				"message":    "⚠️ AMMIT THE DEVOURER AWAITS",
			})
		}
	}

	return alerts
}
