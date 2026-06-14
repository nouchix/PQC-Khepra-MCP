package compliance

import (
	"fmt"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/lorentz"
)

// ComplianceDomain represents a CMMC Domain (e.g., AC, AU, IR)
type ComplianceDomain string

const (
	DomainAC ComplianceDomain = "Access Control"
	DomainAU ComplianceDomain = "Audit and Accountability"
	DomainCM ComplianceDomain = "Configuration Management"
	DomainIA ComplianceDomain = "Identification and Authentication"
	DomainIR ComplianceDomain = "Incident Response"
	DomainMA ComplianceDomain = "Maintenance"
	DomainMP ComplianceDomain = "Media Protection"
	DomainPE ComplianceDomain = "Physical Protection"
	DomainPS ComplianceDomain = "Personnel Security"
	DomainRA ComplianceDomain = "Risk Assessment"
	DomainCA ComplianceDomain = "Security Assessment"
	DomainSC ComplianceDomain = "System and Communications Protection"
	DomainSI ComplianceDomain = "System and Information Integrity"
	DomainSR ComplianceDomain = "Supply Chain Risk Management"
)

// ScannerInterface defines the contract for real-time detection tools (OpenSCAP, STIG-Viewer)
type ScannerInterface interface {
	// ScanControl checks if a specific CMMC/STIG control is passing
	ScanControl(controlID string) (bool, string, error)
	// RemediateControl attempts to fix a failing control automatically
	RemediateControl(controlID string) (bool, string, error)
}

// Control represents a single CMMC practice (e.g., AC.L2-3.1.1)
type Control struct {
	ID          string           `json:"id"`
	Domain      ComplianceDomain `json:"domain"`
	Description string           `json:"description"`
	Level       int              `json:"level"` // 1, 2, 3
}

// ControlImplementation tracks how a control is satisfied in the SSP
type ControlImplementation struct {
	ControlID      string    `json:"control_id"`
	Status         string    `json:"status"` // IMPLEMENTED, PLANNED, PARTIAL, N/A, FAILED_SCAN, AUTO_REMEDIATED
	Narrative      string    `json:"narrative"`
	EvidenceIDs    []string  `json:"evidence_ids"` // Links to DAG nodes verifying this
	LastAudited    time.Time `json:"last_audited"`
	LastScanResult string    `json:"last_scan_result,omitempty"`
}

// SystemSecurityPlan represents the digital SSP
type SystemSecurityPlan struct {
	SystemName      string                           `json:"system_name"`
	CAGECode        string                           `json:"cage_code"`
	SecurityOfficer string                           `json:"security_officer"` // ISSO
	Components      []SystemComponent                `json:"components"`
	Controls        map[string]ControlImplementation `json:"controls"`
	UpdatedAt       time.Time                        `json:"updated_at"`
}

type SystemComponent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"` // SERVER, ENDPOINT, NETWORK
	IsCUIAsset bool   `json:"is_cui_asset"`
}

// Manager handles the SSP and Compliance Lifecycle
type Manager struct {
	store   dag.Store
	SSP     *SystemSecurityPlan
	scanner ScannerInterface
}

// NewManager creates a new Compliance Manager
func NewManager(store dag.Store, scanner ScannerInterface) *Manager {
	return &Manager{
		store:   store,
		scanner: scanner,
		SSP: &SystemSecurityPlan{
			SystemName: "Khepra Protected Enclave",
			Controls:   make(map[string]ControlImplementation),
			Components: []SystemComponent{},
		},
	}
}

// UpdateControl updates the implementation status of a specific control manually
func (m *Manager) UpdateControl(controlID, status, narrative string, privKey []byte) error {
	impl := ControlImplementation{
		ControlID:   controlID,
		Status:      status,
		Narrative:   narrative,
		LastAudited: time.Now(),
	}
	m.SSP.Controls[controlID] = impl
	m.SSP.UpdatedAt = time.Now()

	// Log to DAG
	return m.logControlUpdate(impl, privKey)
}

// AuditControl triggers a scan for a specific control and updates the SSP
func (m *Manager) AuditControl(controlID string, privKey []byte) (bool, error) {
	if m.scanner == nil {
		return false, fmt.Errorf("scanner not initialized")
	}

	passed, evidence, err := m.scanner.ScanControl(controlID)
	if err != nil {
		return false, err
	}

	status := "IMPLEMENTED"
	if !passed {
		status = "FAILED_SCAN"
		// Failed scan is written to SSP and DAG. Trigger auto-remediation
		// by calling RemediateControl(controlID, privKey) on the Manager.
	}

	impl := ControlImplementation{
		ControlID:      controlID,
		Status:         status,
		Narrative:      fmt.Sprintf("Automated Scan Result: %s. Evidence: %s", status, evidence),
		LastAudited:    time.Now(),
		LastScanResult: evidence,
	}

	m.SSP.Controls[controlID] = impl
	m.SSP.UpdatedAt = time.Now()

	return passed, m.logControlUpdate(impl, privKey)
}

func (m *Manager) logControlUpdate(impl ControlImplementation, privKey []byte) error {
	// data, _ := json.Marshal(impl) // unused

	node := dag.Node{
		Action: fmt.Sprintf("ssp-update:%s", impl.ControlID),
		Symbol: "Eban", // Fence/Protection
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"control_id": impl.ControlID,
			"status":     impl.Status,
			"narrative":  impl.Narrative, // Truncate if too long in real impl
			"type":       "SSP_MODIFICATION",
		},
	}
	// Sign and Add
	if err := node.Sign(privKey); err != nil {
		return err
	}
	return m.store.Add(&node, []string{})
}
