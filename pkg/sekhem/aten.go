package sekhem

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/agi"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/ouroboros"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/seshat"
)

const (
	FrameworkNIST80053 = "NIST-800-53"
)

// AtenRealm represents the Sovereign/Iron Bank Mode (strategic orchestration)
// Aten (Egyptian): The sun disk, supreme deity, centralized power
type AtenRealm struct {
	Name      string
	Guardian  *maat.Guardian
	Chronicle *seshat.Chronicle
	Cycle     *ouroboros.Cycle
	KASA      *agi.Engine
	DAGStore  dag.Store

	// Strategic orchestration
	GlobalPolicies  map[string]*GlobalPolicy
	ComplianceRules map[string]*ComplianceRule
	AirGappedMode   bool
	mu              sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// GlobalPolicy represents a strategic, organization-wide policy
type GlobalPolicy struct {
	ID          string
	Name        string
	Description string
	Framework   string // "STIG", FrameworkNIST80053, "CMMC", etc.
	Controls    []ControlMapping
	Enforcement string // "mandatory", "recommended", "audit-only"
	CreatedAt   time.Time
}

// ControlMapping maps a policy to specific compliance controls
type ControlMapping struct {
	ControlID   string
	Framework   string
	Description string
	Automated   bool
}

// ComplianceRule represents a compliance requirement
type ComplianceRule struct {
	ID          string
	Framework   string
	Control     string
	Requirement string
	Severity    maat.Severity
	Automated   bool
}

// NewAtenRealm creates the Sovereign/Iron Bank Mode realm
func NewAtenRealm(kasa *agi.Engine, dagStore dag.Store, airGapped bool) (*AtenRealm, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Generate ML-DSA-65 (Dilithium3) signing key pair for the Aten realm chronicle
	// This provides CNSA 2.0-aligned post-quantum signature integrity
	_, realmPrivKey, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to generate Aten realm signing key: %w", err)
	}

	// Create Chronicle for state awareness
	chronicle := seshat.NewChronicle(dagStore, &seshat.Signer{PrivateKey: realmPrivKey})

	// Create Maat Guardian for this realm
	guardian := maat.NewGuardian("aten-sovereign", kasa, chronicle)

	// Create Ouroboros Cycle (strategic level, very slow iterations)
	// AtenRealm operates at the strategic policy layer and does not consume
	// sensor (WedjatEye) or actuation (KhopeshBlade) streams directly —
	// those are wired at the tactical Aaru/Osiris layer.
	cycle := ouroboros.NewCycle([]ouroboros.WedjatEye{}, guardian, []ouroboros.KhopeshBlade{})

	realm := &AtenRealm{
		Name:            "Aten (Sovereign/Iron Bank Mode)",
		Guardian:        guardian,
		Chronicle:       chronicle,
		Cycle:           cycle,
		KASA:            kasa,
		DAGStore:        dagStore,
		GlobalPolicies:  make(map[string]*GlobalPolicy),
		ComplianceRules: make(map[string]*ComplianceRule),
		AirGappedMode:   airGapped,
		ctx:             ctx,
		cancel:          cancel,
	}

	return realm, nil
}

// Awaken starts the Aten Realm
func (ar *AtenRealm) Awaken() error {
	log.Printf("[Aten] Awakening the sovereign realm...")

	if ar.AirGappedMode {
		log.Printf("[Aten] Running in AIR-GAPPED mode (no external connectivity)")
	}

	// Initialize compliance frameworks
	ar.initializeComplianceFrameworks()

	// Start strategic orchestration (very slow cycle - 5 minutes)
	go ar.orchestrateStrategy()

	// Start compliance monitoring
	go ar.monitorCompliance()

	log.Printf("[Aten] Realm awakened - managing %d global policies", len(ar.GlobalPolicies))
	return nil
}

// Sleep stops the Aten Realm
func (ar *AtenRealm) Sleep() error {
	log.Printf("[Aten] Realm entering sleep...")
	ar.cancel()
	return nil
}

// GetName returns the realm name
func (ar *AtenRealm) GetName() string {
	return ar.Name
}

// orchestrateStrategy performs strategic-level orchestration
func (ar *AtenRealm) orchestrateStrategy() {
	ticker := time.NewTicker(5 * time.Minute) // Strategic orchestration every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ar.ctx.Done():
			return
		case <-ticker.C:
			ar.performStrategicOrchestration()
		}
	}
}

// performStrategicOrchestration executes strategic-level decisions
func (ar *AtenRealm) performStrategicOrchestration() {
	ar.mu.RLock()
	policyCount := len(ar.GlobalPolicies)
	ar.mu.RUnlock()

	log.Printf("[Aten] Performing strategic orchestration (%d global policies)...", policyCount)

	// Evaluate global policies
	ar.evaluateGlobalPolicies()

	// Generate compliance reports
	ar.generateComplianceReport()

	// Record orchestration event to DAG
	ar.Chronicle.Inscribe("aten-orchestration", map[string]any{
		"policies":   policyCount,
		"air_gapped": ar.AirGappedMode,
		"timestamp":  time.Now().Unix(),
	})
}

// evaluateGlobalPolicies evaluates all global policies
func (ar *AtenRealm) evaluateGlobalPolicies() {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	for _, policy := range ar.GlobalPolicies {
		controlCount := len(policy.Controls)
		automatedCount := 0
		for _, ctrl := range policy.Controls {
			if ctrl.Automated {
				automatedCount++
			}
		}
		log.Printf("[Aten] Policy '%s' (%s): %d/%d controls automated, enforcement=%s",
			policy.Name, policy.Framework, automatedCount, controlCount, policy.Enforcement)
	}
}

// generateComplianceReport generates a compliance status report
func (ar *AtenRealm) generateComplianceReport() {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	totalRules := len(ar.ComplianceRules)
	automatedRules := 0

	for _, rule := range ar.ComplianceRules {
		if rule.Automated {
			automatedRules++
		}
	}

	log.Printf("[Aten] Compliance Report: %d/%d rules automated (%.1f%%)",
		automatedRules, totalRules, float64(automatedRules)/float64(totalRules)*100)

	// Record compliance report to DAG
	ar.Chronicle.Inscribe("compliance-report", map[string]any{
		"total_rules":     totalRules,
		"automated_rules": automatedRules,
		"automation_rate": float64(automatedRules) / float64(totalRules),
		"timestamp":       time.Now().Unix(),
	})
}

// monitorCompliance monitors compliance status
func (ar *AtenRealm) monitorCompliance() {
	ticker := time.NewTicker(15 * time.Minute) // Compliance monitoring every 15 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ar.ctx.Done():
			return
		case <-ticker.C:
			ar.checkComplianceStatus()
		}
	}
}

// checkComplianceStatus checks the current compliance status
func (ar *AtenRealm) checkComplianceStatus() {
	ar.mu.RLock()

	totalRules := len(ar.ComplianceRules)
	automated := 0
	manual := 0
	for _, rule := range ar.ComplianceRules {
		if rule.Automated {
			automated++
		} else {
			manual++
		}
	}

	ar.mu.RUnlock() // Release before calling generateComplianceReport (which also locks)

	log.Printf("[Aten] Compliance status: %d total rules (%d automated, %d manual)",
		totalRules, automated, manual)

	if manual > 0 {
		log.Printf("[Aten] WARNING: %d compliance rules require manual verification", manual)
	}

	ar.generateComplianceReport()
}

// initializeComplianceFrameworks initializes compliance frameworks
func (ar *AtenRealm) initializeComplianceFrameworks() {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	// STIG Compliance Policy
	ar.GlobalPolicies["rhel-09-stig"] = &GlobalPolicy{
		ID:          "rhel-09-stig",
		Name:        "RHEL-09-STIG-V1R3 Compliance",
		Description: "DoD STIG compliance for RHEL 9",
		Framework:   "STIG",
		Controls: []ControlMapping{
			{ControlID: "SV-257777", Framework: "RHEL-09-STIG", Description: "System must use FIPS-validated cryptography", Automated: true},
			{ControlID: "SV-257778", Framework: "RHEL-09-STIG", Description: "System must enforce password complexity", Automated: true},
		},
		Enforcement: "mandatory",
		CreatedAt:   time.Now(),
	}

	// NIST 800-53 Compliance Policy
	ar.GlobalPolicies["nist-800-53"] = &GlobalPolicy{
		ID:          "nist-800-53",
		Name:        "NIST 800-53 Rev 5 Compliance",
		Description: "NIST security controls for federal systems",
		Framework:   FrameworkNIST80053,
		Controls: []ControlMapping{
			{ControlID: "AC-2", Framework: FrameworkNIST80053, Description: "Account Management", Automated: true},
			{ControlID: "AU-2", Framework: FrameworkNIST80053, Description: "Audit Events", Automated: true},
			{ControlID: "SC-13", Framework: FrameworkNIST80053, Description: "Cryptographic Protection", Automated: true},
		},
		Enforcement: "mandatory",
		CreatedAt:   time.Now(),
	}

	// CMMC Level 3 Compliance Policy
	ar.GlobalPolicies["cmmc-l3"] = &GlobalPolicy{
		ID:          "cmmc-l3",
		Name:        "CMMC Level 3 Compliance",
		Description: "Cybersecurity Maturity Model Certification Level 3",
		Framework:   "CMMC",
		Controls: []ControlMapping{
			{ControlID: "AC.3.018", Framework: "CMMC", Description: "Audit record generation", Automated: true},
			{ControlID: "SC.3.177", Framework: "CMMC", Description: "Cryptographic protection", Automated: true},
			{ControlID: "SI.3.216", Framework: "CMMC", Description: "Threat monitoring", Automated: true},
		},
		Enforcement: "mandatory",
		CreatedAt:   time.Now(),
	}

	// Initialize compliance rules
	ar.ComplianceRules["stig-crypto"] = &ComplianceRule{
		ID:          "stig-crypto",
		Framework:   "STIG",
		Control:     "SV-257777",
		Requirement: "System must use FIPS-validated cryptography",
		Severity:    maat.SeverityCatastrophic,
		Automated:   true,
	}

	ar.ComplianceRules["nist-audit"] = &ComplianceRule{
		ID:          "nist-audit",
		Framework:   FrameworkNIST80053,
		Control:     "AU-2",
		Requirement: "System must generate audit records",
		Severity:    maat.SeveritySevere,
		Automated:   true,
	}

	log.Printf("[Aten] Initialized %d compliance frameworks and %d rules",
		len(ar.GlobalPolicies), len(ar.ComplianceRules))
}

// AddGlobalPolicy adds a new global policy
func (ar *AtenRealm) AddGlobalPolicy(policy *GlobalPolicy) error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	ar.GlobalPolicies[policy.ID] = policy
	log.Printf("[Aten] Added global policy: %s (%s)", policy.Name, policy.Framework)

	// Record to DAG
	ar.Chronicle.Inscribe("policy-added", map[string]any{
		"policy_id":   policy.ID,
		"framework":   policy.Framework,
		"enforcement": policy.Enforcement,
		"timestamp":   time.Now().Unix(),
	})

	return nil
}

// RemoveGlobalPolicy removes a global policy
func (ar *AtenRealm) RemoveGlobalPolicy(policyID string) error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	policy, exists := ar.GlobalPolicies[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}

	delete(ar.GlobalPolicies, policyID)
	log.Printf("[Aten] Removed global policy: %s", policy.Name)

	// Record to DAG
	ar.Chronicle.Inscribe("policy-removed", map[string]any{
		"policy_id": policyID,
		"timestamp": time.Now().Unix(),
	})

	return nil
}

// GetComplianceStatus returns the current compliance status
func (ar *AtenRealm) GetComplianceStatus() map[string]any {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	totalRules := len(ar.ComplianceRules)
	automatedRules := 0

	for _, rule := range ar.ComplianceRules {
		if rule.Automated {
			automatedRules++
		}
	}

	return map[string]any{
		"total_policies":  len(ar.GlobalPolicies),
		"total_rules":     totalRules,
		"automated_rules": automatedRules,
		"automation_rate": float64(automatedRules) / float64(totalRules),
		"air_gapped_mode": ar.AirGappedMode,
		"frameworks":      []string{"STIG", "NIST-800-53", "CMMC"},
	}
}
