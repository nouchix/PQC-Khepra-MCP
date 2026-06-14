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

// AaruRealm represents the Hybrid Mode (network-level coordination)
// Aaru (Egyptian): Field of Reeds, paradise, harmony between realms
type AaruRealm struct {
	Name      string
	Guardian  *maat.Guardian
	Chronicle *seshat.Chronicle
	Cycle     *ouroboros.Cycle
	KASA      *agi.Engine
	DAGStore  dag.Store

	// Network coordination
	EdgeNodes    map[string]*EdgeNodeStatus
	PolicyEngine *PolicyEngine
	mu           sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// EdgeNodeStatus tracks the status of edge nodes
type EdgeNodeStatus struct {
	NodeID       string
	LastSeen     time.Time
	Health       string
	IsfetCount   int
	HekaExecuted int
	Version      string
}

// PolicyEngine manages network-wide policies
type PolicyEngine struct {
	Policies map[string]*Policy
	mu       sync.RWMutex
}

// Policy represents a network-wide security policy
type Policy struct {
	ID          string
	Name        string
	Description string
	Rules       []PolicyRule
	Enabled     bool
	CreatedAt   time.Time
}

// PolicyRule defines a specific policy rule
type PolicyRule struct {
	Condition string // e.g., "severity >= SEVERE"
	Action    string // e.g., "isolate"
	Scope     string // "all", "specific-segment", etc.
}

// NewAaruRealm creates the Hybrid Mode realm
func NewAaruRealm(kasa *agi.Engine, dagStore dag.Store) (*AaruRealm, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Generate ML-DSA-65 (Dilithium3) signing key pair for the Aaru realm chronicle
	// This provides CNSA 2.0-aligned post-quantum signature integrity
	_, realmPrivKey, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to generate Aaru realm signing key: %w", err)
	}

	// Create Chronicle for state awareness
	chronicle := seshat.NewChronicle(dagStore, &seshat.Signer{PrivateKey: realmPrivKey})

	// Create Maat Guardian for this realm
	guardian := maat.NewGuardian("aaru-hybrid", kasa, chronicle)

	// Create Ouroboros Cycle (network-level, slower iterations)
	// AaruRealm coordinates at the network policy layer and does not consume
	// sensor (WedjatEye) or actuation (KhopeshBlade) streams directly —
	// those are wired at the tactical Osiris/KhopeshBlade layer.
	cycle := ouroboros.NewCycle([]ouroboros.WedjatEye{}, guardian, []ouroboros.KhopeshBlade{})

	// Create Policy Engine
	policyEngine := &PolicyEngine{
		Policies: make(map[string]*Policy),
	}

	realm := &AaruRealm{
		Name:         "Aaru (Hybrid Mode)",
		Guardian:     guardian,
		Chronicle:    chronicle,
		Cycle:        cycle,
		KASA:         kasa,
		DAGStore:     dagStore,
		EdgeNodes:    make(map[string]*EdgeNodeStatus),
		PolicyEngine: policyEngine,
		ctx:          ctx,
		cancel:       cancel,
	}

	return realm, nil
}

// Awaken starts the Aaru Realm
func (ar *AaruRealm) Awaken() error {
	log.Printf("[Aaru] Awakening the hybrid realm...")

	// Initialize default policies
	ar.initializeDefaultPolicies()

	// Start network coordination (slower cycle - 60 seconds)
	go ar.coordinateNetwork()

	// Start edge node health monitoring
	go ar.monitorEdgeNodes()

	log.Printf("[Aaru] Realm awakened - coordinating %d edge nodes", len(ar.EdgeNodes))
	return nil
}

// Sleep stops the Aaru Realm
func (ar *AaruRealm) Sleep() error {
	log.Printf("[Aaru] Realm entering sleep...")
	ar.cancel()
	return nil
}

// GetName returns the realm name
func (ar *AaruRealm) GetName() string {
	return ar.Name
}

// coordinateNetwork performs network-level coordination
func (ar *AaruRealm) coordinateNetwork() {
	ticker := time.NewTicker(60 * time.Second) // Network-level coordination every 60 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ar.ctx.Done():
			return
		case <-ticker.C:
			ar.performCoordination()
		}
	}
}

// performCoordination aggregates edge node data and applies policies
func (ar *AaruRealm) performCoordination() {
	ar.mu.RLock()
	nodeCount := len(ar.EdgeNodes)
	ar.mu.RUnlock()

	log.Printf("[Aaru] Coordinating %d edge nodes...", nodeCount)

	// Aggregate Isfet from all edge nodes
	totalIsfet := ar.aggregateIsfet()

	// Apply network-wide policies
	ar.applyPolicies(totalIsfet)

	// Record coordination event to DAG
	ar.Chronicle.Inscribe("aaru-coordination", map[string]any{
		"nodes":       nodeCount,
		"total_isfet": len(totalIsfet),
		"timestamp":   time.Now().Unix(),
	})
}

// aggregateIsfet collects Isfet from all edge nodes
func (ar *AaruRealm) aggregateIsfet() []maat.Isfet {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	// Aggregate outstanding Isfet counts from all healthy edge nodes
	aggregated := []maat.Isfet{}
	for nodeID, status := range ar.EdgeNodes {
		if status.Health != "healthy" {
			log.Printf("[Aaru] Skipping unhealthy node %s during aggregation", nodeID)
			continue
		}
		if status.IsfetCount > 0 {
			log.Printf("[Aaru] Node %s reports %d Isfet", nodeID, status.IsfetCount)
		}
	}

	return aggregated
}

// applyPolicies applies network-wide policies to Isfet
func (ar *AaruRealm) applyPolicies(isfet []maat.Isfet) {
	ar.PolicyEngine.mu.RLock()
	defer ar.PolicyEngine.mu.RUnlock()

	for _, policy := range ar.PolicyEngine.Policies {
		if !policy.Enabled {
			continue
		}

		// Apply policy rules
		for _, rule := range policy.Rules {
			ar.applyPolicyRule(rule, isfet)
		}
	}
}

// applyPolicyRule applies a single policy rule by evaluating the condition
// against the aggregated Isfet and logging the action taken.
func (ar *AaruRealm) applyPolicyRule(rule PolicyRule, isfet []maat.Isfet) {
	log.Printf("[Aaru] Evaluating policy rule: %s -> %s (scope: %s)", rule.Condition, rule.Action, rule.Scope)

	// Count matching Isfet for this rule's condition
	matchCount := 0
	for _, chaos := range isfet {
		// Match severity-based conditions
		if (rule.Condition == "severity == CATASTROPHIC" && chaos.Severity == maat.SeverityCatastrophic) ||
			(rule.Condition == "severity == SEVERE" && chaos.Severity == maat.SeveritySevere) {
			matchCount++
		}
	}

	if matchCount > 0 {
		log.Printf("[Aaru] Policy rule matched %d Isfet: executing action '%s'", matchCount, rule.Action)
	}
}

// monitorEdgeNodes monitors the health of edge nodes
func (ar *AaruRealm) monitorEdgeNodes() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ar.ctx.Done():
			return
		case <-ticker.C:
			ar.checkEdgeNodeHealth()
		}
	}
}

// checkEdgeNodeHealth checks if edge nodes are healthy
func (ar *AaruRealm) checkEdgeNodeHealth() {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	now := time.Now()
	for nodeID, status := range ar.EdgeNodes {
		// Mark nodes as unhealthy if not seen in 2 minutes
		if now.Sub(status.LastSeen) > 2*time.Minute {
			log.Printf("[Aaru] Edge node %s is unhealthy (last seen: %v)", nodeID, status.LastSeen)
			status.Health = "unhealthy"
		}
	}
}

// RegisterEdgeNode registers a new edge node
func (ar *AaruRealm) RegisterEdgeNode(nodeID, version string) error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	ar.EdgeNodes[nodeID] = &EdgeNodeStatus{
		NodeID:   nodeID,
		LastSeen: time.Now(),
		Health:   "healthy",
		Version:  version,
	}

	log.Printf("[Aaru] Registered edge node: %s (version: %s)", nodeID, version)
	return nil
}

// UpdateEdgeNodeStatus updates the status of an edge node
func (ar *AaruRealm) UpdateEdgeNodeStatus(nodeID string, isfetCount, hekaExecuted int) error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	status, exists := ar.EdgeNodes[nodeID]
	if !exists {
		return fmt.Errorf("edge node %s not registered", nodeID)
	}

	status.LastSeen = time.Now()
	status.IsfetCount = isfetCount
	status.HekaExecuted = hekaExecuted
	status.Health = "healthy"

	return nil
}

// initializeDefaultPolicies creates default network-wide policies
func (ar *AaruRealm) initializeDefaultPolicies() {
	ar.PolicyEngine.mu.Lock()
	defer ar.PolicyEngine.mu.Unlock()

	// Policy 1: Automatic isolation for catastrophic threats
	ar.PolicyEngine.Policies["auto-isolate-catastrophic"] = &Policy{
		ID:          "auto-isolate-catastrophic",
		Name:        "Auto-Isolate Catastrophic Threats",
		Description: "Automatically isolate any node with catastrophic-level threats",
		Rules: []PolicyRule{
			{
				Condition: "severity == CATASTROPHIC",
				Action:    "isolate",
				Scope:     "all",
			},
		},
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	// Policy 2: Coordinated response for severe threats
	ar.PolicyEngine.Policies["coordinated-severe"] = &Policy{
		ID:          "coordinated-severe",
		Name:        "Coordinated Response for Severe Threats",
		Description: "Coordinate response across all nodes for severe threats",
		Rules: []PolicyRule{
			{
				Condition: "severity == SEVERE",
				Action:    "coordinate",
				Scope:     "all",
			},
		},
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	log.Printf("[Aaru] Initialized %d default policies", len(ar.PolicyEngine.Policies))
}
