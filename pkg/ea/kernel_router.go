// Package ea — KernelRouter implements a mythos-router-inspired security capability
// dispatcher. Each security domain (STIG, Forensics, IR, etc.) is a registered
// KernelAgent. The router classifies the incoming SecurityContext and dispatches
// to the appropriate set of agents. The EA engine continuously optimises the
// capability sequencing based on real-world outcome signals.
package ea

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/google/uuid"
)

// ─── Capability Registry ──────────────────────────────────────────────────────

// Capability identifies a distinct security domain handled by a KernelAgent.
type Capability int

const (
	CapSTIG       Capability = iota // STIG validation + auto-remediation
	CapForensics                     // Memory/disk forensics snapshots
	CapIR                            // Incident response playbooks
	CapBCDR                          // Backup/recovery verification
	CapPQC                           // Crypto inventory + PQC migration
	CapFIM                           // File integrity monitoring
	CapNetwork                       // Network topology + attack path analysis
	CapSBOM                          // Software bill of materials generation
)

var capabilityNames = map[Capability]string{
	CapSTIG:      "stig",
	CapForensics: "forensics",
	CapIR:        "ir",
	CapBCDR:      "bcdr",
	CapPQC:       "pqc",
	CapFIM:       "fim",
	CapNetwork:   "network",
	CapSBOM:      "sbom",
}

func (c Capability) String() string {
	if s, ok := capabilityNames[c]; ok {
		return s
	}
	return fmt.Sprintf("capability(%d)", int(c))
}

// ─── Agent Interface ──────────────────────────────────────────────────────────

// KernelAgent is the interface every security sub-agent must implement.
type KernelAgent interface {
	// Capability returns the domain this agent handles.
	Capability() Capability

	// Execute runs the agent for the given context and returns a structured result.
	// Implementations must respect ctx.Done() for cancellation.
	Execute(ctx context.Context, sec *SecurityContext) (*AgentResult, error)

	// Name returns a human-readable identifier for logging and DAG annotation.
	Name() string
}

// AgentResult carries the output of a KernelAgent execution.
type AgentResult struct {
	AgentName    string                 `json:"agent_name"`
	Capability   string                 `json:"capability"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  time.Time              `json:"completed_at"`
	FindingCount int                    `json:"finding_count"`
	RiskScore    float64                `json:"risk_score"` // 0–100
	Findings     []Finding              `json:"findings,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	DAGNodeID    string                 `json:"dag_node_id,omitempty"`
}

// Finding is a single security issue discovered by a KernelAgent.
type Finding struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Control     string    `json:"control,omitempty"` // STIG rule / CMMC control
	Remediation string    `json:"remediation,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// ─── Security Context ─────────────────────────────────────────────────────────

// SecurityContext describes the environment being assessed.
// The KernelRouter uses it to decide which capabilities to invoke and in what order.
type SecurityContext struct {
	// Environment signals
	Target          string   `json:"target"`           // hostname or IP
	HasCUI          bool     `json:"has_cui"`          // Controlled Unclassified Info present
	IsAirGapped     bool     `json:"is_air_gapped"`
	IsContainerised bool     `json:"is_containerised"`
	CloudProvider   string   `json:"cloud_provider"`   // aws | azure | gcp | on-prem | govcloud
	OSFamily        string   `json:"os_family"`        // linux | windows | darwin
	Frameworks      []string `json:"frameworks"`       // cmmc | stig | nist-800-53 | hipaa
	Tags            []string `json:"tags"`

	// Threat signals
	HasAnomalySignal  bool     `json:"has_anomaly_signal"`
	ActiveIncident    bool     `json:"active_incident"`
	LegacyCryptoFound bool     `json:"legacy_crypto_found"`
	UnpatchedCVEs     int      `json:"unpatched_cves"`
	ThreatActors      []string `json:"threat_actors,omitempty"`

	// Runtime metadata
	RequestID string    `json:"request_id"`
	CreatedAt time.Time `json:"created_at"`
}

// NewSecurityContext constructs a SecurityContext with sane defaults.
func NewSecurityContext(target string) *SecurityContext {
	return &SecurityContext{
		Target:    target,
		RequestID: uuid.New().String(),
		CreatedAt: time.Now().UTC(),
	}
}

// ─── Routing Table ────────────────────────────────────────────────────────────

// RouteWeights holds EA-evolved weights controlling how eagerly each capability
// is triggered. The EA engine writes to these weights every generation.
type RouteWeights struct {
	mu      sync.RWMutex
	weights map[Capability]float64
}

func newDefaultRouteWeights() *RouteWeights {
	return &RouteWeights{
		weights: map[Capability]float64{
			CapSTIG:      1.0,
			CapForensics: 0.6,
			CapIR:        0.5,
			CapBCDR:      0.4,
			CapPQC:       0.8,
			CapFIM:       0.7,
			CapNetwork:   0.6,
			CapSBOM:      0.5,
		},
	}
}

// Update replaces the weight for a capability. Called by EA after each evolution.
func (r *RouteWeights) Update(cap Capability, weight float64) {
	r.mu.Lock()
	r.weights[cap] = weight
	r.mu.Unlock()
}

// Get returns the current weight for a capability.
func (r *RouteWeights) Get(cap Capability) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.weights[cap]
}

// ─── KernelRouter ─────────────────────────────────────────────────────────────

// KernelRouter dispatches a SecurityContext to the set of KernelAgents determined
// by context classification and EA-evolved routing weights.
type KernelRouter struct {
	mu       sync.RWMutex
	agents   map[Capability]KernelAgent
	weights  *RouteWeights
	dag      dag.Store
	eaEngine *EAEngine // optional; enables weight evolution
}

// NewKernelRouter creates a router with an in-memory DAG store.
func NewKernelRouter(dagStore dag.Store) *KernelRouter {
	if dagStore == nil {
		dagStore = dag.NewMemory()
	}
	return &KernelRouter{
		agents:  make(map[Capability]KernelAgent),
		weights: newDefaultRouteWeights(),
		dag:     dagStore,
	}
}

// Register adds a KernelAgent to the router. Panics on duplicate capability.
func (r *KernelRouter) Register(agent KernelAgent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cap := agent.Capability()
	if _, exists := r.agents[cap]; exists {
		panic(fmt.Sprintf("ea: KernelRouter: duplicate agent for capability %s", cap))
	}
	r.agents[cap] = agent
}

// AttachEA wires the EA engine so that routing weights evolve each generation.
func (r *KernelRouter) AttachEA(eng *EAEngine) {
	r.mu.Lock()
	r.eaEngine = eng
	r.mu.Unlock()
}

// Classify determines which capabilities to invoke for a given SecurityContext.
// The result is ordered by activation weight (descending) so higher-priority
// capabilities execute first.
func (r *KernelRouter) Classify(sec *SecurityContext) []Capability {
	type scored struct {
		cap    Capability
		weight float64
	}

	candidates := make([]scored, 0, 8)

	// STIG: always for CUI or government frameworks
	if sec.HasCUI || containsAny(sec.Frameworks, "stig", "cmmc", "nist-800-53") {
		candidates = append(candidates, scored{CapSTIG, r.weights.Get(CapSTIG)})
	}

	// PQC: always when legacy crypto found or when CUI present
	if sec.LegacyCryptoFound || sec.HasCUI {
		candidates = append(candidates, scored{CapPQC, r.weights.Get(CapPQC)})
	}

	// Forensics: anomaly signal or active incident
	if sec.HasAnomalySignal || sec.ActiveIncident {
		candidates = append(candidates, scored{CapForensics, r.weights.Get(CapForensics)})
	}

	// IR: active incident
	if sec.ActiveIncident {
		candidates = append(candidates, scored{CapIR, r.weights.Get(CapIR)})
	}

	// FIM: always for air-gapped or sensitive environments
	if sec.IsAirGapped || sec.HasCUI {
		candidates = append(candidates, scored{CapFIM, r.weights.Get(CapFIM)})
	}

	// BCDR: air-gapped environments need recovery verification
	if sec.IsAirGapped {
		candidates = append(candidates, scored{CapBCDR, r.weights.Get(CapBCDR)})
	}

	// Network: always for non-air-gapped targets
	if !sec.IsAirGapped || sec.HasAnomalySignal {
		candidates = append(candidates, scored{CapNetwork, r.weights.Get(CapNetwork)})
	}

	// SBOM: containerised or when CVEs present
	if sec.IsContainerised || sec.UnpatchedCVEs > 0 {
		candidates = append(candidates, scored{CapSBOM, r.weights.Get(CapSBOM)})
	}

	// De-duplicate
	seen := make(map[Capability]bool)
	result := make([]scored, 0, len(candidates))
	for _, s := range candidates {
		if !seen[s.cap] {
			seen[s.cap] = true
			result = append(result, s)
		}
	}

	// Sort by weight descending
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && result[j].weight > result[j-1].weight; j-- {
			result[j], result[j-1] = result[j-1], result[j]
		}
	}

	caps := make([]Capability, len(result))
	for i, s := range result {
		caps[i] = s.cap
	}
	return caps
}

// Route executes the capabilities identified for sec, sequentially, respecting
// ctx cancellation. Results from all agents are returned together.
func (r *KernelRouter) Route(ctx context.Context, sec *SecurityContext) ([]*AgentResult, error) {
	if sec == nil {
		return nil, errors.New("ea: KernelRouter.Route: SecurityContext is nil")
	}

	caps := r.Classify(sec)
	if len(caps) == 0 {
		return nil, errors.New("ea: KernelRouter.Route: no capabilities matched the security context")
	}

	r.mu.RLock()
	agentsCopy := make(map[Capability]KernelAgent, len(r.agents))
	for k, v := range r.agents {
		agentsCopy[k] = v
	}
	r.mu.RUnlock()

	results := make([]*AgentResult, 0, len(caps))
	for _, cap := range caps {
		agent, ok := agentsCopy[cap]
		if !ok {
			// Capability classified but no agent registered — fail loudly
			return nil, fmt.Errorf("ea: KernelRouter: no agent registered for capability %s", cap)
		}

		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		result, err := agent.Execute(ctx, sec)
		if err != nil {
			return results, fmt.Errorf("ea: agent %s failed: %w", agent.Name(), err)
		}

		// Record result to DAG
		if err := r.recordResultDAG(sec, result); err != nil {
			fmt.Printf("[EA-ROUTER] WARN: DAG record failed for %s: %v\n", agent.Name(), err)
		}

		results = append(results, result)
	}

	return results, nil
}

// UpdateWeightsFromGenome updates routing weights from the best EA individual's genome.
// Should be called after each EAEngine.Evolve() cycle.
func (r *KernelRouter) UpdateWeightsFromGenome(genome []byte) {
	if len(genome) < GenomeSize {
		return
	}
	traits := GenomeFitness(genome)

	// Capability flags byte layout (genome[8:16]):
	//   [0]=STIG, [1]=Forensics, [2]=IR, [3]=BCDR, [4]=PQC, [5]=FIM, [6]=Network, [7]=SBOM
	caps := []Capability{CapSTIG, CapForensics, CapIR, CapBCDR, CapPQC, CapFIM, CapNetwork, CapSBOM}
	for i, cap := range caps {
		if i < len(traits.CapFlags) {
			// Blend genome flag (0–1) with trait-derived base weight
			base := 0.4 + 0.6*normByte(traits.CapFlags[i])
			r.weights.Update(cap, base)
		}
	}
}

// ─── DAG Recording ────────────────────────────────────────────────────────────

func (r *KernelRouter) recordResultDAG(sec *SecurityContext, result *AgentResult) error {
	payload, err := json.Marshal(map[string]interface{}{
		"request_id":    sec.RequestID,
		"target":        sec.Target,
		"agent":         result.AgentName,
		"capability":    result.Capability,
		"finding_count": result.FindingCount,
		"risk_score":    result.RiskScore,
		"duration_ms":   result.CompletedAt.Sub(result.StartedAt).Milliseconds(),
	})
	if err != nil {
		return err
	}

	n := &dag.Node{
		Action: fmt.Sprintf("kernel_route:%s", result.Capability),
		Symbol: "Eban",
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		PQC:    map[string]string{"payload": string(payload)},
	}

	parents := []string{}
	if result.DAGNodeID != "" {
		parents = append(parents, result.DAGNodeID)
	}

	if err := r.dag.Add(n, parents); err != nil {
		return err
	}
	result.DAGNodeID = n.ID
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func containsAny(slice []string, targets ...string) bool {
	for _, s := range slice {
		for _, t := range targets {
			if s == t {
				return true
			}
		}
	}
	return false
}
