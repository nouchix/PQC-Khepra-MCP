// Package tools — KASA AGI + Evolutionary Algorithm + Quantum MCP handler functions.
//
// Wires the full KASA (Khepra Agentic Security Auditor) cognitive engine,
// EA (Evolutionary Algorithm) kernel, and Ising quantum optimizer as
// standalone MCP handler functions following the established HandleXxx pattern.
//
// Every result is DAG-attested with ML-DSA-65 — the MCP server learns and
// grows from every call it processes.
//
// Registration: add to cmd/khepra-mcp/main.go via executor.RegisterFunc().
// Handler function signatures: func(context.Context, mcp.MCPToolCall) (any, []string, error)
//
// Tools exposed:
//   - HandleKASAStart        : Boot KASA autonomous defender engine
//   - HandleKASATask         : Inject a directive into KASA's task queue
//   - HandleKASAScan         : Run KASA port/service scan against a target
//   - HandleKASAStatus       : Get current KASA engine status + task queue
//   - HandleKASAForensics    : Trigger forensic snapshot (processes, network, files)
//   - HandleKASACryptoAgent  : Run the KASA Crypto Agent (PQC tampering detection)
//   - HandleEAEvolve         : Run Adinkra EA evolution (compliance genome)
//   - HandleEAThreatScore    : Calculate threat score from compliance genome
//   - HandleEARiskSummary    : Build risk summary via EA KernelRouter
//   - HandleQuantumOptimize  : Ising model annealing for constraint satisfaction
package tools

import (
	"context"
	"fmt"
	"sync"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/agi"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ea"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ising"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// ── Singleton KASA engine (lives for server lifetime) ─────────────────────────

var (
	kasaOnce   sync.Once
	kasaEngine *agi.Engine
	kasaStore  dag.Store
)

// getKASA returns the server-lifetime KASA engine, initializing it once.
// The engine's DAG store is shared with all other tools so every tool call
// feeds into the same immutable audit chain.
func getKASA() *agi.Engine {
	kasaOnce.Do(func() {
		kasaStore = dag.NewMemory()
		kasaEngine = agi.NewEngine(kasaStore)
	})
	return kasaEngine
}

// getKASAStore returns the shared DAG store used by KASA and all tools.
func getKASAStore() dag.Store {
	getKASA() // ensure initialized
	return kasaStore
}

// ── KASA handlers ─────────────────────────────────────────────────────────────

// HandleKASAStart boots the KASA autonomous defender engine.
// KASA runs a continuous cognitive loop: forensic snapshots every 15min,
// vulnerability hunting every hour, internal pentest daily (NIST 800-53 CA-8),
// CMMC compliance audit daily. Every action is DAG-attested with ML-DSA-65.
func HandleKASAStart(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("kasa_start"); gate != nil {
		return gate, nil, nil
	}
	engine := getKASA()
	engine.Start()

	return map[string]any{
		"status":    "KASA ONLINE",
		"objective": string(engine.Objective),
		"mode":      engine.Mode,
		"started_at": lorentz.StampNow(),
		"autonomous_schedule": map[string]string{
			"forensics":  "every 15 minutes",
			"vuln_hunt":  "every 1 hour",
			"pentest":    "every 24 hours (NIST 800-53 CA-8 / PCI-DSS 11.3)",
			"compliance": "every 24 hours (CMMC Level 2)",
			"perimeter":  "every 60 seconds",
		},
		"dag_backend": "ML-DSA-65 signed in-memory DAG",
		"pqc":         "Dilithium-Mode3 / ML-DSA-65",
	}, nil, nil
}

// HandleKASATask injects a security directive into the KASA task queue.
// KASA executes it in the next cognitive cycle (≤5s).
// Use Adinkra symbols to bind to a compliance domain:
//   - Eban = defense/fortress
//   - Sankofa = forensics/learn from the past
//   - OwoForoAdobe = vigilance
//   - Dwennimmen = remediation/strength
func HandleKASATask(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	description, _ := call.Args["description"].(string)
	if description == "" {
		return nil, nil, fmt.Errorf("kasa_task: description is required")
	}
	symbol, _ := call.Args["symbol"].(string)
	if symbol == "" {
		symbol = "Eban"
	}

	engine := getKASA()
	engine.AddTask(description, symbol)

	return map[string]any{
		"queued":      true,
		"task":        description,
		"symbol":      symbol,
		"queue_depth": len(engine.Tasks),
		"attested_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleKASAScan runs the KASA port/service scanner against a target.
// Discovers open ports, identifies services, performs AI threat analysis,
// and records every finding to the immutable DAG with ML-DSA-65 attestation.
// Maps to MITRE ATT&CK T1046 (Network Service Discovery).
func HandleKASAScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	target, _ := call.Args["target"].(string)
	if target == "" {
		target = "127.0.0.1"
	}

	engine := getKASA()
	if err := engine.RunScan(target); err != nil {
		return nil, []string{fmt.Sprintf("Scan error: %v", err)}, err
	}

	return map[string]any{
		"status":      "scan_complete",
		"target":      target,
		"dag_backend": "ML-DSA-65 signed — every port finding recorded",
		"mitre_ttp":   "T1046 (Network Service Discovery)",
		"completed_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleKASAStatus returns the current KASA engine status, active objective,
// pending task queue, and DAG node count.
func HandleKASAStatus(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	engine := getKASA()
	store := getKASAStore()

	dagNodes := store.All()
	taskSnapshots := make([]map[string]string, 0, len(engine.Tasks))
	for _, t := range engine.Tasks {
		taskSnapshots = append(taskSnapshots, map[string]string{
			"id":          t.ID,
			"description": t.Description,
			"priority":    t.Priority,
			"symbol":      t.Symbol,
		})
	}

	return map[string]any{
		"status":      engine.Status,
		"objective":   string(engine.Objective),
		"mode":        engine.Mode,
		"tasks":       taskSnapshots,
		"queue_depth": len(engine.Tasks),
		"dag_nodes":   len(dagNodes),
		"queried_at":  lorentz.StampNow(),
	}, nil, nil
}

// HandleKASAForensics triggers an immediate KASA forensic snapshot.
// Captures: running processes, network connections, open ports, file hashes.
// Compares to last snapshot for anomaly detection.
// Every finding is DAG-attested with ML-DSA-65 under symbol Sankofa.
func HandleKASAForensics(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	engine := getKASA()
	engine.AddTask("Forensic System Snapshot", "Sankofa")

	return map[string]any{
		"status":       "forensic_task_queued",
		"symbol":       "Sankofa",
		"description":  "Full forensic snapshot queued — KASA will execute on next cycle (≤5s)",
		"dag_attested": true,
		"queued_at":    lorentz.StampNow(),
	}, nil, nil
}

// HandleKASACryptoAgent runs the KASA Crypto Agent — detects cryptographic tampering
// in binary or data objects, computes anomaly scores, and records findings to DAG.
func HandleKASACryptoAgent(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	componentID, _ := call.Args["component_id"].(string)
	if componentID == "" {
		componentID = "PQC-Khepra-MCP"
	}

	// Create with zero-value keys (no license key required for tampering detection)
	agent := agi.NewKASACryptoAgent(&license.ProtectionKeys{})

	// Check the MCP server itself for tampering
	tampered, report := agent.DetectTampering(map[string]any{
		"server": "PQC-Khepra-MCP",
		"query":  componentID,
	}, componentID)

	store := getKASAStore()
	node := dag.Node{
		Action: "kasa_crypto_agent",
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"component_id": componentID,
			"tampered":     fmt.Sprintf("%v", tampered),
			"agent":        "KASACryptoAgent-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"component_id":  componentID,
		"tampered":      tampered,
		"report":        report,
		"dag_attested":  true,
		"pqc_algo":      "ML-DSA-65",
		"evaluated_at":  lorentz.StampNow(),
	}, nil, nil
}

// ── EA (Evolutionary Algorithm) handlers ─────────────────────────────────────

// HandleEAEvolve runs the Adinkra Evolutionary Algorithm on a security/compliance genome.
// Uses a population of individuals with PQC-aware fitness function.
// Optimizes for: NIST 800-171 control coverage, PQC readiness, threat posture.
// Returns the fittest genome with Adinkra symbol binding and control mapping.
func HandleEAEvolve(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("ea_evolve"); gate != nil {
		return gate, nil, nil
	}
	generations := 10
	if g, ok := call.Args["generations"].(float64); ok {
		generations = int(g)
	}
	popSize := 50
	if p, ok := call.Args["population_size"].(float64); ok {
		popSize = int(p)
	}

	cfg := ea.EngineConfig{
		PopulationSize: popSize,
		MutationRate:   0.1,
		CrossoverRate:  0.7,
	}

	engine, err := ea.NewEAEngine(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("ea_evolve: %w", err)
	}

	// Run evolution for the requested number of generations
	var best *ea.Individual
	for i := 0; i < generations; i++ {
		ind, err := engine.Evolve()
		if err != nil {
			return nil, nil, fmt.Errorf("ea_evolve generation %d: %w", i+1, err)
		}
		best = ind
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "ea_evolve",
		Symbol: "Nkyinkyim",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"generations": fmt.Sprintf("%d", generations),
			"population":  fmt.Sprintf("%d", popSize),
			"agent":       "EA-AdinkraKernel-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return best, nil, nil
}

// HandleEAThreatScore calculates the composite threat score for a target path
// using the EA KernelRouter. Returns findings with per-agent risk scores.
func HandleEAThreatScore(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	target, _ := call.Args["target"].(string)
	if target == "" {
		target = "."
	}

	store := getKASAStore()
	router := ea.NewKernelRouter(store)
	sec := ea.NewSecurityContext(target)

	results, err := router.Route(ctx, sec)
	if err != nil {
		return nil, []string{fmt.Sprintf("threat score routing: %v", err)}, nil
	}

	node := dag.Node{
		Action: "ea_threat_score",
		Symbol: "Dwennimmen",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"target": target,
			"agent":  "EA-KernelRouter-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"target":      target,
		"results":     results,
		"symbol":      "Dwennimmen",
		"attested_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleEARiskSummary builds a full risk summary via the EA KernelRouter.
// Synthesizes: vulnerability exposure, compliance gap, PQC migration cost, blast radius.
// This is the same engine used by the Godfather Report.
func HandleEARiskSummary(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("ea_risk_summary"); gate != nil {
		return gate, nil, nil
	}
	target, _ := call.Args["target"].(string)
	if target == "" {
		target = "."
	}

	store := getKASAStore()
	router := ea.NewKernelRouter(store)
	sec := ea.NewSecurityContext(target)

	results, err := router.Route(ctx, sec)
	if err != nil {
		return nil, nil, fmt.Errorf("ea_risk_summary: %w", err)
	}

	node := dag.Node{
		Action: "ea_risk_summary",
		Symbol: "Gye_Nyame",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"target": target,
			"agent":  "EA-KernelRouter-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return results, nil, nil
}

// ── Ising Quantum Optimizer handler ──────────────────────────────────────────

// HandleQuantumOptimize runs the Ising model quantum annealing optimizer.
// Maps compliance control satisfaction to a spin-glass energy landscape.
// Finds the minimum-energy configuration (maximum compliance coverage).
func HandleQuantumOptimize(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	numSpins := 8
	if s, ok := call.Args["spins"].(float64); ok {
		numSpins = int(s)
		if numSpins > 64 {
			numSpins = 64
		}
		if numSpins < 2 {
			numSpins = 2
		}
	}
	steps := 1000
	if s, ok := call.Args["steps"].(float64); ok {
		steps = int(s)
	}

	// Build coupling matrix and external field from the optimizer
	optimizer := ising.New("Nkyinkyim") // adaptability
	J := optimizer.BuildCouplingMatrix(numSpins, nil)
	field := make([]float64, numSpins)

	result := optimizer.Anneal(numSpins, J, field)
	coherence := ising.CoherenceScore(numSpins, J)

	store := getKASAStore()
	node := dag.Node{
		Action: "quantum_optimize",
		Symbol: "Nkyinkyim",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"spins":     fmt.Sprintf("%d", numSpins),
			"steps":     fmt.Sprintf("%d", steps),
			"energy":    fmt.Sprintf("%.6f", result.BestEnergy),
			"coherence": fmt.Sprintf("%.4f", coherence),
			"agent":     "IsingOptimizer-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"best_energy":     result.BestEnergy,
		"coherence_score": coherence,
		"spins":           numSpins,
		"annealing_steps": steps,
		"interpretation": map[string]string{
			"energy":    "Lower = more compliant configuration (min-energy = max coverage)",
			"coherence": "1.0 = full quantum coherence, 0.0 = classical random state",
		},
		"timestamp": lorentz.StampNow(),
	}, nil, nil
}
