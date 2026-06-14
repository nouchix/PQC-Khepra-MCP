// Package ea implements the Evolutionary Algorithm (EA) kernel for AdinKhepra v2.0.
//
// The EA engine maintains a population of candidate security strategies and evolves
// them over generations using selection, crossover, and mutation. Every generation
// is committed to the immutable DAG, providing a tamper-evident audit trail of how
// the system's intelligence developed over time — a key differentiator for CMMC/FedRAMP.
//
// Architecture: mythos-router-inspired kernel that dispatches to specialized sub-agents
// while the EA continuously optimises the routing weights and strategy genomes.
package ea

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/google/uuid"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	DefaultPopulationSize = 50
	DefaultMutationRate   = 0.02
	DefaultCrossoverRate  = 0.75
	TournamentSize        = 5
	EliteCount            = 2 // top N individuals carried forward unchanged (elitism)

	// GenomeSize encodes: 32 strategy weights + 8 capability flags + 8 threshold bytes
	GenomeSize = 48
)

// ─── Core Types ───────────────────────────────────────────────────────────────

// Individual is a single candidate solution in the evolutionary population.
type Individual struct {
	ID         string  `json:"id"`
	Genome     []byte  `json:"genome"` // GenomeSize bytes encoding the strategy
	Fitness    float64 `json:"fitness"`
	Generation int     `json:"generation"`
	Symbol     string  `json:"symbol"`    // Adinkra symbol governing this individual
	DAGNodeID  string  `json:"dag_node_id"` // Pointer to the immutable DAG audit record
	CreatedAt  time.Time `json:"created_at"`
}

// FitnessFunc evaluates an individual's quality. Higher is better.
// Implementations must be pure (no side effects) and deterministic for a given genome.
type FitnessFunc func(ind *Individual) (float64, error)

// EAEngine manages the evolutionary loop over a population of Individuals.
type EAEngine struct {
	mu           sync.RWMutex
	population   []*Individual
	generation   int
	mutationRate float64
	crossoverRate float64
	fitnessFunc  FitnessFunc
	dag          dag.Store
	agentID      string    // signing identity for DAG vertices
	dilithiumSK  []byte    // ML-DSA-65 private key for DAG signing
	dilithiumPK  []byte    // corresponding public key
}

// EngineConfig carries constructor parameters.
type EngineConfig struct {
	PopulationSize int
	MutationRate   float64
	CrossoverRate  float64
	FitnessFunc    FitnessFunc
	DAGStore       dag.Store   // nil → uses in-memory store
	AgentID        string
	DilithiumSK    []byte
	DilithiumPK    []byte
}

// ─── Constructor ──────────────────────────────────────────────────────────────

// NewEAEngine creates an EAEngine, seeds the initial population with random
// genomes, evaluates their fitness, and records genesis to the DAG.
func NewEAEngine(cfg EngineConfig) (*EAEngine, error) {
	if cfg.FitnessFunc == nil {
		return nil, errors.New("ea: FitnessFunc is required")
	}
	if cfg.PopulationSize <= 0 {
		cfg.PopulationSize = DefaultPopulationSize
	}
	if cfg.MutationRate <= 0 {
		cfg.MutationRate = DefaultMutationRate
	}
	if cfg.CrossoverRate <= 0 {
		cfg.CrossoverRate = DefaultCrossoverRate
	}
	if cfg.DAGStore == nil {
		cfg.DAGStore = dag.NewMemory()
	}

	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, fmt.Errorf("ea: failed to generate session signing key: %w", err)
	}
	// Prefer caller-supplied keys; fall back to ephemeral session key.
	if len(cfg.DilithiumSK) == 0 {
		cfg.DilithiumSK = sk
		cfg.DilithiumPK = pk
	}
	if cfg.AgentID == "" {
		cfg.AgentID = "ea-engine-" + uuid.New().String()[:8]
	}

	eng := &EAEngine{
		population:    make([]*Individual, cfg.PopulationSize),
		mutationRate:  cfg.MutationRate,
		crossoverRate: cfg.CrossoverRate,
		fitnessFunc:   cfg.FitnessFunc,
		dag:           cfg.DAGStore,
		agentID:       cfg.AgentID,
		dilithiumSK:   cfg.DilithiumSK,
		dilithiumPK:   cfg.DilithiumPK,
	}

	// Seed population
	for i := range eng.population {
		ind, err := eng.newRandomIndividual(0)
		if err != nil {
			return nil, fmt.Errorf("ea: seed individual %d: %w", i, err)
		}
		eng.population[i] = ind
	}

	// Initial fitness evaluation
	if err := eng.evaluateAll(); err != nil {
		return nil, fmt.Errorf("ea: initial fitness evaluation: %w", err)
	}

	// Record genesis generation to DAG
	if err := eng.recordGenerationDAG("genesis"); err != nil {
		return nil, fmt.Errorf("ea: genesis DAG record: %w", err)
	}

	return eng, nil
}

// ─── Evolution ────────────────────────────────────────────────────────────────

// Evolve runs one generation: select → crossover → mutate → evaluate → elitism → DAG record.
// Returns the best individual after this generation.
func (e *EAEngine) Evolve() (*Individual, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	popSize := len(e.population)
	offspring := make([]*Individual, 0, popSize)

	// Elitism: preserve top-N unchanged
	sorted := e.sortedByFitness()
	for i := 0; i < EliteCount && i < len(sorted); i++ {
		clone := e.cloneIndividual(sorted[i])
		clone.Generation = e.generation + 1
		offspring = append(offspring, clone)
	}

	// Fill rest via tournament selection + crossover + mutation
	for len(offspring) < popSize {
		parentA := e.tournamentSelect(sorted)
		parentB := e.tournamentSelect(sorted)

		childGenome := e.crossover(parentA.Genome, parentB.Genome)
		childGenome = e.mutate(childGenome)

		child, err := e.newIndividualFromGenome(childGenome, e.generation+1)
		if err != nil {
			return nil, fmt.Errorf("ea: create offspring: %w", err)
		}
		offspring = append(offspring, child)
	}

	e.population = offspring
	e.generation++

	if err := e.evaluateAllLocked(); err != nil {
		return nil, fmt.Errorf("ea: generation %d fitness eval: %w", e.generation, err)
	}

	if err := e.recordGenerationDAG(fmt.Sprintf("gen-%d", e.generation)); err != nil {
		// Non-fatal: log but do not abort evolution
		fmt.Printf("[EA] WARN: DAG record failed for gen %d: %v\n", e.generation, err)
	}

	best := e.sortedByFitness()[0]
	return e.cloneIndividual(best), nil
}

// BestIndividual returns a copy of the highest-fitness individual in the current population.
func (e *EAEngine) BestIndividual() *Individual {
	e.mu.RLock()
	defer e.mu.RUnlock()
	sorted := e.sortedByFitness()
	if len(sorted) == 0 {
		return nil
	}
	return e.cloneIndividual(sorted[0])
}

// Status returns a snapshot of the engine's current state.
func (e *EAEngine) Status() EngineStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	sorted := e.sortedByFitness()
	s := EngineStatus{
		Generation:     e.generation,
		PopulationSize: len(e.population),
		AgentID:        e.agentID,
	}
	if len(sorted) > 0 {
		s.BestFitness = sorted[0].Fitness
		s.BestSymbol = sorted[0].Symbol
		s.BestGenome = sorted[0].Genome
	}
	if len(sorted) >= 2 {
		var sum float64
		for _, ind := range sorted {
			sum += ind.Fitness
		}
		s.MeanFitness = sum / float64(len(sorted))
		s.WorstFitness = sorted[len(sorted)-1].Fitness
	}
	return s
}

// EngineStatus is a point-in-time snapshot of the EA engine.
type EngineStatus struct {
	Generation     int     `json:"generation"`
	PopulationSize int     `json:"population_size"`
	BestFitness    float64 `json:"best_fitness"`
	MeanFitness    float64 `json:"mean_fitness"`
	WorstFitness   float64 `json:"worst_fitness"`
	BestSymbol     string  `json:"best_symbol"`
	BestGenome     []byte  `json:"best_genome,omitempty"`
	AgentID        string  `json:"agent_id"`
}

// ─── Selection ────────────────────────────────────────────────────────────────

// tournamentSelect picks the best individual from TournamentSize random candidates.
func (e *EAEngine) tournamentSelect(sorted []*Individual) *Individual {
	n := len(sorted)
	best := sorted[randomIndex(n)]
	for i := 1; i < TournamentSize; i++ {
		candidate := sorted[randomIndex(n)]
		if candidate.Fitness > best.Fitness {
			best = candidate
		}
	}
	return best
}

// ─── Genetic Operators ────────────────────────────────────────────────────────

// crossover performs uniform crossover: each byte drawn randomly from one parent.
func (e *EAEngine) crossover(a, b []byte) []byte {
	if randomFloat64() > e.crossoverRate {
		// No crossover: return copy of parent A
		out := make([]byte, len(a))
		copy(out, a)
		return out
	}
	out := make([]byte, len(a))
	for i := range out {
		if randomBit() {
			out[i] = a[i]
		} else {
			out[i] = b[i]
		}
	}
	return out
}

// mutate applies per-byte mutation at rate e.mutationRate.
// Uses bit-flip mutation: with probability mutationRate, each byte is XOR'd with
// a random byte (equivalent to flipping a random subset of its bits).
func (e *EAEngine) mutate(genome []byte) []byte {
	out := make([]byte, len(genome))
	copy(out, genome)
	for i := range out {
		if randomFloat64() < e.mutationRate {
			var noise [1]byte
			rand.Read(noise[:]) //nolint:errcheck
			out[i] ^= noise[0]
		}
	}
	return out
}

// ─── Fitness Evaluation ───────────────────────────────────────────────────────

func (e *EAEngine) evaluateAll() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.evaluateAllLocked()
}

func (e *EAEngine) evaluateAllLocked() error {
	for _, ind := range e.population {
		f, err := e.fitnessFunc(ind)
		if err != nil {
			return fmt.Errorf("fitness eval individual %s: %w", ind.ID, err)
		}
		ind.Fitness = f
	}
	return nil
}

// ─── DAG Integration ──────────────────────────────────────────────────────────

// recordGenerationDAG commits a generation summary to the immutable audit DAG.
// Each node is Dilithium3-signed, making the evolution history tamper-evident.
func (e *EAEngine) recordGenerationDAG(label string) error {
	sorted := e.sortedByFitness()
	summary := map[string]interface{}{
		"label":       label,
		"generation":  e.generation,
		"pop_size":    len(e.population),
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	if len(sorted) > 0 {
		summary["best_fitness"] = sorted[0].Fitness
		summary["best_symbol"] = sorted[0].Symbol
		summary["best_id"] = sorted[0].ID
	}

	payload, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("marshal generation summary: %w", err)
	}

	sig, err := adinkra.Sign(e.dilithiumSK, payload)
	if err != nil {
		return fmt.Errorf("sign generation payload: %w", err)
	}

	// Collect parent node IDs from all living individuals that have DAG records
	parents := make([]string, 0, len(e.population))
	seen := make(map[string]bool)
	for _, ind := range e.population {
		if ind.DAGNodeID != "" && !seen[ind.DAGNodeID] {
			parents = append(parents, ind.DAGNodeID)
			seen[ind.DAGNodeID] = true
		}
	}

	symbol := "Nkyinkyim" // Adaptability — governs evolution nodes
	if len(sorted) > 0 {
		symbol = sorted[0].Symbol
	}

	n := &dag.Node{
		Action: fmt.Sprintf("ea_generation:%s", label),
		Symbol: symbol,
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		PQC: map[string]string{
			"scheme":    "ML-DSA-65",
			"signature": fmt.Sprintf("%x", sig),
			"pubkey":    fmt.Sprintf("%x", e.dilithiumPK),
			"payload":   string(payload),
		},
	}

	if err := e.dag.Add(n, parents); err != nil {
		return fmt.Errorf("DAG add: %w", err)
	}

	// Back-annotate the best individual with the DAG node ID
	if len(sorted) > 0 {
		sorted[0].DAGNodeID = n.ID
	}

	return nil
}

// ─── Individual Construction ──────────────────────────────────────────────────

func (e *EAEngine) newRandomIndividual(generation int) (*Individual, error) {
	genome := make([]byte, GenomeSize)
	if _, err := rand.Read(genome); err != nil {
		return nil, fmt.Errorf("generate genome entropy: %w", err)
	}
	return e.newIndividualFromGenome(genome, generation)
}

func (e *EAEngine) newIndividualFromGenome(genome []byte, generation int) (*Individual, error) {
	if len(genome) != GenomeSize {
		return nil, fmt.Errorf("genome must be %d bytes, got %d", GenomeSize, len(genome))
	}
	symbol := genomeSymbol(genome)
	return &Individual{
		ID:         uuid.New().String(),
		Genome:     genome,
		Generation: generation,
		Symbol:     symbol,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

func (e *EAEngine) cloneIndividual(src *Individual) *Individual {
	clone := *src
	clone.Genome = make([]byte, len(src.Genome))
	copy(clone.Genome, src.Genome)
	clone.ID = uuid.New().String()
	return &clone
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// sortedByFitness returns a copy of the population slice sorted descending by fitness.
// Caller must hold e.mu (read or write).
func (e *EAEngine) sortedByFitness() []*Individual {
	sorted := make([]*Individual, len(e.population))
	copy(sorted, e.population)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Fitness > sorted[j].Fitness
	})
	return sorted
}

// genomeSymbol derives the Adinkra symbol that governs an individual based on
// the spectral analysis of its genome's first byte. This links the EA to the
// Adinkra crypto framework, making symbol selection part of evolution.
func genomeSymbol(genome []byte) string {
	symbols := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
	idx := int(genome[0]) % len(symbols)
	return symbols[idx]
}

// GenomeFitness extracts normalised trait values from a raw genome byte slice.
// Index layout (within GenomeSize=48 bytes):
//   [0]     symbol selector
//   [1–7]   strategy weights (STIG priority, PQC strength, speed, accuracy, etc.)
//   [8–15]  capability activation flags
//   [16–23] threshold parameters
//   [24–47] reserved for future trait expansion
func GenomeFitness(genome []byte) GenomeTraits {
	if len(genome) < GenomeSize {
		panic(fmt.Sprintf("ea: genome too short: %d < %d", len(genome), GenomeSize))
	}
	return GenomeTraits{
		STIGPriority:   normByte(genome[1]),
		PQCStrength:    normByte(genome[2]),
		ScanSpeed:      normByte(genome[3]),
		Accuracy:       normByte(genome[4]),
		FPRPenalty:     normByte(genome[5]),
		PrivEscRisk:    normByte(genome[6]),
		RemediationCov: normByte(genome[7]),
		CapFlags:       genome[8:16],
		Thresholds:     genome[16:24],
	}
}

// GenomeTraits holds decoded trait values from a genome.
type GenomeTraits struct {
	STIGPriority   float64
	PQCStrength    float64
	ScanSpeed      float64
	Accuracy       float64
	FPRPenalty     float64
	PrivEscRisk    float64
	RemediationCov float64
	CapFlags       []byte
	Thresholds     []byte
}

// normByte normalises a byte to [0.0, 1.0].
func normByte(b byte) float64 { return float64(b) / 255.0 }

// ─── Secure Random Helpers ────────────────────────────────────────────────────

func randomIndex(n int) int {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	rand.Read(buf[:]) //nolint:errcheck
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}

func randomFloat64() float64 {
	var buf [8]byte
	rand.Read(buf[:]) //nolint:errcheck
	// Mask to [0, 2^53) then divide for uniform [0.0, 1.0)
	v := binary.BigEndian.Uint64(buf[:]) & ((1 << 53) - 1)
	return float64(v) / math.Pow(2, 53)
}

func randomBit() bool {
	var buf [1]byte
	rand.Read(buf[:]) //nolint:errcheck
	return buf[0]&0x01 == 0x01
}
