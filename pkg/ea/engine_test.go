package ea

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// sumFitnessFunc returns a FitnessFunc that scores by summing genome bytes,
// normalised to [0,1]. Deterministic, side-effect-free, production-accurate.
func sumFitnessFunc() FitnessFunc {
	return func(ind *Individual) (float64, error) {
		if len(ind.Genome) == 0 {
			return 0, nil
		}
		var sum uint64
		for _, b := range ind.Genome {
			sum += uint64(b)
		}
		max := uint64(255) * uint64(len(ind.Genome))
		return float64(sum) / float64(max), nil
	}
}

// errorFitnessFunc always returns an error — used to test eval failure paths.
func errorFitnessFunc() FitnessFunc {
	return func(ind *Individual) (float64, error) {
		return 0, fmt.Errorf("synthetic fitness error for individual %s", ind.ID)
	}
}

// newTestEngine creates a minimal valid engine backed by a real in-memory DAG
// and real ML-DSA-65 keys. Any test failure here is a real production blocker.
func newTestEngine(t *testing.T, popSize int, ff FitnessFunc) *EAEngine {
	t.Helper()
	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("GenerateDilithiumKey: %v", err)
	}
	if ff == nil {
		ff = sumFitnessFunc()
	}
	eng, err := NewEAEngine(EngineConfig{
		PopulationSize: popSize,
		FitnessFunc:    ff,
		DAGStore:       dag.NewMemory(),
		DilithiumSK:    sk,
		DilithiumPK:    pk,
	})
	if err != nil {
		t.Fatalf("NewEAEngine: %v", err)
	}
	return eng
}

// ─── NewEAEngine ──────────────────────────────────────────────────────────────

func TestNewEAEngine_RequiresFitnessFunc(t *testing.T) {
	_, err := NewEAEngine(EngineConfig{
		PopulationSize: 5,
		FitnessFunc:    nil,
		DAGStore:       dag.NewMemory(),
	})
	if err == nil {
		t.Fatal("expected error when FitnessFunc is nil, got none")
	}
}

func TestNewEAEngine_DefaultsApplied(t *testing.T) {
	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	eng, err := NewEAEngine(EngineConfig{
		PopulationSize: 0, // triggers default
		MutationRate:   0, // triggers default
		CrossoverRate:  0, // triggers default
		FitnessFunc:    sumFitnessFunc(),
		DAGStore:       dag.NewMemory(),
		DilithiumSK:    sk,
		DilithiumPK:    pk,
	})
	if err != nil {
		t.Fatalf("NewEAEngine: %v", err)
	}
	if len(eng.population) != DefaultPopulationSize {
		t.Errorf("population size: got %d, want %d", len(eng.population), DefaultPopulationSize)
	}
	if eng.mutationRate != DefaultMutationRate {
		t.Errorf("mutation rate: got %f, want %f", eng.mutationRate, DefaultMutationRate)
	}
	if eng.crossoverRate != DefaultCrossoverRate {
		t.Errorf("crossover rate: got %f, want %f", eng.crossoverRate, DefaultCrossoverRate)
	}
}

func TestNewEAEngine_PopulationSeededAndEvaluated(t *testing.T) {
	eng := newTestEngine(t, 10, sumFitnessFunc())

	if len(eng.population) != 10 {
		t.Fatalf("expected 10 individuals, got %d", len(eng.population))
	}
	for i, ind := range eng.population {
		if ind.ID == "" {
			t.Errorf("individual[%d].ID empty", i)
		}
		if len(ind.Genome) != GenomeSize {
			t.Errorf("individual[%d].Genome length: got %d, want %d", i, len(ind.Genome), GenomeSize)
		}
		if ind.Fitness < 0 || ind.Fitness > 1.0 {
			t.Errorf("individual[%d].Fitness out of [0,1]: %f", i, ind.Fitness)
		}
		if ind.CreatedAt.IsZero() {
			t.Errorf("individual[%d].CreatedAt is zero time", i)
		}
		if ind.Symbol == "" {
			t.Errorf("individual[%d].Symbol is empty", i)
		}
	}
}

func TestNewEAEngine_GenesisRecordedToDAG(t *testing.T) {
	store := dag.NewMemory()
	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	_, err = NewEAEngine(EngineConfig{
		PopulationSize: 5,
		FitnessFunc:    sumFitnessFunc(),
		DAGStore:       store,
		DilithiumSK:    sk,
		DilithiumPK:    pk,
	})
	if err != nil {
		t.Fatalf("NewEAEngine: %v", err)
	}
	nodes := store.All()
	if len(nodes) == 0 {
		t.Fatal("expected genesis DAG node, got 0 nodes")
	}
	// Genesis node must have the correct action label
	found := false
	for _, n := range nodes {
		if n.Action == "ea_generation:genesis" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("genesis node not found in DAG; nodes: %v", nodes)
	}
}

func TestNewEAEngine_EphemeralKeysWhenNoneProvided(t *testing.T) {
	eng, err := NewEAEngine(EngineConfig{
		PopulationSize: 5,
		FitnessFunc:    sumFitnessFunc(),
		DAGStore:       dag.NewMemory(),
		// No DilithiumSK/PK — engine must generate ephemeral keys
	})
	if err != nil {
		t.Fatalf("NewEAEngine: %v", err)
	}
	if len(eng.dilithiumSK) == 0 {
		t.Error("ephemeral dilithiumSK not generated")
	}
	if len(eng.dilithiumPK) == 0 {
		t.Error("ephemeral dilithiumPK not generated")
	}
}

// ─── Evolve ───────────────────────────────────────────────────────────────────

func TestEvolve_ReturnsNonNilBest(t *testing.T) {
	eng := newTestEngine(t, 10, sumFitnessFunc())
	best, err := eng.Evolve()
	if err != nil {
		t.Fatalf("Evolve: %v", err)
	}
	if best == nil {
		t.Fatal("Evolve returned nil individual")
	}
}

func TestEvolve_IncrementGeneration(t *testing.T) {
	eng := newTestEngine(t, 10, sumFitnessFunc())
	if eng.generation != 0 {
		t.Fatalf("initial generation: want 0, got %d", eng.generation)
	}
	for i := 1; i <= 3; i++ {
		if _, err := eng.Evolve(); err != nil {
			t.Fatalf("Evolve round %d: %v", i, err)
		}
		if eng.generation != i {
			t.Errorf("after Evolve #%d: generation want %d, got %d", i, i, eng.generation)
		}
	}
}

func TestEvolve_PopulationSizePreserved(t *testing.T) {
	const size = 15
	eng := newTestEngine(t, size, sumFitnessFunc())
	for i := 0; i < 5; i++ {
		if _, err := eng.Evolve(); err != nil {
			t.Fatalf("Evolve: %v", err)
		}
	}
	eng.mu.RLock()
	got := len(eng.population)
	eng.mu.RUnlock()
	if got != size {
		t.Errorf("population size after 5 generations: want %d, got %d", size, got)
	}
}

func TestEvolve_BestFitnessNonDecreasing(t *testing.T) {
	// With elitism the all-time best fitness must not decrease across generations.
	eng := newTestEngine(t, 20, sumFitnessFunc())
	prevBest := eng.BestIndividual().Fitness
	for i := 0; i < 10; i++ {
		best, err := eng.Evolve()
		if err != nil {
			t.Fatalf("Evolve #%d: %v", i+1, err)
		}
		// Elitism guarantees the best never regresses.
		if best.Fitness < prevBest-1e-9 {
			t.Errorf("gen %d: best fitness regressed from %.6f to %.6f", i+1, prevBest, best.Fitness)
		}
		if best.Fitness > prevBest {
			prevBest = best.Fitness
		}
	}
}

func TestEvolve_FitnessErrorPropagates(t *testing.T) {
	// NewEAEngine calls evaluateAll during construction; errorFitnessFunc causes
	// that to return an error, which must be propagated to the caller.
	pk, sk, _ := adinkra.GenerateDilithiumKey()
	_, err := NewEAEngine(EngineConfig{
		PopulationSize: 5,
		FitnessFunc:    errorFitnessFunc(),
		DAGStore:       dag.NewMemory(),
		DilithiumSK:    sk,
		DilithiumPK:    pk,
	})
	if err == nil {
		t.Fatal("expected error from errorFitnessFunc during initial evaluation, got nil")
	}
}

func TestEvolve_DAGRecordsEachGeneration(t *testing.T) {
	store := dag.NewMemory()
	pk, sk, _ := adinkra.GenerateDilithiumKey()
	eng, err := NewEAEngine(EngineConfig{
		PopulationSize: 5,
		FitnessFunc:    sumFitnessFunc(),
		DAGStore:       store,
		DilithiumSK:    sk,
		DilithiumPK:    pk,
	})
	if err != nil {
		t.Fatalf("NewEAEngine: %v", err)
	}

	const gens = 3
	for i := 0; i < gens; i++ {
		if _, err := eng.Evolve(); err != nil {
			t.Fatalf("Evolve #%d: %v", i+1, err)
		}
	}

	nodes := store.All()
	// genesis + gens = gens+1 DAG entries minimum
	if len(nodes) < gens+1 {
		t.Errorf("expected ≥%d DAG nodes, got %d", gens+1, len(nodes))
	}
}

// ─── BestIndividual ───────────────────────────────────────────────────────────

func TestBestIndividual_ReturnsCopy(t *testing.T) {
	eng := newTestEngine(t, 10, sumFitnessFunc())
	b1 := eng.BestIndividual()
	b2 := eng.BestIndividual()
	if b1 == b2 {
		t.Error("BestIndividual returned same pointer twice (should return copy each time)")
	}
	if b1.ID == b2.ID {
		t.Error("cloneIndividual should assign a new UUID each call")
	}
}

func TestBestIndividual_HighestFitness(t *testing.T) {
	eng := newTestEngine(t, 20, sumFitnessFunc())
	best := eng.BestIndividual()

	eng.mu.RLock()
	for _, ind := range eng.population {
		if ind.Fitness > best.Fitness+1e-9 {
			t.Errorf("BestIndividual fitness %.6f < population member %.6f", best.Fitness, ind.Fitness)
		}
	}
	eng.mu.RUnlock()
}

// ─── Status ───────────────────────────────────────────────────────────────────

func TestStatus_InitialState(t *testing.T) {
	eng := newTestEngine(t, 12, sumFitnessFunc())
	s := eng.Status()
	if s.Generation != 0 {
		t.Errorf("initial generation: want 0, got %d", s.Generation)
	}
	if s.PopulationSize != 12 {
		t.Errorf("population size: want 12, got %d", s.PopulationSize)
	}
	if s.AgentID == "" {
		t.Error("AgentID empty")
	}
	if s.BestFitness < 0 || s.BestFitness > 1.0 {
		t.Errorf("BestFitness out of [0,1]: %f", s.BestFitness)
	}
	if s.BestSymbol == "" {
		t.Error("BestSymbol empty")
	}
}

func TestStatus_AfterEvolution(t *testing.T) {
	eng := newTestEngine(t, 10, sumFitnessFunc())
	for i := 0; i < 4; i++ {
		eng.Evolve() //nolint:errcheck
	}
	s := eng.Status()
	if s.Generation != 4 {
		t.Errorf("generation after 4 calls: want 4, got %d", s.Generation)
	}
	if s.MeanFitness <= 0 {
		t.Errorf("MeanFitness should be positive after evolution, got %f", s.MeanFitness)
	}
	if s.WorstFitness > s.BestFitness+1e-9 {
		t.Errorf("WorstFitness %.6f > BestFitness %.6f", s.WorstFitness, s.BestFitness)
	}
}

// ─── GenomeFitness / GenomeTraits ─────────────────────────────────────────────

func TestGenomeFitness_TraitRanges(t *testing.T) {
	genome := make([]byte, GenomeSize)
	// Manually set known values
	genome[1] = 255 // STIGPriority → 1.0
	genome[2] = 0   // PQCStrength  → 0.0
	genome[3] = 128 // ScanSpeed    → 128/255 ≈ 0.502

	traits := GenomeFitness(genome)

	if traits.STIGPriority != 1.0 {
		t.Errorf("STIGPriority: want 1.0, got %.4f", traits.STIGPriority)
	}
	if traits.PQCStrength != 0.0 {
		t.Errorf("PQCStrength: want 0.0, got %.4f", traits.PQCStrength)
	}
	expected := float64(128) / 255.0
	if traits.ScanSpeed < expected-1e-9 || traits.ScanSpeed > expected+1e-9 {
		t.Errorf("ScanSpeed: want %.6f, got %.6f", expected, traits.ScanSpeed)
	}
	if len(traits.CapFlags) != 8 {
		t.Errorf("CapFlags length: want 8, got %d", len(traits.CapFlags))
	}
	if len(traits.Thresholds) != 8 {
		t.Errorf("Thresholds length: want 8, got %d", len(traits.Thresholds))
	}
}

func TestGenomeFitness_PanicsOnShortGenome(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on short genome, got none")
		}
	}()
	GenomeFitness(make([]byte, GenomeSize-1))
}

// ─── genomeSymbol ─────────────────────────────────────────────────────────────

func TestGenomeSymbol_ValidSymbols(t *testing.T) {
	valid := map[string]bool{
		"Eban": true, "Fawohodie": true, "Nkyinkyim": true, "Dwennimmen": true,
	}
	for b := 0; b < 256; b++ {
		genome := make([]byte, GenomeSize)
		genome[0] = byte(b)
		sym := genomeSymbol(genome)
		if !valid[sym] {
			t.Errorf("byte %d produced invalid symbol: %q", b, sym)
		}
	}
}

func TestGenomeSymbol_Deterministic(t *testing.T) {
	genome := make([]byte, GenomeSize)
	genome[0] = 42
	s1 := genomeSymbol(genome)
	s2 := genomeSymbol(genome)
	if s1 != s2 {
		t.Errorf("genomeSymbol is not deterministic: %q != %q", s1, s2)
	}
}

func TestGenomeSymbol_AllFourSymbolsReachable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 256 && len(seen) < 4; i++ {
		g := make([]byte, GenomeSize)
		g[0] = byte(i)
		seen[genomeSymbol(g)] = true
	}
	if len(seen) != 4 {
		t.Errorf("only %d symbols reachable: %v", len(seen), seen)
	}
}

// ─── normByte ─────────────────────────────────────────────────────────────────

func TestNormByte_Boundaries(t *testing.T) {
	if normByte(0) != 0.0 {
		t.Errorf("normByte(0): want 0.0, got %f", normByte(0))
	}
	if normByte(255) != 1.0 {
		t.Errorf("normByte(255): want 1.0, got %f", normByte(255))
	}
}

func TestNormByte_Midpoint(t *testing.T) {
	// 127/255 ≈ 0.498
	got := normByte(127)
	want := float64(127) / 255.0
	if got < want-1e-9 || got > want+1e-9 {
		t.Errorf("normByte(127): want %.9f, got %.9f", want, got)
	}
}

// ─── Secure Random Helpers ────────────────────────────────────────────────────

func TestRandomIndex_InRange(t *testing.T) {
	for _, n := range []int{1, 2, 10, 100} {
		for i := 0; i < 200; i++ {
			idx := randomIndex(n)
			if idx < 0 || idx >= n {
				t.Errorf("randomIndex(%d) = %d, out of [0,%d)", n, idx, n)
			}
		}
	}
}

func TestRandomIndex_ZeroReturnsZero(t *testing.T) {
	if randomIndex(0) != 0 {
		t.Error("randomIndex(0) should return 0")
	}
}

func TestRandomFloat64_InUnitInterval(t *testing.T) {
	for i := 0; i < 1000; i++ {
		v := randomFloat64()
		if v < 0.0 || v >= 1.0 {
			t.Errorf("randomFloat64() = %f, out of [0,1)", v)
		}
	}
}

func TestRandomBit_BothValuesReachable(t *testing.T) {
	trueCount := 0
	const trials = 1000
	for i := 0; i < trials; i++ {
		if randomBit() {
			trueCount++
		}
	}
	// Statistical: probability of all same in 1000 trials is vanishingly small.
	if trueCount == 0 || trueCount == trials {
		t.Errorf("randomBit appears biased: trueCount=%d/%d", trueCount, trials)
	}
}

// ─── Genetic Operators ────────────────────────────────────────────────────────

func TestCrossover_LengthPreserved(t *testing.T) {
	eng := newTestEngine(t, 5, sumFitnessFunc())
	a := make([]byte, GenomeSize)
	b := make([]byte, GenomeSize)
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(255 - i)
	}
	child := eng.crossover(a, b)
	if len(child) != GenomeSize {
		t.Errorf("crossover output length: want %d, got %d", GenomeSize, len(child))
	}
}

func TestCrossover_EachByteFromOneParent(t *testing.T) {
	eng := newTestEngine(t, 5, sumFitnessFunc())
	// Force crossover by running many trials; at least some must mix bytes.
	a := make([]byte, GenomeSize)
	b := make([]byte, GenomeSize)
	for i := range a {
		a[i] = 0x00
		b[i] = 0xFF
	}

	mixed := false
	for trial := 0; trial < 500; trial++ {
		child := eng.crossover(a, b)
		for _, c := range child {
			if c != 0x00 && c != 0xFF {
				t.Errorf("crossover produced byte %02x not in either parent", c)
			}
		}
		// Check mixing occurred at least once across trials
		hasA, hasB := false, false
		for _, c := range child {
			if c == 0x00 {
				hasA = true
			}
			if c == 0xFF {
				hasB = true
			}
		}
		if hasA && hasB {
			mixed = true
			break
		}
	}
	if !mixed {
		t.Error("crossover never produced a child with bytes from both parents across 500 trials")
	}
}

func TestMutate_LengthPreserved(t *testing.T) {
	eng := newTestEngine(t, 5, sumFitnessFunc())
	genome := make([]byte, GenomeSize)
	for i := range genome {
		genome[i] = byte(i)
	}
	mutated := eng.mutate(genome)
	if len(mutated) != len(genome) {
		t.Errorf("mutate: length changed from %d to %d", len(genome), len(mutated))
	}
}

func TestMutate_OriginalUnmodified(t *testing.T) {
	eng := newTestEngine(t, 5, sumFitnessFunc())
	original := make([]byte, GenomeSize)
	for i := range original {
		original[i] = 0xAA
	}
	genome := make([]byte, GenomeSize)
	copy(genome, original)

	eng.mutate(genome)

	// Original slice must not be altered
	for i := range original {
		if original[i] != 0xAA {
			t.Errorf("mutate modified original genome at index %d", i)
		}
	}
}

// ─── newIndividualFromGenome ───────────────────────────────────────────────────

func TestNewIndividualFromGenome_WrongSizeErrors(t *testing.T) {
	eng := newTestEngine(t, 5, sumFitnessFunc())
	for _, size := range []int{0, GenomeSize - 1, GenomeSize + 1} {
		_, err := eng.newIndividualFromGenome(make([]byte, size), 0)
		if err == nil {
			t.Errorf("expected error for genome size %d, got nil", size)
		}
	}
}

func TestNewIndividualFromGenome_CorrectSize(t *testing.T) {
	eng := newTestEngine(t, 5, sumFitnessFunc())
	genome := make([]byte, GenomeSize)
	ind, err := eng.newIndividualFromGenome(genome, 7)
	if err != nil {
		t.Fatalf("newIndividualFromGenome: %v", err)
	}
	if ind.Generation != 7 {
		t.Errorf("generation: want 7, got %d", ind.Generation)
	}
	if ind.ID == "" {
		t.Error("ID empty")
	}
	if ind.Symbol == "" {
		t.Error("Symbol empty")
	}
	if ind.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero time")
	}
}

// ─── cloneIndividual ──────────────────────────────────────────────────────────

func TestCloneIndividual_Independence(t *testing.T) {
	eng := newTestEngine(t, 5, sumFitnessFunc())
	ind, _ := eng.newIndividualFromGenome(make([]byte, GenomeSize), 0)
	ind.Genome[0] = 0xAA

	clone := eng.cloneIndividual(ind)
	if clone == ind {
		t.Error("clone is same pointer as source")
	}
	// Mutate clone; source must not change
	clone.Genome[0] = 0xBB
	if ind.Genome[0] != 0xAA {
		t.Error("clone genome modification affected source genome (shared backing array)")
	}
	if clone.ID == ind.ID {
		t.Error("clone must have a new UUID")
	}
}

// ─── Concurrent safety ────────────────────────────────────────────────────────

func TestEvolve_ConcurrentStatus(t *testing.T) {
	eng := newTestEngine(t, 20, sumFitnessFunc())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5; i++ {
			eng.Evolve() //nolint:errcheck
		}
	}()
	// Status reads must not race with Evolve writes
	for i := 0; i < 20; i++ {
		_ = eng.Status()
		time.Sleep(time.Millisecond)
	}
	<-done
}

// ─── Engine / engineConfig AgentID ────────────────────────────────────────────

func TestNewEAEngine_CustomAgentID(t *testing.T) {
	const want = "sentinel-agent"
	pk, sk, _ := adinkra.GenerateDilithiumKey()
	eng, err := NewEAEngine(EngineConfig{
		PopulationSize: 5,
		FitnessFunc:    sumFitnessFunc(),
		DAGStore:       dag.NewMemory(),
		DilithiumSK:    sk,
		DilithiumPK:    pk,
		AgentID:        want,
	})
	if err != nil {
		t.Fatalf("NewEAEngine: %v", err)
	}
	if eng.agentID != want {
		t.Errorf("agentID: want %q, got %q", want, eng.agentID)
	}
	s := eng.Status()
	if s.AgentID != want {
		t.Errorf("Status.AgentID: want %q, got %q", want, s.AgentID)
	}
}

// ─── sortedByFitness ──────────────────────────────────────────────────────────

func TestSortedByFitness_DescendingOrder(t *testing.T) {
	eng := newTestEngine(t, 20, sumFitnessFunc())
	eng.mu.RLock()
	sorted := eng.sortedByFitness()
	eng.mu.RUnlock()

	for i := 1; i < len(sorted); i++ {
		if sorted[i].Fitness > sorted[i-1].Fitness+1e-12 {
			t.Errorf("sortedByFitness not descending at index %d: %.8f > %.8f",
				i, sorted[i].Fitness, sorted[i-1].Fitness)
		}
	}
}

// ─── genome entropy uniqueness ────────────────────────────────────────────────

func TestNewRandomIndividual_GenomesAreUnique(t *testing.T) {
	eng := newTestEngine(t, 50, sumFitnessFunc())
	seen := make(map[uint64]bool)

	eng.mu.RLock()
	for i, ind := range eng.population {
		// Use first 8 bytes as a fingerprint proxy
		if len(ind.Genome) < 8 {
			t.Errorf("individual[%d] genome too short", i)
			continue
		}
		key := binary.BigEndian.Uint64(ind.Genome[:8])
		if seen[key] {
			// With 50 random 48-byte genomes, a collision in the first 8 bytes is
			// astronomically unlikely (birthday attack threshold: ~2^32 samples).
			// If this fires, crypto/rand is broken.
			t.Errorf("genome fingerprint collision at individual[%d] — random source may be broken", i)
		}
		seen[key] = true
	}
	eng.mu.RUnlock()
}
