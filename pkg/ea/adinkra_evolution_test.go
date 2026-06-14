package ea

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

// ─── LatticeParams.Validate ───────────────────────────────────────────────────

func TestLatticeParams_ValidBaseline(t *testing.T) {
	valid := LatticeParams{N: 256, Q: 8380417, Sigma: 1.78, K: 4, SecurityBits: 256}
	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid params to pass, got: %v", err)
	}
}

func TestLatticeParams_AllValidNValues(t *testing.T) {
	for _, n := range []int{256, 512, 1024} {
		lp := LatticeParams{N: n, Q: 3329, Sigma: 1.0, K: 2, SecurityBits: 128}
		if err := lp.Validate(); err != nil {
			t.Errorf("N=%d should be valid: %v", n, err)
		}
	}
}

func TestLatticeParams_InvalidN(t *testing.T) {
	for _, n := range []int{0, 128, 255, 257, 513, 1023, 2048} {
		lp := LatticeParams{N: n, Q: 3329, Sigma: 1.0, K: 2, SecurityBits: 128}
		if err := lp.Validate(); err == nil {
			t.Errorf("N=%d should be invalid, got nil", n)
		}
	}
}

func TestLatticeParams_QBoundaries(t *testing.T) {
	base := LatticeParams{N: 256, Q: 3329, Sigma: 1.0, K: 2, SecurityBits: 128}

	// Minimum valid Q
	if err := base.Validate(); err != nil {
		t.Errorf("Q=%d should be valid minimum: %v", base.Q, err)
	}
	// Maximum valid Q
	base.Q = 8380417
	if err := base.Validate(); err != nil {
		t.Errorf("Q=%d should be valid maximum: %v", base.Q, err)
	}
	// Below minimum
	base.Q = 3328
	if err := base.Validate(); err == nil {
		t.Errorf("Q=3328 should be invalid")
	}
	// Above maximum
	base.Q = 8380418
	if err := base.Validate(); err == nil {
		t.Errorf("Q=8380418 should be invalid")
	}
}

func TestLatticeParams_SigmaBoundaries(t *testing.T) {
	base := LatticeParams{N: 256, Q: 3329, K: 2, SecurityBits: 128}

	for _, sigma := range []float64{0.0, -1.0, -0.001} {
		base.Sigma = sigma
		if err := base.Validate(); err == nil {
			t.Errorf("Sigma=%.3f should be invalid (≤0)", sigma)
		}
	}
	for _, sigma := range []float64{0.001, 1.0, 5.5, 10.0} {
		base.Sigma = sigma
		if err := base.Validate(); err != nil {
			t.Errorf("Sigma=%.3f should be valid: %v", sigma, err)
		}
	}
	base.Sigma = 10.001
	if err := base.Validate(); err == nil {
		t.Errorf("Sigma=10.001 should be invalid (>10)")
	}
}

func TestLatticeParams_KBoundaries(t *testing.T) {
	base := LatticeParams{N: 256, Q: 3329, Sigma: 1.0, SecurityBits: 128}
	for _, k := range []int{2, 3, 4} {
		base.K = k
		if err := base.Validate(); err != nil {
			t.Errorf("K=%d should be valid: %v", k, err)
		}
	}
	for _, k := range []int{0, 1, 5, 10} {
		base.K = k
		if err := base.Validate(); err == nil {
			t.Errorf("K=%d should be invalid", k)
		}
	}
}

func TestLatticeParams_SecurityBitsMinimum(t *testing.T) {
	base := LatticeParams{N: 256, Q: 3329, Sigma: 1.0, K: 2}

	base.SecurityBits = 128
	if err := base.Validate(); err != nil {
		t.Errorf("SecurityBits=128 should be valid: %v", err)
	}
	base.SecurityBits = 127
	if err := base.Validate(); err == nil {
		t.Errorf("SecurityBits=127 should be invalid")
	}
	base.SecurityBits = 0
	if err := base.Validate(); err == nil {
		t.Errorf("SecurityBits=0 should be invalid")
	}
}

func TestLatticeParams_PreservesNISTCompliance(t *testing.T) {
	valid := LatticeParams{N: 256, Q: 3329, Sigma: 1.0, K: 2, SecurityBits: 128}
	if !valid.PreservesNISTCompliance() {
		t.Error("valid params should preserve NIST compliance")
	}

	invalid := LatticeParams{N: 128, Q: 3329, Sigma: 1.0, K: 2, SecurityBits: 128}
	if invalid.PreservesNISTCompliance() {
		t.Error("invalid N=128 should not preserve NIST compliance")
	}

	lowSecurity := LatticeParams{N: 256, Q: 3329, Sigma: 1.0, K: 2, SecurityBits: 64}
	if lowSecurity.PreservesNISTCompliance() {
		t.Error("SecurityBits=64 should not preserve NIST compliance")
	}
}

// ─── Attack Simulators ────────────────────────────────────────────────────────

// newCompliantAdinkraGenome builds a genome where all 4 symbols have NIST-compliant params.
func newCompliantAdinkraGenome() *AdinkraGenome {
	g := newAdinkraGenome()
	// Ensure Eban has 256-bit security to satisfy shorAttack
	g.SymbolMappings["Eban"] = LatticeParams{N: 256, Q: 8380417, Sigma: 1.78, K: 4, SecurityBits: 256}
	return g
}

func TestShorAttack_ResistanceRange(t *testing.T) {
	atk := shorAttack{}
	if atk.Probability() <= 0 || atk.Probability() > 1 {
		t.Errorf("shorAttack.Probability out of (0,1]: %f", atk.Probability())
	}
	if atk.Name() == "" {
		t.Error("shorAttack.Name empty")
	}

	// High-security Eban: expect high resistance
	good := newCompliantAdinkraGenome()
	r := atk.SimulateAgainst(good)
	if r < 0.9 {
		t.Errorf("high-security Eban: shorAttack resistance want ≥0.9, got %.4f", r)
	}

	// Low-security Eban: expect degraded resistance
	bad := newAdinkraGenome()
	bad.SymbolMappings["Eban"] = LatticeParams{N: 256, Q: 3329, Sigma: 1.0, K: 2, SecurityBits: 128}
	r2 := atk.SimulateAgainst(bad)
	if r2 > 0.5 {
		t.Errorf("low-security Eban: shorAttack resistance want <0.5, got %.4f", r2)
	}
}

func TestGroverAttack_ResistanceRange(t *testing.T) {
	atk := groverAttack{}
	if atk.Probability() <= 0 || atk.Probability() > 1 {
		t.Errorf("groverAttack.Probability out of (0,1]: %f", atk.Probability())
	}

	// All 256-bit security → Grover resistance should be 1.0
	g256 := newAdinkraGenome()
	for _, sym := range []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"} {
		p := g256.SymbolMappings[sym]
		p.SecurityBits = 256
		g256.SymbolMappings[sym] = p
	}
	r := atk.SimulateAgainst(g256)
	if r < 0.99 {
		t.Errorf("all 256-bit: groverAttack resistance want ≈1.0, got %.4f", r)
	}

	// All 128-bit security → halved by Grover → 128/256 = 0.5
	g128 := newAdinkraGenome()
	for _, sym := range []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"} {
		p := g128.SymbolMappings[sym]
		p.SecurityBits = 128
		g128.SymbolMappings[sym] = p
	}
	r2 := atk.SimulateAgainst(g128)
	expected := 128.0 / 256.0
	if math.Abs(r2-expected) > 0.01 {
		t.Errorf("all 128-bit: groverAttack resistance want %.4f, got %.4f", expected, r2)
	}
}

func TestLatticeReductionAttack_ResistanceRange(t *testing.T) {
	atk := latticeReductionAttack{Dimension: 256}
	if atk.Probability() <= 0 || atk.Probability() > 1 {
		t.Errorf("latticeReductionAttack.Probability out of (0,1]: %f", atk.Probability())
	}
	if atk.Name() == "" {
		t.Error("latticeReductionAttack.Name empty")
	}

	g := newCompliantAdinkraGenome()
	r := atk.SimulateAgainst(g)
	if r < 0 || r > 1 {
		t.Errorf("latticeReductionAttack resistance out of [0,1]: %.4f", r)
	}
	// Genome without Eban degrades resistance
	noEban := newAdinkraGenome()
	delete(noEban.SymbolMappings, "Eban")
	r2 := atk.SimulateAgainst(noEban)
	if r2 > 0.35 {
		t.Errorf("missing Eban: latticeReduction resistance should be ≤0.35, got %.4f", r2)
	}
}

func TestSideChannelTimingAttack_KThreshold(t *testing.T) {
	atk := sideChannelTimingAttack{}
	if atk.Probability() <= 0 || atk.Probability() > 1 {
		t.Errorf("sideChannelTimingAttack.Probability out of (0,1]: %f", atk.Probability())
	}

	// K ≥ 3 everywhere → high resistance
	good := newAdinkraGenome()
	for _, sym := range []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"} {
		p := good.SymbolMappings[sym]
		p.K = 3
		good.SymbolMappings[sym] = p
	}
	r := atk.SimulateAgainst(good)
	if r < 0.85 {
		t.Errorf("K≥3 everywhere: timing resistance want ≥0.85, got %.4f", r)
	}

	// One symbol with K=2 → degraded
	bad := newAdinkraGenome()
	p := bad.SymbolMappings["Dwennimmen"]
	p.K = 2
	bad.SymbolMappings["Dwennimmen"] = p
	r2 := atk.SimulateAgainst(bad)
	if r2 > 0.65 {
		t.Errorf("K=2 present: timing resistance want ≤0.65, got %.4f", r2)
	}
}

func TestSymbolCollisionAttack_DiversityEffect(t *testing.T) {
	atk := symbolCollisionAttack{}
	if atk.Probability() <= 0 || atk.Probability() > 1 {
		t.Errorf("symbolCollisionAttack.Probability out of (0,1]: %f", atk.Probability())
	}

	// All same Q → low diversity → lower resistance
	samQ := newAdinkraGenome()
	for _, sym := range []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"} {
		p := samQ.SymbolMappings[sym]
		p.Q = 3329
		samQ.SymbolMappings[sym] = p
	}
	r := atk.SimulateAgainst(samQ)
	expected := 0.4 + 0.6*(1.0/4.0) // 1 unique Q out of 4
	if math.Abs(r-expected) > 0.01 {
		t.Errorf("all same Q: collision resistance want ≈%.4f, got %.4f", expected, r)
	}

	// All different Q → full diversity → higher resistance
	diffQ := newAdinkraGenome()
	qs := []int{3329, 4096, 7681, 8380417}
	syms := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
	for i, sym := range syms {
		p := diffQ.SymbolMappings[sym]
		p.Q = qs[i]
		diffQ.SymbolMappings[sym] = p
	}
	r2 := atk.SimulateAgainst(diffQ)
	if r2 < 0.99 {
		t.Errorf("all different Q: collision resistance want ≈1.0, got %.4f", r2)
	}
}

func TestAllAttackSimulators_ResistanceInUnitInterval(t *testing.T) {
	attacks := []AttackSimulator{
		shorAttack{},
		groverAttack{},
		latticeReductionAttack{Dimension: 256},
		sideChannelTimingAttack{},
		symbolCollisionAttack{},
	}
	genomes := []*AdinkraGenome{
		newAdinkraGenome(),
		newCompliantAdinkraGenome(),
	}

	for _, atk := range attacks {
		for gi, g := range genomes {
			r := atk.SimulateAgainst(g)
			if r < 0 || r > 1 {
				t.Errorf("%s.SimulateAgainst(genome[%d]) = %.4f out of [0,1]", atk.Name(), gi, r)
			}
		}
	}
}

// ─── AdinkraFitnessFunc ───────────────────────────────────────────────────────

func TestAdinkraFitnessFunc_ValidRange(t *testing.T) {
	ff := AdinkraFitnessFunc()

	// Test with multiple genome varieties
	testCases := [][]byte{
		make([]byte, AdinkraGenomeSize),        // all zeros
		func() []byte { g := make([]byte, AdinkraGenomeSize); for i := range g { g[i] = 0xFF }; return g }(), // all 0xFF
		func() []byte { g := make([]byte, AdinkraGenomeSize); for i := range g { g[i] = byte(i % 256) }; return g }(),
	}

	for i, genome := range testCases {
		ind := &Individual{ID: "test", Genome: genome}
		f, err := ff(ind)
		if err != nil {
			t.Errorf("case %d: fitness error: %v", i, err)
		}
		if f < 0 || f > 1.0 {
			t.Errorf("case %d: fitness %.6f out of [0,1]", i, f)
		}
	}
}

func TestAdinkraFitnessFunc_NISTBonusApplied(t *testing.T) {
	ff := AdinkraFitnessFunc()

	// Build a genome that decodes to a fully NIST-compliant AdinkraGenome.
	// Use the canonical genome (produced by newAdinkraGenome, which is compliant).
	g := newAdinkraGenome()
	encoded, err := EncodeAdinkraGenome(g)
	if err != nil {
		t.Fatalf("EncodeAdinkraGenome: %v", err)
	}

	ind := &Individual{ID: "nist-compliant", Genome: encoded}
	f, err := ff(ind)
	if err != nil {
		t.Fatalf("fitness eval: %v", err)
	}
	// NIST-compliant genomes get ×1.5 multiplier then clamp; expect high fitness.
	if f < 0.5 {
		t.Errorf("NIST-compliant genome fitness too low: %.4f", f)
	}
}

func TestAdinkraFitnessFunc_ShortGenomeNearZeroFitness(t *testing.T) {
	ff := AdinkraFitnessFunc()
	// Too short to decode lattice params (< GenomeSize) but we need GenomeSize minimum.
	// The fitness func handles this via decodeAdinkraGenome returning an error.
	ind := &Individual{ID: "short", Genome: make([]byte, GenomeSize-1)}
	f, err := ff(ind)
	if err != nil {
		t.Fatalf("unexpected error from fitness func with short genome: %v", err)
	}
	if f != 0.001 {
		t.Errorf("short genome fitness: want 0.001 (invalid genome fallback), got %.6f", f)
	}
}

// ─── EncodeAdinkraGenome / decodeAdinkraGenome ────────────────────────────────

func TestEncodeDecodeAdinkraGenome_RoundTrip(t *testing.T) {
	g := newAdinkraGenome()
	encoded, err := EncodeAdinkraGenome(g)
	if err != nil {
		t.Fatalf("EncodeAdinkraGenome: %v", err)
	}
	if len(encoded) != AdinkraGenomeSize {
		t.Errorf("encoded length: want %d, got %d", AdinkraGenomeSize, len(encoded))
	}

	decoded, err := decodeAdinkraGenome(encoded)
	if err != nil {
		t.Fatalf("decodeAdinkraGenome: %v", err)
	}

	// Each symbol must survive the encode→decode round-trip within quantisation error.
	// Encoding uses integer truncation (e.g., Q/100000), so check approximate equality.
	for _, sym := range []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"} {
		orig := g.SymbolMappings[sym]
		got := decoded.SymbolMappings[sym]

		// N round-trips exactly (genome[base] = N/4, decode = *4)
		if got.N != orig.N {
			t.Errorf("%s: N round-trip: want %d, got %d", sym, orig.N, got.N)
		}
		// K round-trips exactly
		if got.K != orig.K {
			t.Errorf("%s: K round-trip: want %d, got %d", sym, orig.K, got.K)
		}
		// SecurityBits round-trips within 32-bit quantisation
		if abs(got.SecurityBits, orig.SecurityBits) > 32 {
			t.Errorf("%s: SecurityBits round-trip: want ≈%d, got %d", sym, orig.SecurityBits, got.SecurityBits)
		}
	}
}

func TestDecodeAdinkraGenome_TooShortErrors(t *testing.T) {
	_, err := decodeAdinkraGenome(make([]byte, GenomeSize-1))
	if err == nil {
		t.Error("expected error for genome shorter than GenomeSize, got nil")
	}
}

func TestDecodeAdinkraGenome_NISTFloorEnforced(t *testing.T) {
	// Build a genome that would decode to sub-NIST values if floors weren't applied.
	genome := make([]byte, AdinkraGenomeSize)
	symbols := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
	for i := range symbols {
		base := 48 + i*8
		genome[base+0] = 0   // N = 0*4 = 0 → must be clamped to 256
		genome[base+1] = 0   // Q = 0*100000 = 0 → must be clamped to 3329
		genome[base+2] = 0   // Sigma = 0/10 = 0.0 → must be clamped to 1.0
		genome[base+3] = 0   // K = 0 → must be clamped to 2
		genome[base+4] = 0   // SecurityBits = 0*32 = 0 → must be clamped to 128
	}

	decoded, err := decodeAdinkraGenome(genome)
	if err != nil {
		t.Fatalf("decodeAdinkraGenome: %v", err)
	}

	for _, sym := range symbols {
		p := decoded.SymbolMappings[sym]
		if p.N < 256 {
			t.Errorf("%s: N floor not enforced: got %d", sym, p.N)
		}
		if p.Q < 3329 {
			t.Errorf("%s: Q floor not enforced: got %d", sym, p.Q)
		}
		if p.Sigma <= 0 {
			t.Errorf("%s: Sigma floor not enforced: got %f", sym, p.Sigma)
		}
		if p.K < 2 {
			t.Errorf("%s: K floor not enforced: got %d", sym, p.K)
		}
		if p.SecurityBits < 128 {
			t.Errorf("%s: SecurityBits floor not enforced: got %d", sym, p.SecurityBits)
		}
	}
}

func TestDecodeAdinkraGenome_DAGWeightsDecoded(t *testing.T) {
	g := newAdinkraGenome()
	// Set known consensus weights
	g.DAGConsensusWeights = [4]float64{1.0, 0.5, 0.25, 0.0}

	encoded, _ := EncodeAdinkraGenome(g)
	decoded, err := decodeAdinkraGenome(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Weight 1.0 → byte 255 → decoded as 255/255 = 1.0
	if math.Abs(decoded.DAGConsensusWeights[0]-1.0) > 0.005 {
		t.Errorf("DAGConsensusWeights[0]: want ≈1.0, got %.4f", decoded.DAGConsensusWeights[0])
	}
	// Weight 0.0 → byte 0 → decoded as 0/255 = 0.0
	if math.Abs(decoded.DAGConsensusWeights[3]-0.0) > 0.005 {
		t.Errorf("DAGConsensusWeights[3]: want ≈0.0, got %.4f", decoded.DAGConsensusWeights[3])
	}
}

func TestDecodeAdinkraGenome_ZeroTrustThresholdsDecoded(t *testing.T) {
	g := newAdinkraGenome()
	g.ZeroTrustThresholds["trust_score_min"] = 0.80   // → byte = 80*25 = 20 → decoded = 20/25 = 0.8
	g.ZeroTrustThresholds["anomaly_sigma"]   = 3.0    // → byte = 3*25 = 75 → decoded = 75/25 = 3.0

	encoded, _ := EncodeAdinkraGenome(g)
	decoded, err := decodeAdinkraGenome(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	trust := decoded.ZeroTrustThresholds["trust_score_min"]
	if math.Abs(trust-0.80) > 0.04 { // allow quantisation error
		t.Errorf("trust_score_min round-trip: want ≈0.80, got %.4f", trust)
	}
	anomaly := decoded.ZeroTrustThresholds["anomaly_sigma"]
	if math.Abs(anomaly-3.0) > 0.04 {
		t.Errorf("anomaly_sigma round-trip: want ≈3.0, got %.4f", anomaly)
	}
}

// ─── allNISTCompliant ─────────────────────────────────────────────────────────

func TestAllNISTCompliant_AllValid(t *testing.T) {
	g := newAdinkraGenome()
	if !allNISTCompliant(g) {
		t.Error("canonical adinkra genome should be NIST compliant")
	}
}

func TestAllNISTCompliant_OneInvalidParam(t *testing.T) {
	g := newAdinkraGenome()
	// Introduce one invalid param
	p := g.SymbolMappings["Eban"]
	p.SecurityBits = 64
	g.SymbolMappings["Eban"] = p

	if allNISTCompliant(g) {
		t.Error("genome with SecurityBits=64 should not be NIST compliant")
	}
}

func TestAllNISTCompliant_EmptyMappings(t *testing.T) {
	g := &AdinkraGenome{SymbolMappings: map[string]LatticeParams{}}
	// Empty mappings have no invalid params → compliant (vacuously true)
	if !allNISTCompliant(g) {
		t.Error("empty symbol mappings should vacuously satisfy NIST compliance")
	}
}

// ─── AdinkraEAEngine ──────────────────────────────────────────────────────────

func TestNewAdinkraEAEngine_CreatesValidEngine(t *testing.T) {
	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("GenerateDilithiumKey: %v", err)
	}

	eng, err := NewAdinkraEAEngine(dag.NewMemory(), sk, pk)
	if err != nil {
		t.Fatalf("NewAdinkraEAEngine: %v", err)
	}
	if eng.EAEngine == nil {
		t.Error("embedded EAEngine is nil")
	}

	s := eng.Status()
	if s.Generation != 0 {
		t.Errorf("initial generation: want 0, got %d", s.Generation)
	}
	if s.PopulationSize != DefaultPopulationSize {
		t.Errorf("population size: want %d, got %d", DefaultPopulationSize, s.PopulationSize)
	}
}

func TestNewAdinkraEAEngine_NilDAGStore(t *testing.T) {
	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("GenerateDilithiumKey: %v", err)
	}
	// nil DAGStore must be accepted (engine creates an in-memory store)
	eng, err := NewAdinkraEAEngine(nil, sk, pk)
	if err != nil {
		t.Fatalf("NewAdinkraEAEngine(nil DAGStore): %v", err)
	}
	if eng == nil {
		t.Fatal("got nil engine")
	}
}

func TestAdinkraEAEngine_Evolve(t *testing.T) {
	pk, sk, _ := adinkra.GenerateDilithiumKey()
	eng, err := NewAdinkraEAEngine(dag.NewMemory(), sk, pk)
	if err != nil {
		t.Fatalf("NewAdinkraEAEngine: %v", err)
	}

	for i := 0; i < 3; i++ {
		best, err := eng.Evolve()
		if err != nil {
			t.Fatalf("Evolve #%d: %v", i+1, err)
		}
		if best == nil {
			t.Fatalf("Evolve #%d returned nil", i+1)
		}
		if best.Fitness < 0 || best.Fitness > 1.0 {
			t.Errorf("Evolve #%d fitness out of [0,1]: %.4f", i+1, best.Fitness)
		}
	}
}

func TestBestAdinkraGenome_ReturnsNISTCompliant(t *testing.T) {
	pk, sk, _ := adinkra.GenerateDilithiumKey()
	eng, err := NewAdinkraEAEngine(dag.NewMemory(), sk, pk)
	if err != nil {
		t.Fatalf("NewAdinkraEAEngine: %v", err)
	}

	// Run a few generations so the genome is decoded from the evolving population
	for i := 0; i < 3; i++ {
		eng.Evolve() //nolint:errcheck
	}

	g, err := eng.BestAdinkraGenome()
	if err != nil {
		t.Fatalf("BestAdinkraGenome: %v", err)
	}
	if g == nil {
		t.Fatal("BestAdinkraGenome returned nil")
	}

	// NIST floors in decodeAdinkraGenome must guarantee compliance
	for sym, p := range g.SymbolMappings {
		if err := p.Validate(); err != nil {
			t.Errorf("symbol %q: validate failed: %v", sym, err)
		}
	}
}

func TestBestAdinkraGenome_MetadataPropagated(t *testing.T) {
	pk, sk, _ := adinkra.GenerateDilithiumKey()
	eng, err := NewAdinkraEAEngine(dag.NewMemory(), sk, pk)
	if err != nil {
		t.Fatalf("NewAdinkraEAEngine: %v", err)
	}
	eng.Evolve() //nolint:errcheck

	g, err := eng.BestAdinkraGenome()
	if err != nil {
		t.Fatalf("BestAdinkraGenome: %v", err)
	}
	if g.Generation != 1 {
		t.Errorf("genome generation: want 1, got %d", g.Generation)
	}
	if g.Fitness <= 0 {
		t.Errorf("genome fitness should be >0, got %.6f", g.Fitness)
	}
}

// ─── ExportBestAsJSON ─────────────────────────────────────────────────────────

func TestExportBestAsJSON_ValidSchema(t *testing.T) {
	pk, sk, _ := adinkra.GenerateDilithiumKey()
	eng, err := NewAdinkraEAEngine(dag.NewMemory(), sk, pk)
	if err != nil {
		t.Fatalf("NewAdinkraEAEngine: %v", err)
	}
	eng.Evolve() //nolint:errcheck

	raw, err := eng.ExportBestAsJSON()
	if err != nil {
		t.Fatalf("ExportBestAsJSON: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("ExportBestAsJSON returned empty bytes")
	}

	// Must be valid JSON
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("ExportBestAsJSON is not valid JSON: %v", err)
	}

	requiredFields := []string{
		"schema", "exported_at", "generation", "fitness",
		"symbol_mappings", "consensus_weights", "zero_trust", "nist_compliant",
	}
	for _, field := range requiredFields {
		if _, ok := m[field]; !ok {
			t.Errorf("ExportBestAsJSON missing field: %q", field)
		}
	}

	// Schema URI must match
	const wantSchema = "https://adinkhepra.dev/ea/adinkra-genome/v1"
	if s, ok := m["schema"].(string); !ok || s != wantSchema {
		t.Errorf("schema field: want %q, got %v", wantSchema, m["schema"])
	}

	// nist_compliant must be a bool
	if _, ok := m["nist_compliant"].(bool); !ok {
		t.Errorf("nist_compliant should be a bool, got %T", m["nist_compliant"])
	}
}

func TestExportBestAsJSON_FitnessInRange(t *testing.T) {
	pk, sk, _ := adinkra.GenerateDilithiumKey()
	eng, _ := NewAdinkraEAEngine(dag.NewMemory(), sk, pk)
	eng.Evolve() //nolint:errcheck

	raw, _ := eng.ExportBestAsJSON()
	var m map[string]interface{}
	json.Unmarshal(raw, &m) //nolint:errcheck

	fitness, ok := m["fitness"].(float64)
	if !ok {
		t.Fatalf("fitness is not float64: %T", m["fitness"])
	}
	if fitness < 0 || fitness > 1.0 {
		t.Errorf("exported fitness out of [0,1]: %f", fitness)
	}
}

// ─── newAdinkraGenome ─────────────────────────────────────────────────────────

func TestNewAdinkraGenome_FourSymbolsPresent(t *testing.T) {
	g := newAdinkraGenome()
	required := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
	for _, sym := range required {
		if _, ok := g.SymbolMappings[sym]; !ok {
			t.Errorf("newAdinkraGenome missing symbol: %q", sym)
		}
	}
}

func TestNewAdinkraGenome_BaselineIsNISTCompliant(t *testing.T) {
	g := newAdinkraGenome()
	for sym, p := range g.SymbolMappings {
		if err := p.Validate(); err != nil {
			t.Errorf("symbol %q baseline params invalid: %v", sym, err)
		}
	}
}

func TestNewAdinkraGenome_UniqueIDs(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		g := newAdinkraGenome()
		if ids[g.ID] {
			t.Errorf("duplicate AdinkraGenome ID at iteration %d: %q", i, g.ID)
		}
		ids[g.ID] = true
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func abs(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
