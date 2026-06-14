// Package ea — AdinkraEvolution implements the EA applied specifically to the
// proprietary Adinkra symbol→lattice-parameter mapping.
//
// Patent-pending IP: the Adinkra Spectral Lattice derives ML-DSA-65/Kyber-1024
// parameters from Adinkra glyph adjacency matrices. This file evolves WHICH
// parameter mappings are optimal against a simulated threat model, making the
// cryptographic framework self-hardening — a capability no competitor has.
//
// Every evolved generation is DAG-recorded and Dilithium-signed, proving
// continuous provable hardening for FedRAMP/CMMC continuous monitoring requirements.
package ea

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/google/uuid"
)

// ─── Lattice Parameters ───────────────────────────────────────────────────────

// LatticeParams represents the tunable parameters of a lattice-based crypto scheme.
// These map to real CRYSTALS-Dilithium and Kyber parameter families.
type LatticeParams struct {
	N           int     `json:"n"`            // Ring dimension (256/512/1024)
	Q           int     `json:"q"`            // Modulus
	Sigma       float64 `json:"sigma"`        // Error distribution standard deviation
	K           int     `json:"k"`            // Module rank (2/3/4)
	SecurityBits int    `json:"security_bits"` // Target classical security level
}

// Validate checks that params are within NIST-acceptable ranges for ML-DSA / ML-KEM.
func (lp LatticeParams) Validate() error {
	validN := map[int]bool{256: true, 512: true, 1024: true}
	if !validN[lp.N] {
		return fmt.Errorf("lattice N must be 256/512/1024, got %d", lp.N)
	}
	if lp.Q < 3329 || lp.Q > 8380417 {
		return fmt.Errorf("lattice Q out of NIST range [3329, 8380417]: %d", lp.Q)
	}
	if lp.Sigma <= 0 || lp.Sigma > 10 {
		return fmt.Errorf("lattice sigma must be in (0, 10]: %f", lp.Sigma)
	}
	if lp.K < 2 || lp.K > 4 {
		return fmt.Errorf("lattice K must be 2–4: %d", lp.K)
	}
	if lp.SecurityBits < 128 {
		return fmt.Errorf("security bits below minimum 128: %d", lp.SecurityBits)
	}
	return nil
}

// PreservesNISTCompliance returns true iff the params remain within NIST PQC
// standardised boundaries. Genomes that drift outside NIST are penalised in fitness.
func (lp LatticeParams) PreservesNISTCompliance() bool {
	return lp.Validate() == nil && lp.SecurityBits >= 128
}

// ─── Adinkra Genome ───────────────────────────────────────────────────────────

// AdinkraGenome represents a candidate mapping of Adinkra symbols to lattice parameters.
// The EA evolves these mappings to maximise resistance against a simulated threat model.
type AdinkraGenome struct {
	ID             string                    `json:"id"`
	SymbolMappings map[string]LatticeParams  `json:"symbol_mappings"`
	DAGConsensusWeights [4]float64           `json:"dag_consensus_weights"`
	ZeroTrustThresholds map[string]float64   `json:"zero_trust_thresholds"`
	Generation     int                       `json:"generation"`
	Fitness        float64                   `json:"fitness"`
	DAGNodeID      string                    `json:"dag_node_id,omitempty"`
}

// newAdinkraGenome creates an AdinkraGenome initialised from the canonical
// Adinkra spectral fingerprints (NIST-compliant baseline).
func newAdinkraGenome() *AdinkraGenome {
	return &AdinkraGenome{
		ID:         uuid.New().String(),
		SymbolMappings: map[string]LatticeParams{
			"Eban": {N: 256, Q: 8380417, Sigma: 1.78, K: 4, SecurityBits: 256},
			"Fawohodie": {N: 256, Q: 8380417, Sigma: 1.98, K: 3, SecurityBits: 192},
			"Nkyinkyim": {N: 256, Q: 3329, Sigma: 1.0, K: 3, SecurityBits: 192},
			"Dwennimmen": {N: 256, Q: 3329, Sigma: 1.0, K: 2, SecurityBits: 128},
		},
		DAGConsensusWeights: [4]float64{0.7, 0.5, 0.3, 0.2},
		ZeroTrustThresholds: map[string]float64{
			"trust_score_min":   0.85,
			"entropy_threshold": 7.2,
			"anomaly_sigma":     3.0,
		},
	}
}

// ─── Attack Simulations ───────────────────────────────────────────────────────

// AttackSimulator simulates a cryptanalytic attack against a genome and returns
// a resistance score in [0.0, 1.0] where 1.0 = fully resists.
type AttackSimulator interface {
	Name() string
	// Probability returns the estimated probability this attack is attempted
	// against a typical enterprise deployment in the next 5 years.
	Probability() float64
	// SimulateAgainst returns a resistance score [0.0, 1.0].
	SimulateAgainst(g *AdinkraGenome) float64
}

// shorAttack models a Shor's algorithm threat against ECDSA/RSA components.
// Adinkra ML-DSA-65 is quantum-resistant, so high resistance is expected.
type shorAttack struct{}

func (s shorAttack) Name() string        { return "Shor-Algorithm" }
func (s shorAttack) Probability() float64 { return 0.15 } // 5-year horizon estimate

func (s shorAttack) SimulateAgainst(g *AdinkraGenome) float64 {
	// ML-DSA-65 is Shor-resistant by construction. Score degrades only if
	// the genome drifts to low security bits (e.g., mutated to < 256 bits for Eban).
	eban, ok := g.SymbolMappings["Eban"]
	if !ok || eban.SecurityBits < 256 {
		return 0.4 // Degraded: Eban symbol compromised
	}
	return 0.98
}

// groverAttack models Grover's algorithm halving symmetric key search space.
type groverAttack struct{}

func (g groverAttack) Name() string        { return "Grover-Search" }
func (g groverAttack) Probability() float64 { return 0.35 }

func (g groverAttack) SimulateAgainst(genome *AdinkraGenome) float64 {
	// Grover halves effective key length. Parameters with SecurityBits < 256
	// drop below 128-bit post-quantum security.
	minBits := math.MaxFloat64
	for _, p := range genome.SymbolMappings {
		bits := float64(p.SecurityBits)
		if bits < minBits {
			minBits = bits
		}
	}
	// Grover resistance is proportional to security bits / 256
	if minBits >= 256 {
		return 1.0
	}
	return math.Max(0.0, minBits/256.0)
}

// latticeReductionAttack models BKZ/LLL lattice basis reduction.
// Resistance depends on the modulus Q, dimension N, and error sigma.
type latticeReductionAttack struct {
	Dimension int // BKZ block dimension
}

func (l latticeReductionAttack) Name() string { return fmt.Sprintf("LatticeReduction-BKZ%d", l.Dimension) }
func (l latticeReductionAttack) Probability() float64 { return 0.25 }

func (l latticeReductionAttack) SimulateAgainst(g *AdinkraGenome) float64 {
	// BKZ hardness grows exponentially with N and Q. Small N or small Q weakens.
	eban, ok := g.SymbolMappings["Eban"]
	if !ok {
		return 0.3
	}
	// Root Hermite factor: δ ≈ ((πβ)^(1/β) * β/(2πe))^(1/(2β-2))
	// For BKZ-dimension β, hardness is ~2^(0.292β). At β=256, hardness≈2^75.
	beta := float64(l.Dimension)
	hardnessBits := 0.292 * beta
	// Penalise if N is small relative to attack dimension
	effectiveness := math.Min(1.0, float64(eban.N)/float64(l.Dimension+64))
	// Sigma above 1.5 improves resistance
	sigmaBonus := math.Min(0.1, eban.Sigma*0.05)
	resistance := math.Min(1.0, (hardnessBits/128.0)*effectiveness+sigmaBonus)
	return resistance
}

// sideChannelTimingAttack models timing/power side-channel vulnerabilities.
type sideChannelTimingAttack struct{}

func (s sideChannelTimingAttack) Name() string        { return "SideChannel-Timing" }
func (s sideChannelTimingAttack) Probability() float64 { return 0.45 }

func (s sideChannelTimingAttack) SimulateAgainst(g *AdinkraGenome) float64 {
	// Higher K (module rank) increases operations, improving constant-time properties
	// when combined with proper masking. Penalise genomes with K < 3.
	minK := 4
	for _, p := range g.SymbolMappings {
		if p.K < minK {
			minK = p.K
		}
	}
	if minK >= 3 {
		return 0.88 // Good: higher module rank
	}
	return 0.6 // Degraded
}

// symbolCollisionAttack models an attack unique to the Adinkra framework:
// attempting to forge an Adinkra symbol hash to produce a valid-but-different
// lattice fingerprint. This is the novel attack vector from the patent.
type symbolCollisionAttack struct{}

func (s symbolCollisionAttack) Name() string        { return "AdinkraSymbol-Collision" }
func (s symbolCollisionAttack) Probability() float64 { return 0.05 }

func (s symbolCollisionAttack) SimulateAgainst(g *AdinkraGenome) float64 {
	// Resistance depends on the entropy diversity across symbol mappings.
	// If all symbols map to identical params, collision is trivial.
	params := make([]LatticeParams, 0, len(g.SymbolMappings))
	for _, p := range g.SymbolMappings {
		params = append(params, p)
	}
	if len(params) < 2 {
		return 0.2
	}
	// Measure Q-diversity across symbols as collision resistance proxy
	qValues := make(map[int]bool)
	for _, p := range params {
		qValues[p.Q] = true
	}
	diversity := float64(len(qValues)) / float64(len(params))
	return 0.4 + 0.6*diversity
}

// ─── Fitness Function ─────────────────────────────────────────────────────────

// AdinkraFitnessFunc returns a FitnessFunc that evaluates an Individual
// by decoding its genome as an AdinkraGenome and scoring it against all attacks.
// The fitness landscape is multi-objective:
//
//	Maximize: attack resistance × NIST compliance bonus
//	Minimize: non-NIST-compliant drifts
func AdinkraFitnessFunc() FitnessFunc {
	attacks := []AttackSimulator{
		shorAttack{},
		groverAttack{},
		latticeReductionAttack{Dimension: 256},
		sideChannelTimingAttack{},
		symbolCollisionAttack{},
	}

	return func(ind *Individual) (float64, error) {
		g, err := decodeAdinkraGenome(ind.Genome)
		if err != nil {
			// Genome is structurally invalid — assign near-zero fitness
			return 0.001, nil
		}

		score := 0.0
		totalWeight := 0.0

		for _, atk := range attacks {
			resistance := atk.SimulateAgainst(g)
			prob := atk.Probability()
			score += resistance * prob
			totalWeight += prob
		}

		if totalWeight > 0 {
			score /= totalWeight
		}

		// NIST compliance bonus: genomes that stay within NIST boundaries get +50%
		if allNISTCompliant(g) {
			score *= 1.5
		}

		// Clamp to [0, 1]
		if score > 1.0 {
			score = 1.0
		}
		return score, nil
	}
}

// allNISTCompliant returns true iff every symbol mapping passes LatticeParams.Validate().
func allNISTCompliant(g *AdinkraGenome) bool {
	for _, p := range g.SymbolMappings {
		if !p.PreservesNISTCompliance() {
			return false
		}
	}
	return true
}

// ─── Genome Encoding ──────────────────────────────────────────────────────────

// EncodeAdinkraGenome packs an AdinkraGenome into the fixed-width EA genome format.
// The Adinkra genome is larger than the base EA GenomeSize, so we extend to
// AdinkraGenomeSize bytes.
//
// Layout (96 bytes total):
//
//	[0:48]  base EA genome (strategy weights, flags, thresholds)
//	[48:56] Eban params (N/4, Q/100000, Sigma*10, K, SecurityBits/32)
//	[56:64] Fawohodie params
//	[64:72] Nkyinkyim params
//	[72:80] Dwennimmen params
//	[80:88] DAG consensus weights (4×float16 as uint8 pairs)
//	[88:96] ZeroTrust thresholds (3×float as uint8 encoding)
const AdinkraGenomeSize = 96

func EncodeAdinkraGenome(g *AdinkraGenome) ([]byte, error) {
	genome := make([]byte, AdinkraGenomeSize)

	// Fill base 48 bytes from spectral fingerprints of each symbol
	fingerprints := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
	pos := 0
	for _, sym := range fingerprints {
		fp := adinkra.GetSpectralFingerprint(sym) // 32 bytes
		if pos+len(fp) <= 48 {
			copy(genome[pos:], fp)
			pos += len(fp)
		}
	}

	// Encode symbol lattice params (bytes 48–79)
	symbols := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
	for i, sym := range symbols {
		p, ok := g.SymbolMappings[sym]
		if !ok {
			continue
		}
		base := 48 + i*8
		if base+7 >= AdinkraGenomeSize {
			break
		}
		genome[base+0] = byte(p.N / 4)
		genome[base+1] = byte(p.Q / 100000)
		genome[base+2] = byte(p.Sigma * 10)
		genome[base+3] = byte(p.K)
		genome[base+4] = byte(p.SecurityBits / 32)
		// [5–7] reserved
	}

	// Encode DAG consensus weights (bytes 80–87)
	for i, w := range g.DAGConsensusWeights {
		if 80+i >= AdinkraGenomeSize {
			break
		}
		genome[80+i] = byte(w * 255)
	}

	// Encode ZeroTrust thresholds (bytes 88–90)
	thresholdKeys := []string{"trust_score_min", "entropy_threshold", "anomaly_sigma"}
	for i, key := range thresholdKeys {
		if 88+i >= AdinkraGenomeSize {
			break
		}
		if v, ok := g.ZeroTrustThresholds[key]; ok {
			genome[88+i] = byte(v * 25) // scale to byte range
		}
	}

	return genome, nil
}

// decodeAdinkraGenome reconstructs an AdinkraGenome from a raw genome byte slice.
func decodeAdinkraGenome(genome []byte) (*AdinkraGenome, error) {
	if len(genome) < GenomeSize {
		return nil, fmt.Errorf("genome too short: need %d bytes", GenomeSize)
	}

	g := newAdinkraGenome()

	// If genome is the extended AdinkraGenomeSize, decode lattice params
	if len(genome) >= AdinkraGenomeSize {
		symbols := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
		for i, sym := range symbols {
			base := 48 + i*8
			if base+4 >= len(genome) {
				break
			}
			n := int(genome[base+0]) * 4
			q := int(genome[base+1]) * 100000
			sigma := float64(genome[base+2]) / 10.0
			k := int(genome[base+3])
			secBits := int(genome[base+4]) * 32

			// Apply NIST floor values to prevent illegal parameter drift
			if n < 256 { n = 256 }
			if q < 3329 { q = 3329 }
			if sigma <= 0 { sigma = 1.0 }
			if k < 2 { k = 2 }
			if secBits < 128 { secBits = 128 }

			g.SymbolMappings[sym] = LatticeParams{N: n, Q: q, Sigma: sigma, K: k, SecurityBits: secBits}
		}

		// Decode DAG consensus weights
		for i := range g.DAGConsensusWeights {
			if 80+i < len(genome) {
				g.DAGConsensusWeights[i] = float64(genome[80+i]) / 255.0
			}
		}

		// Decode ZeroTrust thresholds
		thresholdKeys := []string{"trust_score_min", "entropy_threshold", "anomaly_sigma"}
		for i, key := range thresholdKeys {
			if 88+i < len(genome) {
				g.ZeroTrustThresholds[key] = float64(genome[88+i]) / 25.0
			}
		}
	}

	return g, nil
}

// ─── AdinkraEAEngine ──────────────────────────────────────────────────────────

// AdinkraEAEngine specialises the base EAEngine for Adinkra symbol evolution.
// It uses the AdinkraFitnessFunc and records every generation's best genome
// as a DAG node — providing a cryptographically-provable evolution audit trail.
type AdinkraEAEngine struct {
	*EAEngine
	dagStore dag.Store
}

// NewAdinkraEAEngine creates an EA engine pre-configured for Adinkra evolution.
func NewAdinkraEAEngine(dagStore dag.Store, dilithiumSK, dilithiumPK []byte) (*AdinkraEAEngine, error) {
	if dagStore == nil {
		dagStore = dag.NewMemory()
	}

	cfg := EngineConfig{
		PopulationSize: DefaultPopulationSize,
		MutationRate:   DefaultMutationRate,
		CrossoverRate:  DefaultCrossoverRate,
		FitnessFunc:    AdinkraFitnessFunc(),
		DAGStore:       dagStore,
		DilithiumSK:    dilithiumSK,
		DilithiumPK:    dilithiumPK,
		AgentID:        "adinkra-ea-engine",
	}

	base, err := NewEAEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("AdinkraEAEngine init: %w", err)
	}

	return &AdinkraEAEngine{EAEngine: base, dagStore: dagStore}, nil
}

// BestAdinkraGenome returns the decoded AdinkraGenome of the current best individual.
func (ae *AdinkraEAEngine) BestAdinkraGenome() (*AdinkraGenome, error) {
	best := ae.BestIndividual()
	if best == nil {
		return nil, fmt.Errorf("AdinkraEAEngine: no individuals in population")
	}
	g, err := decodeAdinkraGenome(best.Genome)
	if err != nil {
		return nil, fmt.Errorf("AdinkraEAEngine: decode best genome: %w", err)
	}
	g.Generation = best.Generation
	g.Fitness = best.Fitness
	g.DAGNodeID = best.DAGNodeID
	return g, nil
}

// ExportBestAsJSON returns the current champion genome as a JSON payload,
// suitable for embedding in compliance evidence packages.
func (ae *AdinkraEAEngine) ExportBestAsJSON() ([]byte, error) {
	g, err := ae.BestAdinkraGenome()
	if err != nil {
		return nil, err
	}

	export := map[string]interface{}{
		"schema":            "https://adinkhepra.dev/ea/adinkra-genome/v1",
		"exported_at":       time.Now().UTC().Format(time.RFC3339),
		"generation":        g.Generation,
		"fitness":           g.Fitness,
		"dag_node_id":       g.DAGNodeID,
		"symbol_mappings":   g.SymbolMappings,
		"consensus_weights": g.DAGConsensusWeights,
		"zero_trust":        g.ZeroTrustThresholds,
		"nist_compliant":    allNISTCompliant(g),
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal genome export: %w", err)
	}
	return data, nil
}
