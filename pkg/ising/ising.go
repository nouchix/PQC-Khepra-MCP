// pkg/ising/ising.go — Native Go port of KhepraCypher/ising_optimizer.js
//
// Ported from G0DM0D KhepraCypher into khepra-protocol as first-class product code.
// The G0DM0D repo retains its own copy for personal use; this is the canonical
// product implementation with no cross-repo dependency.
//
// The Ising model treats a set of agents/nodes as spins on a lattice.
// Coupling strengths are determined by the active Adinkra symbol's 8×8
// adjacency matrix (patent §3.1), modulated by node-level activity entropy.
// Metropolis-Hastings annealing finds the ground state (lowest energy configuration).
//
// Compliance mapping:
//   03.12.01 Security Assessments     — each anneal run is a continuous assessment
//   03.12.03 Internal System Connections — coupling matrix maps system topology
//   03.13.15 Communications Authenticity — coherence score measures trust alignment
//   03.03.08 Audit Protection         — symbol rotation events are PQC-attested

package ising

import (
	"math"
	"math/rand"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// Spin represents the binary state of a node in the Ising lattice.
type Spin int8

const (
	Up   Spin = 1
	Down Spin = -1
)

// Optimizer holds the annealing parameters and the active Adinkra symbol.
type Optimizer struct {
	Temperature  float64
	CoolingRate  float64
	MinTemp      float64
	ActiveSymbol string
}

// New creates an Optimizer with default annealing parameters and the given symbol.
// Default: T=1.5, cooling=0.95, minT=0.01 — matches JS v4 defaults.
func New(symbol string) *Optimizer {
	if _, ok := adinkra.SymbolMatrices[symbol]; !ok {
		symbol = "Eban" // safe default
	}
	return &Optimizer{
		Temperature:  1.5,
		CoolingRate:  0.95,
		MinTemp:      0.01,
		ActiveSymbol: symbol,
	}
}

// SetSymbol rotates to a new Adinkra symbol.
func (o *Optimizer) SetSymbol(symbol string) {
	if _, ok := adinkra.SymbolMatrices[symbol]; ok {
		o.ActiveSymbol = symbol
	}
}

// NextSymbol rotates to the next symbol in the sequence: Eban→Fawohodie→Nkyinkyim→Dwennimmen→Eban
func (o *Optimizer) NextSymbol() string {
	seq := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
	for i, s := range seq {
		if s == o.ActiveSymbol {
			next := seq[(i+1)%len(seq)]
			o.ActiveSymbol = next
			return next
		}
	}
	return o.ActiveSymbol
}

// SpectralFingerprint computes the top-4 dominant eigenvalues of the active
// symbol's adjacency matrix via power iteration with deflation.
// Mirrors getSpectralFingerprint() from KhepraCypher/adinkra.js exactly.
func (o *Optimizer) SpectralFingerprint() [4]float64 {
	matrix, ok := adinkra.SymbolMatrices[o.ActiveSymbol]
	if !ok {
		return [4]float64{}
	}

	const dim = 8
	const topK = 4

	// Copy matrix to float64 for deflation
	A := [dim][dim]float64{}
	for i := 0; i < dim; i++ {
		for j := 0; j < dim; j++ {
			A[i][j] = float64(matrix[i][j])
		}
	}

	var eigenvalues [topK]float64
	for k := 0; k < topK; k++ {
		// Initial vector with k-shifted start (mirrors JS)
		v := [dim]float64{}
		for i := 0; i < dim; i++ {
			v[i] = float64(i+k+1)*0.1 + 0.01
		}
		normalise8(&v)

		lambda := 0.0
		for iter := 0; iter < 64; iter++ {
			w := matvec8(&A, &v)
			lambda = dot8(&v, &w)
			normalise8(&w)
			v = w
		}
		eigenvalues[k] = lambda

		// Deflate: A ← A - λ·v·vᵀ
		for i := 0; i < dim; i++ {
			for j := 0; j < dim; j++ {
				A[i][j] -= lambda * v[i] * v[j]
			}
		}
	}
	return eigenvalues
}

// BuildCouplingMatrix constructs the Adinkra-structured Ising Hamiltonian J[i][j].
//
// Step 1: Map each of n nodes cyclically into the 8-node Adinkra glyph topology.
// Step 2: If A_symbol[i%8][j%8] has an edge, set J[i][j] using the cosine-modulated
//
//	coupling strength from JS: base * cos(2π·(si-sj)/255)
//
// seedValues[i] ∈ [0,1] encodes how "activated" node i is (votes, activity, threat).
func (o *Optimizer) BuildCouplingMatrix(n int, seedValues []float64) [][]float64 {
	matrix, ok := adinkra.SymbolMatrices[o.ActiveSymbol]
	if !ok {
		matrix = adinkra.SymbolMatrices["Eban"]
	}

	J := make([][]float64, n)
	for i := range J {
		J[i] = make([]float64, n)
	}

	for i := 0; i < n; i++ {
		si := 0.5
		if i < len(seedValues) {
			si = seedValues[i]
		}
		mi := i % 8

		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			sj := 0.5
			if j < len(seedValues) {
				sj = seedValues[j]
			}
			mj := j % 8

			base := float64(matrix[mi][mj])
			if base == 0 {
				continue
			}
			// Cosine modulation — mirrors JS exactly
			xorVal := (si - sj) * 255
			J[i][j] = base * math.Cos(2*math.Pi*xorVal/255)
		}
	}
	return J
}

// ComputeEnergy computes the Ising Hamiltonian energy.
// E = -Σ_{i<j} J[i][j]·s[i]·s[j] - Σ_i h[i]·s[i]
func ComputeEnergy(spins []Spin, J [][]float64, externalField []float64) float64 {
	E := 0.0
	n := len(spins)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			E -= J[i][j] * float64(spins[i]) * float64(spins[j])
		}
		if i < len(externalField) {
			E -= externalField[i] * float64(spins[i])
		}
	}
	return E
}

// AnnealResult is the output of a Metropolis-Hastings simulated annealing run.
type AnnealResult struct {
	BestSpins      []Spin
	BestEnergy     float64
	Iterations     int
	FinalTemp      float64
	GroundStateIdx int    // index of the lowest-spin node (most anti-aligned)
	Symbol         string // active Adinkra symbol during this anneal
}

// Anneal runs Metropolis-Hastings simulated annealing on n nodes.
// Returns the ground state (minimum energy configuration).
// Mirrors findOptimalVoteTarget() annealing loop from ising_optimizer.js.
func (o *Optimizer) Anneal(n int, J [][]float64, externalField []float64) AnnealResult {
	spins := make([]Spin, n)
	for i := range spins {
		if rand.Float64() < 0.5 {
			spins[i] = Up
		} else {
			spins[i] = Down
		}
	}

	currentEnergy := ComputeEnergy(spins, J, externalField)
	bestSpins := make([]Spin, n)
	copy(bestSpins, spins)
	bestEnergy := currentEnergy

	temp := o.Temperature
	iters := 500
	if n*50 < iters {
		iters = n * 50
	}

	for iter := 0; iter < iters; iter++ {
		idx := rand.Intn(n)
		spins[idx] *= -1
		newEnergy := ComputeEnergy(spins, J, externalField)
		deltaE := newEnergy - currentEnergy

		if deltaE < 0 || rand.Float64() < math.Exp(-deltaE/temp) {
			currentEnergy = newEnergy
			if currentEnergy < bestEnergy {
				bestEnergy = currentEnergy
				copy(bestSpins, spins)
			}
		} else {
			spins[idx] *= -1
		}
		temp = math.Max(temp*o.CoolingRate, o.MinTemp)
	}

	// Ground state index: node with the lowest spin value (most anti-aligned)
	groundIdx := 0
	for i := range bestSpins {
		if bestSpins[i] < bestSpins[groundIdx] {
			groundIdx = i
		}
	}

	return AnnealResult{
		BestSpins:      bestSpins,
		BestEnergy:     bestEnergy,
		Iterations:     iters,
		FinalTemp:      temp,
		GroundStateIdx: groundIdx,
		Symbol:         o.ActiveSymbol,
	}
}

// DetectClusters runs alliance detection via simulated annealing.
// Returns two spin clusters (A=Up, B=Down) — maps to detectAlliances() in JS.
func (o *Optimizer) DetectClusters(n int, J [][]float64) (clusterA, clusterB []int) {
	spins := make([]Spin, n)
	for i := range spins {
		if rand.Float64() < 0.5 {
			spins[i] = Up
		} else {
			spins[i] = Down
		}
	}
	field := make([]float64, n) // zero external field for alliance detection
	temp := 2.0

	for iter := 0; iter < 1000; iter++ {
		idx := rand.Intn(n)
		spins[idx] *= -1
		ne := ComputeEnergy(spins, J, field)

		// Revert for old energy calculation
		spins[idx] *= -1
		oe := ComputeEnergy(spins, J, field)
		spins[idx] *= -1 // back to flipped

		if ne > oe && rand.Float64() >= math.Exp(-(ne-oe)/temp) {
			spins[idx] *= -1 // revert
		}
		temp = math.Max(temp*0.995, 0.01)
	}

	for i, s := range spins {
		if s == Up {
			clusterA = append(clusterA, i)
		} else {
			clusterB = append(clusterB, i)
		}
	}
	return clusterA, clusterB
}

// CoherenceScore measures polarization in the coupling matrix — 0=chaotic, 1=fully aligned.
// Mirrors computeCoherenceScore() from JS.
func CoherenceScore(n int, J [][]float64) float64 {
	if n < 2 {
		return 0
	}
	maxCoupling, totalCoupling := 0.0, 0.0
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			abs := math.Abs(J[i][j])
			if abs > maxCoupling {
				maxCoupling = abs
			}
			totalCoupling += abs
		}
	}
	avg := totalCoupling / float64(n*(n-1))
	return math.Min(1.0, avg/(maxCoupling+0.001))
}

// ── Internal math helpers ─────────────────────────────────────────────────────

func normalise8(v *[8]float64) {
	mag := 0.0
	for _, x := range v {
		mag += x * x
	}
	mag = math.Sqrt(mag)
	if mag < 1e-12 {
		return
	}
	for i := range v {
		v[i] /= mag
	}
}

func matvec8(A *[8][8]float64, v *[8]float64) [8]float64 {
	var w [8]float64
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			w[i] += A[i][j] * v[j]
		}
	}
	return w
}

func dot8(a, b *[8]float64) float64 {
	s := 0.0
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}
