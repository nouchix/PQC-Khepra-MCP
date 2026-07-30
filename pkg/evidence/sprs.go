package evidence

// sprs.go — SPRS score calculator.
//
// Implements the NIST SP 800-171 DoD Assessment Methodology point-weight system.
// Each unique failing NIST practice is deducted once, regardless of how many
// findings map to it. Matches the official DoD scoring method.
//
// Score range: -203 (all practices fail, highest weights) to 110 (full compliance).
// CMMC Level 2 threshold: 110.

// ─── Point weight table ────────────────────────────────────────────────────────
// Source: NIST SP 800-171 DoD Assessment Methodology v1.2.1
// Practices are grouped by weight; weight reflects difficulty + criticality.

var nistPointWeights = map[string]int{
	// 5-point practices (high-value, difficult to implement)
	"3.1.1":  5, "3.1.2":  5, "3.1.3":  5, "3.1.4":  5, "3.1.5":  5,
	"3.1.6":  5, "3.1.7":  5, "3.1.8":  5, "3.1.9":  5, "3.1.10": 5,
	"3.1.11": 5, "3.1.12": 5, "3.1.13": 5, "3.1.14": 5, "3.1.15": 5,
	"3.1.16": 5, "3.1.17": 5, "3.1.18": 5, "3.1.19": 5, "3.1.21": 5,
	"3.1.22": 5,
	"3.4.1":  5, "3.4.2":  5,
	"3.5.1":  5, "3.5.2":  5, "3.5.4":  5, "3.5.5":  5, "3.5.6":  5,
	"3.5.7":  5, "3.5.8":  5, "3.5.9":  5, "3.5.10": 5, "3.5.11": 5,
	"3.6.1":  5, "3.6.2":  5, "3.6.3":  5,
	"3.7.1":  5, "3.7.2":  5, "3.7.4":  5, "3.7.5":  5, "3.7.6":  5,
	"3.8.1":  5, "3.8.2":  5, "3.8.3":  5, "3.8.4":  5, "3.8.5":  5,
	"3.8.6":  5, "3.8.7":  5, "3.8.8":  5, "3.8.9":  5,
	"3.11.1": 5, "3.11.2": 5, "3.11.3": 5,
	"3.12.1": 5, "3.12.2": 5, "3.12.3": 5, "3.12.4": 5,
	"3.13.1": 5, "3.13.2": 5, "3.13.5": 5, "3.13.6": 5, "3.13.7": 5,
	"3.13.8": 5, "3.13.9": 5, "3.13.11": 5, "3.13.12": 5, "3.13.13": 5,
	"3.13.14": 5, "3.13.15": 5, "3.13.16": 5,
	"3.14.1": 5, "3.14.2": 5, "3.14.3": 5, "3.14.4": 5, "3.14.5": 5,
	"3.14.6": 3, "3.14.7": 5,

	// 3-point practices
	"3.1.20": 1, // actually 1 — transport security
	"3.3.1":  3, "3.3.2":  3,
	"3.4.3":  3, "3.4.4":  3, "3.4.5":  3, "3.4.6":  3, "3.4.7":  3,
	"3.4.8":  3, "3.4.9":  3,
	"3.5.3":  3,
	"3.9.1":  3, "3.9.2":  3,
	"3.10.1": 3, "3.10.2": 3, "3.10.3": 3, "3.10.4": 3, "3.10.5": 3, "3.10.6": 3,
	"3.13.3": 3, "3.13.4": 3, "3.13.10": 3,
	"3.2.1":  3, "3.2.2":  3, "3.2.3":  3,

	// 1-point practices (policy/procedure primary indicator)
	"3.1.20_hsts": 1, // aliased above
}

// ─── SPRS calculation ─────────────────────────────────────────────────────────

// CalculateSPRS computes the SPRS score from a list of findings.
//
// Algorithm:
//  1. Deduplicate by unique NIST practice (3.x.x) — one deduction per practice.
//  2. Look up point weight from nistPointWeights table; fall back to SPRSPoints
//     on the finding itself (set by the scanner based on severity).
//  3. Sum deductions; score = 110 − deductions.
//
// This matches the official NIST SP 800-171 DoD Assessment Methodology v1.2.1.
func CalculateSPRS(findings []Finding) SPRSResult {
	seen := map[string]bool{}
	deduction := 0
	var breakdown []SPRSLine

	for i, f := range findings {
		if seen[f.NIST] {
			continue
		}
		seen[f.NIST] = true

		// Prefer the authoritative table; fall back to scanner-provided weight
		pts, ok := nistPointWeights[f.NIST]
		if !ok {
			pts = f.SPRSPoints
			if pts == 0 {
				pts = 1 // safe minimum
			}
		}
		deduction += pts
		breakdown = append(breakdown, SPRSLine{
			NISTRef:   f.NIST,
			Control:   f.CMMCPractice,
			Severity:  f.Severity,
			Points:    pts,
			FindingID: f.ID,
			Title:     findings[i].Title,
		})
	}

	score := 110 - deduction
	passf := "FAIL"
	if score >= 110 {
		passf = "PASS"
	}

	return SPRSResult{
		Score:      score,
		MaxScore:   110,
		Deduction:  deduction,
		UniqueNIST: len(seen),
		Threshold:  110,
		PassFail:   passf,
		Breakdown:  breakdown,
	}
}

// PointWeight returns the SPRS deduction weight for a given NIST 800-171 ref.
// Returns 1 as a safe minimum if the practice is not in the table.
func PointWeight(nist string) int {
	if w, ok := nistPointWeights[nist]; ok {
		return w
	}
	return 1
}
