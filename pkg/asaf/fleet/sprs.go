// Package fleet — SPRS fleet aggregation engine.
//
// A practice is NOT MET if ANY in-scope CUI asset fails it.
// SPRS deduction is applied ONCE per failing practice, regardless of how many
// assets fail it — per DoD SPRS scoring rules.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package fleet

import (
	"fmt"
	"sort"
)

// nist800171Weights maps each of the 110 CMMC Level 2 practices to its
// SPRS weight (point deduction) per NIST SP 800-171 DoD Assessment Methodology v1.2.1.
// The base score is 110; each "NOT MET" practice deducts its weight.
// Multi-valued weight practices (value/conditional/met) use the full deduction.
var nist800171Weights = map[string]int{
	// AC — Access Control (22 practices)
	"AC.L1-3.1.1":  5, "AC.L1-3.1.2":  3,
	"AC.L2-3.1.3":  5, "AC.L2-3.1.4":  5, "AC.L2-3.1.5":  3,
	"AC.L2-3.1.6":  3, "AC.L2-3.1.7":  5, "AC.L2-3.1.8":  1,
	"AC.L2-3.1.9":  1, "AC.L2-3.1.10": 1, "AC.L2-3.1.11": 1,
	"AC.L2-3.1.12": 3, "AC.L2-3.1.13": 5, "AC.L2-3.1.14": 1,
	"AC.L2-3.1.15": 1, "AC.L2-3.1.16": 1, "AC.L2-3.1.17": 1,
	"AC.L2-3.1.18": 1, "AC.L2-3.1.19": 1, "AC.L2-3.1.20": 1,
	"AC.L2-3.1.21": 1, "AC.L2-3.1.22": 1,
	// AT — Awareness and Training (3 practices)
	"AT.L2-3.2.1": 5, "AT.L2-3.2.2": 5, "AT.L2-3.2.3": 1,
	// AU — Audit and Accountability (9 practices)
	"AU.L2-3.3.1": 5, "AU.L2-3.3.2": 5, "AU.L2-3.3.3": 3,
	"AU.L2-3.3.4": 1, "AU.L2-3.3.5": 3, "AU.L2-3.3.6": 1,
	"AU.L2-3.3.7": 3, "AU.L2-3.3.8": 1, "AU.L2-3.3.9": 1,
	// CM — Configuration Management (9 practices)
	"CM.L2-3.4.1": 5, "CM.L2-3.4.2": 5, "CM.L2-3.4.3": 3,
	"CM.L2-3.4.4": 3, "CM.L2-3.4.5": 3, "CM.L2-3.4.6": 3,
	"CM.L2-3.4.7": 3, "CM.L2-3.4.8": 1, "CM.L2-3.4.9": 1,
	// IA — Identification and Authentication (11 practices)
	"IA.L1-3.5.1": 5, "IA.L1-3.5.2": 5,
	"IA.L2-3.5.3": 5, "IA.L2-3.5.4": 1, "IA.L2-3.5.5": 1,
	"IA.L2-3.5.6": 1, "IA.L2-3.5.7": 5, "IA.L2-3.5.8": 1,
	"IA.L2-3.5.9": 3, "IA.L2-3.5.10": 1, "IA.L2-3.5.11": 1,
	// IR — Incident Response (3 practices)
	"IR.L2-3.6.1": 5, "IR.L2-3.6.2": 5, "IR.L2-3.6.3": 1,
	// MA — Maintenance (6 practices)
	"MA.L2-3.7.1": 3, "MA.L2-3.7.2": 3, "MA.L2-3.7.3": 1,
	"MA.L2-3.7.4": 1, "MA.L2-3.7.5": 1, "MA.L2-3.7.6": 1,
	// MP — Media Protection (9 practices)
	"MP.L1-3.8.3": 5,
	"MP.L2-3.8.1": 3, "MP.L2-3.8.2": 3, "MP.L2-3.8.4": 1,
	"MP.L2-3.8.5": 1, "MP.L2-3.8.6": 3, "MP.L2-3.8.7": 1,
	"MP.L2-3.8.8": 1, "MP.L2-3.8.9": 1,
	// PS — Personnel Security (2 practices)
	"PS.L2-3.9.1": 1, "PS.L2-3.9.2": 1,
	// PE — Physical Protection (6 practices)
	"PE.L1-3.10.1": 5, "PE.L1-3.10.2": 5,
	"PE.L2-3.10.3": 1, "PE.L2-3.10.4": 1, "PE.L2-3.10.5": 1, "PE.L2-3.10.6": 1,
	// RA — Risk Assessment (3 practices)
	"RA.L2-3.11.1": 5, "RA.L2-3.11.2": 5, "RA.L2-3.11.3": 5,
	// CA — Security Assessment (4 practices)
	"CA.L2-3.12.1": 5, "CA.L2-3.12.2": 3, "CA.L2-3.12.3": 3, "CA.L2-3.12.4": 5,
	// SC — System and Communications Protection (16 practices)
	"SC.L1-3.13.1": 5, "SC.L1-3.13.2": 3,
	"SC.L2-3.13.3": 1, "SC.L2-3.13.4": 1, "SC.L2-3.13.5": 5,
	"SC.L2-3.13.6": 1, "SC.L2-3.13.7": 1, "SC.L2-3.13.8": 5,
	"SC.L2-3.13.9": 1, "SC.L2-3.13.10": 3, "SC.L2-3.13.11": 5,
	"SC.L2-3.13.12": 1, "SC.L2-3.13.13": 1, "SC.L2-3.13.14": 1,
	"SC.L2-3.13.15": 1, "SC.L2-3.13.16": 1,
	// SI — System and Information Integrity (7 practices)
	"SI.L1-3.14.1": 5, "SI.L1-3.14.2": 5, "SI.L1-3.14.3": 5,
	"SI.L2-3.14.4": 1, "SI.L2-3.14.5": 1, "SI.L2-3.14.6": 3, "SI.L2-3.14.7": 1,
}

// ScanReport is a lightweight interface the SPRS engine reads.
// The full ScanReport type lives in pkg/remote; we use a local subset
// to avoid circular imports.
type HostReport struct {
	AssetID      string
	CMMCCategory CMMCCategory
	// FailingPractices is a set of CMMC practice IDs that failed on this host.
	FailingPractices map[string]bool
	// PassingPractices is a set of CMMC practice IDs that passed on this host.
	PassingPractices map[string]bool
}

// AggregateFleetSPRS computes the organisation-level SPRS score from all
// host scan reports. Only CUI and SecurityProtectionAsset hosts contribute.
//
// Fleet SPRS = 110 − Σ(weight of each UNIQUE practice that is NOT MET on ANY in-scope CUI host)
//
// A practice is NOT MET fleet-wide if at least one CUI asset fails it.
// A practice is PARTIAL if some-but-not-all CUI assets fail it.
func AggregateFleetSPRS(reports []*HostReport) (sprs int, practices []PracticeStatus) {
	// Only in-scope CUI and security protection assets count
	inScope := make([]*HostReport, 0, len(reports))
	for _, r := range reports {
		if r.CMMCCategory == CUIAsset || r.CMMCCategory == SecurityProtectionAsset {
			inScope = append(inScope, r)
		}
	}

	// Collect all practice IDs seen
	allPractices := make(map[string]bool)
	for p := range nist800171Weights {
		allPractices[p] = true
	}

	// Aggregate pass/fail counts per practice
	failCount := make(map[string]int)
	passCount := make(map[string]int)
	for _, r := range inScope {
		for p := range r.FailingPractices {
			failCount[p]++
		}
		for p := range r.PassingPractices {
			passCount[p]++
		}
	}

	total := len(inScope)
	sprs = 110 // base score

	practiceList := make([]string, 0, len(allPractices))
	for p := range allPractices {
		practiceList = append(practiceList, p)
	}
	sort.Strings(practiceList)

	for _, practice := range practiceList {
		weight, ok := nist800171Weights[practice]
		if !ok {
			continue
		}
		failing := failCount[practice]
		passing := passCount[practice]

		status := "met"
		if failing > 0 && total > 0 {
			sprs -= weight // deduct ONCE regardless of how many hosts fail
			if failing == total {
				status = "not_met"
			} else {
				status = "partial"
			}
		} else if total == 0 {
			status = "unknown"
		}

		blast := 0.0
		if total > 0 {
			blast = float64(failing) / float64(total)
		}

		practices = append(practices, PracticeStatus{
			CMMCPractice: practice,
			SPRSWeight:   weight,
			PassingCount: passing,
			FailingCount: failing,
			TotalCount:   total,
			Status:       status,
			BlastRadius:  blast,
		})
	}

	// Clamp to [-203, 110]
	if sprs < -203 {
		sprs = -203
	}
	return sprs, practices
}

// SimulateBoundaryCost models the SPRS impact of adding or removing assets.
// Returns the delta without mutating the registry.
func SimulateBoundaryCost(
	currentReports []*HostReport,
	addReports []*HostReport,
	removeIDs []string,
) *BoundaryCostSimulation {
	currentSPRS, _ := AggregateFleetSPRS(currentReports)

	removeSet := make(map[string]bool)
	for _, id := range removeIDs {
		removeSet[id] = true
	}

	proposed := make([]*HostReport, 0, len(currentReports)+len(addReports))
	for _, r := range currentReports {
		if !removeSet[r.AssetID] {
			proposed = append(proposed, r)
		}
	}
	proposed = append(proposed, addReports...)

	proposedSPRS, _ := AggregateFleetSPRS(proposed)

	delta := proposedSPRS - currentSPRS
	rec := ""
	switch {
	case delta > 10:
		rec = "This change significantly improves your SPRS score — recommended."
	case delta > 0:
		rec = "Slight improvement in SPRS score."
	case delta == 0:
		rec = "No SPRS impact from this boundary change."
	case delta > -20:
		rec = "Minor SPRS cost. Consider whether these assets are truly in scope."
	default:
		rec = fmt.Sprintf("This boundary change costs %d SPRS points. Isolate if possible before signing.", -delta)
	}

	addIDs := make([]string, 0, len(addReports))
	for _, r := range addReports {
		addIDs = append(addIDs, r.AssetID)
	}

	return &BoundaryCostSimulation{
		CurrentSPRS:       currentSPRS,
		CurrentAssetCount: len(currentReports),
		AddAssetIDs:       addIDs,
		RemoveAssetIDs:    removeIDs,
		ProjectedSPRS:     proposedSPRS,
		SPRSDelta:         delta,
		Recommendation:    rec,
	}
}

// EstimateRemediationCost provides a rough dollar estimate for remediating
// failing practices. Based on industry average labor costs per control.
// Not authoritative — directional only.
func EstimateRemediationCost(practices []PracticeStatus) int64 {
	// Rough labor cost per practice weight point: ~$2,000/point
	const costPerWeightPoint = 2000
	var total int64
	for _, p := range practices {
		if p.Status == "not_met" || p.Status == "partial" {
			total += int64(p.SPRSWeight) * costPerWeightPoint
		}
	}
	return total
}
