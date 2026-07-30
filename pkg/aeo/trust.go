package aeo

// TrustReport scores how consistently an agent's recorded behavior matches
// its identity and history. This is the reputation half of Digital
// Citizenship: not "is the network behaving normally?" but "is this
// autonomous entity behaving consistently with its identity and history?"
type TrustReport struct {
	AgentID string `json:"agent_id"`
	Events  int    `json:"events"`

	// Score components, each 0-100.
	IntegrityScore   int `json:"integrity_score"`   // signatures + chain links verified
	ConsistencyScore int `json:"consistency_score"` // behavioral fingerprint stability
	IntentScore      int `json:"intent_score"`      // declared-intent coverage

	// Overall 0-100 (weighted: integrity 50%, consistency 30%, intent 20%).
	Score int `json:"score"`

	Anomalies []string `json:"anomalies,omitempty"`
}

// Trust evaluates an agent's full history in the ledger.
func (l *Ledger) Trust(agentID string) *TrustReport {
	history := l.History(agentID)
	report := &TrustReport{AgentID: agentID, Events: len(history)}
	if len(history) == 0 {
		report.Anomalies = append(report.Anomalies, "no recorded history")
		return report
	}

	// Integrity: every event must verify and chain correctly.
	valid := 0
	prevHash := ""
	for i, obj := range history {
		ok := true
		if err := obj.Verify(); err != nil {
			report.Anomalies = append(report.Anomalies, "event "+obj.Hash[:12]+": "+err.Error())
			ok = false
		}
		if obj.ParentEvent != prevHash {
			report.Anomalies = append(report.Anomalies, "event "+obj.Hash[:12]+": broken chain link")
			ok = false
		}
		if ok {
			valid++
		}
		_ = i
		prevHash = obj.Hash
	}
	report.IntegrityScore = (valid * 100) / len(history)

	// Consistency: average pairwise Jaccard similarity of consecutive
	// tool graphs. A stable agent works in recognizably similar patterns;
	// an impersonated or compromised one usually does not.
	if len(history) < 2 {
		report.ConsistencyScore = 100
	} else {
		total := 0.0
		pairs := 0
		for i := 1; i < len(history); i++ {
			total += jaccard(history[i-1].BehaviorSignature.ToolGraphEdges,
				history[i].BehaviorSignature.ToolGraphEdges)
			pairs++
		}
		report.ConsistencyScore = int((total / float64(pairs)) * 100)
	}

	// Intent: fraction of events that committed an intent hash.
	declared := 0
	for _, obj := range history {
		if obj.IntentHash != "" {
			declared++
		}
	}
	report.IntentScore = (declared * 100) / len(history)

	report.Score = (report.IntegrityScore*50 + report.ConsistencyScore*30 + report.IntentScore*20) / 100
	return report
}

// jaccard computes |A∩B| / |A∪B| over edge sets. Two empty sets are
// considered identical (similarity 1) — an agent that uses no tools twice
// in a row is behaving consistently.
func jaccard(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	setA := make(map[string]bool, len(a))
	for _, e := range a {
		setA[e] = true
	}
	inter := 0
	union := len(setA)
	seenB := make(map[string]bool, len(b))
	for _, e := range b {
		if seenB[e] {
			continue
		}
		seenB[e] = true
		if setA[e] {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}
