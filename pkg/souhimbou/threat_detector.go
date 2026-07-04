package souhimbou

// threat_detector.go — KASA behavioral anomaly scoring for SouHimBou AI.
//
// Reads recent FlightFrames and scores each agent's behavior against
// known-bad patterns. Returns a ThreatScore per AgentID.
//
// Anomaly patterns detected:
//   - High-frequency tool calls (> N calls/minute)
//   - Secrets/credential access patterns
//   - Unusual tool sequences (read-then-write without approval)
//   - Off-hours activity (configurable)
//   - Repeated failures (risk class escalation)
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
)

// ─── Thresholds ───────────────────────────────────────────────────────────────

const (
	// ThreatThresholdHigh triggers automatic staging playbook execution.
	ThreatThresholdHigh float64 = 0.70

	// ThreatThresholdCritical requires human approval before production.
	ThreatThresholdCritical float64 = 0.85

	// Default observation window for scoring (last N frames per agent).
	defaultWindowFrames = 100

	// High-frequency threshold: >30 calls/minute = suspicious.
	highFreqCallsPerMinute = 30.0

	// Secrets keyword list for tool call pattern matching.
	secretsToolPattern = "secret|credential|key|token|password|auth|vault"
)

// ─── Threat Score ─────────────────────────────────────────────────────────────

// ThreatScore is the KASA anomaly assessment for a single agent.
type ThreatScore struct {
	AgentID      string    `json:"agent_id"`
	AnomalyScore float64   `json:"anomaly_score"` // 0.0 (clean) — 1.0 (critical)
	TopReason    string    `json:"top_reason"`
	ScoredAt     time.Time `json:"scored_at"`

	// Breakdown — individual signal contributions
	FrequencySignal  float64 `json:"frequency_signal"`
	SecretsSignal    float64 `json:"secrets_signal"`
	SequenceSignal   float64 `json:"sequence_signal"`
	FailureSignal    float64 `json:"failure_signal"`
	OffHoursSignal   float64 `json:"off_hours_signal"`
}

// IsClean returns true if the score is below the high anomaly threshold.
func (s ThreatScore) IsClean() bool {
	return s.AnomalyScore < ThreatThresholdHigh
}

// ─── Scorer ───────────────────────────────────────────────────────────────────

// ScoreAllAgents reads recent flight frames and returns a threat score per agent.
// It groups frames by AgentID and applies the KASA scoring model to each group.
func ScoreAllAgents(ctx context.Context, fr *flight.Recorder) (map[string]ThreatScore, error) {
	if fr == nil {
		return map[string]ThreatScore{}, nil
	}

	// Read recent frames — last 1000 or last 10 minutes, whichever is smaller
	frames, err := fr.Recent(defaultWindowFrames * 10)
	if err != nil {
		// Non-fatal — return empty scores
		return map[string]ThreatScore{}, nil
	}

	// Group by AgentID
	byAgent := make(map[string][]flight.FlightFrame)
	for _, f := range frames {
		byAgent[f.AgentID] = append(byAgent[f.AgentID], f)
	}

	scores := make(map[string]ThreatScore, len(byAgent))
	for agentID, agentFrames := range byAgent {
		scores[agentID] = scoreAgent(agentID, agentFrames)
	}
	return scores, nil
}

// scoreAgent applies the KASA model to a single agent's recent frames.
func scoreAgent(agentID string, frames []flight.FlightFrame) ThreatScore {
	if len(frames) == 0 {
		return ThreatScore{AgentID: agentID, ScoredAt: time.Now().UTC()}
	}

	// Use at most the last defaultWindowFrames frames
	if len(frames) > defaultWindowFrames {
		frames = frames[len(frames)-defaultWindowFrames:]
	}

	score := ThreatScore{
		AgentID:  agentID,
		ScoredAt: time.Now().UTC(),
	}

	// ── Signal 1: High frequency ───────────────────────────────────────────
	score.FrequencySignal = frequencySignal(frames)

	// ── Signal 2: Secrets access ───────────────────────────────────────────
	score.SecretsSignal = secretsSignal(frames)

	// ── Signal 3: Suspicious sequences ────────────────────────────────────
	score.SequenceSignal = sequenceSignal(frames)

	// ── Signal 4: Repeated failures ───────────────────────────────────────
	score.FailureSignal = failureSignal(frames)

	// ── Signal 5: Off-hours activity ──────────────────────────────────────
	score.OffHoursSignal = offHoursSignal(frames)

	// ── Weighted composite score ───────────────────────────────────────────
	// Weights tuned for SOC use case (secrets + frequency most dangerous)
	composite := 0.0 +
		score.FrequencySignal*0.30 +
		score.SecretsSignal*0.35 +
		score.SequenceSignal*0.15 +
		score.FailureSignal*0.10 +
		score.OffHoursSignal*0.10

	score.AnomalyScore = math.Min(composite, 1.0)

	// ── Top reason ────────────────────────────────────────────────────────
	score.TopReason = topReason(score)

	return score
}

// frequencySignal scores how many tool calls per minute relative to threshold.
func frequencySignal(frames []flight.FlightFrame) float64 {
	if len(frames) < 2 {
		return 0.0
	}
	first := frames[0].StartedAt
	last := frames[len(frames)-1].StartedAt
	minutes := last.Sub(first).Minutes()
	if minutes <= 0 {
		minutes = 1.0 / 60.0 // sub-second window
	}
	callsPerMin := float64(len(frames)) / minutes
	if callsPerMin < highFreqCallsPerMinute {
		return 0.0
	}
	// Sigmoid-like scaling: 30 cpm = 0.5 signal, 100 cpm ≈ 1.0
	ratio := callsPerMin / highFreqCallsPerMinute
	return math.Min((ratio-1.0)/3.0, 1.0)
}

// secretsSignal detects frames touching secrets/credentials.
func secretsSignal(frames []flight.FlightFrame) float64 {
	secretCount := 0
	for _, f := range frames {
		tool := strings.ToLower(f.ToolName)
		if matchesPattern(tool, secretsToolPattern) {
			secretCount++
		}
	}
	if secretCount == 0 {
		return 0.0
	}
	// 1 secrets call in 100 = 0.1; 10+ = 1.0
	return math.Min(float64(secretCount)/10.0, 1.0)
}

// sequenceSignal detects suspicious tool call sequences (read → write without pause).
func sequenceSignal(frames []flight.FlightFrame) float64 {
	if len(frames) < 2 {
		return 0.0
	}
	suspiciousSeqs := 0
	for i := 1; i < len(frames); i++ {
		prev := strings.ToLower(frames[i-1].ToolName)
		curr := strings.ToLower(frames[i].ToolName)
		delta := frames[i].StartedAt.Sub(frames[i-1].StartedAt)

		// Pattern: read credentials then immediately write/execute
		if matchesPattern(prev, secretsToolPattern) &&
			matchesPattern(curr, "write|exec|run|deploy|delete|rm|drop") &&
			delta < 5*time.Second {
			suspiciousSeqs++
		}
	}
	return math.Min(float64(suspiciousSeqs)/3.0, 1.0)
}

// failureSignal scores proportion of blocked or destructive-risk frames.
func failureSignal(frames []flight.FlightFrame) float64 {
	highRisk := 0
	for _, f := range frames {
		if f.RiskClass == flight.RiskDestructive || f.Outcome == flight.OutcomeBlocked {
			highRisk++
		}
	}
	return math.Min(float64(highRisk)/float64(len(frames)+1), 1.0)
}

// offHoursSignal scores activity outside business hours (0000-0600 UTC).
func offHoursSignal(frames []flight.FlightFrame) float64 {
	offHours := 0
	for _, f := range frames {
		h := f.StartedAt.UTC().Hour()
		if h >= 0 && h < 6 {
			offHours++
		}
	}
	if offHours == 0 {
		return 0.0
	}
	ratio := float64(offHours) / float64(len(frames))
	if ratio < 0.5 {
		return 0.0
	}
	return 0.4 // 40% base signal for majority off-hours activity
}

// topReason returns the human-readable primary anomaly reason.
func topReason(s ThreatScore) string {
	type sig struct {
		label string
		val   float64
	}
	signals := []sig{
		{"High-frequency tool calls", s.FrequencySignal},
		{"Secrets/credential access pattern", s.SecretsSignal},
		{"Suspicious read-then-write sequence", s.SequenceSignal},
		{"Repeated high-risk operations", s.FailureSignal},
		{"Off-hours activity", s.OffHoursSignal},
	}
	best := "No anomaly detected"
	bestVal := 0.0
	for _, sig := range signals {
		if sig.val > bestVal {
			bestVal = sig.val
			best = sig.label
		}
	}
	return best
}

// matchesPattern returns true if s contains any pipe-separated keyword in pattern.
func matchesPattern(s, pattern string) bool {
	for _, kw := range strings.Split(pattern, "|") {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}
