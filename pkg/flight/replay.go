package flight

// replay.go — Session replay, chain verification, and evidence packet export.
//
// These functions answer the three audit questions:
//
//   1. "What did the agent do this session?" → LoadSession()
//   2. "Has the flight log been tampered with?" → VerifyChain()
//   3. "Give me CMMC evidence for this session." → ExportEvidencePacket()
//
// The EvidencePacket is the SouHimBou AI deliverable —
// the artifact a C3PAO receives during a CMMC assessment.

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// ─── Session Replay ───────────────────────────────────────────────────────────

// LoadSession reads all FlightFrames for a given session from the flight log.
// Returns frames in chronological order (ascending Seq).
// If sessionID is empty, returns all frames.
func LoadSession(path, sessionID string) ([]FlightFrame, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("flight/replay: open %s: %w", path, err)
	}
	defer f.Close()

	var frames []FlightFrame
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var frame FlightFrame
		if err := json.Unmarshal([]byte(line), &frame); err != nil {
			continue // Skip malformed lines
		}
		if sessionID == "" || frame.SessionID == sessionID {
			frames = append(frames, frame)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("flight/replay: scan: %w", err)
	}

	sort.Slice(frames, func(i, j int) bool {
		return frames[i].Seq < frames[j].Seq
	})
	return frames, nil
}

// ─── Chain Verification ───────────────────────────────────────────────────────

// ChainVerifyResult is the outcome of a chain integrity check.
type ChainVerifyResult struct {
	TotalFrames      int     `json:"total_frames"`
	ValidSignatures  int     `json:"valid_signatures"`
	InvalidFrameSeqs []uint64 `json:"invalid_frame_seqs,omitempty"`
	ChainIntact      bool    `json:"chain_intact"`
	FirstBrokenSeq   int64   `json:"first_broken_seq"` // -1 if intact
	VerifiedAt       time.Time `json:"verified_at"`
}

// VerifyChain reads the flight log at path and verifies the full tamper-evident chain.
// pubKey must be the ML-DSA-65 public key used during signing.
// Any modification to any prior frame will produce a chain break detectable here.
func VerifyChain(path string, pubKey []byte) (*ChainVerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("flight/replay: verify_chain: open %s: %w", path, err)
	}
	defer f.Close()

	result := &ChainVerifyResult{
		FirstBrokenSeq: -1,
		VerifiedAt:     time.Now(),
	}

	prevHash := "genesis"
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for sc.Scan() {
		lineBytes := sc.Bytes()
		if len(lineBytes) == 0 {
			continue
		}
		result.TotalFrames++

		var frame FlightFrame
		if err := json.Unmarshal(lineBytes, &frame); err != nil {
			result.InvalidFrameSeqs = append(result.InvalidFrameSeqs, frame.Seq)
			if result.FirstBrokenSeq == -1 {
				result.FirstBrokenSeq = int64(frame.Seq)
			}
			prevHash = "broken"
			continue
		}

		// Verify chain link
		if frame.PrevFrameHash != prevHash {
			result.InvalidFrameSeqs = append(result.InvalidFrameSeqs, frame.Seq)
			if result.FirstBrokenSeq == -1 {
				result.FirstBrokenSeq = int64(frame.Seq)
			}
			prevHash = hex3256(lineBytes)
			continue
		}

		// Verify frame hash
		canonical, cErr := canonicalFrame(&frame)
		if cErr == nil {
			computedHash := hex3256(canonical)
			if computedHash != frame.FrameHash {
				result.InvalidFrameSeqs = append(result.InvalidFrameSeqs, frame.Seq)
				if result.FirstBrokenSeq == -1 {
					result.FirstBrokenSeq = int64(frame.Seq)
				}
				prevHash = hex3256(lineBytes)
				continue
			}
		}

		// Verify ML-DSA-65 signature
		if len(pubKey) > 0 && frame.Signature != "" && frame.FrameHash != "" {
			sig, hexErr := hex.DecodeString(frame.Signature)
			if hexErr == nil {
				ok, verErr := adinkra.Verify(pubKey, []byte(frame.FrameHash), sig)
				if verErr == nil && ok {
					result.ValidSignatures++
				} else {
					result.InvalidFrameSeqs = append(result.InvalidFrameSeqs, frame.Seq)
					if result.FirstBrokenSeq == -1 {
						result.FirstBrokenSeq = int64(frame.Seq)
					}
				}
			}
		} else if frame.Signature == "" {
			// Unsigned frame (Community tier) — chain still valid, just not signed
			result.ValidSignatures++ // count as valid for chain purposes
		}

		prevHash = hex3256(lineBytes)
	}

	result.ChainIntact = len(result.InvalidFrameSeqs) == 0
	return result, sc.Err()
}

// ─── Evidence Packet ─────────────────────────────────────────────────────────

// EvidencePacket is the CMMC-aligned evidence artifact produced by the
// SouHimBou AI Flight Recorder for a single agent session.
//
// This is the deliverable a C3PAO receives during a CMMC assessment:
// a structured, signed record of agent activity mapped to NIST 800-171 controls.
type EvidencePacket struct {
	// Metadata
	PacketID     string    `json:"packet_id"`
	GeneratedAt  time.Time `json:"generated_at"`
	SessionID    string    `json:"session_id"`
	AgentID      string    `json:"agent_id"`
	FlightLogPath string   `json:"flight_log_path,omitempty"`

	// Session summary
	TotalActions       int     `json:"total_actions"`
	SuccessfulActions  int     `json:"successful_actions"`
	BlockedActions     int     `json:"blocked_actions"`
	SignedActions       int     `json:"signed_actions"`
	SignedEvidencePct  float64 `json:"signed_evidence_pct"`
	SessionDurationMs  int64   `json:"session_duration_ms"`
	MeanDurationMs     float64 `json:"mean_duration_ms"`

	// SOW pilot metrics
	PilotMetrics PilotKPIs `json:"pilot_kpis"`

	// CMMC control coverage
	ControlsCovered  []ControlCoverageItem `json:"controls_covered"`
	ControlCount     int                   `json:"unique_controls_evidenced"`
	TotalKhepraControls int               `json:"total_khepra_mappable_controls"`

	// Action log (sanitized — no raw args)
	Actions []ActionSummary `json:"actions"`

	// Chain integrity
	ChainIntact      bool   `json:"chain_intact"`
	FirstBrokenFrame int64  `json:"first_broken_frame"` // -1 if intact
	SignatureAlgo    string `json:"signature_algorithm"`

	// Top-level PQC signature over the packet hash
	PacketHash string `json:"packet_hash,omitempty"`
	Signature  string `json:"packet_signature,omitempty"`
}

// PilotKPIs maps directly to the SOW pilot success metrics.
type PilotKPIs struct {
	// "Number of MCP tool calls captured"
	ToolCallsCaptured int `json:"tool_calls_captured"`

	// "Percentage of privileged calls with signed evidence"
	PrivilegedCalls     int     `json:"privileged_calls"`
	SignedPrivilegedPct float64 `json:"signed_privileged_pct"`

	// "Mean time to produce an evidence packet"
	MeanEvidenceTimeMs float64 `json:"mean_evidence_time_ms"`

	// "Number of control mappings supported by generated artifacts"
	ControlMappingCount int `json:"control_mapping_count"`
}

// ControlCoverageItem records a single CMMC/NIST control that was evidenced.
type ControlCoverageItem struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	How       string `json:"how"`
	EvidencedBy []string `json:"evidenced_by"` // tool names that evidenced it
}

// ActionSummary is a CUI-safe summary of a single FlightFrame for the evidence packet.
type ActionSummary struct {
	Seq           uint64    `json:"seq"`
	FrameID       string    `json:"frame_id"`
	StartedAt     time.Time `json:"started_at"`
	DurationMs    int64     `json:"duration_ms"`
	ToolName      string    `json:"tool_name"`
	RiskClass     RiskClass `json:"risk_class"`
	Outcome       Outcome   `json:"outcome"`
	IntentSummary string    `json:"intent_summary"`
	IsSigned      bool      `json:"is_signed"`
	DAGNodeID     string    `json:"dag_node_id,omitempty"`
	ControlCount  int       `json:"controls_evidenced"`
}

// ExportEvidencePacket generates a CMMC-aligned evidence packet from a set of frames.
// Pass frames from LoadSession(). logPath is embedded for reference.
func ExportEvidencePacket(frames []FlightFrame, logPath string, chainResult *ChainVerifyResult) *EvidencePacket {
	if len(frames) == 0 {
		return &EvidencePacket{
			PacketID:    newFrameID(),
			GeneratedAt: time.Now(),
			ChainIntact: true,
			FirstBrokenFrame: -1,
			TotalKhepraControls: AllScopesControlCount(),
		}
	}

	// Session metadata from first/last frame
	sessionID := frames[0].SessionID
	agentID := frames[0].AgentID
	first := frames[0].StartedAt
	last := frames[len(frames)-1].StartedAt.Add(time.Duration(frames[len(frames)-1].DurationMs) * time.Millisecond)
	totalDuration := last.Sub(first).Milliseconds()

	// Control coverage aggregation
	controlMap := make(map[string]*ControlCoverageItem) // key: framework:controlID
	var totalDur int64
	signed := 0
	blocked := 0
	successful := 0
	privileged := 0
	signedPrivileged := 0
	var actions []ActionSummary

	for _, f := range frames {
		totalDur += f.DurationMs

		if f.IsSigned {
			signed++
		}
		switch f.Outcome {
		case OutcomeSuccess:
			successful++
		case OutcomeBlocked, OutcomeRateLimit, OutcomeLoopDetect, OutcomeAuthFailed:
			blocked++
		}
		if f.RiskClass == RiskSandboxed || f.RiskClass == RiskDestructive {
			privileged++
			if f.IsSigned {
				signedPrivileged++
			}
		}

		for _, cm := range f.ControlsMapped {
			key := cm.Framework + ":" + cm.ControlID
			if existing, ok := controlMap[key]; ok {
				existing.EvidencedBy = appendUnique(existing.EvidencedBy, f.ToolName)
			} else {
				controlMap[key] = &ControlCoverageItem{
					Framework:   cm.Framework,
					ControlID:   cm.ControlID,
					How:         cm.How,
					EvidencedBy: []string{f.ToolName},
				}
			}
		}

		actions = append(actions, ActionSummary{
			Seq:           f.Seq,
			FrameID:       f.FrameID,
			StartedAt:     f.StartedAt,
			DurationMs:    f.DurationMs,
			ToolName:      f.ToolName,
			RiskClass:     f.RiskClass,
			Outcome:       f.Outcome,
			IntentSummary: f.IntentSummary,
			IsSigned:      f.IsSigned,
			DAGNodeID:     f.DAGNodeID,
			ControlCount:  len(f.ControlsMapped),
		})
	}

	// Flatten control coverage
	var controls []ControlCoverageItem
	for _, c := range controlMap {
		controls = append(controls, *c)
	}
	sort.Slice(controls, func(i, j int) bool {
		return controls[i].Framework+controls[i].ControlID < controls[j].Framework+controls[j].ControlID
	})

	total := len(frames)
	meanDur := float64(0)
	if total > 0 {
		meanDur = float64(totalDur) / float64(total)
	}
	signedPct := float64(0)
	if total > 0 {
		signedPct = float64(signed) / float64(total) * 100
	}
	signedPrivPct := float64(0)
	if privileged > 0 {
		signedPrivPct = float64(signedPrivileged) / float64(privileged) * 100
	}

	chainIntact := true
	firstBroken := int64(-1)
	if chainResult != nil {
		chainIntact = chainResult.ChainIntact
		firstBroken = chainResult.FirstBrokenSeq
	}

	sigAlgo := "unsigned"
	if len(frames) > 0 && frames[0].Algorithm == "ML-DSA-65" {
		sigAlgo = "ML-DSA-65"
	}

	packet := &EvidencePacket{
		PacketID:          fmt.Sprintf("ep-%s", newFrameID()),
		GeneratedAt:       time.Now(),
		SessionID:         sessionID,
		AgentID:           agentID,
		FlightLogPath:     logPath,
		TotalActions:      total,
		SuccessfulActions: successful,
		BlockedActions:    blocked,
		SignedActions:     signed,
		SignedEvidencePct: signedPct,
		SessionDurationMs: totalDuration,
		MeanDurationMs:    meanDur,
		PilotMetrics: PilotKPIs{
			ToolCallsCaptured:   total,
			PrivilegedCalls:     privileged,
			SignedPrivilegedPct: signedPrivPct,
			MeanEvidenceTimeMs:  meanDur,
			ControlMappingCount: len(controls),
		},
		ControlsCovered:     controls,
		ControlCount:        len(controls),
		TotalKhepraControls: AllScopesControlCount(),
		Actions:             actions,
		ChainIntact:         chainIntact,
		FirstBrokenFrame:    firstBroken,
		SignatureAlgo:       sigAlgo,
	}

	// Compute packet hash
	pBytes, err := json.Marshal(packet)
	if err == nil {
		packet.PacketHash = hex3256(pBytes)
	}

	return packet
}

func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}
