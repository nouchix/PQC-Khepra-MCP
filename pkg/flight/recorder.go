package flight

// recorder.go — SouHimBou AI Flight Recorder.
//
// Persistent, tamper-evident, ML-DSA-65-signed semantic log of every agent
// action that flows through the KHEPRA MCP router.
//
// Aviation black box analogy:
//   CVR (Cockpit Voice Recorder) → agent intent + policy decisions
//   FDR (Flight Data Recorder)   → execution metrics + CMMC controls
//   DFDR (Digital FDR)           → PQC-signed, content-addressed, replayable
//
// File format: NDJSON, one FlightFrame per line.
// Chain: each frame's PrevFrameHash = SHA3-256(raw bytes of previous line).
// Each frame is ML-DSA-65 signed before writing.
//
// Integration point: call Recorder.Record() at the end of Router.HandleToolCall().

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"golang.org/x/crypto/sha3"
)

// ─── Recorder ────────────────────────────────────────────────────────────────

// Recorder is the SouHimBou AI Flight Recorder.
// Thread-safe. One instance per server process.
type Recorder struct {
	path   string
	mu     sync.Mutex
	seq    atomic.Uint64
	prev   string // SHA3-256 hex of last written line ("genesis" for first)

	privKey []byte
	pubKey  []byte
	pubHex  string

	file   *os.File
	writer *bufio.Writer
}

// RecorderConfig holds Recorder constructor parameters.
type RecorderConfig struct {
	// Path is the NDJSON flight log file path.
	// If empty, defaults to $KHEPRA_DATA_DIR/flight.ndjson or ./khepra-flight.ndjson.
	// New entries are appended; existing log is resumed (chain-safe).
	Path string

	// PrivKey is the ML-DSA-65 private key for frame signing.
	// If empty, frames are written unsigned (Community tier behavior).
	PrivKey []byte

	// PubKey is the corresponding public key — embedded in each frame for offline verify.
	PubKey []byte
}

// New creates and opens a FlightRecorder.
func New(cfg RecorderConfig) (*Recorder, error) {
	path := cfg.Path
	if path == "" {
		dir := os.Getenv("KHEPRA_DATA_DIR")
		if dir == "" {
			dir = "."
		}
		path = filepath.Join(dir, "khepra-flight.ndjson")
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("flight/recorder: open %s: %w", path, err)
	}

	r := &Recorder{
		path:    path,
		privKey: cfg.PrivKey,
		pubKey:  cfg.PubKey,
		pubHex:  hex.EncodeToString(cfg.PubKey),
		file:    f,
		writer:  bufio.NewWriterSize(f, 64*1024),
		prev:    "genesis",
	}

	if err := r.resume(); err != nil {
		// Non-fatal: start fresh chain on first run or corruption
		r.prev = "genesis"
		r.seq.Store(0)
	}

	return r, nil
}

// resume reads the last NDJSON line to restore the chain state.
func (r *Recorder) resume() error {
	rf, err := os.Open(r.path)
	if err != nil {
		return err
	}
	defer rf.Close()

	sc := bufio.NewScanner(rf)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	var lastLine string
	for sc.Scan() {
		if t := sc.Text(); t != "" {
			lastLine = t
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("resume: scan flight log: %w", err)
	}
	if lastLine == "" {
		return nil
	}
	var last FlightFrame
	if err := json.Unmarshal([]byte(lastLine), &last); err != nil {
		return fmt.Errorf("resume: parse last frame: %w", err)
	}
	r.prev = hex3256([]byte(lastLine))
	r.seq.Store(last.Seq + 1)
	return nil
}

// ─── Record ──────────────────────────────────────────────────────────────────

// RecordInput carries the data the router passes to the flight recorder
// at the conclusion of each HandleToolCall execution.
type RecordInput struct {
	// Identity
	AgentID   string
	Subject   string
	SessionID string

	// Tool
	ToolName  string
	ToolScope string
	RiskClass RiskClass

	// Intent (sanitized)
	IntentSummary string // Router-generated: "stig_check on /opt/app with framework RHEL-09-STIG-V1R3"
	RawParams     []byte // Hashed but NOT stored

	// Policy decisions (accumulated by router during call)
	PolicyDecisions []PolicyDecision

	// Outcome
	Outcome      Outcome
	ErrorSummary string
	Warnings     []string

	// Evidence anchors (filled after DAG + signing)
	DAGNodeID string
	IsSigned  bool

	// Timing
	StartedAt  time.Time
	DurationMs int64
}

// Record writes a signed FlightFrame to the log.
// Called by Router.HandleToolCall at step 7 (after attestation).
func (r *Recorder) Record(in RecordInput) (*FlightFrame, error) {
	seq := r.seq.Add(1) - 1

	// Build frame ID: SHA3-256(seq + agentID + toolName + timestamp)
	idSrc := fmt.Sprintf("%d|%s|%s|%s", seq, in.AgentID, in.ToolName, in.StartedAt.UTC().Format(time.RFC3339Nano))
	frameID := hex3256([]byte(idSrc))[:16] // 16 hex chars (8 bytes) — compact

	// Hash params (never store content)
	paramsHash := ""
	if len(in.RawParams) > 0 {
		paramsHash = hex3256(in.RawParams)
	}

	// Intent summary: auto-generate if not provided
	intent := in.IntentSummary
	if intent == "" {
		intent = fmt.Sprintf("tool=%s scope=%s agent=%s", in.ToolName, in.ToolScope, in.AgentID)
	}

	sigAlgo := "unsigned"
	if r.hasKey() {
		sigAlgo = "ML-DSA-65"
	}

	frame := FlightFrame{
		FrameID:         frameID,
		Seq:             seq,
		SessionID:       in.SessionID,
		AgentID:         in.AgentID,
		Subject:         in.Subject,
		StartedAt:       in.StartedAt,
		DurationMs:      in.DurationMs,
		ToolName:        in.ToolName,
		ToolScope:       in.ToolScope,
		RiskClass:       in.RiskClass,
		IntentSummary:   intent,
		ParamsHash:      paramsHash,
		ParamsLen:       len(in.RawParams),
		PolicyDecisions: in.PolicyDecisions,
		Outcome:         in.Outcome,
		ErrorSummary:    in.ErrorSummary,
		Warnings:        in.Warnings,
		DAGNodeID:       in.DAGNodeID,
		IsSigned:        in.IsSigned,
		SignatureAlgo:   sigAlgo,
		ControlsMapped:  ControlsForScope(in.ToolScope),
		Algorithm:       sigAlgo,
		PublicKeyHex:    r.pubHex,
		PrevFrameHash:   "", // set in writeFrame
		FrameHash:       "", // set in writeFrame
		Signature:       "", // set in writeFrame
	}

	return r.writeFrame(&frame)
}

// writeFrame computes the hash, signs, and appends the frame.
func (r *Recorder) writeFrame(frame *FlightFrame) (*FlightFrame, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	frame.PrevFrameHash = r.prev

	// Compute FrameHash = SHA3-256(canonical JSON excluding Signature + FrameHash)
	canonical, err := canonicalFrame(frame)
	if err != nil {
		return nil, fmt.Errorf("flight/recorder: canonicalize frame: %w", err)
	}
	frame.FrameHash = hex3256(canonical)

	// ML-DSA-65 sign the FrameHash
	if r.hasKey() {
		sig, err := adinkra.Sign(r.privKey, []byte(frame.FrameHash))
		if err != nil {
			return nil, fmt.Errorf("flight/recorder: sign frame: %w", err)
		}
		frame.Signature = hex.EncodeToString(sig)
	}

	// Marshal and write
	line, err := json.Marshal(frame)
	if err != nil {
		return nil, fmt.Errorf("flight/recorder: marshal frame: %w", err)
	}
	if _, err := r.writer.Write(line); err != nil {
		return nil, fmt.Errorf("flight/recorder: write frame: %w", err)
	}
	if err := r.writer.WriteByte('\n'); err != nil {
		return nil, fmt.Errorf("flight/recorder: write newline: %w", err)
	}
	if err := r.writer.Flush(); err != nil {
		return nil, fmt.Errorf("flight/recorder: flush: %w", err)
	}

	// Advance chain
	r.prev = hex3256(line)
	return frame, nil
}

// Close flushes and closes the flight log.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.writer.Flush(); err != nil {
		return err
	}
	return r.file.Close()
}

// Path returns the filesystem path of the flight log.
func (r *Recorder) Path() string { return r.path }

// TotalFrames returns the total number of frames written (restart-persistent seq).
func (r *Recorder) TotalFrames() uint64 { return r.seq.Load() }

func (r *Recorder) hasKey() bool { return len(r.privKey) > 0 }

// ─── Intent Summary Generator ─────────────────────────────────────────────────

// BuildIntentSummary generates a human-readable, CUI-safe description of a tool call
// from the tool name, scope, and sanitized arg keys (no values).
// Called by the router before passing RecordInput to Record().
func BuildIntentSummary(toolName, scope string, argKeys []string) string {
	if len(argKeys) == 0 {
		return fmt.Sprintf("%s [%s]", toolName, scope)
	}
	return fmt.Sprintf("%s [%s] args={%v}", toolName, scope, argKeys)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

type canonicalFrameView struct {
	FrameID         string           `json:"frame_id"`
	Seq             uint64           `json:"seq"`
	SessionID       string           `json:"session_id"`
	AgentID         string           `json:"agent_id"`
	Subject         string           `json:"subject"`
	StartedAt       time.Time        `json:"started_at"`
	DurationMs      int64            `json:"duration_ms"`
	ToolName        string           `json:"tool_name"`
	ToolScope       string           `json:"tool_scope"`
	RiskClass       RiskClass        `json:"risk_class"`
	IntentSummary   string           `json:"intent_summary"`
	ParamsHash      string           `json:"params_hash"`
	ParamsLen       int              `json:"params_len"`
	PolicyDecisions []PolicyDecision `json:"policy_decisions"`
	Outcome         Outcome          `json:"outcome"`
	ErrorSummary    string           `json:"error_summary,omitempty"`
	Warnings        []string         `json:"warnings,omitempty"`
	DAGNodeID       string           `json:"dag_node_id,omitempty"`
	IsSigned        bool             `json:"is_signed"`
	ControlsMapped  []ControlMapping `json:"controls_mapped,omitempty"`
	PrevFrameHash   string           `json:"prev_frame_hash"`
	Algorithm       string           `json:"algorithm"`
}

func canonicalFrame(f *FlightFrame) ([]byte, error) {
	return json.Marshal(canonicalFrameView{
		FrameID: f.FrameID, Seq: f.Seq, SessionID: f.SessionID,
		AgentID: f.AgentID, Subject: f.Subject, StartedAt: f.StartedAt,
		DurationMs: f.DurationMs, ToolName: f.ToolName, ToolScope: f.ToolScope,
		RiskClass: f.RiskClass, IntentSummary: f.IntentSummary,
		ParamsHash: f.ParamsHash, ParamsLen: f.ParamsLen,
		PolicyDecisions: f.PolicyDecisions, Outcome: f.Outcome,
		ErrorSummary: f.ErrorSummary, Warnings: f.Warnings,
		DAGNodeID: f.DAGNodeID, IsSigned: f.IsSigned,
		ControlsMapped: f.ControlsMapped, PrevFrameHash: f.PrevFrameHash,
		Algorithm: f.Algorithm,
	})
}

func hex3256(data []byte) string {
	h := sha3.New256()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// newFrameID generates a random 8-byte hex frame ID (fallback when seq unavailable).
func newFrameID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var _ = newFrameID // prevent unused warning — used in tests
