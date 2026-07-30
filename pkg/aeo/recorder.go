package aeo

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// Recorder binds an agent identity (ML-DSA-65 key pair) to a stream of task
// recordings. Each sealed task becomes one EvidenceObject whose ParentEvent
// is the hash of the previous one — the agent's operational history chain.
type Recorder struct {
	mu       sync.Mutex
	agentID  string
	privKey  []byte
	pubKey   []byte
	lastHash string // parent for the next AEO ("" until the genesis event)
}

// NewRecorder creates a recorder for the given ML-DSA-65 key pair.
func NewRecorder(privKey, pubKey []byte) *Recorder {
	return &Recorder{
		agentID: AgentDID(pubKey),
		privKey: privKey,
		pubKey:  pubKey,
	}
}

// AgentID returns the recorder's did:khepra identifier.
func (r *Recorder) AgentID() string { return r.agentID }

// TaskRecording accumulates the evidence for one in-flight task.
type TaskRecording struct {
	mu           sync.Mutex
	recorder     *Recorder
	task         string
	intentHash   string
	toolCalls    []ToolCall
	observations []Observation
	startedAt    time.Time
}

// StartTask opens a recording. The intent is committed (hashed) here, before
// any tool runs, so the declaration provably precedes the action.
func (r *Recorder) StartTask(task, intent string) *TaskRecording {
	return &TaskRecording{
		recorder:   r,
		task:       task,
		intentHash: IntentHash(intent),
		startedAt:  time.Now().UTC(),
	}
}

// RecordToolCall appends one tool invocation to the recording.
func (t *TaskRecording) RecordToolCall(tool, target string, latency time.Duration, outcome string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.toolCalls = append(t.toolCalls, ToolCall{
		Tool:      tool,
		Target:    target,
		StartedAt: time.Now().UTC(),
		LatencyMS: latency.Milliseconds(),
		Outcome:   outcome,
	})
}

// RecordObservation appends a finding to the recording.
func (t *TaskRecording) RecordObservation(target, finding string, confidence float64, evidence string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.observations = append(t.observations, Observation{
		Target:     target,
		Finding:    finding,
		Confidence: confidence,
		Evidence:   evidence,
	})
}

// Seal closes the recording: computes the behavioral fingerprint, chains the
// AEO to the agent's previous event, and signs it with ML-DSA-65.
func (t *TaskRecording) Seal() (*EvidenceObject, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	r := t.recorder
	r.mu.Lock()
	defer r.mu.Unlock()

	obj := &EvidenceObject{
		SpecVersion:       SpecVersion,
		AgentID:           r.agentID,
		Task:              t.task,
		IntentHash:        t.intentHash,
		ToolsUsed:         uniqueTools(t.toolCalls),
		ToolCalls:         t.toolCalls,
		Observations:      t.observations,
		BehaviorSignature: fingerprint(t.toolCalls),
		Timestamp:         time.Now().UTC(),
		ParentEvent:       r.lastHash,
	}
	if obj.Observations == nil {
		obj.Observations = []Observation{}
	}

	if err := obj.Seal(r.privKey, r.pubKey); err != nil {
		return nil, err
	}
	r.lastHash = obj.Hash
	return obj, nil
}

// uniqueTools returns the sorted set of distinct tools used.
func uniqueTools(calls []ToolCall) []string {
	seen := make(map[string]bool)
	var tools []string
	for _, c := range calls {
		if !seen[c.Tool] {
			seen[c.Tool] = true
			tools = append(tools, c.Tool)
		}
	}
	sort.Strings(tools)
	if tools == nil {
		tools = []string{}
	}
	return tools
}

// fingerprint derives the behavioral signature from the recorded tool calls:
//   - ExecutionPattern: hash of the exact ordered tool sequence
//   - ToolGraph: hash of the sorted set of tool->tool transitions
//   - LatencyVector: per-call latencies, order preserved
func fingerprint(calls []ToolCall) BehaviorSignature {
	sequence := make([]string, 0, len(calls))
	latencies := make([]int64, 0, len(calls))
	edgeSet := make(map[string]bool)

	for i, c := range calls {
		sequence = append(sequence, c.Tool)
		latencies = append(latencies, c.LatencyMS)
		if i > 0 {
			edgeSet[calls[i-1].Tool+"->"+c.Tool] = true
		}
	}

	edges := make([]string, 0, len(edgeSet))
	for e := range edgeSet {
		edges = append(edges, e)
	}
	sort.Strings(edges)

	return BehaviorSignature{
		ExecutionPattern: adinkra.Hash([]byte(strings.Join(sequence, "|"))),
		ToolGraph:        adinkra.Hash([]byte(strings.Join(edges, "|"))),
		ToolGraphEdges:   edges,
		LatencyVector:    latencies,
	}
}
