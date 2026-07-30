// Package aeo implements the AI Evidence Object (AEO) — the fundamental
// forensic unit of the KHEPRA Digital Citizenship layer.
//
// "Trust me" becomes "Prove it."
//
// An AEO turns every autonomous agent action into a forensic artifact:
//
//	Agent identity (did:khepra:...) + declared intent + tools used +
//	observations + behavioral fingerprint + ML-DSA-65 attestation +
//	parent-event hash chain
//
// Where pkg/forensics (Imhotep's Eye) documents the HOST, pkg/aeo documents
// the AGENT: which subagents existed, what they inspected, what evidence they
// used, what they decided, and what changed. The chain of AEOs is the agent's
// verifiable operational history — its Proof of Work History.
//
// Every AEO is content-addressed (Khepra lattice hash), signed with
// ML-DSA-65 (Dilithium3), and anchored into the immutable KHEPRA DAG so the
// state transition S(t0) -> Action -> S(t1) can be reconstructed from
// evidence alone (forensic replay, the "anti-action").
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
// Patent: USPTO #73565085 (KHEPRA Protocol)
package aeo

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// SpecVersion identifies the AEO schema revision.
const SpecVersion = "khepra-aeo/1.0"

// AttestAlgorithm is the PQC signature scheme sealing every AEO.
const AttestAlgorithm = "ML-DSA-65"

// DIDMethod is the prefix for KHEPRA agent decentralized identifiers.
const DIDMethod = "did:khepra:"

// Observation is a single finding the agent made while executing its task.
type Observation struct {
	Target     string  `json:"target"`             // file, host, control, endpoint...
	Finding    string  `json:"finding"`            // what was observed
	Confidence float64 `json:"confidence"`         // 0.0 - 1.0
	Evidence   string  `json:"evidence,omitempty"` // hash or pointer to raw evidence
}

// ToolCall is one recorded tool invocation inside a task.
type ToolCall struct {
	Tool      string    `json:"tool"`
	Target    string    `json:"target,omitempty"`
	StartedAt time.Time `json:"started_at"`
	LatencyMS int64     `json:"latency_ms"`
	Outcome   string    `json:"outcome"` // ok | error | denied
}

// BehaviorSignature is the agent's behavioral fingerprint for one task —
// how it worked, not just what it produced. Two agents claiming the same
// identity but exhibiting different execution patterns are distinguishable.
type BehaviorSignature struct {
	ExecutionPattern string   `json:"execution_pattern"` // hash of the ordered tool sequence
	ToolGraph        string   `json:"tool_graph"`        // hash of the tool transition edges
	ToolGraphEdges   []string `json:"tool_graph_edges"`  // sorted "a->b" transitions
	LatencyVector    []int64  `json:"latency_vector"`    // per-call latency in ms
}

// Attestation is the cryptographic seal over the canonical AEO content.
type Attestation struct {
	Algorithm string `json:"algorithm"`  // ML-DSA-65
	PublicKey string `json:"public_key"` // hex
	Signature string `json:"signature"`  // hex, over the canonical content hash
}

// EvidenceObject is the AI Evidence Object — one immutable record of one
// agent task. The Hash field is the content address; ParentEvent links AEOs
// into the agent's operational history chain.
type EvidenceObject struct {
	SpecVersion  string        `json:"spec_version"`
	AgentID      string        `json:"agent_id"` // did:khepra:...
	Task         string        `json:"task"`
	IntentHash   string        `json:"intent_hash"` // hash of the declared intent, pre-execution
	ToolsUsed    []string      `json:"tools_used"`
	ToolCalls    []ToolCall    `json:"tool_calls,omitempty"`
	Observations []Observation `json:"observations"`

	BehaviorSignature BehaviorSignature `json:"behavior_signature"`

	Timestamp   time.Time `json:"timestamp"`
	ParentEvent string    `json:"parent_event"` // hash of the previous AEO ("" for genesis)

	Hash                     string      `json:"hash"` // Khepra lattice hash of canonical content
	CryptographicAttestation Attestation `json:"cryptographic_attestation"`
}

// AgentDID derives a KHEPRA decentralized identifier from an ML-DSA-65
// public key. The DID is stable for the lifetime of the key pair.
func AgentDID(pubKey []byte) string {
	return DIDMethod + adinkra.Hash(pubKey)[:32]
}

// canonicalContent is the deterministic view of an AEO that gets hashed and
// signed: everything except the hash and the attestation themselves.
type canonicalContent struct {
	SpecVersion       string            `json:"spec_version"`
	AgentID           string            `json:"agent_id"`
	Task              string            `json:"task"`
	IntentHash        string            `json:"intent_hash"`
	ToolsUsed         []string          `json:"tools_used"`
	ToolCalls         []ToolCall        `json:"tool_calls,omitempty"`
	Observations      []Observation     `json:"observations"`
	BehaviorSignature BehaviorSignature `json:"behavior_signature"`
	Timestamp         time.Time         `json:"timestamp"`
	ParentEvent       string            `json:"parent_event"`
}

// CanonicalBytes returns the deterministic serialization of the AEO content
// (signature and hash excluded). Struct field order fixes the JSON layout,
// so the same content always yields the same bytes.
func (e *EvidenceObject) CanonicalBytes() ([]byte, error) {
	return json.Marshal(canonicalContent{
		SpecVersion:       e.SpecVersion,
		AgentID:           e.AgentID,
		Task:              e.Task,
		IntentHash:        e.IntentHash,
		ToolsUsed:         e.ToolsUsed,
		ToolCalls:         e.ToolCalls,
		Observations:      e.Observations,
		BehaviorSignature: e.BehaviorSignature,
		Timestamp:         e.Timestamp,
		ParentEvent:       e.ParentEvent,
	})
}

// ComputeHash calculates the content address of the AEO.
func (e *EvidenceObject) ComputeHash() (string, error) {
	raw, err := e.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return adinkra.Hash(raw), nil
}

// Seal computes the content hash and signs it with the agent's ML-DSA-65
// private key. The public key must belong to the same pair; the AgentID must
// have been derived from it, otherwise Verify will reject the object.
func (e *EvidenceObject) Seal(privKey, pubKey []byte) error {
	h, err := e.ComputeHash()
	if err != nil {
		return err
	}
	e.Hash = h

	sig, err := adinkra.Sign(privKey, []byte(h))
	if err != nil {
		return fmt.Errorf("aeo: seal failed: %w", err)
	}

	e.CryptographicAttestation = Attestation{
		Algorithm: AttestAlgorithm,
		PublicKey: hex.EncodeToString(pubKey),
		Signature: hex.EncodeToString(sig),
	}
	return nil
}

// Verify checks the AEO end to end:
//  1. the content hash matches the canonical content (tamper evidence),
//  2. the ML-DSA-65 signature over the hash is valid,
//  3. the agent DID matches the attesting public key (identity binding).
func (e *EvidenceObject) Verify() error {
	computed, err := e.ComputeHash()
	if err != nil {
		return err
	}
	if e.Hash != computed {
		return errors.New("aeo: integrity violation: content hash mismatch")
	}

	pub, err := hex.DecodeString(e.CryptographicAttestation.PublicKey)
	if err != nil {
		return fmt.Errorf("aeo: bad public key encoding: %w", err)
	}
	sig, err := hex.DecodeString(e.CryptographicAttestation.Signature)
	if err != nil {
		return fmt.Errorf("aeo: bad signature encoding: %w", err)
	}

	ok, err := adinkra.Verify(pub, []byte(e.Hash), sig)
	if err != nil {
		return fmt.Errorf("aeo: verify failed: %w", err)
	}
	if !ok {
		return errors.New("aeo: invalid ML-DSA-65 signature")
	}

	if AgentDID(pub) != e.AgentID {
		return errors.New("aeo: identity violation: agent DID does not match attesting key")
	}
	return nil
}

// IntentHash derives the pre-execution intent commitment. Recording the
// intent hash BEFORE acting lets an auditor later prove the agent declared
// what it was going to do, not just what it did.
func IntentHash(intent string) string {
	return adinkra.Hash([]byte(intent))
}
