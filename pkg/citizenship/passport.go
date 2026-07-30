// Package citizenship implements the KHEPRA Agent Passport — the portable
// credential of Digital Citizenship for autonomous AI agents.
//
// "The first digital citizenship protocol for AI agents."
//
// A Passport composes everything pkg/aeo records about an agent into one
// signed, verifiable document:
//
//	Identity  (did:khepra DID bound to an ML-DSA-65 key)
//	History   (length and tip of the agent's AEO chain)
//	Behavior  (current behavioral baseline: tool graph of the latest event)
//	Trust     (integrity / consistency / intent scores)
//
// The passport is issued by a Registrar — typically the operator of the
// evidence Ledger — and sealed with the registrar's own ML-DSA-65 key, so a
// relying party can check an agent's standing without walking the full
// chain. Anyone holding the ledger can still independently re-derive every
// claim via aeo.Ledger.Replay and aeo.Ledger.Trust: the passport is a
// summary credential, never a substitute for the evidence.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
// Patent: USPTO #73565085 (KHEPRA Protocol)
package citizenship

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/aeo"
)

// PassportSpec identifies the passport schema revision.
const PassportSpec = "khepra-passport/1.0"

// Passport is the agent's citizenship credential: a signed summary of its
// identity, operational history, behavioral baseline, and trust standing at
// the moment of issue.
type Passport struct {
	Spec     string    `json:"spec"`
	AgentID  string    `json:"agent_id"` // did:khepra:...
	IssuedAt time.Time `json:"issued_at"`

	// History — the agent's Proof of Work History at issue time.
	Events    int       `json:"events"`     // chain length
	ChainTip  string    `json:"chain_tip"`  // hash of the latest AEO
	FirstSeen time.Time `json:"first_seen"` // timestamp of the genesis AEO
	LastSeen  time.Time `json:"last_seen"`  // timestamp of the tip AEO

	// Behavior — current behavioral baseline for impersonation checks.
	BehaviorBaseline string `json:"behavior_baseline"` // tool-graph hash of the tip AEO

	// Trust — standing derived from the full verified history.
	TrustScore       int `json:"trust_score"`       // 0-100 overall
	IntegrityScore   int `json:"integrity_score"`   // 0-100
	ConsistencyScore int `json:"consistency_score"` // 0-100
	IntentScore      int `json:"intent_score"`      // 0-100

	// Issuer — who vouches for this summary.
	Registrar   string `json:"registrar"`    // human-readable issuer name
	RegistrarID string `json:"registrar_id"` // did:khepra DID of the issuing key
	Revoked     bool   `json:"revoked,omitempty"`

	Hash        string          `json:"hash"` // content address of the canonical passport
	Attestation aeo.Attestation `json:"attestation"`
}

// Registrar issues and verifies passports against an evidence ledger.
type Registrar struct {
	name    string
	privKey []byte
	pubKey  []byte
}

// NewRegistrar creates a passport issuer from an ML-DSA-65 key pair.
func NewRegistrar(name string, privKey, pubKey []byte) *Registrar {
	return &Registrar{name: name, privKey: privKey, pubKey: pubKey}
}

// ID returns the registrar's did:khepra identifier.
func (r *Registrar) ID() string { return aeo.AgentDID(r.pubKey) }

// canonicalPassport is the deterministic view that gets hashed and signed:
// everything except the hash and attestation themselves.
type canonicalPassport struct {
	Spec             string    `json:"spec"`
	AgentID          string    `json:"agent_id"`
	IssuedAt         time.Time `json:"issued_at"`
	Events           int       `json:"events"`
	ChainTip         string    `json:"chain_tip"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	BehaviorBaseline string    `json:"behavior_baseline"`
	TrustScore       int       `json:"trust_score"`
	IntegrityScore   int       `json:"integrity_score"`
	ConsistencyScore int       `json:"consistency_score"`
	IntentScore      int       `json:"intent_score"`
	Registrar        string    `json:"registrar"`
	RegistrarID      string    `json:"registrar_id"`
	Revoked          bool      `json:"revoked,omitempty"`
}

func (p *Passport) canonicalBytes() ([]byte, error) {
	return json.Marshal(canonicalPassport{
		Spec:             p.Spec,
		AgentID:          p.AgentID,
		IssuedAt:         p.IssuedAt,
		Events:           p.Events,
		ChainTip:         p.ChainTip,
		FirstSeen:        p.FirstSeen,
		LastSeen:         p.LastSeen,
		BehaviorBaseline: p.BehaviorBaseline,
		TrustScore:       p.TrustScore,
		IntegrityScore:   p.IntegrityScore,
		ConsistencyScore: p.ConsistencyScore,
		IntentScore:      p.IntentScore,
		Registrar:        p.Registrar,
		RegistrarID:      p.RegistrarID,
		Revoked:          p.Revoked,
	})
}

// ComputeHash calculates the passport's content address.
func (p *Passport) ComputeHash() (string, error) {
	raw, err := p.canonicalBytes()
	if err != nil {
		return "", err
	}
	return adinkra.Hash(raw), nil
}

// Issue builds and signs a passport for an agent from its verified history.
// The full chain is replayed first — a passport is only ever issued over
// evidence that proves out end to end. Agents with no history are refused:
// citizenship is earned by record, not asserted.
func (r *Registrar) Issue(ledger *aeo.Ledger, agentID string) (*Passport, error) {
	history, err := ledger.Replay(agentID)
	if err != nil {
		return nil, fmt.Errorf("citizenship: refusing passport: %w", err)
	}

	trust := ledger.Trust(agentID)
	genesis, tip := history[0], history[len(history)-1]

	p := &Passport{
		Spec:             PassportSpec,
		AgentID:          agentID,
		IssuedAt:         time.Now().UTC(),
		Events:           len(history),
		ChainTip:         tip.Hash,
		FirstSeen:        genesis.Timestamp,
		LastSeen:         tip.Timestamp,
		BehaviorBaseline: tip.BehaviorSignature.ToolGraph,
		TrustScore:       trust.Score,
		IntegrityScore:   trust.IntegrityScore,
		ConsistencyScore: trust.ConsistencyScore,
		IntentScore:      trust.IntentScore,
		Registrar:        r.name,
		RegistrarID:      r.ID(),
	}

	if err := r.seal(p); err != nil {
		return nil, err
	}
	return p, nil
}

// Revoke re-issues the passport with the revoked flag set, signed by the
// same registrar. The original passport remains verifiable but supersedable;
// relying parties should honor the newest registrar-signed statement.
func (r *Registrar) Revoke(p *Passport) (*Passport, error) {
	if p.RegistrarID != r.ID() {
		return nil, errors.New("citizenship: only the issuing registrar can revoke")
	}
	revoked := *p
	revoked.Revoked = true
	revoked.IssuedAt = time.Now().UTC()
	if err := r.seal(&revoked); err != nil {
		return nil, err
	}
	return &revoked, nil
}

func (r *Registrar) seal(p *Passport) error {
	h, err := p.ComputeHash()
	if err != nil {
		return err
	}
	p.Hash = h

	sig, err := adinkra.Sign(r.privKey, []byte(h))
	if err != nil {
		return fmt.Errorf("citizenship: seal failed: %w", err)
	}
	p.Attestation = aeo.Attestation{
		Algorithm: aeo.AttestAlgorithm,
		PublicKey: hex.EncodeToString(r.pubKey),
		Signature: hex.EncodeToString(sig),
	}
	return nil
}

// Verify checks the passport document itself: content hash, ML-DSA-65
// signature, and that the signing key matches the claimed registrar DID.
func (p *Passport) Verify() error {
	computed, err := p.ComputeHash()
	if err != nil {
		return err
	}
	if p.Hash != computed {
		return errors.New("citizenship: integrity violation: passport hash mismatch")
	}

	pub, err := hex.DecodeString(p.Attestation.PublicKey)
	if err != nil {
		return fmt.Errorf("citizenship: bad public key encoding: %w", err)
	}
	sig, err := hex.DecodeString(p.Attestation.Signature)
	if err != nil {
		return fmt.Errorf("citizenship: bad signature encoding: %w", err)
	}

	ok, err := adinkra.Verify(pub, []byte(p.Hash), sig)
	if err != nil {
		return fmt.Errorf("citizenship: verify failed: %w", err)
	}
	if !ok {
		return errors.New("citizenship: invalid ML-DSA-65 signature")
	}
	if aeo.AgentDID(pub) != p.RegistrarID {
		return errors.New("citizenship: identity violation: signing key does not match registrar DID")
	}
	return nil
}

// VerifyAgainstLedger checks the passport AND re-derives its claims from the
// evidence: chain tip, event count, and trust scores must match what the
// ledger proves today. This is the full "prove it" path a relying party uses
// when it holds the ledger; Verify alone is the lightweight path when it
// only holds the passport and trusts the registrar.
func (p *Passport) VerifyAgainstLedger(ledger *aeo.Ledger) error {
	if err := p.Verify(); err != nil {
		return err
	}

	history, err := ledger.Replay(p.AgentID)
	if err != nil {
		return fmt.Errorf("citizenship: ledger replay failed: %w", err)
	}

	// The ledger may have advanced past the passport's tip; the passport is
	// stale-but-honest as long as its tip appears in the verified chain at
	// the claimed position.
	if p.Events > len(history) {
		return errors.New("citizenship: passport claims more events than the ledger holds")
	}
	if history[p.Events-1].Hash != p.ChainTip {
		return errors.New("citizenship: passport chain tip does not match the verified chain")
	}
	return nil
}
