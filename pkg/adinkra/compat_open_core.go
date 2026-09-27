package adinkra

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

// =============================================================================
// OPEN-CORE COMPATIBILITY SUBSTRATE
// Provides standard cryptographic implementations (AES-GCM, HMAC-SHA512, BLAKE2b)
// for open-source MCP transport and agent observability.
// Proprietary lattice transformations (Merkaba White Box cipher, D8 dihedral
// permutations, dynamic chaos S-boxes) are quarantined in KTOS Enterprise.
// =============================================================================

// Merkaba provides standard AEAD sealing for license/key persistence in open-source mode.
type Merkaba struct {
	key []byte
}

// NewMerkaba creates a standard AES-256-GCM cipher wrapper from a 32-byte seed.
func NewMerkaba(seed []byte) *Merkaba {
	key := make([]byte, 32)
	copy(key, seed)
	return &Merkaba{key: key}
}

// Seal encrypts data using AES-256-GCM and returns hex-encoded ciphertext.
func (m *Merkaba) Seal(data []byte) (string, error) {
	ct, err := EncryptAESGCM(m.key, data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ct), nil
}

// Unseal decrypts hex-encoded ciphertext using AES-256-GCM.
func (m *Merkaba) Unseal(sealed string) ([]byte, error) {
	ct, err := hex.DecodeString(sealed)
	if err != nil {
		return nil, err
	}
	return DecryptAESGCM(m.key, ct)
}

// =============================================================================
// SESSION KEY DERIVATION (KDF)
// =============================================================================

// KHEPRASessionKeys holds derived session keys for encryption, auth, and audit.
type KHEPRASessionKeys struct {
	KEnc       []byte // 32-byte AES-256-GCM key
	KAuth      []byte // 32-byte HMAC-SHA512 key
	KAudit     []byte // 32-byte audit signing context key
	SymbolA    string
	SymbolB    string
	Transcript []byte
}

var (
	domainEnc   = []byte("KHEPRA-OPEN-ENC-V1")
	domainAuth  = []byte("KHEPRA-OPEN-AUTH-V1")
	domainAudit = []byte("KHEPRA-OPEN-AUDIT-V1")
)

// DeriveKHEPRASessionKeys derives session keys using BLAKE2b-512 domain separation.
func DeriveKHEPRASessionKeys(sharedSecret []byte, symbolA, symbolB string, transcript []byte) (*KHEPRASessionKeys, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("KDF: shared secret cannot be empty")
	}

	hA := sha256.Sum256([]byte(symbolA))
	hB := sha256.Sum256([]byte(symbolB))

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(transcript)))

	base := make([]byte, 0, len(sharedSecret)+64+4+len(transcript))
	base = append(base, sharedSecret...)
	base = append(base, hA[:]...)
	base = append(base, hB[:]...)
	base = append(base, lenBuf[:]...)
	base = append(base, transcript...)

	kEnc, err := deriveBlake2b32(domainEnc, base)
	if err != nil {
		return nil, err
	}
	kAuth, err := deriveBlake2b32(domainAuth, base)
	if err != nil {
		return nil, err
	}
	kAudit, err := deriveBlake2b32(domainAudit, base)
	if err != nil {
		return nil, err
	}

	return &KHEPRASessionKeys{
		KEnc:       kEnc,
		KAuth:      kAuth,
		KAudit:     kAudit,
		SymbolA:    symbolA,
		SymbolB:    symbolB,
		Transcript: transcript,
	}, nil
}

func deriveBlake2b32(domain, base []byte) ([]byte, error) {
	key := make([]byte, 32)
	copy(key, domain)
	h, err := blake2b.New512(key)
	if err != nil {
		return nil, err
	}
	h.Write(base)
	digest := h.Sum(nil)
	return digest[:32], nil
}

// SecureDestroySessionKeys zeroes all key material.
func (sk *KHEPRASessionKeys) SecureDestroySessionKeys() {
	if sk == nil {
		return
	}
	for i := range sk.KEnc {
		sk.KEnc[i] = 0
	}
	for i := range sk.KAuth {
		sk.KAuth[i] = 0
	}
	for i := range sk.KAudit {
		sk.KAudit[i] = 0
	}
	sk.KEnc = nil
	sk.KAuth = nil
	sk.KAudit = nil
}

// =============================================================================
// ZERO TRUST TOKENS
// =============================================================================

const (
	// ZTTokenTTL is the default token lifetime (15 minutes).
	ZTTokenTTL = 15 * time.Minute
	ztNonceSize = 32
)

// ZeroTrustToken is a short-lived continuous authentication credential.
type ZeroTrustToken struct {
	AgentID    string  // Identifier of the authenticated agent
	Symbol     string  // Symbol binding
	TrustScore float64 // Behavioural trust score [0.0, 1.0]
	IssuedAt   int64   // Unix timestamp (nanoseconds)
	ExpiresAt  int64   // Unix timestamp (nanoseconds)
	Nonce      []byte  // 32-byte cryptographic nonce
	MAC        []byte  // HMAC-SHA512 over canonical fields
}

// IssueZeroTrustToken creates and signs a new 15-minute token.
func IssueZeroTrustToken(agentID, symbol string, trustScore float64, kAuth []byte) (*ZeroTrustToken, error) {
	return IssueZeroTrustTokenWithTTL(agentID, symbol, trustScore, kAuth, ZTTokenTTL)
}

// IssueZeroTrustTokenWithTTL creates a token with a custom TTL.
func IssueZeroTrustTokenWithTTL(agentID, symbol string, trustScore float64, kAuth []byte, ttl time.Duration) (*ZeroTrustToken, error) {
	if len(kAuth) == 0 {
		return nil, errors.New("ZeroTrustToken: kAuth key cannot be empty")
	}
	if agentID == "" {
		return nil, errors.New("ZeroTrustToken: agentID cannot be empty")
	}

	now := time.Now().UnixNano()
	expiresAt := now + ttl.Nanoseconds()

	nonce := make([]byte, ztNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("ZeroTrustToken: nonce generation: %w", err)
	}

	tok := &ZeroTrustToken{
		AgentID:    agentID,
		Symbol:     symbol,
		TrustScore: trustScore,
		IssuedAt:   now,
		ExpiresAt:  expiresAt,
		Nonce:      nonce,
	}

	tok.MAC = tok.computeMAC(kAuth)
	return tok, nil
}

// Verify verifies the HMAC and expiry of a ZeroTrustToken.
func (tok *ZeroTrustToken) Verify(kAuth []byte) error {
	if tok == nil {
		return errors.New("ZeroTrustToken: token is nil")
	}
	if len(kAuth) == 0 {
		return errors.New("ZeroTrustToken: verification key cannot be empty")
	}

	if time.Now().UnixNano() > tok.ExpiresAt {
		return errors.New("ZeroTrustToken: token has expired")
	}

	expectedMAC := tok.computeMAC(kAuth)
	if !hmac.Equal(tok.MAC, expectedMAC) {
		return errors.New("ZeroTrustToken: invalid MAC signature")
	}

	return nil
}

func (tok *ZeroTrustToken) computeMAC(kAuth []byte) []byte {
	mac := hmac.New(sha512.New, kAuth)
	mac.Write([]byte(tok.AgentID))
	mac.Write([]byte(tok.Symbol))

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], math.Float64bits(tok.TrustScore))
	mac.Write(buf[:])

	binary.BigEndian.PutUint64(buf[:], uint64(tok.IssuedAt))
	mac.Write(buf[:])

	binary.BigEndian.PutUint64(buf[:], uint64(tok.ExpiresAt))
	mac.Write(buf[:])

	mac.Write(tok.Nonce)
	return mac.Sum(nil)
}

// =============================================================================
// DAG CONSENSUS & AUDIT CHAIN
// =============================================================================

// DAGVertex is a single node in the Agent Consensus DAG.
type DAGVertex struct {
	ID          string   `json:"id"`
	Symbol      string   `json:"symbol"`
	AgentID     string   `json:"agent_id"`
	Transaction []byte   `json:"transaction"`
	Parents     []string `json:"parents"`
	Hash        []byte   `json:"hash"`
	Signature   []byte   `json:"signature"`
	Timestamp   int64    `json:"timestamp"`
}

// DAGConsensus holds an in-memory DAG audit store.
type DAGConsensus struct {
	vertices map[string]*DAGVertex
	mu       sync.RWMutex
}

// NewDAGConsensus creates a new in-memory DAG.
func NewDAGConsensus() *DAGConsensus {
	return &DAGConsensus{
		vertices: make(map[string]*DAGVertex),
	}
}

// AddVertex appends a new signed vertex to the DAG.
func (d *DAGConsensus) AddVertex(tx []byte, symbol, agentID string, parents []string, priv *AdinkhepraPQCPrivateKey) (*DAGVertex, error) {
	if priv == nil {
		return nil, errors.New("DAGConsensus: private key is nil")
	}

	d.mu.RLock()
	for _, pid := range parents {
		if _, ok := d.vertices[pid]; !ok {
			d.mu.RUnlock()
			return nil, fmt.Errorf("DAGConsensus: unknown parent vertex %q", pid)
		}
	}
	d.mu.RUnlock()

	ts := time.Now().UnixNano()
	v := &DAGVertex{
		Symbol:      symbol,
		AgentID:     agentID,
		Transaction: tx,
		Parents:     parents,
		Timestamp:   ts,
	}

	h := sha512.New()
	h.Write([]byte(symbol))
	h.Write([]byte(agentID))
	h.Write(tx)
	for _, pid := range parents {
		h.Write([]byte(pid))
	}
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(ts))
	h.Write(tsBuf[:])

	v.Hash = h.Sum(nil)
	v.ID = hex.EncodeToString(v.Hash[:16])

	sig, err := SignAdinkhepraPQC(priv, v.Hash)
	if err != nil {
		return nil, fmt.Errorf("DAGConsensus: signing failed: %w", err)
	}
	v.Signature = sig

	d.mu.Lock()
	d.vertices[v.ID] = v
	d.mu.Unlock()

	return v, nil
}

// Verify checks a vertex signature against a public key.
func (d *DAGConsensus) Verify(vertexID string, pub *AdinkhepraPQCPublicKey) error {
	d.mu.RLock()
	v, ok := d.vertices[vertexID]
	d.mu.RUnlock()

	if !ok {
		return fmt.Errorf("DAGConsensus: vertex %q not found", vertexID)
	}

	return VerifyAdinkhepraPQC(pub, v.Hash, v.Signature)
}

// ResolveConflict resolves conflict using symbol precedence or earlier timestamp.
func (d *DAGConsensus) ResolveConflict(v1, v2 *DAGVertex) *DAGVertex {
	p1 := AdinkraPrecedence[v1.Symbol]
	p2 := AdinkraPrecedence[v2.Symbol]

	if p1 > p2 {
		return v1
	}
	if p2 > p1 {
		return v2
	}
	if v1.Timestamp <= v2.Timestamp {
		return v1
	}
	return v2
}

// GetVertex retrieves a vertex by ID.
func (d *DAGConsensus) GetVertex(vertexID string) *DAGVertex {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vertices[vertexID]
}

// All returns a snapshot of all vertices.
func (d *DAGConsensus) All() []*DAGVertex {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*DAGVertex, 0, len(d.vertices))
	for _, v := range d.vertices {
		out = append(out, v)
	}
	return out
}

// DAGAuditChain wraps DAGConsensus and computes a continuous rolling SHA-512 chain hash.
type DAGAuditChain struct {
	dag       *DAGConsensus
	chainHash []byte
	mu        sync.Mutex
}

// NewDAGAuditChain creates a chain-hash audit tracker.
func NewDAGAuditChain(dag *DAGConsensus) *DAGAuditChain {
	genesis := sha512.Sum512([]byte("KHEPRA-DAG-OPEN-GENESIS"))
	return &DAGAuditChain{
		dag:       dag,
		chainHash: genesis[:],
	}
}

// Append appends a vertex and updates the rolling chain hash.
func (ac *DAGAuditChain) Append(tx []byte, symbol, agentID string, parents []string, priv *AdinkhepraPQCPrivateKey) (*DAGVertex, error) {
	v, err := ac.dag.AddVertex(tx, symbol, agentID, parents, priv)
	if err != nil {
		return nil, err
	}

	ac.mu.Lock()
	combined := append(ac.chainHash, v.Hash...)
	next := sha512.Sum512(combined)
	ac.chainHash = next[:]
	ac.mu.Unlock()

	return v, nil
}

// ChainHash returns the rolling chain hash.
func (ac *DAGAuditChain) ChainHash() []byte {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	out := make([]byte, len(ac.chainHash))
	copy(out, ac.chainHash)
	return out
}
