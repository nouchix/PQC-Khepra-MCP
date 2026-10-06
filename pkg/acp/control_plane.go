// Package acp implements the Agent Control Plane (ACP) for the Khepra Protocol.
// ACP issues short-lived PQC credentials, manages JIT access, and records all
// provisioning events in the DAG audit chain.
package acp

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// DefaultCredentialTTL is the default lifetime for ACP-issued credentials.
const DefaultCredentialTTL = 1 * time.Hour

// AgentCredential is a Khepra-issued, quantum-resistant credential for an AI agent.
type AgentCredential struct {
	ID        string   // "agt-KHEPRA-<uuid>"
	AgentID   string   // External agent identifier
	Symbol    string   // Adinkra symbol (policy binding)
	PublicKey []byte   // AdinkhepraPQC quantum-resistant public key
	Token     *adinkra.ZeroTrustToken // 15-min TTL continuous auth token
	Scopes    []string // JIT-scoped permissions
	IssuedAt  time.Time
	ExpiresAt time.Time
	DAGVertex string // ID of the DAG vertex recording this issuance

	// Internal: private key is held ephemerally and never persisted.
	privateKey *adinkra.AdinkhepraPQCPrivateKey
}

// IsExpired returns true if the credential has passed its expiry.
func (c *AgentCredential) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// SecondsUntilExpiry returns remaining lifetime in seconds.
func (c *AgentCredential) SecondsUntilExpiry() int64 {
	return int64(time.Until(c.ExpiresAt).Seconds())
}

// AgentControlPlane manages the full lifecycle of PQC agent credentials.
type AgentControlPlane struct {
	dag        *adinkra.DAGConsensus
	auditChain *adinkra.DAGAuditChain
	masterKey  *adinkra.HybridKeyPair // Master key pair for ACP itself
	credentials map[string]*AgentCredential
	mu          sync.RWMutex

	// authSecret is the server-held secret that zero-trust token keys are
	// derived from. It never leaves the control plane.
	authSecret []byte
}

// NewAgentControlPlane creates an ACP with a freshly generated master key pair.
func NewAgentControlPlane() (*AgentControlPlane, error) {
	dag := adinkra.NewDAGConsensus()

	masterKP, err := adinkra.GenerateHybridKeyPair("acp-master", "Eban", 12)
	if err != nil {
		return nil, fmt.Errorf("ACP: master key generation failed: %w", err)
	}

	authSecret := make([]byte, 32)
	if _, err := generateEntropy(authSecret); err != nil {
		return nil, fmt.Errorf("ACP: auth secret generation failed: %w", err)
	}

	return &AgentControlPlane{
		dag:         dag,
		auditChain:  adinkra.NewDAGAuditChain(dag),
		masterKey:   masterKP,
		credentials: make(map[string]*AgentCredential),
		authSecret:  authSecret,
	}, nil
}

// tokenKeys derives the zero-trust token keys for an agent from the control
// plane's server-held secret.
func (acp *AgentControlPlane) tokenKeys(agentID, symbol string) (*adinkra.KHEPRASessionKeys, error) {
	return adinkra.DeriveKHEPRASessionKeys(acp.authSecret, symbol, "Eban", []byte(agentID))
}

// VerifyToken checks a zero-trust token this control plane issued.
func (acp *AgentControlPlane) VerifyToken(token *adinkra.ZeroTrustToken) error {
	if token == nil {
		return fmt.Errorf("ACP: token is nil")
	}
	keys, err := acp.tokenKeys(token.AgentID, token.Symbol)
	if err != nil {
		return err
	}
	defer keys.SecureDestroySessionKeys()
	return adinkra.VerifyZeroTrustToken(token, keys.KAuth)
}

// IssueCredential provisions a new PQC credential for an AI agent.
// The credential is recorded in the DAG audit chain with the given symbol.
func (acp *AgentControlPlane) IssueCredential(agentID, symbol string, scopes []string, ttl time.Duration) (*AgentCredential, error) {
	if agentID == "" {
		return nil, fmt.Errorf("ACP: agentID cannot be empty")
	}
	if _, ok := adinkra.AdinkraPrecedence[symbol]; !ok {
		symbol = "Nkyinkyim" // default to adaptive symbol for unrecognised inputs
	}
	if ttl <= 0 {
		ttl = DefaultCredentialTTL
	}

	// Generate a fresh PQC key pair for this agent.
	pub, priv, err := adinkra.GenerateAdinkhepraPQCKeyPair(symbol)
	if err != nil {
		return nil, fmt.Errorf("ACP: PQC key generation failed: %w", err)
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ACP: public key marshal failed: %w", err)
	}

	// Derive the zero-trust token key from the control plane's server-held
	// secret, never from public data such as the agent's public key.
	sessionKeys, err := acp.tokenKeys(agentID, symbol)
	if err != nil {
		return nil, fmt.Errorf("ACP: session key derivation failed: %w", err)
	}
	defer sessionKeys.SecureDestroySessionKeys()

	// Issue a 15-minute ZT token.
	ztToken, err := adinkra.IssueZeroTrustTokenWithTTL(agentID, symbol, 1.0, sessionKeys.KAuth, adinkra.ZTTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("ACP: ZT token issuance failed: %w", err)
	}

	// Record issuance in DAG with the ACP master private key.
	txPayload := []byte(fmt.Sprintf("ISSUE:%s:%s:%v", agentID, symbol, scopes))
	vertex, err := acp.auditChain.Append(txPayload, symbol, "acp", nil, acp.masterKey.AdinkhepraPQCPrivate)
	if err != nil {
		return nil, fmt.Errorf("ACP: DAG recording failed: %w", err)
	}

	credID := "agt-KHEPRA-" + uuid.New().String()[:8]
	cred := &AgentCredential{
		ID:         credID,
		AgentID:    agentID,
		Symbol:     symbol,
		PublicKey:  pubBytes,
		Token:      ztToken,
		Scopes:     scopes,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
		DAGVertex:  vertex.ID,
		privateKey: priv,
	}

	acp.mu.Lock()
	acp.credentials[credID] = cred
	acp.mu.Unlock()

	adinkra.AuditSensitiveOperation(fmt.Sprintf("ACP:IssueCredential:%s:%s", agentID, symbol), true)
	return cred, nil
}

// ValidateCredential verifies that a credential is valid and its ZT token is fresh.
func (acp *AgentControlPlane) ValidateCredential(cred *AgentCredential) error {
	if cred == nil {
		return fmt.Errorf("ACP: credential is nil")
	}
	if len(cred.PublicKey) == 0 {
		return fmt.Errorf("ACP: credential %s has no public key (tampered?)", cred.ID)
	}
	if cred.Token == nil {
		return fmt.Errorf("ACP: credential %s has no ZeroTrustToken (tampered?)", cred.ID)
	}
	if cred.IsExpired() {
		return fmt.Errorf("ACP: credential %s has expired", cred.ID)
	}

	acp.mu.RLock()
	stored, ok := acp.credentials[cred.ID]
	acp.mu.RUnlock()
	if !ok {
		return fmt.Errorf("ACP: credential %s not found (revoked?)", cred.ID)
	}
	if stored.AgentID != cred.AgentID || cred.Token.AgentID != cred.AgentID {
		return fmt.Errorf("ACP: credential %s does not match its agent (tampered?)", cred.ID)
	}
	if err := acp.VerifyToken(cred.Token); err != nil {
		return fmt.Errorf("ACP: credential %s token invalid: %w", cred.ID, err)
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("ACP:ValidateCredential:%s", cred.AgentID), true)
	return nil
}

// RevokeCredential revokes a credential with a Fawohodie DAG transaction.
func (acp *AgentControlPlane) RevokeCredential(id string) error {
	acp.mu.Lock()
	cred, ok := acp.credentials[id]
	if !ok {
		acp.mu.Unlock()
		return fmt.Errorf("ACP: credential %s not found", id)
	}
	delete(acp.credentials, id)
	acp.mu.Unlock()

	// Record revocation in DAG with Fawohodie (privilege revocation) symbol.
	txPayload := []byte(fmt.Sprintf("REVOKE:%s", id))
	_, err := acp.auditChain.Append(txPayload, "Fawohodie", "acp", []string{cred.DAGVertex}, acp.masterKey.AdinkhepraPQCPrivate)
	if err != nil {
		return fmt.Errorf("ACP: DAG revocation record failed: %w", err)
	}

	// Zeroize the private key if still held.
	if cred.privateKey != nil {
		cred.privateKey.DestroyPrivateKey()
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("ACP:RevokeCredential:%s", id), true)
	return nil
}

// RotateCredential revokes the current credential and issues a new one.
func (acp *AgentControlPlane) RotateCredential(id string) (*AgentCredential, error) {
	acp.mu.RLock()
	old, ok := acp.credentials[id]
	acp.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("ACP: credential %s not found", id)
	}

	newCred, err := acp.IssueCredential(old.AgentID, old.Symbol, old.Scopes, time.Until(old.ExpiresAt.Add(DefaultCredentialTTL)))
	if err != nil {
		return nil, err
	}

	_ = acp.RevokeCredential(id)
	return newCred, nil
}

// ListCredentials returns all active (non-expired) credentials.
func (acp *AgentControlPlane) ListCredentials() []*AgentCredential {
	acp.mu.RLock()
	defer acp.mu.RUnlock()
	var out []*AgentCredential
	for _, c := range acp.credentials {
		if !c.IsExpired() {
			out = append(out, c)
		}
	}
	return out
}

// AuditChainHash returns the current DAG audit chain hash (tamper evidence).
func (acp *AgentControlPlane) AuditChainHash() []byte {
	return acp.auditChain.ChainHash()
}

// generateEntropy fills b with cryptographically random bytes.
func generateEntropy(b []byte) (int, error) {
	return rand.Read(b)
}
