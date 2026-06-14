// Package nhi provides Non-Human Identity (NHI) governance for AI agents.
// Tracks API keys, OAuth tokens, service accounts, and other machine credentials
// held by AI agents across all cloud and SaaS environments.
package nhi

import (
	"fmt"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// NHIType classifies the credential type.
type NHIType string

const (
	NHITypeAPIKey         NHIType = "api-key"
	NHITypeOAuthToken     NHIType = "oauth-token"
	NHITypeServiceAccount NHIType = "service-account"
	NHITypeSSHKey         NHIType = "ssh-key"
	NHITypePAT            NHIType = "pat" // Personal Access Token
	NHITypeJWT            NHIType = "jwt"
)

// NHIRecord represents a single non-human identity credential.
type NHIRecord struct {
	ID        string    // Unique identifier (e.g. "nhi-aws-1a2b3c")
	Type      NHIType   // Credential type
	Owner     string    // Agent ID or service that owns this credential
	Platform  string    // "aws", "github", "slack", "openai", "k8s", etc.
	Scopes    []string  // Permission scopes granted
	ExpiresAt *time.Time // nil = never expires
	LastUsed  time.Time
	RiskScore float64  // 0.0 (low) → 1.0 (critical)
	Managed   bool     // true = Khepra-managed, false = shadow/external

	// PQC attestation (present only for Khepra-issued credentials)
	PQCAttestation []byte
}

// IsExpired returns true if the credential has a hard expiry that has passed.
func (r *NHIRecord) IsExpired() bool {
	if r.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*r.ExpiresAt)
}

// DaysUntilExpiry returns the number of days until expiry (-1 if no expiry).
func (r *NHIRecord) DaysUntilExpiry() int {
	if r.ExpiresAt == nil {
		return -1
	}
	return int(time.Until(*r.ExpiresAt).Hours() / 24)
}

// NHITracker manages the inventory of non-human identities.
type NHITracker struct {
	records  map[string]*NHIRecord
	mu       sync.RWMutex
	// Optional revocation hook — called when RevokeNHI is invoked.
	RevokeFunc func(id, platform string) error
}

// NewNHITracker creates an empty NHI tracker.
func NewNHITracker() *NHITracker {
	return &NHITracker{
		records: make(map[string]*NHIRecord),
	}
}

// Register adds or updates an NHI record.
func (t *NHITracker) Register(r *NHIRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.records[r.ID] = r
	adinkra.AuditSensitiveOperation(fmt.Sprintf("NHI:Register:%s:%s", r.ID, r.Platform), true)
}

// Inventory returns all tracked NHI records.
func (t *NHITracker) Inventory() ([]*NHIRecord, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*NHIRecord, 0, len(t.records))
	for _, r := range t.records {
		out = append(out, r)
	}
	return out, nil
}

// IdentifyOrphans returns credentials whose owner agent no longer exists
// (owner field is empty or set to "unknown").
func (t *NHITracker) IdentifyOrphans() []*NHIRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var orphans []*NHIRecord
	for _, r := range t.records {
		if r.Owner == "" || r.Owner == "unknown" {
			orphans = append(orphans, r)
		}
	}
	return orphans
}

// IdentifyExcessive returns credentials with more than maxScopes granted scopes
// or with a RiskScore above the threshold.
func (t *NHITracker) IdentifyExcessive(maxScopes int, riskThreshold float64) []*NHIRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var excessive []*NHIRecord
	for _, r := range t.records {
		if len(r.Scopes) > maxScopes || r.RiskScore > riskThreshold {
			excessive = append(excessive, r)
		}
	}
	return excessive
}

// IdentifyExpired returns credentials that have passed their expiry date.
func (t *NHITracker) IdentifyExpired() []*NHIRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var expired []*NHIRecord
	for _, r := range t.records {
		if r.IsExpired() {
			expired = append(expired, r)
		}
	}
	return expired
}

// RevokeNHI revokes a credential by ID, routing through the registered RevokeFunc.
// Requires the caller to have Fawohodie-level authority (enforced at API layer).
func (t *NHITracker) RevokeNHI(id string) error {
	t.mu.Lock()
	r, ok := t.records[id]
	if !ok {
		t.mu.Unlock()
		return fmt.Errorf("NHITracker: credential %q not found", id)
	}
	platform := r.Platform
	delete(t.records, id)
	t.mu.Unlock()

	adinkra.AuditSensitiveOperation(fmt.Sprintf("NHI:Revoke:%s:%s", id, platform), true)

	if t.RevokeFunc != nil {
		return t.RevokeFunc(id, platform)
	}
	return nil
}

// Get returns a single record by ID (nil if not found).
func (t *NHITracker) Get(id string) *NHIRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.records[id]
}
