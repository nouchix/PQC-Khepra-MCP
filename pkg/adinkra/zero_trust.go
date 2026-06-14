package adinkra

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// =============================================================================
// ZERO TRUST CONTINUOUS AUTHENTICATION TOKENS
// Patent §3.5: 15-minute TTL tokens with HMAC-SHA512 using k_auth.
// Tokens bind AgentID, Symbol, TrustScore, and a random nonce together.
// Verification is constant-time to prevent timing side-channels.
// =============================================================================

const (
	// ZTTokenTTL is the default token lifetime (15 minutes per patent §3.5).
	ZTTokenTTL = 15 * time.Minute

	// ztNonceSize is the random nonce length in bytes.
	ztNonceSize = 32
)

// ZeroTrustToken is a short-lived continuous authentication credential.
type ZeroTrustToken struct {
	AgentID    string  // Identifier of the authenticated agent
	Symbol     string  // Adinkra symbol binding
	TrustScore float64 // Behavioural trust score [0.0, 1.0]
	IssuedAt   int64   // Unix timestamp (nanoseconds)
	ExpiresAt  int64   // Unix timestamp (nanoseconds)
	Nonce      []byte  // 32-byte cryptographic nonce
	MAC        []byte  // HMAC-SHA512 over canonical fields using k_auth
}

// IssueZeroTrustToken creates and signs a new 15-minute token.
// kAuth is the 32-byte authentication key from KHEPRA-KDF.
func IssueZeroTrustToken(agentID, symbol string, trustScore float64, kAuth []byte) (*ZeroTrustToken, error) {
	return issueTokenWithTTL(agentID, symbol, trustScore, kAuth, ZTTokenTTL)
}

// IssueZeroTrustTokenWithTTL creates a token with a custom TTL.
func IssueZeroTrustTokenWithTTL(agentID, symbol string, trustScore float64, kAuth []byte, ttl time.Duration) (*ZeroTrustToken, error) {
	return issueTokenWithTTL(agentID, symbol, trustScore, kAuth, ttl)
}

func issueTokenWithTTL(agentID, symbol string, trustScore float64, kAuth []byte, ttl time.Duration) (*ZeroTrustToken, error) {
	if agentID == "" {
		return nil, errors.New("ZeroTrustToken: agentID cannot be empty")
	}
	if len(kAuth) < 32 {
		return nil, errors.New("ZeroTrustToken: kAuth must be at least 32 bytes")
	}
	if trustScore < 0 || trustScore > 1.0 {
		return nil, errors.New("ZeroTrustToken: trustScore must be in [0.0, 1.0]")
	}

	nonce := make([]byte, ztNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("ZeroTrustToken: nonce generation failed: %w", err)
	}

	now := time.Now().UnixNano()
	exp := now + ttl.Nanoseconds()

	token := &ZeroTrustToken{
		AgentID:    agentID,
		Symbol:     symbol,
		TrustScore: trustScore,
		IssuedAt:   now,
		ExpiresAt:  exp,
		Nonce:      nonce,
	}

	mac, err := computeTokenMAC(token, kAuth)
	if err != nil {
		return nil, fmt.Errorf("ZeroTrustToken: MAC computation failed: %w", err)
	}
	token.MAC = mac

	AuditSensitiveOperation(fmt.Sprintf("ZeroTrustToken:Issue:%s:%s", agentID, symbol), true)
	return token, nil
}

// VerifyZeroTrustToken checks the MAC and expiry of a token.
func VerifyZeroTrustToken(token *ZeroTrustToken, kAuth []byte) error {
	if token == nil {
		return errors.New("ZeroTrustToken: token is nil")
	}
	if len(kAuth) < 32 {
		return errors.New("ZeroTrustToken: kAuth must be at least 32 bytes")
	}

	if time.Now().UnixNano() > token.ExpiresAt {
		return errors.New("ZeroTrustToken: token expired")
	}

	expected, err := computeTokenMAC(token, kAuth)
	if err != nil {
		return fmt.Errorf("ZeroTrustToken: MAC recomputation failed: %w", err)
	}

	if !hmac.Equal(expected, token.MAC) {
		AuditSensitiveOperation(fmt.Sprintf("ZeroTrustToken:VerifyFailed:%s", token.AgentID), false)
		return errors.New("ZeroTrustToken: MAC verification failed — token tampered or wrong key")
	}

	return nil
}

// RefreshToken issues a new token from a valid old one with an updated trust score.
func RefreshToken(old *ZeroTrustToken, kAuth []byte, newTrustScore float64) (*ZeroTrustToken, error) {
	if err := VerifyZeroTrustToken(old, kAuth); err != nil {
		return nil, fmt.Errorf("RefreshToken: cannot refresh invalid token: %w", err)
	}
	return IssueZeroTrustToken(old.AgentID, old.Symbol, newTrustScore, kAuth)
}

// IsExpired returns true if the token's expiry has passed.
func (t *ZeroTrustToken) IsExpired() bool {
	return time.Now().UnixNano() > t.ExpiresAt
}

// SecondsUntilExpiry returns the remaining lifetime in seconds (negative if expired).
func (t *ZeroTrustToken) SecondsUntilExpiry() int64 {
	remaining := t.ExpiresAt - time.Now().UnixNano()
	return remaining / int64(time.Second)
}

// =============================================================================
// INTERNAL
// =============================================================================

// computeTokenMAC builds HMAC-SHA512 over the canonical token fields.
// Format: agentID NUL symbol NUL trustScore(8LE) issuedAt(8LE) expiresAt(8LE) nonce
func computeTokenMAC(t *ZeroTrustToken, kAuth []byte) ([]byte, error) {
	mac := hmac.New(sha512.New, kAuth[:32])

	mac.Write([]byte(t.AgentID))
	mac.Write([]byte{0})
	mac.Write([]byte(t.Symbol))
	mac.Write([]byte{0})

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(t.TrustScore))
	mac.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], uint64(t.IssuedAt))
	mac.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], uint64(t.ExpiresAt))
	mac.Write(buf[:])

	mac.Write(t.Nonce)

	return mac.Sum(nil), nil
}
