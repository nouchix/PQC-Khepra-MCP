package adinkra

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// SecureCommand wraps a command payload with replay protection and integrity metadata.
type SecureCommand struct {
	Command   string    `json:"command"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     string    `json:"nonce"`      // Cryptographically random
	ExpiresAt time.Time `json:"expires_at"` // Max 5 minutes validity
	Signature string    `json:"signature"`  // Signs ALL above fields (Adinkra/Dilithium)
	SenderID  string    `json:"sender_id"`  // Public Key ID or User ID
}

// NewSecureCommand creates a wrapper for a raw command string
func NewSecureCommand(cmd string, ttl time.Duration, senderID string) (*SecureCommand, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}

	now := time.Now()
	return &SecureCommand{
		Command:   cmd,
		Timestamp: now,
		Nonce:     hex.EncodeToString(nonceBytes),
		ExpiresAt: now.Add(ttl),
		SenderID:  senderID,
	}, nil
}

// Bytes returns the canonical byte representation for signing
func (sc *SecureCommand) Bytes() []byte {
	// We use JSON marshalling of a struct *without* the signature to create the payload to sign
	type Payload struct {
		Command   string    `json:"command"`
		Timestamp time.Time `json:"timestamp"`
		Nonce     string    `json:"nonce"`
		ExpiresAt time.Time `json:"expires_at"`
		SenderID  string    `json:"sender_id"`
	}

	p := Payload{
		Command:   sc.Command,
		Timestamp: sc.Timestamp,
		Nonce:     sc.Nonce,
		ExpiresAt: sc.ExpiresAt,
		SenderID:  sc.SenderID,
	}

	data, _ := json.Marshal(p)
	return data
}

var (
	ErrCommandExpired   = errors.New("command expired")
	ErrReplayAttack     = errors.New("nonce reused (replay attack detected)")
	ErrInvalidSignature = errors.New("invalid signature")
)
