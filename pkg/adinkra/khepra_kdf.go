package adinkra

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// =============================================================================
// KHEPRA-KDF: Symbol-Keyed Session Key Derivation
// Patent §3.2 QKE Phase 3: derives three context-specific keys from a shared
// secret, cryptographically binding them to the Adinkra symbol semantics and
// the session transcript.
//
//	k_enc  — AES-256-GCM encryption key
//	k_auth — HMAC-SHA512 authentication key (used by ZeroTrustToken)
//	k_audit — DAG signing context key (used by DAGConsensus)
// =============================================================================

// KHEPRASessionKeys holds the three derived keys and metadata.
type KHEPRASessionKeys struct {
	KEnc       []byte // 32-byte AES-256-GCM encryption key
	KAuth      []byte // 32-byte HMAC-SHA512 authentication key
	KAudit     []byte // 32-byte DAG signing context key
	SymbolA    string
	SymbolB    string
	Transcript []byte
}

// Domain separation tags (patent §3.2 §3.5).
var (
	domainEnc   = []byte("KHEPRA-KDF-ENC-V1")
	domainAuth  = []byte("KHEPRA-KDF-AUTH-V1")
	domainAudit = []byte("KHEPRA-KDF-AUDIT-V1")
)

// DeriveKHEPRASessionKeys derives (k_enc, k_auth, k_audit) from a Kyber/ECDH shared secret.
//
// Algorithm:
//  1. base = sharedSecret || spectralFP(symbolA) || spectralFP(symbolB) || len(transcript) || transcript
//  2. k_enc   = BLAKE2b-512(domainEnc   || base)[0:32]
//  3. k_auth  = BLAKE2b-512(domainAuth  || base)[0:32]
//  4. k_audit = BLAKE2b-512(domainAudit || base)[0:32]
func DeriveKHEPRASessionKeys(sharedSecret []byte, symbolA, symbolB string, transcript []byte) (*KHEPRASessionKeys, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("KHEPRA-KDF: shared secret cannot be empty")
	}

	fpA := GetSpectralFingerprint(symbolA)
	fpB := GetSpectralFingerprint(symbolB)

	// Build the base input once.
	base := buildKDFBase(sharedSecret, fpA, fpB, transcript)

	kEnc, err := blake2bDerive(domainEnc, base)
	if err != nil {
		return nil, fmt.Errorf("KHEPRA-KDF enc derivation: %w", err)
	}

	kAuth, err := blake2bDerive(domainAuth, base)
	if err != nil {
		return nil, fmt.Errorf("KHEPRA-KDF auth derivation: %w", err)
	}

	kAudit, err := blake2bDerive(domainAudit, base)
	if err != nil {
		return nil, fmt.Errorf("KHEPRA-KDF audit derivation: %w", err)
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

// buildKDFBase constructs the canonical input for the KDF.
// Format: sharedSecret || fpA || fpB || uint32(len(transcript)) || transcript
func buildKDFBase(sharedSecret, fpA, fpB, transcript []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(transcript)))

	total := len(sharedSecret) + len(fpA) + len(fpB) + 4 + len(transcript)
	base := make([]byte, 0, total)
	base = append(base, sharedSecret...)
	base = append(base, fpA...)
	base = append(base, fpB...)
	base = append(base, lenBuf[:]...)
	base = append(base, transcript...)
	return base
}

// blake2bDerive produces a 32-byte key using BLAKE2b-512 keyed with the domain tag.
func blake2bDerive(domain, base []byte) ([]byte, error) {
	// BLAKE2b supports a key up to 64 bytes; we use a fixed-length domain tag.
	key := make([]byte, 32)
	copy(key, domain) // zero-padded if domain < 32 bytes

	h, err := blake2b.New512(key)
	if err != nil {
		return nil, err
	}
	h.Write(base)
	digest := h.Sum(nil) // 64 bytes
	return digest[:32], nil
}

// SecureDestroySessionKeys zeroes all key material.
func (sk *KHEPRASessionKeys) SecureDestroySessionKeys() {
	SecureZeroMemory(sk.KEnc)
	SecureZeroMemory(sk.KAuth)
	SecureZeroMemory(sk.KAudit)
	sk.KEnc = nil
	sk.KAuth = nil
	sk.KAudit = nil
}
