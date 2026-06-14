// pkg/kms/argon2.go — Argon2id KDF parameters for ASAF key derivation
//
// Replaces the legacy PBKDF2-SHA512 call in root.go.
// Argon2id is the OWASP 2024 and NIST SP 800-63B recommended KDF.
// It is memory-hard: each guess requires 64MB RAM, making GPU/ASIC
// brute-force attacks economically infeasible at current hardware prices.
//
// ~300ms on a single modern core — acceptable for key derivation,
// prohibitive for offline GPU brute-force (~100 guesses/sec vs millions/sec
// with PBKDF2-SHA512).

package kms

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams defines the key derivation parameters.
// All fields are exported to allow audit logging and future version detection.
type Argon2idParams struct {
	Time    uint32 // number of passes over memory
	Memory  uint32 // KiB of memory to use
	Threads uint8  // degree of parallelism
	KeyLen  uint32 // output key length in bytes
}

// DefaultKDFParams meets OWASP 2024 Argon2id recommendations:
// - Time=3 (iterations), Memory=64MiB, Parallelism=4, KeyLen=96 bytes
//
// The 96-byte output is split into three 32-byte AES-256 keys for the
// triple-encryption layers in kms.tripleEncryptAndSeal.
//
// KDFVersion is embedded in sealed artifacts so future upgrades to these
// parameters can detect and handle legacy-sealed keys correctly.
const KDFVersion = "argon2id-v1"

var DefaultKDFParams = Argon2idParams{
	Time:    3,
	Memory:  64 * 1024, // 64 MiB — forces 64MB RAM per guess, kills GPU parallelism
	Threads: 4,
	KeyLen:  96, // 3 × 32-byte keys: enc + auth + audit layer
}

// DeriveKey derives KeyLen bytes from password and salt using Argon2id.
// This is the canonical KDF for all ASAF key material derivation.
//
// Callers must treat the output as a key — zero it after use where possible.
func DeriveKey(password, salt []byte, p Argon2idParams) []byte {
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

// NewSalt generates a cryptographically random 32-byte salt.
// A new salt must be generated for every key derivation operation.
func NewSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}
