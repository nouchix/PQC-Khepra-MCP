package adinkra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/nouchix/khepra-pqc/envelope"
	"github.com/nouchix/khepra-pqc/kem"
	"github.com/nouchix/khepra-pqc/sign"
)

// ============================================================================
// KHEPRA HYBRID KEY BUNDLE
//
// A HybridKeyPair holds everything one identity needs:
//   - an ML-DSA-87 (FIPS 204) signing identity bound to an Adinkra symbol,
//   - an ML-KEM-1024 (FIPS 203) key for receiving encrypted envelopes,
//   - an ECDSA P-384 key used only to issue X.509 certificate signing
//     requests, because X.509 tooling does not yet accept ML-DSA. It is never
//     used for envelopes or signatures.
//
// All keys come from the Go Cryptographic Module's approved random bit
// generator. There is no deterministic or seeded key generation.
// ============================================================================

const (
	// EnvelopeVersion identifies SecureEnvelope v3: one ML-DSA-87 signature,
	// and KHQ3 (ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM) encryption.
	EnvelopeVersion = 3

	// ECDSACurve is the curve of the CSR-only classical key.
	ECDSACurve = "P-384"
)

// hybridLabel binds EncryptForRecipient envelopes to their purpose.
const hybridLabel = "khepra/v3/hybrid"

// HybridKeyPair is the key bundle for one identity.
type HybridKeyPair struct {
	// Signing identity: ML-DSA-87 bound to Symbol.
	AdinkhepraPQCPublic  *AdinkhepraPQCPublicKey
	AdinkhepraPQCPrivate *AdinkhepraPQCPrivateKey

	// Key encapsulation: ML-KEM-1024 encapsulation key and 64-byte seed.
	KEMPublic  []byte
	KEMPrivate []byte

	// CSR-only classical key (see package comment above).
	ECDSAPublic  *ecdsa.PublicKey
	ECDSAPrivate *ecdsa.PrivateKey

	// Metadata
	Symbol     string
	KeyID      string
	Created    time.Time
	Purpose    string
	Expiration time.Time
}

// SecureEnvelope is the signed or encrypted artifact container.
//
// SignArtifact fills Signature and stores the signed data in EncryptedData.
// EncryptForRecipient stores a KHQ3 envelope in EncryptedData.
type SecureEnvelope struct {
	Version   int
	Timestamp int64

	// ML-DSA-87 signature over the canonical artifact bytes (SignArtifact).
	Signature []byte

	// Signed data (SignArtifact) or KHQ3 envelope (EncryptForRecipient).
	EncryptedData []byte

	SignerKeyID    string
	RecipientKeyID string
}

// ============================================================================
// KEY GENERATION
// ============================================================================

// GenerateHybridKeyPair generates a new key bundle bound to symbol.
func GenerateHybridKeyPair(purpose string, symbol string, expirationMonths int) (*HybridKeyPair, error) {
	sigPub, sigPriv, err := GenerateAdinkhepraPQCKeyPair(symbol)
	if err != nil {
		return nil, err
	}

	dk, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("ML-KEM-1024 keygen failed: %w", err)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa keygen failed: %w", err)
	}

	now := time.Now()
	return &HybridKeyPair{
		AdinkhepraPQCPublic:  sigPub,
		AdinkhepraPQCPrivate: sigPriv,
		KEMPublic:            dk.EncapsulationKey().Bytes(),
		KEMPrivate:           dk.Bytes(),
		ECDSAPublic:          &ecPriv.PublicKey,
		ECDSAPrivate:         ecPriv,
		Symbol:               symbol,
		KeyID:                keyIDFor(sigPub.Raw),
		Created:              now,
		Purpose:              purpose,
		Expiration:           now.AddDate(0, expirationMonths, 0),
	}, nil
}

// keyIDFor derives a stable key identifier from the signing public key.
func keyIDFor(signingPub []byte) string {
	sum := sha512.Sum384(signingPub)
	return fmt.Sprintf("KHEPRA-%X", sum[:8])
}

// ============================================================================
// SIGNING
// ============================================================================

// SignArtifact signs data with the bundle's ML-DSA-87 identity under the
// khepra/v3/attest context. The signature covers the envelope version,
// timestamp and signer key ID as well as the data.
func (kp *HybridKeyPair) SignArtifact(data []byte) (*SecureEnvelope, error) {
	if kp.isExpired() {
		return nil, errors.New("key pair expired")
	}
	env := &SecureEnvelope{
		Version:       EnvelopeVersion,
		Timestamp:     time.Now().Unix(),
		SignerKeyID:   kp.KeyID,
		EncryptedData: data,
	}
	sig, err := signWithContext(kp.AdinkhepraPQCPrivate, sign.ContextAttest, artifactSignBytes(env))
	if err != nil {
		return nil, fmt.Errorf("ML-DSA-87 signing failed: %w", err)
	}
	env.Signature = sig
	return env, nil
}

// VerifyArtifact checks a SecureEnvelope produced by SignArtifact.
func VerifyArtifact(env *SecureEnvelope, publicKeys *HybridKeyPair) error {
	if env == nil || publicKeys == nil {
		return errors.New("verify artifact: nil envelope or keys")
	}
	if env.Version != EnvelopeVersion {
		return fmt.Errorf("unsupported envelope version %d", env.Version)
	}
	if err := verifyWithContext(publicKeys.AdinkhepraPQCPublic, sign.ContextAttest, artifactSignBytes(env), env.Signature); err != nil {
		return fmt.Errorf("ML-DSA-87 verification failed: %w", err)
	}
	return nil
}

// artifactSignBytes is the canonical byte string SignArtifact signs:
// version(8) ‖ timestamp(8) ‖ len(keyID)(4) ‖ keyID ‖ data.
func artifactSignBytes(env *SecureEnvelope) []byte {
	out := make([]byte, 0, 20+len(env.SignerKeyID)+len(env.EncryptedData))
	out = binary.BigEndian.AppendUint64(out, uint64(env.Version))
	out = binary.BigEndian.AppendUint64(out, uint64(env.Timestamp))
	out = binary.BigEndian.AppendUint32(out, uint32(len(env.SignerKeyID)))
	out = append(out, env.SignerKeyID...)
	return append(out, env.EncryptedData...)
}

// ============================================================================
// ENCRYPTION
// ============================================================================

// EncryptForRecipient encrypts data to the recipient's ML-KEM-1024 key using
// a KHQ3 envelope. There is no classical fallback: an envelope opens only with
// the ML-KEM decapsulation key.
func EncryptForRecipient(data []byte, recipientKeys *HybridKeyPair) (*SecureEnvelope, error) {
	ek, err := kem.NewEncapsulationKey(recipientKeys.KEMPublic)
	if err != nil {
		return nil, fmt.Errorf("recipient ML-KEM key: %w", err)
	}
	sealed, err := envelope.Seal(ek, hybridLabel, data)
	if err != nil {
		return nil, err
	}
	return &SecureEnvelope{
		Version:        EnvelopeVersion,
		Timestamp:      time.Now().Unix(),
		EncryptedData:  sealed,
		RecipientKeyID: recipientKeys.KeyID,
	}, nil
}

// DecryptEnvelope opens an envelope produced by EncryptForRecipient.
func DecryptEnvelope(env *SecureEnvelope, recipientKeys *HybridKeyPair) ([]byte, error) {
	if env == nil || recipientKeys == nil {
		return nil, errors.New("decrypt envelope: nil envelope or keys")
	}
	if env.Version != EnvelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", env.Version)
	}
	dk, err := kem.NewDecapsulationKey(recipientKeys.KEMPrivate)
	if err != nil {
		return nil, fmt.Errorf("recipient ML-KEM key: %w", err)
	}
	plaintext, err := envelope.Open(dk, hybridLabel, env.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return plaintext, nil
}

func (kp *HybridKeyPair) isExpired() bool {
	return time.Now().After(kp.Expiration)
}
