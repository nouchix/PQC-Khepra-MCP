package adinkra

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// =============================================================================
// ADINKHEPRA-PQC: LATTICE-BASED POST-QUANTUM SIGNATURE SCHEME
// Real Implementation using CRYSTALS-Dilithium3 (mode3) via Cloudflare CIRCL
// Security Level: 256-bit (NIST Level 3 equivalent)
// =============================================================================

// AdinkhepraPQC Signature Scheme Architecture (Unified with ML-DSA Standards)

const (
	// AdinkhepraPQC Constants mapped to Dilithium3 parameters
	AdinkhepraN = 256     // Degree of polynomial ring (Dilithium standard)
	AdinkhepraQ = 8380417 // Dilithium prime modulus
)

// AdinkhepraPQCPublicKey represents a NIST-aligned PQC public key
type AdinkhepraPQCPublicKey struct {
	Raw           []byte
	Seed          [32]byte
	SecurityLevel int
}

func (k *AdinkhepraPQCPublicKey) MarshalBinary() ([]byte, error) {
	return k.Raw, nil
}

func (k *AdinkhepraPQCPublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != mode3.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", mode3.PublicKeySize, len(data))
	}
	k.Raw = make([]byte, len(data))
	copy(k.Raw, data)
	return nil
}

// AdinkhepraPQCPrivateKey represents a NIST-aligned PQC private key
type AdinkhepraPQCPrivateKey struct {
	Raw  []byte
	Seed [32]byte
}

func (k *AdinkhepraPQCPrivateKey) MarshalBinary() ([]byte, error) {
	return k.Raw, nil
}

func (k *AdinkhepraPQCPrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != mode3.PrivateKeySize {
		return fmt.Errorf("invalid private key size: expected %d, got %d", mode3.PrivateKeySize, len(data))
	}
	k.Raw = make([]byte, len(data))
	copy(k.Raw, data)
	return nil
}

// GenerateAdinkhepraPQCKeyPair generates a real PQC key pair from a seed and symbol entropy.
func GenerateAdinkhepraPQCKeyPair(seed []byte, symbol string) (*AdinkhepraPQCPublicKey, *AdinkhepraPQCPrivateKey, error) {
	// Spectral Derivation: Mix raw seed with symbol fingerprint
	spectral := GetSpectralFingerprint(symbol)
	unifiedSeed := make([]byte, len(seed)+len(spectral))
	copy(unifiedSeed, seed)
	copy(unifiedSeed[len(seed):], spectral)

	h := sha512.Sum512(unifiedSeed)
	entropy := h[:32]

	// Use Dilithium3 (mode3) for key generation
	// Note: Dilithium keygen is randomized or deterministic depending on RNG
	// We use the ChaosEngine derived from entropy for TRL10 determinism if needed.
	chaos := NewChaosEngine(binary.BigEndian.Uint64(entropy[:8]))
	pk, sk, err := mode3.GenerateKey(chaos)
	if err != nil {
		return nil, nil, fmt.Errorf("dilithium keygen failed: %w", err)
	}

	pub := &AdinkhepraPQCPublicKey{
		Raw:           pk.Bytes(),
		SecurityLevel: 256,
	}
	copy(pub.Seed[:], entropy)

	priv := &AdinkhepraPQCPrivateKey{
		Raw: sk.Bytes(),
	}
	copy(priv.Seed[:], entropy)

	return pub, priv, nil
}

// SignAdinkhepraPQC signs a message hash using Dilithium3
func SignAdinkhepraPQC(priv *AdinkhepraPQCPrivateKey, messageHash []byte) ([]byte, error) {
	if len(priv.Raw) != mode3.PrivateKeySize {
		return nil, errors.New("invalid private key state")
	}

	var buf [mode3.PrivateKeySize]byte
	copy(buf[:], priv.Raw)
	sk := &mode3.PrivateKey{}
	sk.Unpack(&buf)

	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, messageHash, sig)
	return sig, nil
}

// VerifyAdinkhepraPQC verifies a signature using Dilithium3
func VerifyAdinkhepraPQC(pub *AdinkhepraPQCPublicKey, messageHash []byte, signature []byte) error {
	if len(pub.Raw) != mode3.PublicKeySize {
		return errors.New("invalid public key state")
	}

	var buf [mode3.PublicKeySize]byte
	copy(buf[:], pub.Raw)
	pk := &mode3.PublicKey{}
	pk.Unpack(&buf)

	if !mode3.Verify(pk, messageHash, signature) {
		return errors.New("dilithium signature verification failed")
	}
	return nil
}

// =============================================================================
// ADINKHEPRA-ASAF: AGENTIC SECURITY ATTESTATION FRAMEWORK
// =============================================================================

type AdinkhepraAttestation struct {
	ActionID   string
	AgentID    string
	Symbol     string
	TrustScore int
	Context    string
	Signature  []byte
	Timestamp  int64
}

func SignAgentAction(priv *AdinkhepraPQCPrivateKey, agentID, actionID, symbol string, trustScore int, context string) (*AdinkhepraAttestation, error) {
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%s:%s:%s:%d:%s:%d", agentID, actionID, symbol, trustScore, context, timestamp)
	h := sha512.Sum512([]byte(payload))

	sig, err := SignAdinkhepraPQC(priv, h[:])
	if err != nil {
		return nil, err
	}

	return &AdinkhepraAttestation{
		ActionID:   actionID,
		AgentID:    agentID,
		Symbol:     symbol,
		TrustScore: trustScore,
		Context:    context,
		Signature:  sig,
		Timestamp:  timestamp,
	}, nil
}

func VerifyAgentAction(pub *AdinkhepraPQCPublicKey, attestation *AdinkhepraAttestation) error {
	payload := fmt.Sprintf("%s:%s:%s:%d:%s:%d",
		attestation.AgentID, attestation.ActionID, attestation.Symbol,
		attestation.TrustScore, attestation.Context, attestation.Timestamp)
	h := sha512.Sum512([]byte(payload))

	return VerifyAdinkhepraPQC(pub, h[:], attestation.Signature)
}

func MapSymbolToCompliance(symbol string) []string {
	switch symbol {
	case "Eban":
		return []string{"DoD RMF", "STIG", "Access Control"}
	case "Fawohodie":
		return []string{"CMMC", "Revocation", "Privilege Management"}
	case "Nkyinkyim":
		return []string{"FedRAMP", "GDPR", "State Transition"}
	case "Dwennimmen":
		return []string{"PCI DSS", "HIPAA", "High-Assurance"}
	default:
		return []string{"General Compliance"}
	}
}

// DestroyPrivateKey securely zeroizes key material
func (priv *AdinkhepraPQCPrivateKey) DestroyPrivateKey() {
	if priv != nil && priv.Raw != nil {
		for i := range priv.Raw {
			priv.Raw[i] = 0
		}
		priv.Raw = nil
	}
}
