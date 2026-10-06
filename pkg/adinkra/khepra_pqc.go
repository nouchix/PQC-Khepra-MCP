package adinkra

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"time"

	"github.com/nouchix/khepra-pqc/sign"
)

// =============================================================================
// ADINKHEPRA-PQC: SYMBOL-BOUND ML-DSA-87 SIGNING IDENTITY
//
// An AdinkhepraPQC key is an ML-DSA-87 (FIPS 204) key pair tagged with the
// Adinkra symbol it acts under. Keys come only from the Go Cryptographic
// Module's approved random bit generator: the symbol labels a key, it never
// seeds one. Signatures use the khepra/v3/adinkra/agent context so they can
// never verify as signatures made for another purpose.
// =============================================================================

// agentContext is the FIPS 204 context for AdinkhepraPQC signatures.
var agentContext = mustContext(sign.ContextAdinkra.WithLabel("agent"))

// dagContext is the FIPS 204 context for DAG vertex signatures.
var dagContext = sign.ContextDAG

func mustContext(c sign.Context, err error) sign.Context {
	if err != nil {
		panic(err)
	}
	return c
}

// AdinkhepraPQCPublicKey is an ML-DSA-87 public key bound to a symbol.
type AdinkhepraPQCPublicKey struct {
	Raw           []byte // ML-DSA-87 public key (2592 bytes)
	Symbol        string
	SecurityLevel int // NIST security category (5 for ML-DSA-87)
}

func (k *AdinkhepraPQCPublicKey) MarshalBinary() ([]byte, error) {
	return k.Raw, nil
}

func (k *AdinkhepraPQCPublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != SigningPublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", SigningPublicKeySize, len(data))
	}
	k.Raw = append([]byte(nil), data...)
	k.SecurityLevel = 5
	return nil
}

// AdinkhepraPQCPrivateKey is an ML-DSA-87 private key in its 32-byte FIPS 204
// seed form, bound to a symbol.
type AdinkhepraPQCPrivateKey struct {
	Raw    []byte
	Symbol string
}

func (k *AdinkhepraPQCPrivateKey) MarshalBinary() ([]byte, error) {
	return k.Raw, nil
}

func (k *AdinkhepraPQCPrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != SigningPrivateKeySize {
		return fmt.Errorf("invalid private key size: expected %d, got %d", SigningPrivateKeySize, len(data))
	}
	k.Raw = append([]byte(nil), data...)
	return nil
}

// Public returns the public key that pairs with k.
func (k *AdinkhepraPQCPrivateKey) Public() (*AdinkhepraPQCPublicKey, error) {
	sk, err := sign.NewPrivateKey(k.Raw)
	if err != nil {
		return nil, err
	}
	return &AdinkhepraPQCPublicKey{Raw: sk.PublicKey().Bytes(), Symbol: k.Symbol, SecurityLevel: 5}, nil
}

// GenerateAdinkhepraPQCKeyPair generates a new ML-DSA-87 signing identity
// bound to symbol.
func GenerateAdinkhepraPQCKeyPair(symbol string) (*AdinkhepraPQCPublicKey, *AdinkhepraPQCPrivateKey, error) {
	sk, err := sign.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("adinkhepra-pqc keygen failed: %w", err)
	}
	pub := &AdinkhepraPQCPublicKey{Raw: sk.PublicKey().Bytes(), Symbol: symbol, SecurityLevel: 5}
	priv := &AdinkhepraPQCPrivateKey{Raw: sk.Bytes(), Symbol: symbol}
	return pub, priv, nil
}

// SignAdinkhepraPQC signs a message with an AdinkhepraPQC identity.
func SignAdinkhepraPQC(priv *AdinkhepraPQCPrivateKey, message []byte) ([]byte, error) {
	return signWithContext(priv, agentContext, message)
}

// VerifyAdinkhepraPQC verifies a signature made by SignAdinkhepraPQC.
func VerifyAdinkhepraPQC(pub *AdinkhepraPQCPublicKey, message []byte, signature []byte) error {
	return verifyWithContext(pub, agentContext, message, signature)
}

func signWithContext(priv *AdinkhepraPQCPrivateKey, ctx sign.Context, message []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("adinkhepra-pqc: nil private key")
	}
	sk, err := sign.NewPrivateKey(priv.Raw)
	if err != nil {
		return nil, fmt.Errorf("adinkhepra-pqc: %w", err)
	}
	return sk.Sign(ctx, message)
}

func verifyWithContext(pub *AdinkhepraPQCPublicKey, ctx sign.Context, message, signature []byte) error {
	if pub == nil {
		return errors.New("adinkhepra-pqc: nil public key")
	}
	pk, err := sign.NewPublicKey(pub.Raw)
	if err != nil {
		return fmt.Errorf("adinkhepra-pqc: %w", err)
	}
	return pk.Verify(ctx, message, signature)
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
	h := sha512.Sum384([]byte(payload))

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
	h := sha512.Sum384([]byte(payload))

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

// DestroyPrivateKey zeroizes the key seed held by priv.
func (priv *AdinkhepraPQCPrivateKey) DestroyPrivateKey() {
	if priv != nil && priv.Raw != nil {
		for i := range priv.Raw {
			priv.Raw[i] = 0
		}
		priv.Raw = nil
	}
}
