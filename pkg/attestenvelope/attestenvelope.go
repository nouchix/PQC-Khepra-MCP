package attestenvelope

import (
	"encoding/json"
	"fmt"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"
)

type EnvelopeHeader struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

func Marshal(env any) ([]byte, error) {
	return json.Marshal(env)
}

func Unmarshal(data []byte, env any) error {
	return json.Unmarshal(data, env)
}

// Verify uses the kernelports.Signer to verify the signature on a digest.
func Verify(digest, sig []byte, pubKey []byte, signer kernelports.Signer) bool {
	if signer == nil {
		return false
	}
	ok, err := signer.Verify(pubKey, digest, sig)
	if err != nil {
		return false
	}
	return ok
}

// Sign uses the kernelports.Signer to sign a digest.
func Sign(digest []byte, privKey []byte, signer kernelports.Signer) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("no signer provided")
	}
	return signer.Sign(privKey, digest)
}

// AdinkraSigner implements kernelports.Signer over ML-DSA (adinkra).
// Parameter order MUST match the interface — Sign(privKey, digest) — every
// caller passes positionally. The previous (data, privateKey) ordering
// silently used the 32-byte digest as the signing key.
type AdinkraSigner struct{}

func (s AdinkraSigner) Sign(privateKey []byte, digest []byte) ([]byte, error) {
	return adinkra.Sign(privateKey, digest)
}

func (s AdinkraSigner) Verify(publicKey []byte, data []byte, signature []byte) (bool, error) {
	return adinkra.Verify(publicKey, data, signature)
}
