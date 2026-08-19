package attestenvelope

import (
	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"encoding/json"
	"fmt"

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


type AdinkraSigner struct{}

func (s AdinkraSigner) Sign(data []byte, privateKey []byte) ([]byte, error) {
	return adinkra.Sign(privateKey, data)
}

func (s AdinkraSigner) Verify(publicKey []byte, data []byte, signature []byte) (bool, error) {
	return adinkra.Verify(publicKey, data, signature)
}
