//go:build hsm

package crypto

import (
	"errors"

	"github.com/nouchix/khepra-pqc/sign"
)

// ErrNoHSM is returned by every operation in hsm builds until a PKCS#11
// driver with ML-KEM and ML-DSA support is integrated. An hsm build never
// generates or uses software keys in place of hardware ones.
var ErrNoHSM = errors.New("crypto: hsm build has no hardware module available")

// HSMBackend is the hardware backend. It fails closed.
type HSMBackend struct{}

func initBackendImpl() error {
	Backend = HSMBackend{}
	return ErrNoHSM
}

// GenerateSigningKey fails closed.
func (HSMBackend) GenerateSigningKey() (publicKey, privateKey []byte, err error) {
	return nil, nil, ErrNoHSM
}

// Sign fails closed.
func (HSMBackend) Sign(sign.Context, []byte, []byte) ([]byte, error) {
	return nil, ErrNoHSM
}

// Verify fails closed.
func (HSMBackend) Verify(sign.Context, []byte, []byte, []byte) bool {
	return false
}

// GenerateKEMKey fails closed.
func (HSMBackend) GenerateKEMKey() (encapsulationKey, decapsulationKey []byte, err error) {
	return nil, nil, ErrNoHSM
}

// Encapsulate fails closed.
func (HSMBackend) Encapsulate([]byte) (ciphertext, sharedSecret []byte, err error) {
	return nil, nil, ErrNoHSM
}

// Decapsulate fails closed.
func (HSMBackend) Decapsulate([]byte, []byte) ([]byte, error) {
	return nil, ErrNoHSM
}

// BackendName returns the backend identifier.
func (HSMBackend) BackendName() string {
	return "HSM (unavailable)"
}

// IsHSM returns true.
func (HSMBackend) IsHSM() bool {
	return true
}

// Version returns the backend status.
func (HSMBackend) Version() string {
	return "no hardware module"
}
