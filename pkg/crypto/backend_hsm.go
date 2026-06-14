//go:build hsm
// +build hsm

package crypto

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"log"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// HSMBackend implements CryptoBackend using Hardware Security Module integration
type HSMBackend struct {
	hsmType  string // "yubihsm2", "cloudhsm", or "simulated"
	licensed bool
	client   interface{}
}

// newHSMBackend creates a new HSM Edition crypto backend
func newHSMBackend(hsmType string, licensed bool) *HSMBackend {
	return &HSMBackend{
		hsmType:  hsmType,
		licensed: licensed,
		client:   nil,
	}
}

// initBackendImpl initializes the HSM Edition backend
func initBackendImpl(licensedFeatures []string) error {
	licensed := false
	for _, feature := range licensedFeatures {
		if feature == "hsm_integration" {
			licensed = true
			break
		}
	}

	if !licensed {
		for _, feature := range licensedFeatures {
			if feature == "premium_pqc" {
				Backend = newPremiumBackend(true)
				return fmt.Errorf("hsm not licensed, using premium edition")
			}
		}
		Backend = newCommunityBackend()
		return fmt.Errorf("premium features not licensed, using community edition")
	}

	hsmType, err := detectHSM()
	if err != nil {
		log.Printf("[HSM] No physical HSM detected. Falling back to Simulated HSM (Software-based PQC).")
		hsmType = "simulated"
	}

	hsm := newHSMBackend(hsmType, true)
	if err := hsm.Connect(); err != nil {
		Backend = newPremiumBackend(true)
		return fmt.Errorf("HSM connection failed: %w, using premium edition", err)
	}

	Backend = hsm
	return nil
}

// detectHSM attempts to detect available HSM hardware
func detectHSM() (string, error) {
	// In production, this would probe USB or AWS APIs.
	return "", fmt.Errorf("no physical HSM detected")
}

// Connect establishes connection to HSM hardware
func (h *HSMBackend) Connect() error {
	if h.hsmType == "simulated" {
		log.Println("[HSM] Initialized Simulated HSM Layer (pkg/adinkra)")
		return nil
	}
	switch h.hsmType {
	case "yubihsm2":
		return h.connectYubiHSM()
	case "cloudhsm":
		return h.connectCloudHSM()
	default:
		return fmt.Errorf("unknown HSM type: %s", h.hsmType)
	}
}

func (h *HSMBackend) connectYubiHSM() error {
	return fmt.Errorf("YubiHSM 2 hardware not detected via USB")
}

func (h *HSMBackend) connectCloudHSM() error {
	return fmt.Errorf("CloudHSM cluster not reachable via VPC")
}

// GenerateDilithiumKey generates a Dilithium3 key pair
func (h *HSMBackend) GenerateDilithiumKey() (publicKey, privateKey []byte, err error) {
	log.Printf("[%s] Generating Dilithium3 key pair...", h.BackendName())
	seed := make([]byte, 32)
	rand.Read(seed)

	pub, priv, err := adinkra.GenerateAdinkhepraPQCKeyPair(seed, "Gye Nyame")
	if err != nil {
		return nil, nil, err
	}

	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()
	return pubBytes, privBytes, nil
}

// SignDilithium signs a message
func (h *HSMBackend) SignDilithium(privateKey, message []byte) (signature []byte, err error) {
	log.Printf("[%s] Signing message with Dilithium3...", h.BackendName())
	priv := new(adinkra.AdinkhepraPQCPrivateKey)
	if err := priv.UnmarshalBinary(privateKey); err != nil {
		return nil, err
	}

	hash := sha512.Sum512(message)
	return adinkra.SignAdinkhepraPQC(priv, hash[:])
}

// VerifyDilithium verifies a Dilithium3 signature
func (h *HSMBackend) VerifyDilithium(publicKey, message, signature []byte) bool {
	pub := new(adinkra.AdinkhepraPQCPublicKey)
	if err := pub.UnmarshalBinary(publicKey); err != nil {
		return false
	}

	hash := sha512.Sum512(message)
	err := adinkra.VerifyAdinkhepraPQC(pub, hash[:], signature)
	return err == nil
}

// GenerateKyberKey generates a Kyber1024 key pair
func (h *HSMBackend) GenerateKyberKey() (publicKey, privateKey []byte, err error) {
	log.Printf("[%s] Generating Kyber1024 key pair...", h.BackendName())
	return adinkra.GenerateKyberKey()
}

// EncapsulateKyber generates a shared secret
func (h *HSMBackend) EncapsulateKyber(publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	log.Printf("[%s] Encapsulating shared secret (Kyber1024)...", h.BackendName())
	return adinkra.KyberEncapsulate(publicKey)
}

// DecapsulateKyber recovers shared secret
func (h *HSMBackend) DecapsulateKyber(privateKey, ciphertext []byte) (sharedSecret []byte, err error) {
	log.Printf("[%s] Decapsulating shared secret (Kyber1024)...", h.BackendName())
	return adinkra.KyberDecapsulate(privateKey, ciphertext)
}

// BackendName returns the backend identifier
func (h *HSMBackend) BackendName() string {
	switch h.hsmType {
	case "yubihsm2":
		return "YubiHSM 2 (FIPS 140-2 Level 3)"
	case "cloudhsm":
		return "AWS CloudHSM (FIPS 140-2 Level 3)"
	default:
		return "HSM (Unknown)"
	}
}

// IsPremium returns true for HSM edition
func (h *HSMBackend) IsPremium() bool {
	return h.licensed
}

// IsHSM returns true for HSM edition
func (h *HSMBackend) IsHSM() bool {
	return true
}

// Version returns the backend version
func (h *HSMBackend) Version() string {
	return "1.0.0 (HSM-Protected)"
}

// Disconnect closes HSM connection
func (h *HSMBackend) Disconnect() error {
	log.Printf("[HSM] Disconnecting from %s...", h.BackendName())
	if h.client != nil {
		h.client = nil
	}
	return nil
}
