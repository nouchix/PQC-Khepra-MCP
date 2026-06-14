package adinkra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/blake2b"
)

// ============================================================================
// KHEPRA HYBRID CRYPTOGRAPHY ENGINE
// Triple-Layer Defense: Khepra-PQC + CRYSTALS (Dilithium/Kyber) + Classical (ECDSA/ECDH)
// ============================================================================

const (
	ErrDilithiumKeygen = "dilithium keygen failed: %w"

	// Adinkhepra-PQC Parameters (Proprietary NIST ML-DSA layer)
	AdinkhepraPQCSecurityLevel = 256
	AdinkhepraPQCModulus       = 8380417
	AdinkhepraLatticeRank      = 8
	AdinkhepraPQCSignatureSize = 3309 // Matches ML-DSA-65

	// CRYSTALS-Dilithium3 (NIST ML-DSA)
	DilithiumPublicKeySize  = 1952
	DilithiumPrivateKeySize = 4000
	DilithiumSignatureSize  = 3293

	// CRYSTALS-Kyber1024 (NIST ML-KEM)
	KyberPublicKeySize    = 1568
	KyberPrivateKeySize   = 3168
	KyberCiphertextSize   = 1568
	KyberSharedSecretSize = 32

	// Classical Algorithms
	ECDSACurve           = "P-384"
	ECDHSharedSecretSize = 48

	// Hybrid Envelope Structure
	EnvelopeVersion = 2
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// HybridKeyPair represents the complete key bundle for all three layers
type HybridKeyPair struct {
	// Layer 1: Adinkhepra-PQC (Proprietary NIST ML-DSA layer)
	AdinkhepraPQCPublic  *AdinkhepraPQCPublicKey
	AdinkhepraPQCPrivate *AdinkhepraPQCPrivateKey

	// Layer 2: CRYSTALS (NIST Standardized)
	DilithiumPublic  []byte
	DilithiumPrivate []byte
	KyberPublic      []byte
	KyberPrivate     []byte

	// Layer 3: Classical (Fallback/Compatibility)
	ECDSAPublic  *ecdsa.PublicKey
	ECDSAPrivate *ecdsa.PrivateKey

	// Metadata
	Symbol     string
	KeyID      string
	Created    time.Time
	Purpose    string
	Expiration time.Time
}

// SecureEnvelope - The encrypted + signed artifact container
type SecureEnvelope struct {
	Version   int
	Timestamp int64

	// Triple-Layer Signatures (concatenated)
	SignatureKhepra    []byte
	SignatureDilithium []byte
	SignatureECDSA     []byte

	// Triple-Layer Encryption
	EncryptedData   []byte
	KyberCiphertext []byte // Encrypted session key
	ECDHCiphertext  []byte // Backup encrypted session key

	// Key Identifiers
	SignerKeyID    string
	RecipientKeyID string

	// Integrity
	Blake2bHash [64]byte
}

// ============================================================================
// KEY GENERATION (Entropy-Hardened)
// ============================================================================

func GenerateHybridKeyPair(purpose string, symbol string, expirationMonths int) (*HybridKeyPair, error) {
	entropy := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return nil, fmt.Errorf("FATAL: insufficient entropy for key generation: %w", err)
	}

	if !verifyEntropyQuality(entropy) {
		return nil, errors.New("FATAL: entropy failed quality check")
	}

	keyPair := &HybridKeyPair{
		KeyID:      generateKeyID(entropy),
		Created:    time.Now(),
		Purpose:    purpose,
		Expiration: time.Now().AddDate(0, expirationMonths, 0),
		Symbol:     symbol,
	}

	kPub, kPriv, err := GenerateAdinkhepraPQCKeyPair(entropy[:32], symbol)
	if err != nil {
		return nil, fmt.Errorf("adinkhepra-pqc keygen failed: %w", err)
	}
	keyPair.AdinkhepraPQCPublic = kPub
	keyPair.AdinkhepraPQCPrivate = kPriv

	dPub, dPriv, err := generateDilithiumKeys(entropy[32:])
	if err != nil {
		return nil, fmt.Errorf(ErrDilithiumKeygen, err)
	}
	keyPair.DilithiumPublic = dPub
	keyPair.DilithiumPrivate = dPriv

	kyPub, kyPriv, err := generateKyberKeys(entropy)
	if err != nil {
		return nil, fmt.Errorf("kyber keygen failed: %w", err)
	}
	keyPair.KyberPublic = kyPub
	keyPair.KyberPrivate = kyPriv

	ecPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa keygen failed: %w", err)
	}
	keyPair.ECDSAPrivate = ecPriv
	keyPair.ECDSAPublic = &ecPriv.PublicKey

	return keyPair, nil
}

func GenerateHybridKeyPairFromSeed(seed []byte, purpose string, symbol string) (*HybridKeyPair, error) {
	if len(seed) < 64 {
		return nil, errors.New("seed too short (must be 64 bytes)")
	}

	keyPair := &HybridKeyPair{
		KeyID:      generateKeyID(seed),
		Created:    time.Now(),
		Purpose:    purpose,
		Expiration: time.Now().AddDate(99, 0, 0),
		Symbol:     symbol,
	}

	kPub, kPriv, err := GenerateAdinkhepraPQCKeyPair(seed[:32], symbol)
	if err != nil {
		return nil, fmt.Errorf("adinkhepra-pqc keygen failed: %w", err)
	}
	keyPair.AdinkhepraPQCPublic = kPub
	keyPair.AdinkhepraPQCPrivate = kPriv

	dPub, dPriv, err := generateDilithiumKeys(seed[32:])
	if err != nil {
		return nil, fmt.Errorf(ErrDilithiumKeygen, err)
	}
	keyPair.DilithiumPublic = dPub
	keyPair.DilithiumPrivate = dPriv

	kyberSeed := make([]byte, 64)
	copy(kyberSeed, seed)
	for i, b := range []byte("KYBER-KEYGEN") {
		if i < len(kyberSeed) {
			kyberSeed[i] ^= b
		}
	}
	kyPub, kyPriv, err := generateKyberKeys(kyberSeed)
	if err != nil {
		return nil, fmt.Errorf("kyber keygen failed: %w", err)
	}
	keyPair.KyberPublic = kyPub
	keyPair.KyberPrivate = kyPriv

	ecdsaSeed := make([]byte, 64)
	copy(ecdsaSeed, seed)
	for i, b := range []byte("ECDSA-KEYGEN") {
		if i < len(ecdsaSeed) {
			ecdsaSeed[i] ^= b
		}
	}
	ecPriv, err := deterministicECDSAPrivateKeyFromSeed(ecdsaSeed)
	if err != nil {
		return nil, fmt.Errorf("ecdsa keygen failed: %w", err)
	}
	keyPair.ECDSAPrivate = ecPriv
	keyPair.ECDSAPublic = &ecPriv.PublicKey

	return keyPair, nil
}

// ============================================================================
// TRIPLE-LAYER SIGNING
// ============================================================================

func (kp *HybridKeyPair) SignArtifact(data []byte) (*SecureEnvelope, error) {
	if kp.isExpired() {
		return nil, errors.New("key pair expired")
	}

	msgHash := computeCanonicalHash(data, "KHEPRA-ARTIFACT-V2")

	envelope := &SecureEnvelope{
		Version:     EnvelopeVersion,
		Timestamp:   time.Now().Unix(),
		SignerKeyID: kp.KeyID,
	}

	adinkhepraSlg, err := SignAdinkhepraPQC(kp.AdinkhepraPQCPrivate, msgHash)
	if err != nil {
		return nil, fmt.Errorf("adinkhepra-pqc signing failed: %w", err)
	}
	envelope.SignatureKhepra = adinkhepraSlg

	dilithiumSig, err := signDilithium(kp.DilithiumPrivate, msgHash)
	if err != nil {
		return nil, fmt.Errorf("dilithium signing failed: %w", err)
	}
	envelope.SignatureDilithium = dilithiumSig

	ecdsaSig, err := signECDSA(kp.ECDSAPrivate, msgHash)
	if err != nil {
		return nil, fmt.Errorf("ecdsa signing failed: %w", err)
	}
	envelope.SignatureECDSA = ecdsaSig

	envelope.EncryptedData = data
	envelope.Blake2bHash = computeBlake2bHash(envelope)

	return envelope, nil
}

func VerifyArtifact(envelope *SecureEnvelope, publicKeys *HybridKeyPair) error {
	if envelope.Version != EnvelopeVersion {
		return errors.New("unsupported envelope version")
	}

	expectedHash := computeBlake2bHash(envelope)
	if envelope.Blake2bHash != expectedHash {
		return errors.New("envelope integrity check failed")
	}

	msgHash := computeCanonicalHash(envelope.EncryptedData, "KHEPRA-ARTIFACT-V2")

	if err := VerifyAdinkhepraPQC(publicKeys.AdinkhepraPQCPublic, msgHash, envelope.SignatureKhepra); err != nil {
		return fmt.Errorf("adinkhepra-pqc verification failed: %w", err)
	}

	if err := verifyDilithium(publicKeys.DilithiumPublic, msgHash, envelope.SignatureDilithium); err != nil {
		return fmt.Errorf("dilithium verification failed: %w", err)
	}

	if err := verifyECDSA(publicKeys.ECDSAPublic, msgHash, envelope.SignatureECDSA); err != nil {
		return fmt.Errorf("ecdsa verification failed: %w", err)
	}

	return nil
}

// ============================================================================
// TRIPLE-LAYER ENCRYPTION
// ============================================================================

func EncryptForRecipient(data []byte, recipientKeys *HybridKeyPair) (*SecureEnvelope, error) {
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, err
	}

	envelope := &SecureEnvelope{
		Version:        EnvelopeVersion,
		Timestamp:      time.Now().Unix(),
		RecipientKeyID: recipientKeys.KeyID,
	}

	kyberCiphertext, err := encryptKyber(recipientKeys.KyberPublic, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("kyber encryption failed: %w", err)
	}
	envelope.KyberCiphertext = kyberCiphertext

	ecdhCiphertext, err := encryptECDH(recipientKeys.ECDSAPublic, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh encryption failed: %w", err)
	}
	envelope.ECDHCiphertext = ecdhCiphertext

	encryptedData, err := encryptAESGCM(sessionKey, data)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm encryption failed: %w", err)
	}
	envelope.EncryptedData = encryptedData

	envelope.Blake2bHash = computeBlake2bHash(envelope)

	return envelope, nil
}

func DecryptEnvelope(envelope *SecureEnvelope, recipientKeys *HybridKeyPair) ([]byte, error) {
	sessionKey, err := decryptKyber(recipientKeys.KyberPrivate, envelope.KyberCiphertext)
	if err != nil {
		sessionKey, err = decryptECDH(recipientKeys.ECDSAPrivate, envelope.ECDHCiphertext)
		if err != nil {
			return nil, errors.New("failed to decrypt session key with both Kyber and ECDH")
		}
	}

	plaintext, err := decryptAESGCM(sessionKey, envelope.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func verifyEntropyQuality(entropy []byte) bool {
	ones := 0
	for _, b := range entropy {
		for i := 0; i < 8; i++ {
			if b&(1<<i) != 0 {
				ones++
			}
		}
	}
	ratio := float64(ones) / float64(len(entropy)*8)
	return ratio > 0.4 && ratio < 0.6
}

func generateKeyID(entropy []byte) string {
	hash := sha512.Sum512(entropy)
	return fmt.Sprintf("KHEPRA-%X", hash[:8])
}

func computeCanonicalHash(data []byte, domain string) []byte {
	hasher, _ := blake2b.New512(nil)
	hasher.Write([]byte(domain))
	hasher.Write(data)
	return hasher.Sum(nil)
}

func computeBlake2bHash(envelope *SecureEnvelope) [64]byte {
	hasher, _ := blake2b.New512(nil)
	binary.Write(hasher, binary.BigEndian, int64(envelope.Version))
	binary.Write(hasher, binary.BigEndian, envelope.Timestamp)
	hasher.Write(envelope.SignatureKhepra)
	hasher.Write(envelope.SignatureDilithium)
	hasher.Write(envelope.SignatureECDSA)
	hasher.Write(envelope.EncryptedData)
	var hash [64]byte
	copy(hash[:], hasher.Sum(nil))
	return hash
}

func (kp *HybridKeyPair) isExpired() bool {
	return time.Now().After(kp.Expiration)
}

func deterministicECDSAPrivateKeyFromSeed(seed []byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P384()
	n := curve.Params().N
	var d *big.Int
	for ctr := uint32(0); ctr < 1000; ctr++ {
		combined := append(seed, byte(ctr>>24), byte(ctr>>16), byte(ctr>>8), byte(ctr))
		h := sha512.Sum512(combined)
		d = new(big.Int).SetBytes(h[:])
		d.Mod(d, n)
		if d.Sign() != 0 {
			break
		}
	}

	if d == nil || d.Sign() == 0 {
		return nil, errors.New("failed to derive ECDSA private scalar")
	}

	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = curve
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return priv, nil
}

func generateDilithiumKeys(seed []byte) ([]byte, []byte, error) {
	if len(seed) < 8 {
		return nil, nil, errors.New("insufficient seed length")
	}
	chaos := NewChaosEngine(binary.BigEndian.Uint64(seed[:8]))
	pub, priv, err := mode3.GenerateKey(chaos)
	if err != nil {
		return nil, nil, err
	}
	return pub.Bytes(), priv.Bytes(), nil
}

func signDilithium(priv, msgHash []byte) ([]byte, error) {
	var buf [mode3.PrivateKeySize]byte
	copy(buf[:], priv)
	sk := &mode3.PrivateKey{}
	sk.Unpack(&buf)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, msgHash, sig)
	return sig, nil
}

func verifyDilithium(pub, msgHash, signature []byte) error {
	var buf [mode3.PublicKeySize]byte
	copy(buf[:], pub)
	pk := &mode3.PublicKey{}
	pk.Unpack(&buf)
	if !mode3.Verify(pk, msgHash, signature) {
		return errors.New("dilithium signature invalid")
	}
	return nil
}

func generateKyberKeys(seed []byte) ([]byte, []byte, error) {
	if len(seed) < 8 {
		return nil, nil, errors.New("insufficient seed length")
	}
	chaos := NewChaosEngine(binary.BigEndian.Uint64(seed[:8]))
	kyberseed := make([]byte, 64)
	chaos.Read(kyberseed)
	pub, priv := kyber1024.NewKeyFromSeed(kyberseed)
	pubBuf := make([]byte, kyber1024.PublicKeySize)
	privBuf := make([]byte, kyber1024.PrivateKeySize)
	pub.Pack(pubBuf)
	priv.Pack(privBuf)
	return pubBuf, privBuf, nil
}

func encryptKyber(pubBytes, sessionKey []byte) ([]byte, error) {
	pub := &kyber1024.PublicKey{}
	pub.Unpack(pubBytes)
	ciphertext := make([]byte, kyber1024.CiphertextSize)
	sharedSecret := make([]byte, kyber1024.SharedKeySize)
	seed := make([]byte, 32)
	io.ReadFull(rand.Reader, seed)
	pub.EncapsulateTo(ciphertext, sharedSecret, seed)
	wrappedSessionKey := make([]byte, len(sessionKey))
	for i := 0; i < len(sessionKey); i++ {
		wrappedSessionKey[i] = sessionKey[i] ^ sharedSecret[i]
	}
	return append(ciphertext, wrappedSessionKey...), nil
}

func decryptKyber(privBytes, blob []byte) ([]byte, error) {
	if len(blob) < kyber1024.CiphertextSize {
		return nil, errors.New("kyber blob too short")
	}
	ciphertext := blob[:kyber1024.CiphertextSize]
	wrappedKey := blob[kyber1024.CiphertextSize:]
	priv := &kyber1024.PrivateKey{}
	priv.Unpack(privBytes)
	sharedSecret := make([]byte, kyber1024.SharedKeySize)
	priv.DecapsulateTo(sharedSecret, ciphertext)
	sessionKey := make([]byte, len(wrappedKey))
	for i := 0; i < len(wrappedKey); i++ {
		sessionKey[i] = wrappedKey[i] ^ sharedSecret[i%len(sharedSecret)]
	}
	return sessionKey, nil
}

func signECDSA(priv *ecdsa.PrivateKey, msgHash []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, priv, msgHash)
}

func verifyECDSA(pub *ecdsa.PublicKey, msgHash, signature []byte) error {
	if !ecdsa.VerifyASN1(pub, msgHash, signature) {
		return errors.New("ecdsa signature invalid")
	}
	return nil
}

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	return EncryptAESGCM(key, plaintext)
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	return DecryptAESGCM(key, ciphertext)
}
