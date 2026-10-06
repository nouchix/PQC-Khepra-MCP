package license

import (
	"errors"
	"fmt"

	"github.com/nouchix/khepra-pqc/sign"
)

// License signatures.
//
// License roots, issuing authorities and device identities are ML-DSA-87
// (FIPS 204) keys in 32-byte seed form. Each kind of signed object has its
// own FIPS 204 context, so a signature over one can never be replayed as
// another.
//
// The root pinned before the ML-DSA-87 root ceremony is an ML-DSA-65 key that
// signed with an empty context. verifyWithRoot still accepts it so licenses
// already issued keep verifying until the new root replaces it. Nothing in
// this package signs with ML-DSA-65.
var (
	licenseContext    = sign.ContextLicense
	revocationContext = mustLabel(sign.ContextLicense, "revocation")
	capsuleContext    = mustLabel(sign.ContextLicense, "capsule")
	deviceContext     = mustLabel(sign.ContextLicense, "device")
)

// legacyMLDSA65PublicKeySize is the size of the historical ML-DSA-65 root.
const legacyMLDSA65PublicKeySize = 1952

// legacyMLDSA65PrivateKeySize is the expanded ML-DSA-65 private key size
// written by the old tooling. Those keys can no longer sign.
const legacyMLDSA65PrivateKeySize = 4032

// errRetiredSigningKey is returned when a caller passes an old expanded
// ML-DSA-65 private key.
var errRetiredSigningKey = errors.New("license: ML-DSA-65 signing keys are retired; sign with an ML-DSA-87 key (32-byte seed)")

func mustLabel(ctx sign.Context, label string) sign.Context {
	c, err := ctx.WithLabel(label)
	if err != nil {
		panic(err)
	}
	return c
}

// signWith signs message with an ML-DSA-87 seed under ctx.
func signWith(ctx sign.Context, privateKey, message []byte) ([]byte, error) {
	if len(privateKey) == legacyMLDSA65PrivateKeySize {
		return nil, errRetiredSigningKey
	}
	sk, err := sign.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("license: signing key: %w", err)
	}
	sig, err := sk.Sign(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("license: sign: %w", err)
	}
	return sig, nil
}

// verifyWithRoot verifies a signature made by a pinned root or authority:
// ML-DSA-87 under ctx, or the historical ML-DSA-65 root with an empty
// context.
func verifyWithRoot(ctx sign.Context, publicKey, message, signature []byte) error {
	switch len(publicKey) {
	case sign.PublicKeySize:
		pk, err := sign.NewPublicKey(publicKey)
		if err != nil {
			return fmt.Errorf("license: public key: %w", err)
		}
		return pk.Verify(ctx, message, signature)
	case legacyMLDSA65PublicKeySize:
		return sign.VerifyMLDSA65(publicKey, "", message, signature)
	}
	return fmt.Errorf("license: public key is %d bytes, want %d (ML-DSA-87) or %d (historical ML-DSA-65 root)",
		len(publicKey), sign.PublicKeySize, legacyMLDSA65PublicKeySize)
}

// verifyDevice verifies a device signature. Device keys are always ML-DSA-87.
func verifyDevice(publicKey, message, signature []byte) error {
	pk, err := sign.NewPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("license: device public key: %w", err)
	}
	return pk.Verify(deviceContext, message, signature)
}

// SignLicenseBytes signs a license payload with an ML-DSA-87 authority key
// (32-byte seed) under the license context. Issuing tools use it so their
// output verifies with VerifySovereignLicense, Verify and the signed-license
// file loader.
func SignLicenseBytes(privateKey, payload []byte) ([]byte, error) {
	return signWith(licenseContext, privateKey, payload)
}

// AuthorityPublicKey returns the ML-DSA-87 public key for an authority's
// 32-byte seed.
func AuthorityPublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) == legacyMLDSA65PrivateKeySize {
		return nil, errRetiredSigningKey
	}
	sk, err := sign.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("license: authority key: %w", err)
	}
	return sk.PublicKey().Bytes(), nil
}

// LoadOrCreateDeviceKey returns this machine's hex ML-DSA-87 device key
// (KHEPRA_LICENSE_KEY, then ~/.khepra/license.key, else a new key saved there
// with mode 0600).
func LoadOrCreateDeviceKey() (string, error) {
	return loadOrGenerateKey()
}

// SignDeviceMessage signs a license server call as the device: operation,
// machine ID and Unix time, under the device context.
func SignDeviceMessage(privateKey []byte, operation, machineID string, unixSeconds int64) ([]byte, error) {
	return signWith(deviceContext, privateKey, deviceMessage(operation, machineID, unixSeconds))
}

// VerifyRootSignature verifies a license-context signature made by a pinned
// root (see verifyWithRoot).
func VerifyRootSignature(publicKey, message, signature []byte) error {
	return verifyWithRoot(licenseContext, publicKey, message, signature)
}
