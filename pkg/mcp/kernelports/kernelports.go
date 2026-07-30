// Package kernelports provides the default signing configuration used by
// manifest-gen and other build-time utilities. Enterprise builds inject a
// real ML-DSA-65 signer via Config; the OSS default uses HMAC-SHA256.
package kernelports

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Signer abstracts the manifest signing operation.
type Signer interface {
	Sign(key, payload []byte) ([]byte, error)
}

// Config holds kernel port defaults for a build target.
type Config struct {
	Signer Signer
}

// hmacSigner is the default OSS signer using HMAC-SHA256.
type hmacSigner struct{}

func (hmacSigner) Sign(key, payload []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

// Defaults returns a Config with the OSS default signer.
// Enterprise/sovereign builds should replace Signer with an ML-DSA-65 backend.
func Defaults() Config {
	return Config{Signer: hmacSigner{}}
}
