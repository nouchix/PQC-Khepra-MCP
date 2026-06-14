package adinkra

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// GenerateCSR creates a standard x.509 Certificate Signing Request (CSR)
// using the Classical (ECDSA P-384) layer of the Hybrid Key Pair.
// This allows Khepra users to interface with standard PKI (like Cloudflare mTLS).
func GenerateCSR(keyPair *HybridKeyPair, commonName, org string) ([]byte, error) {
	if keyPair.ECDSAPrivate == nil {
		return nil, fmt.Errorf("hybrid key pair missing classical ECDSA layer")
	}

	subj := pkix.Name{
		CommonName:   commonName,
		Organization: []string{org},
		Country:      []string{"XX"}, // Khepra/Adinkra Nation
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyPair.ECDSAPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	// PEM Encode
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return csrPEM, nil
}

// ExportECDSAPrivateKeyPEM exports the classical private key in standard PEM format.
// This is required for importing into browsers/OS keystores to match the CSR.
func ExportECDSAPrivateKeyPEM(keyPair *HybridKeyPair) ([]byte, error) {
	if keyPair.ECDSAPrivate == nil {
		return nil, fmt.Errorf("hybrid key pair missing classical ECDSA layer")
	}

	keyBytes, err := x509.MarshalECPrivateKey(keyPair.ECDSAPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return keyPEM, nil
}
