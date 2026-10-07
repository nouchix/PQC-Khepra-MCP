package license

// Issuer delegation.
//
// The license root key stays offline, as Shamir shards. Day-to-day issuance
// (for example the Stripe webhook minting API keys) uses an issuer key that the
// root has delegated to with a signed IssuerCertificate. A signature verifies
// when it is made either
//
//   - by the pinned root directly, or
//   - by an issuer whose certificate is signed by the pinned root (ML-DSA-87,
//     context khepra/v3/license/issuer), is inside its validity window, names
//     the pinned root's fingerprint, and lists the purpose being verified.
//
// Certificates are public. They are compiled in from trust/issuers/*.json or
// loaded from KHEPRA_ISSUER_CERTS (a file or a directory of *.json files);
// either way each one is verified against the pinned root before use, so a
// certificate from the environment cannot widen trust.

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nouchix/khepra-pqc/sign"
)

// Purposes an issuer can be delegated.
const (
	PurposeAPIKey  = "apikey"
	PurposeLicense = "license"
)

// IssuerCertsEnv names a file or directory of extra issuer certificates.
const IssuerCertsEnv = "KHEPRA_ISSUER_CERTS"

var issuerCertContext = mustLabel(sign.ContextLicense, "issuer")

//go:embed trust/issuers
var embeddedIssuers embed.FS

// IssuerCertificate delegates signing for the listed purposes to an issuer key.
type IssuerCertificate struct {
	Version         int       `json:"version"`
	Serial          string    `json:"serial"`
	Purposes        []string  `json:"purposes"`
	IssuerPublicKey []byte    `json:"issuer_public_key"` // ML-DSA-87
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	RootFingerprint string    `json:"root_fingerprint"` // KeyFingerprint of the root
}

// SignedIssuerCertificate is the published form: the certificate JSON (as
// opaque bytes, so re-encoding can never change what was signed) and the
// root's signature over exactly those bytes.
type SignedIssuerCertificate struct {
	Certificate []byte `json:"certificate"`
	Signature   []byte `json:"signature"`
}

// KeyFingerprint is the hex SHA-256 of a public key.
func KeyFingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// IssueIssuerCertificate signs a delegation to issuerPublicKey with the root
// seed rootPrivate. It returns the SignedIssuerCertificate JSON.
func IssueIssuerCertificate(rootPrivate, issuerPublicKey []byte, purposes []string, notBefore, notAfter time.Time) ([]byte, error) {
	if len(issuerPublicKey) != sign.PublicKeySize {
		return nil, fmt.Errorf("license: issuer public key is %d bytes, want %d (ML-DSA-87)", len(issuerPublicKey), sign.PublicKeySize)
	}
	if len(purposes) == 0 {
		return nil, errors.New("license: an issuer certificate needs at least one purpose")
	}
	for _, p := range purposes {
		if p != PurposeAPIKey && p != PurposeLicense {
			return nil, fmt.Errorf("license: unknown issuer purpose %q", p)
		}
	}
	if !notAfter.After(notBefore) {
		return nil, errors.New("license: issuer certificate not_after must be after not_before")
	}
	rootKey, err := sign.NewPrivateKey(rootPrivate)
	if err != nil {
		return nil, fmt.Errorf("license: root key: %w", err)
	}
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		return nil, fmt.Errorf("license: serial: %w", err)
	}
	cert, err := json.Marshal(IssuerCertificate{
		Version:         1,
		Serial:          hex.EncodeToString(serial),
		Purposes:        purposes,
		IssuerPublicKey: issuerPublicKey,
		NotBefore:       notBefore.UTC(),
		NotAfter:        notAfter.UTC(),
		RootFingerprint: KeyFingerprint(rootKey.PublicKey().Bytes()),
	})
	if err != nil {
		return nil, fmt.Errorf("license: marshal issuer certificate: %w", err)
	}
	sig, err := rootKey.Sign(issuerCertContext, cert)
	if err != nil {
		return nil, fmt.Errorf("license: sign issuer certificate: %w", err)
	}
	return json.MarshalIndent(SignedIssuerCertificate{Certificate: cert, Signature: sig}, "", "  ")
}

// ParseIssuerCertificate verifies a SignedIssuerCertificate against the pinned
// root and checks its validity at now. Only an ML-DSA-87 root can delegate.
func ParseIssuerCertificate(data, root []byte, now time.Time) (*IssuerCertificate, error) {
	var sc SignedIssuerCertificate
	if err := json.Unmarshal(data, &sc); err != nil || len(sc.Certificate) == 0 {
		return nil, errors.New("license: not a signed issuer certificate")
	}
	if len(root) != sign.PublicKeySize {
		return nil, errors.New("license: issuer delegation needs an ML-DSA-87 root")
	}
	rootKey, err := sign.NewPublicKey(root)
	if err != nil {
		return nil, fmt.Errorf("license: root key: %w", err)
	}
	if err := rootKey.Verify(issuerCertContext, sc.Certificate, sc.Signature); err != nil {
		return nil, fmt.Errorf("license: issuer certificate signature: %w", err)
	}
	var c IssuerCertificate
	if err := json.Unmarshal(sc.Certificate, &c); err != nil {
		return nil, fmt.Errorf("license: issuer certificate: %w", err)
	}
	switch {
	case c.Version != 1:
		return nil, fmt.Errorf("license: unsupported issuer certificate version %d", c.Version)
	case c.RootFingerprint != KeyFingerprint(root):
		return nil, errors.New("license: issuer certificate names a different root")
	case len(c.IssuerPublicKey) != sign.PublicKeySize:
		return nil, errors.New("license: issuer certificate key is not ML-DSA-87")
	case now.Before(c.NotBefore) || !now.Before(c.NotAfter):
		return nil, fmt.Errorf("license: issuer certificate %s is not valid at %s", c.Serial, now.UTC().Format(time.RFC3339))
	}
	return &c, nil
}

func (c *IssuerCertificate) allows(purpose string) bool {
	for _, p := range c.Purposes {
		if p == purpose {
			return true
		}
	}
	return false
}

// issuerCertificateSources returns the raw certificates compiled in and those
// named by IssuerCertsEnv.
func issuerCertificateSources() [][]byte {
	var out [][]byte
	_ = fs.WalkDir(embeddedIssuers, "trust/issuers", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
			if b, err := embeddedIssuers.ReadFile(p); err == nil {
				out = append(out, b)
			}
		}
		return nil
	})
	if path := strings.TrimSpace(os.Getenv(IssuerCertsEnv)); path != "" {
		_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
				if b, err := os.ReadFile(p); err == nil {
					out = append(out, b)
				}
			}
			return nil
		})
	}
	return out
}

// verifyTrusted accepts a signature by the pinned root, or by an issuer the
// root has delegated purpose to.
func verifyTrusted(ctx sign.Context, purpose string, root, message, signature []byte) error {
	rootErr := verifyWithRoot(ctx, root, message, signature)
	if rootErr == nil {
		return nil
	}
	now := time.Now()
	for _, raw := range issuerCertificateSources() {
		cert, err := ParseIssuerCertificate(raw, root, now)
		if err != nil || !cert.allows(purpose) {
			continue
		}
		pk, err := sign.NewPublicKey(cert.IssuerPublicKey)
		if err != nil {
			continue
		}
		if pk.Verify(ctx, message, signature) == nil {
			return nil
		}
	}
	return rootErr
}
