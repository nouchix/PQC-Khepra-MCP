// Package license — sacred_license.go: customer-facing Sacred Runes encoding
// for already-signed KhepraLicense artifacts.
//
// SCOPE RULE — read before touching this file:
// This is ENCODING, not encryption. sacredLicenseSeed is fixed and public;
// anyone with this source can decode any artifact this produces. That is
// fine here because a KhepraLicense contains no confidential material —
// tier/tenant/expiry/capabilities are all visible to anyone who verifies the
// signature anyway, and the signature + SignerPublicKey are public by
// definition. All real trust comes from VerifySovereignLicense against the
// pinned MasterPublicKey, completely unaffected by this encoding.
//
// Do NOT reuse this seed, this pattern, or this file's approach for anything
// that needs actual confidentiality: API keys, pkg/keytwin twin artifacts,
// the root private key or its Shamir shards. Those need real encryption
// (Kyber-1024 KEM + an authentication tag), and Sacred Runes provides none —
// it's a fixed-seed, fully-reversible transform anyone can invert. Encoding
// real secrets this way would make them invisible to secret scanners
// (TruffleHog, gitleaks, GitHub push protection) without making them any
// harder for a real adversary to recover — net loss, not a defense.
package license

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// sacredLicenseSeed is fixed and public — see package doc above. Anyone
// running this code can both encode and decode; that symmetry is required
// for customers' own tooling (and ours) to round-trip the value.
var sacredLicenseSeed32 = sha256.Sum256([]byte("KHEPRA-LICENSE-SACRED-OVERLAY-V1"))

// EncodeLicenseDisplay renders an already-signed KhepraLicense in the Sacred
// Runes alphabet, for distribution as the customer-facing KHEPRA_LICENSE_KEY
// value. Purely cosmetic/brand-evasion encoding — see package doc.
func EncodeLicenseDisplay(lic *KhepraLicense) (string, error) {
	raw, err := json.Marshal(lic)
	if err != nil {
		return "", fmt.Errorf("license: marshal for sacred encoding: %w", err)
	}
	mk := adinkra.NewMerkaba(sacredLicenseSeed32[:])
	sealed, err := mk.Seal(raw)
	if err != nil {
		return "", fmt.Errorf("license: sacred encoding failed: %w", err)
	}
	return sealed, nil
}

// DecodeLicenseDisplay reverses EncodeLicenseDisplay. The returned license is
// NOT yet verified — callers must still run it through VerifySovereignLicense.
// ParseMCPLicense does this automatically and accepts either this encoding or
// raw JSON.
func DecodeLicenseDisplay(sacred string) (*KhepraLicense, error) {
	mk := adinkra.NewMerkaba(sacredLicenseSeed32[:])
	raw, err := mk.Unseal(sacred)
	if err != nil {
		return nil, fmt.Errorf("license: sacred decoding failed: %w", err)
	}
	var lic KhepraLicense
	if err := json.Unmarshal(raw, &lic); err != nil {
		return nil, fmt.Errorf("license: unmarshal decoded license: %w", err)
	}
	return &lic, nil
}
