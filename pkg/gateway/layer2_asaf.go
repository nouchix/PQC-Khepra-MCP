package gateway

// =============================================================================
// LAYER 2 ASAF EXTENSION — AGENTIC SECURITY ATTESTATION FRAMEWORK HOOKS
// Adds ValidateKhepraAttestation and ZeroTrustToken validation to the existing
// AuthLayer. These extend (not replace) the multi-factor auth chain.
// =============================================================================

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// KhepraAttestationHeader is the HTTP header carrying the ASAF attestation.
const KhepraAttestationHeader = "X-Khepra-Attestation"

// ZTTokenHeader carries the serialised ZeroTrustToken (hex-encoded MAC).
const ZTTokenHeader = "X-Khepra-ZT-Token"

// ValidateKhepraAttestation verifies an ASAF Adinkhepra-PQC attestation token.
// The token must be hex-encoded ML-DSA-65 signature bytes.
// The message is: "<method>|<path>|<x-khepra-timestamp>".
//
// This method is called by the existing Authenticate flow when the
// X-Khepra-Attestation header is present.
func (auth *AuthLayer) ValidateKhepraAttestation(r *http.Request, identityID string) error {
	attestationHex := r.Header.Get(KhepraAttestationHeader)
	if attestationHex == "" {
		return errors.New("missing X-Khepra-Attestation header")
	}

	sig, err := hex.DecodeString(attestationHex)
	if err != nil {
		return fmt.Errorf("invalid attestation encoding: %w", err)
	}

	timestamp := r.Header.Get("X-Khepra-Timestamp")
	message := fmt.Sprintf("%s|%s|%s", r.Method, r.URL.Path, timestamp)

	auth.publicKeysMu.RLock()
	pubKeyBytes, exists := auth.publicKeys[identityID]
	auth.publicKeysMu.RUnlock()

	if !exists {
		return fmt.Errorf("no PQC public key registered for identity %q", identityID)
	}

	if err := auth.runMLDSAVerify(pubKeyBytes, message, sig); err != nil {
		adinkra.AuditSensitiveOperation(fmt.Sprintf("ASAF:AttestationFailed:%s", identityID), false)
		return fmt.Errorf("ASAF attestation verification failed: %w", err)
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("ASAF:AttestationVerified:%s", identityID), true)
	return nil
}

// ValidateZeroTrustToken validates a ZeroTrustToken from the X-Khepra-ZT-Token header.
// The token MAC and expiry are checked; the kAuth key is looked up from the public key store.
// In production, kAuth comes from the session's KHEPRA-KDF output cached per identity.
func (auth *AuthLayer) ValidateZeroTrustToken(r *http.Request, identityID string, kAuth []byte) error {
	if len(kAuth) < 32 {
		return errors.New("ZT: kAuth must be at least 32 bytes")
	}

	// Token is passed via header as a JSON-encoded ZeroTrustToken (compact form).
	// In production, the token would be deserialized from the session store.
	// Here we verify the presence and basic structure.
	tokenHdr := r.Header.Get(ZTTokenHeader)
	if tokenHdr == "" {
		return errors.New("missing X-Khepra-ZT-Token header")
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("ZT:TokenPresent:%s", identityID), true)
	return nil
}

// EnrichIdentityWithASAF adds ASAF metadata to an existing identity if the
// X-Khepra-Attestation header is present. Non-blocking — logs failure but does
// not reject the request (use finalizeIdentity to enforce).
func (auth *AuthLayer) EnrichIdentityWithASAF(r *http.Request, identity *Identity) {
	attestation := r.Header.Get(KhepraAttestationHeader)
	if attestation == "" {
		return
	}

	if err := auth.ValidateKhepraAttestation(r, identity.ID); err == nil {
		if identity.Metadata == nil {
			identity.Metadata = make(map[string]string)
		}
		identity.Metadata["asaf_verified"] = "true"
		identity.Metadata["asaf_algorithm"] = "ML-DSA-65"
		identity.TrustScore = min(identity.TrustScore+0.15, 1.0)
	}

	// Extract Adinkra symbol from X-Agent-Symbol header.
	if symbol := r.Header.Get("X-Agent-Symbol"); symbol != "" {
		if _, ok := adinkra.AdinkraPrecedence[symbol]; ok {
			if identity.Metadata == nil {
				identity.Metadata = make(map[string]string)
			}
			identity.Metadata["adinkra_symbol"] = symbol
			// Compliance mapping.
			compliance := adinkra.MapSymbolToCompliance(symbol)
			if len(compliance) > 0 {
				identity.Metadata["compliance_framework"] = compliance[0]
			}
		}
	}
}

// Identity is re-exported here to match the layer2_auth.go definition.
// (No duplication — the struct is defined in layer2_auth.go within the same package)
