// Package mcp — manifest store and verifier implementations.
//
// FileManifestStore loads the signed manifest from a JSON file.
// AdinkraManifestVerifier verifies the manifest's ML-DSA-65 signature.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"
)

// ─── File-Based Manifest Store ─────────────────────────────────────────────────

// FileManifestStore loads a signed manifest from a local JSON file.
type FileManifestStore struct {
	Path string
}

// LoadSignedManifest reads and parses the manifest from the configured path.
func (s *FileManifestStore) LoadSignedManifest(_ context.Context) (*SignedToolManifest, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("manifest store: read %s: %w", s.Path, err)
	}

	var manifest SignedToolManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("manifest store: parse %s: %w", s.Path, err)
	}

	return &manifest, nil
}

// ─── Embedded Manifest Store ───────────────────────────────────────────────────

// EmbeddedManifestStore holds a manifest in memory (for testing and bootstrap).
type EmbeddedManifestStore struct {
	Manifest *SignedToolManifest
}

// LoadSignedManifest returns the pre-loaded manifest.
func (s *EmbeddedManifestStore) LoadSignedManifest(_ context.Context) (*SignedToolManifest, error) {
	if s.Manifest == nil {
		return nil, fmt.Errorf("manifest store: no embedded manifest")
	}
	return s.Manifest, nil
}

// ─── PQC Manifest Verifier ─────────────────────────────────────────────────────

// AdinkraManifestVerifier uses ML-DSA-65 (Dilithium-3) to verify manifest signatures.
type AdinkraManifestVerifier struct {
	Signer kernelports.Signer
	// PublicKey is the PQC verification key for manifest signing.
	PublicKey []byte
}

// Verify validates the manifest's PQC signature.
func (v *AdinkraManifestVerifier) Verify(manifest *SignedToolManifest) error {
	if manifest.Signature == "" {
		return fmt.Errorf("manifest verifier: missing signature")
	}

	// Reconstruct the canonical payload that was signed
	payload := canonicalManifestPayload(manifest)
	h := sha256.Sum256(payload)

	// Decode the signature
	sigBytes, err := hex.DecodeString(manifest.Signature)
	if err != nil {
		return fmt.Errorf("manifest verifier: decode signature: %w", err)
	}

	// Verify using adinkra PQC
	valid, err := v.Signer.Verify(v.PublicKey, h[:], sigBytes)
	if err != nil {
		return fmt.Errorf("manifest verifier: verification error: %w", err)
	}
	if !valid {
		return fmt.Errorf("manifest verifier: signature verification FAILED — manifest may be tampered")
	}

	return nil
}

// ─── Bootstrap Verifier (Development) ──────────────────────────────────────────

// BootstrapManifestVerifier always passes verification.
// ONLY for initial bootstrap before PQC keys are provisioned.
// Must be replaced with AdinkraManifestVerifier in production.
type BootstrapManifestVerifier struct{}

// Verify always returns nil (development-only bypass).
func (v *BootstrapManifestVerifier) Verify(_ *SignedToolManifest) error {
	return nil
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

// canonicalManifestPayload creates the deterministic byte representation
// of a manifest for signing/verification (excludes the signature field).
func canonicalManifestPayload(m *SignedToolManifest) []byte {
	// Create a copy without the signature
	canonical := struct {
		Version       string    `json:"version"`
		Revision      string    `json:"revision"`
		GeneratedAt   string    `json:"generated_at"`
		HashAlgorithm string    `json:"hash_algorithm"`
		PublicKeyID   string    `json:"public_key_id"`
		Tools         []ToolSpec `json:"tools"`
	}{
		Version:       m.Version,
		Revision:      m.Revision,
		GeneratedAt:   m.GeneratedAt.Format("2006-01-02T15:04:05Z"),
		HashAlgorithm: m.HashAlgorithm,
		PublicKeyID:   m.PublicKeyID,
		Tools:         m.Tools,
	}

	b, _ := json.Marshal(canonical)
	return b
}

// GenerateSignedManifest creates a new signed manifest from tool specs.
// This is used by the build process to generate the initial manifest.json.
func GenerateSignedManifest(tools []ToolSpec, privKey []byte, keyID string, signer kernelports.Signer) (*SignedToolManifest, error) {
	manifest := &SignedToolManifest{
		Version:       "1.0.0",
		Revision:      fmt.Sprintf("build-%d", currentTimestamp()),
		GeneratedAt:   currentTime(),
		HashAlgorithm: "SHA-256",
		PublicKeyID:   keyID,
		Tools:         tools,
	}

	// Sign the canonical payload
	payload := canonicalManifestPayload(manifest)
	h := sha256.Sum256(payload)

	sig, err := signer.Sign(privKey, h[:])
	if err != nil {
		return nil, fmt.Errorf("manifest sign: %w", err)
	}

	manifest.Signature = hex.EncodeToString(sig)
	return manifest, nil
}

// currentTimestamp returns the current Unix timestamp.
func currentTimestamp() int64 {
	return currentTime().Unix()
}

// currentTime returns the current UTC time. Extracted for testability.
func currentTime() time.Time {
	return time.Now().UTC()
}

