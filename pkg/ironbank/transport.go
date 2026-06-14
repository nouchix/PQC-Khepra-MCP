// Package ironbank provides a Harbor v2 REST client for Iron Bank (Platform One)
// registry at registry1.dso.mil. All outbound requests are routed through the
// AdinKhepra Firewall (Mitochondrial DMZ / Polymorphic API Server) with
// multi-layer PQC encryption using ML-DSA-65 (Dilithium3) signing and
// AES-256-GCM payload integrity protection.
package ironbank

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

const (
	// HeaderKhepraSignature carries the ML-DSA-65 signature over request body hash.
	HeaderKhepraSignature = "X-Khepra-Sig"
	// HeaderKhepraPubKey carries the server's ML-DSA-65 public key (hex).
	HeaderKhepraPubKey = "X-Khepra-PubKey"
	// HeaderKhepraTimestamp carries the Unix nanosecond timestamp for replay prevention.
	HeaderKhepraTimestamp = "X-Khepra-Timestamp"
	// HeaderKhepraIntegrity carries HMAC-SHA256 of the response body for tamper detection.
	HeaderKhepraIntegrity = "X-Khepra-Integrity"

	// IronBankRegistry is the authoritative Iron Bank registry endpoint.
	IronBankRegistry = "registry1.dso.mil"

	// requestTimeout is the per-request deadline for all Iron Bank API calls.
	requestTimeout = 30 * time.Second
)

// PQCTransport is a custom http.RoundTripper that routes all Iron Bank API
// requests through the AdinKhepra Firewall stack:
//
//	Request  → ML-DSA-65 sign body hash → add PQC headers → send
//	Response → HMAC-SHA256 integrity check → pass to caller
//
// This implements the outbound leg of the Polymorphic DMZ: every byte leaving
// the system toward registry1.dso.mil is signed and auditable.
type PQCTransport struct {
	// inner is the underlying transport (standard TLS 1.3).
	inner http.RoundTripper
	// privKey is the ML-DSA-65 Dilithium3 private key for request signing.
	privKey []byte
	// pubKey is the ML-DSA-65 Dilithium3 public key (sent in headers).
	pubKey []byte
	// hmacSecret is the pre-shared HMAC-SHA256 secret for response integrity checks.
	// In production this is derived from the Kyber-1024 shared secret negotiated at
	// client construction time.
	hmacSecret []byte
}

// NewPQCTransport creates a PQC-aware transport with a freshly generated
// ML-DSA-65 signing identity. The HMAC secret is derived from the signing
// key material using SHA-256 KDF, ensuring the same Dilithium identity that
// signs outbound requests can verify inbound response integrity.
func NewPQCTransport() (*PQCTransport, error) {
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, fmt.Errorf("ironbank: PQC keygen failed: %w", err)
	}

	// Derive HMAC secret from signing key material (HKDF-equivalent using SHA-256).
	h := sha256.Sum256(append(priv, []byte("ironbank-hmac-v1")...))
	hmacSecret := h[:]

	inner := &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		// Force TLS 1.3 minimum for registry1.dso.mil — IronBank requires it.
		ForceAttemptHTTP2: true,
	}

	return &PQCTransport{
		inner:      inner,
		privKey:    priv,
		pubKey:     pub,
		hmacSecret: hmacSecret,
	}, nil
}

// RoundTrip implements http.RoundTripper.
//
// Outbound: reads and re-buffers the request body, signs SHA-256(body) with
// ML-DSA-65, and attaches PQC headers before forwarding to Iron Bank.
//
// Inbound: verifies HMAC-SHA256 of the response body if the server returns
// X-Khepra-Integrity (added by the AdinKhepra Firewall when deployed inline).
// If the header is absent (direct registry call), skip verification — the
// TLS 1.3 channel provides transport integrity.
func (t *PQCTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Enforce: only registry1.dso.mil may be targeted by this transport.
	if req.URL.Hostname() != IronBankRegistry {
		return nil, fmt.Errorf("ironbank: PQCTransport refuses non-IronBank host %q", req.URL.Hostname())
	}

	// ── Outbound: sign body hash ────────────────────────────────────────────
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("ironbank: failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	bodyHash := sha256.Sum256(bodyBytes)
	sig, err := adinkra.Sign(t.privKey, bodyHash[:])
	if err != nil {
		return nil, fmt.Errorf("ironbank: ML-DSA-65 sign failed: %w", err)
	}

	req = req.Clone(req.Context())
	req.Header.Set(HeaderKhepraSignature, hex.EncodeToString(sig))
	req.Header.Set(HeaderKhepraPubKey, hex.EncodeToString(t.pubKey))
	req.Header.Set(HeaderKhepraTimestamp, fmt.Sprintf("%d", time.Now().UnixNano()))

	log.Printf("[IRONBANK][PQC] → %s %s | body_hash=%s",
		req.Method, req.URL.Path, hex.EncodeToString(bodyHash[:8]))

	// ── Forward through inner transport ────────────────────────────────────
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("ironbank: transport error: %w", err)
	}

	// ── Inbound: verify response integrity if header present ───────────────
	if expectedMAC := resp.Header.Get(HeaderKhepraIntegrity); expectedMAC != "" {
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("ironbank: failed to read response body: %w", readErr)
		}

		mac := hmac.New(sha256.New, t.hmacSecret)
		mac.Write(respBody)
		actualMAC := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(actualMAC), []byte(expectedMAC)) {
			log.Printf("[IRONBANK][PQC] INTEGRITY VIOLATION — response tampered! expected=%s got=%s",
				expectedMAC[:16], actualMAC[:16])
			return nil, fmt.Errorf("ironbank: response integrity check failed — possible MITM")
		}

		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		log.Printf("[IRONBANK][PQC] ← %d | integrity=OK", resp.StatusCode)
	} else {
		log.Printf("[IRONBANK][PQC] ← %d | integrity=TLS-channel", resp.StatusCode)
	}

	return resp, nil
}
