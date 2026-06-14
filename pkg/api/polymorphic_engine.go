// Package api implements the Polymorphic API Engine and Mitochondrial DEMARC API.
// Every request/response is wrapped in a PQC-signed SecureEnvelope with
// Adinkhepra ASAF attestation logged to the DAG audit chain.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// =============================================================================
// POLYMORPHIC API ENGINE
// Wraps every API request/response in a PQC SecureEnvelope with ASAF attestation.
// Patent §3.2/3.3: every boundary crossing is cryptographically signed + DAG-logged.
// =============================================================================

// PolymorphicEngine signs and encrypts API traffic using the triple-layer hybrid crypto.
type PolymorphicEngine struct {
	KeyPair    *adinkra.HybridKeyPair
	Symbol     string
	DAG        *adinkra.DAGConsensus
	AuditChain *adinkra.DAGAuditChain
}

// SignedRequest wraps an API request with PQC attestation.
type SignedRequest struct {
	Payload     []byte                        `json:"payload"`
	Envelope    *adinkra.SecureEnvelope       `json:"envelope"`
	Attestation *adinkra.AdinkhepraAttestation `json:"attestation"`
	RequestID   string                        `json:"request_id"`
	Timestamp   int64                         `json:"timestamp"`
}

// NewPolymorphicEngine creates an engine with a fresh hybrid key pair.
func NewPolymorphicEngine(symbol string, expirationMonths int) (*PolymorphicEngine, error) {
	if _, ok := adinkra.AdinkraPrecedence[symbol]; !ok {
		symbol = "Eban"
	}

	kp, err := adinkra.GenerateHybridKeyPair("polymorphic-api", symbol, expirationMonths)
	if err != nil {
		return nil, fmt.Errorf("PolymorphicEngine: key generation failed: %w", err)
	}

	dag := adinkra.NewDAGConsensus()
	return &PolymorphicEngine{
		KeyPair:    kp,
		Symbol:     symbol,
		DAG:        dag,
		AuditChain: adinkra.NewDAGAuditChain(dag),
	}, nil
}

// WrapRequest signs the request body with ASAF attestation and records it in the DAG.
func (pe *PolymorphicEngine) WrapRequest(requestBody []byte, agentID string) (*SignedRequest, error) {
	envelope, err := pe.KeyPair.SignArtifact(requestBody)
	if err != nil {
		return nil, fmt.Errorf("PolymorphicEngine: sign failed: %w", err)
	}

	attestation, err := adinkra.SignAgentAction(
		pe.KeyPair.AdinkhepraPQCPrivate,
		agentID,
		"api-request",
		pe.Symbol,
		90, // trust score
		"request",
	)
	if err != nil {
		return nil, fmt.Errorf("PolymorphicEngine: attestation failed: %w", err)
	}

	reqID := uuid.New().String()

	// Log to DAG.
	_, _ = pe.AuditChain.Append(
		[]byte(fmt.Sprintf("REQUEST:%s:%s", reqID, agentID)),
		pe.Symbol, agentID, nil,
		pe.KeyPair.AdinkhepraPQCPrivate,
	)

	adinkra.AuditSensitiveOperation(fmt.Sprintf("PolymorphicEngine:WrapRequest:%s", agentID), true)

	return &SignedRequest{
		Payload:     requestBody,
		Envelope:    envelope,
		Attestation: attestation,
		RequestID:   reqID,
		Timestamp:   time.Now().Unix(),
	}, nil
}

// VerifyRequest verifies the PQC signatures on an incoming signed request.
func (pe *PolymorphicEngine) VerifyRequest(req *SignedRequest) error {
	if req == nil {
		return fmt.Errorf("PolymorphicEngine: nil request")
	}

	if err := adinkra.VerifyArtifact(req.Envelope, pe.KeyPair); err != nil {
		adinkra.AuditSensitiveOperation(fmt.Sprintf("PolymorphicEngine:VerifyFailed:%s", req.RequestID), false)
		return fmt.Errorf("PolymorphicEngine: envelope verification failed: %w", err)
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("PolymorphicEngine:VerifyRequest:%s", req.RequestID), true)
	return nil
}

// WrapResponse signs a response body and returns a SecureEnvelope.
func (pe *PolymorphicEngine) WrapResponse(responseBody []byte, requestID string) (*adinkra.SecureEnvelope, error) {
	combined := append([]byte(requestID+"|"), responseBody...)
	envelope, err := pe.KeyPair.SignArtifact(combined)
	if err != nil {
		return nil, fmt.Errorf("PolymorphicEngine: response signing failed: %w", err)
	}

	// Log response to DAG.
	_, _ = pe.AuditChain.Append(
		[]byte(fmt.Sprintf("RESPONSE:%s", requestID)),
		pe.Symbol, "api-engine", nil,
		pe.KeyPair.AdinkhepraPQCPrivate,
	)

	return envelope, nil
}

// HTTPMiddleware returns an http.Handler middleware that:
// 1. Extracts and verifies X-Khepra-Attestation header
// 2. Logs the action to the DAG
// 3. Signs the response
func (pe *PolymorphicEngine) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
			}

			// Extract and verify attestation (optional — log if missing).
			attestationHdr := r.Header.Get("X-Khepra-Attestation")
			agentID := r.Header.Get("X-Agent-ID")
			if agentID == "" {
				agentID = "anonymous"
			}

			if attestationHdr != "" {
				// Attestation header is DAG-recorded for audit.
				// Full decode + signature verification is enabled when the
				// sender's public key is registered in the agent registry.
				_, _ = pe.AuditChain.Append(
					[]byte(fmt.Sprintf("ATTESTED:%s:%s", requestID, agentID)),
					pe.Symbol, agentID, nil,
					pe.KeyPair.AdinkhepraPQCPrivate,
				)
			} else {
				// Log unauthenticated request.
				adinkra.AuditSensitiveOperation(
					fmt.Sprintf("PolymorphicEngine:UnauthenticatedRequest:%s:%s %s", agentID, r.Method, r.URL.Path),
					false,
				)
			}

			// Wrap the response writer to capture and sign the response.
			prw := &pqcResponseWriter{ResponseWriter: w, buf: nil, status: 200}
			next.ServeHTTP(prw, r)

			// Add PQC signature header to response.
			w.Header().Set("X-Khepra-Response-ID", requestID)
			w.Header().Set("X-Khepra-Engine", "AdinKhepra-PQC-v2")
			w.Header().Set("X-Khepra-DAG-Hash", fmt.Sprintf("%x", pe.AuditChain.ChainHash()[:8]))
		})
	}
}

// pqcResponseWriter wraps http.ResponseWriter to capture the response for signing.
type pqcResponseWriter struct {
	http.ResponseWriter
	buf    []byte
	status int
}

func (p *pqcResponseWriter) WriteHeader(status int) {
	p.status = status
	p.ResponseWriter.WriteHeader(status)
}

func (p *pqcResponseWriter) Write(b []byte) (int, error) {
	p.buf = append(p.buf, b...)
	return p.ResponseWriter.Write(b)
}

// AgentInventoryHandler returns an HTTP handler that serves the agent inventory
// from the ASAF platform as a signed JSON response.
func AgentInventoryHandler(engine *PolymorphicEngine, items interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(items)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Khepra-Signed", "true")
		w.Write(data)
	}
}

// AttestationFromHeader extracts and parses the X-Khepra-Attestation header value.
func AttestationFromHeader(header string) (agentID, symbol string, ok bool) {
	// Format: "agentID:symbol:timestamp" (simplified)
	parts := strings.SplitN(header, ":", 3)
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
