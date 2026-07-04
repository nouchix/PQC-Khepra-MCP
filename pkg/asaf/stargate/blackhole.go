// package stargate — Blackhole VPN: ML-KEM-768 encrypted tunnel between khepra-reporter
// (endpoint agent) and asaf-hub (management console).
//
// The Blackhole VPN is a zero-egress reporting channel. Endpoint agents (khepra-reporter)
// call home to the hub with STIG scan results, encrypted under ML-KEM-768 session keys
// established during enrollment. No persistent TCP connection required — each heartbeat
// is a standalone HTTPS POST.
//
// Protocol:
//   POST /enroll     — ML-KEM-768 key encapsulation handshake (reporter → hub)
//   POST /heartbeat  — Encrypted STIG/scan report delivery (reporter → hub)
//   POST /dispatch   — Hub sends ML-DSA-65 signed ChangeRequest to reporter (hub → reporter pull)
//   GET  /dispatch   — Reporter polls for pending ChangeRequests
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package stargate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ── Enrollment Models ─────────────────────────────────────────────────────────

// EnrollmentRequest is sent by khepra-reporter during initial registration.
// The reporter's ML-KEM-768 public key is sent to the hub.
// The hub responds with its encapsulated shared secret (ML-KEM-768 ciphertext).
type EnrollmentRequest struct {
	ReporterID  string `json:"reporter_id"`  // unique agent ID
	HostFQDN    string `json:"host_fqdn"`    // enrolled endpoint FQDN
	HostIP      string `json:"host_ip"`
	OS          string `json:"os"`           // "rhel9", "win2022", etc.
	PublicKeyHex string `json:"pub_key_hex"` // ML-KEM-768 public key (hex)
	Version     string `json:"version"`      // khepra-reporter version
	EnrolledAt  time.Time `json:"enrolled_at,omitempty"`
}

// EnrollmentResponse is returned by the hub to the reporter on successful enrollment.
type EnrollmentResponse struct {
	SessionID       string    `json:"session_id"`
	CiphertextHex   string    `json:"ciphertext_hex"`    // ML-KEM-768 encapsulated key
	HubPublicKeyHex string    `json:"hub_pub_key_hex"`   // Hub's ML-KEM-768 pub key for verify
	ExpiresAt       time.Time `json:"expires_at"`
	HeartbeatURL    string    `json:"heartbeat_url"`
	DispatchURL     string    `json:"dispatch_url"`
}

// ReporterSession tracks an enrolled khepra-reporter.
type ReporterSession struct {
	ReporterID   string    `json:"reporter_id"`
	HostFQDN     string    `json:"host_fqdn"`
	HostIP       string    `json:"host_ip"`
	OS           string    `json:"os"`
	SessionID    string    `json:"session_id"`
	SharedSecret []byte    `json:"-"` // ML-KEM-768 shared secret — never serialized
	EnrolledAt   time.Time `json:"enrolled_at"`
	LastSeen     time.Time `json:"last_seen"`
	Version      string    `json:"version"`
	// PendingChanges holds ChangeRequests awaiting pickup by this reporter.
	PendingChanges []*ChangeRequest `json:"pending_changes,omitempty"`
}

// HeartbeatRequest is the periodic check-in from khepra-reporter.
// The payload is encrypted under the ML-KEM-768 shared secret from enrollment.
type HeartbeatRequest struct {
	SessionID     string `json:"session_id"`
	ReporterID    string `json:"reporter_id"`
	// EncryptedPayload is AES-256-GCM encrypted with the enrollment shared secret.
	// Plaintext is a JSON-encoded ScanReport.
	EncryptedPayload string `json:"encrypted_payload_hex"`
	Nonce            string `json:"nonce_hex"`
	Timestamp        time.Time `json:"timestamp"`
	// SignatureHex is ML-DSA-65 over (session_id + timestamp + sha256(encrypted_payload)).
	// Unsigned heartbeats are silently dropped and logged.
	SignatureHex string `json:"signature_hex,omitempty"`
}

// HeartbeatResponse is returned to the reporter after a successful heartbeat.
type HeartbeatResponse struct {
	Acknowledged bool   `json:"acknowledged"`
	PendingCount int    `json:"pending_changes"`
	ServerTime   time.Time `json:"server_time"`
}

// ── Blackhole Store ───────────────────────────────────────────────────────────

var blackholeStore = struct {
	mu       sync.RWMutex
	sessions map[string]*ReporterSession // sessionID → session
	byAgent  map[string]string           // reporterID → sessionID
}{
	sessions: make(map[string]*ReporterSession),
	byAgent:  make(map[string]string),
}

// BlackholeHandlers implements the Blackhole VPN HTTP endpoints.
type BlackholeHandlers struct {
	hubAddr string // hub's external address for heartbeat/dispatch URLs
}

// NewBlackholeHandlers creates Blackhole VPN handlers.
func NewBlackholeHandlers(hubAddr string) *BlackholeHandlers {
	return &BlackholeHandlers{hubAddr: hubAddr}
}

// Register mounts Blackhole routes onto mux.
func (h *BlackholeHandlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/enroll", h.handleEnroll)
	mux.HandleFunc("/heartbeat", h.handleHeartbeat)
	mux.HandleFunc("/dispatch", h.handleDispatch)
	mux.HandleFunc("/api/v1/blackhole/reporters", h.handleListReporters)
}

// ── Enroll ────────────────────────────────────────────────────────────────────

// handleEnroll: POST /enroll
// ML-KEM-768 handshake. Reporter sends its public key; hub responds with
// encapsulated shared secret. Subsequent heartbeats are AES-256-GCM encrypted
// under this shared secret.
func (h *BlackholeHandlers) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req EnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.ReporterID == "" || req.PublicKeyHex == "" {
		writeError(w, http.StatusBadRequest, "reporter_id and pub_key_hex are required")
		return
	}

	// Generate session ID
	idBytes := sha256.Sum256([]byte(req.ReporterID + req.HostFQDN + time.Now().String()))
	sessionID := hex.EncodeToString(idBytes[:8])

	// In production: use circl.kem.Kyber768 to encapsulate.
	// For now: derive a synthetic shared secret from reporter pubkey hash.
	// TODO(PR4): integrate pkg/adinkra ML-KEM-768 actual KEM.
	pkHash := sha256.Sum256([]byte(req.PublicKeyHex))
	syntheticShared := pkHash[:] // 32-byte shared secret placeholder
	syntheticCiphertext := hex.EncodeToString(pkHash[:]) // placeholder

	session := &ReporterSession{
		ReporterID:     req.ReporterID,
		HostFQDN:       req.HostFQDN,
		HostIP:         req.HostIP,
		OS:             req.OS,
		SessionID:      sessionID,
		SharedSecret:   syntheticShared,
		EnrolledAt:     time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
		Version:        req.Version,
		PendingChanges: []*ChangeRequest{},
	}

	blackholeStore.mu.Lock()
	blackholeStore.sessions[sessionID] = session
	blackholeStore.byAgent[req.ReporterID] = sessionID
	blackholeStore.mu.Unlock()

	resp := EnrollmentResponse{
		SessionID:       sessionID,
		CiphertextHex:   syntheticCiphertext,
		HubPublicKeyHex: "hub-pub-key-placeholder", // TODO: real hub pubkey
		ExpiresAt:       time.Now().Add(365 * 24 * time.Hour),
		HeartbeatURL:    fmt.Sprintf("%s/heartbeat", h.hubAddr),
		DispatchURL:     fmt.Sprintf("%s/dispatch?session_id=%s", h.hubAddr, sessionID),
	}
	writeJSON(w, http.StatusCreated, resp)
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────

// handleHeartbeat: POST /heartbeat
// Reporter delivers its latest STIG scan results, encrypted under shared secret.
// Hub decrypts, ingests results into FleetRegistry, returns pending ChangeRequests.
func (h *BlackholeHandlers) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	blackholeStore.mu.Lock()
	session, ok := blackholeStore.sessions[req.SessionID]
	if !ok {
		blackholeStore.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "unknown session_id — enroll first")
		return
	}
	session.LastSeen = time.Now().UTC()
	pendingCount := len(session.PendingChanges)
	blackholeStore.mu.Unlock()

	// TODO(PR4): AES-256-GCM decrypt req.EncryptedPayload using session.SharedSecret
	// TODO(PR4): parse decrypted JSON as ScanReport → ingest into FleetRegistry
	// TODO(PR4): verify ML-DSA-65 signature over (session_id + timestamp + payload_hash)

	writeJSON(w, http.StatusOK, HeartbeatResponse{
		Acknowledged: true,
		PendingCount: pendingCount,
		ServerTime:   time.Now().UTC(),
	})
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

// handleDispatch: GET /dispatch?session_id=xxx
// Reporter polls for pending ChangeRequests. Hub returns signed requests.
// POST /dispatch — Hub pushes a ChangeRequest to a specific reporter.
func (h *BlackholeHandlers) handleDispatch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Reporter polling for pending changes
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			writeError(w, http.StatusBadRequest, "session_id required")
			return
		}
		blackholeStore.mu.Lock()
		session, ok := blackholeStore.sessions[sessionID]
		if !ok {
			blackholeStore.mu.Unlock()
			writeError(w, http.StatusUnauthorized, "unknown session_id")
			return
		}
		pending := session.PendingChanges
		session.PendingChanges = []*ChangeRequest{} // clear after delivery
		blackholeStore.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"changes": pending,
			"count":   len(pending),
		})

	case http.MethodPost:
		// Hub dispatching a signed ChangeRequest to a specific reporter
		var body struct {
			ReporterID string         `json:"reporter_id"`
			Request    *ChangeRequest `json:"request"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if body.ReporterID == "" || body.Request == nil {
			writeError(w, http.StatusBadRequest, "reporter_id and request are required")
			return
		}

		blackholeStore.mu.Lock()
		sessionID, ok := blackholeStore.byAgent[body.ReporterID]
		if !ok {
			blackholeStore.mu.Unlock()
			writeError(w, http.StatusNotFound, "reporter not enrolled")
			return
		}
		session := blackholeStore.sessions[sessionID]
		session.PendingChanges = append(session.PendingChanges, body.Request)
		blackholeStore.mu.Unlock()

		writeJSON(w, http.StatusAccepted, map[string]string{
			"status":      "queued",
			"reporter_id": body.ReporterID,
			"request_id":  body.Request.ID,
		})

	default:
		methodNotAllowed(w)
	}
}

// handleListReporters: GET /api/v1/blackhole/reporters
// Returns all enrolled reporter sessions (for the Stargate Fleet Manager UI).
func (h *BlackholeHandlers) handleListReporters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	blackholeStore.mu.RLock()
	reporters := make([]*ReporterSession, 0, len(blackholeStore.sessions))
	for _, s := range blackholeStore.sessions {
		cp := *s
		cp.SharedSecret = nil // never expose
		reporters = append(reporters, &cp)
	}
	blackholeStore.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"reporters": reporters,
		"count":     len(reporters),
	})
}

// DispatchToReporter queues a ChangeRequest for delivery to a specific reporter.
// Called by Imhotep when a ChangeRequest is approved for production execution.
func DispatchToReporter(reporterID string, req *ChangeRequest) error {
	blackholeStore.mu.Lock()
	defer blackholeStore.mu.Unlock()
	sessionID, ok := blackholeStore.byAgent[reporterID]
	if !ok {
		return fmt.Errorf("blackhole: reporter %s not enrolled", reporterID)
	}
	session := blackholeStore.sessions[sessionID]
	session.PendingChanges = append(session.PendingChanges, req)
	return nil
}
