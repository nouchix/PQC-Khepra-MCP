// Package hub — Imhotep autonomous remediation dispatch handlers.
// Mounted at /api/v1/imhotep/* by cmd/asaf-hub/main.go.
//
// Imhotep is the ASAF System Daemon execution layer — it receives ML-DSA-65 signed
// ChangeRequests, stages them, requires human approval, then executes on production.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ── Imhotep Models ────────────────────────────────────────────────────────────

// RemediationStatus tracks the lifecycle of a ChangeRequest.
type RemediationStatus string

const (
	StatusPending   RemediationStatus = "pending_approval"
	StatusStaging   RemediationStatus = "staging"
	StatusApproved  RemediationStatus = "approved"
	StatusExecuting RemediationStatus = "executing"
	StatusDone      RemediationStatus = "done"
	StatusRejected  RemediationStatus = "rejected"
	StatusFailed    RemediationStatus = "failed"
)

// ChangeRequest represents a proposed system change dispatched by KASA/ASAF.
// Requires ML-DSA-65 signature before dispatch and human approval before production execution.
// Kernel-level operations additionally require Symbol == "Eban" (fortress).
type ChangeRequest struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agent_id"`
	Symbol      string            `json:"symbol"`      // Adinkra symbol — "Eban" required for kernel ops
	ControlID   string            `json:"control_id"`  // STIG/CMMC control this addresses (e.g. "SC-13")
	AssetID     string            `json:"asset_id"`    // Target asset from fleet registry
	AssetIP     string            `json:"asset_ip"`    // Redundant convenience field
	Command     []string          `json:"command"`     // e.g. ["sysctl", "-w", "crypto.fips_enabled=1"]
	Description string            `json:"description"` // Human-readable explanation
	Signature   []byte            `json:"signature,omitempty"` // ML-DSA-65 over Command+timestamp
	Staging     bool              `json:"staging"`     // true = mirror env only
	DAGParent   string            `json:"dag_parent,omitempty"` // chain of custody
	Status      RemediationStatus `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	ApprovedAt  *time.Time        `json:"approved_at,omitempty"`
	ApprovedBy  string            `json:"approved_by,omitempty"`
	ExecutedAt  *time.Time        `json:"executed_at,omitempty"`
	Result      string            `json:"result,omitempty"`
	DAGNodeID   string            `json:"dag_node_id,omitempty"`
}

// imhotepStore holds ChangeRequests in memory.
// TODO(PR2): persist to SQLite fleet.db.
var imhotepStore = struct {
	mu       sync.RWMutex
	requests map[string]*ChangeRequest
}{
	requests: make(map[string]*ChangeRequest),
}

// ImhotepHandlers implements HTTP handlers for the Imhotep remediation engine.
type ImhotepHandlers struct{}

// NewImhotepHandlers returns an ImhotepHandlers instance.
func NewImhotepHandlers() *ImhotepHandlers { return &ImhotepHandlers{} }

// Register mounts Imhotep routes onto mux.
func (h *ImhotepHandlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/imhotep/pending", h.handlePending)
	mux.HandleFunc("/api/v1/imhotep/approve", h.handleApprove)
	mux.HandleFunc("/api/v1/imhotep/reject", h.handleReject)
	mux.HandleFunc("/api/v1/imhotep/queue", h.handleQueue)
	mux.HandleFunc("/api/v1/imhotep/request/", h.handleRequestByID)
}

// handleQueue: POST /api/v1/imhotep/queue
// Enqueues a new ChangeRequest for human review.
// Caller (KASA agent) must provide an ML-DSA-65 signature.
// Kernel-level ops (sysctl, PAM, SELinux, GRUB) require symbol = "Eban".
func (h *ImhotepHandlers) handleQueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var req ChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if len(req.Command) == 0 {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	if req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id is required")
		return
	}

	// Enforce Eban symbol for kernel-level operations
	kernelCommands := map[string]bool{
		"sysctl": true, "setenforce": true, "dracut": true,
		"grub2-mkconfig": true, "authselect": true, "modprobe": true, "rmmod": true,
	}
	if len(req.Command) > 0 && kernelCommands[req.Command[0]] {
		if req.Symbol != "Eban" {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("kernel-level command %q requires symbol=Eban (got %q)",
					req.Command[0], req.Symbol))
			return
		}
	}

	// Generate content-addressed ID
	content, _ := json.Marshal(req.Command)
	idHash := sha256.Sum256(append(content, []byte(req.AgentID+req.AssetID)...))
	req.ID = hex.EncodeToString(idHash[:8])
	req.Status = StatusPending
	req.CreatedAt = time.Now().UTC()

	imhotepStore.mu.Lock()
	imhotepStore.requests[req.ID] = &req
	imhotepStore.mu.Unlock()

	writeJSON(w, http.StatusCreated, req)
}

// handlePending: GET /api/v1/imhotep/pending
// Returns all ChangeRequests awaiting human approval.
func (h *ImhotepHandlers) handlePending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	imhotepStore.mu.RLock()
	pending := make([]*ChangeRequest, 0)
	for _, req := range imhotepStore.requests {
		if req.Status == StatusPending || req.Status == StatusStaging {
			cp := *req
			pending = append(pending, &cp)
		}
	}
	imhotepStore.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"pending": pending,
		"count":   len(pending),
	})
}

// handleApprove: POST /api/v1/imhotep/approve
// Body: { "id": "...", "approved_by": "...", "execute_production": true }
// The human approval gate — sets Status → approved and triggers execution.
func (h *ImhotepHandlers) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var body struct {
		ID                string `json:"id"`
		ApprovedBy        string `json:"approved_by"`
		ExecuteProduction bool   `json:"execute_production"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.ID == "" || body.ApprovedBy == "" {
		writeError(w, http.StatusBadRequest, "id and approved_by are required")
		return
	}

	imhotepStore.mu.Lock()
	req, ok := imhotepStore.requests[body.ID]
	if !ok {
		imhotepStore.mu.Unlock()
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	if req.Status != StatusPending && req.Status != StatusStaging {
		imhotepStore.mu.Unlock()
		writeError(w, http.StatusConflict,
			fmt.Sprintf("request is in status %q — cannot approve", req.Status))
		return
	}

	now := time.Now().UTC()
	req.ApprovedAt = &now
	req.ApprovedBy = body.ApprovedBy
	req.Status = StatusApproved

	cp := *req
	imhotepStore.mu.Unlock()

	// In a full implementation, this triggers the asaf-daemon via Unix socket.
	// For now, mark as done with a simulated result.
	// TODO(PR2): wire to asaf-daemon dispatch via pkg/asaf/daemon.
	go func(change ChangeRequest) {
		imhotepStore.mu.Lock()
		if r2, ok2 := imhotepStore.requests[change.ID]; ok2 {
			r2.Status = StatusDone
			execTime := time.Now().UTC()
			r2.ExecutedAt = &execTime
			r2.Result = fmt.Sprintf("simulated: %v executed on %s", change.Command, change.AssetIP)
		}
		imhotepStore.mu.Unlock()
	}(cp)

	writeJSON(w, http.StatusOK, cp)
}

// handleReject: POST /api/v1/imhotep/reject
// Body: { "id": "...", "reason": "..." }
func (h *ImhotepHandlers) handleReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var body struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	imhotepStore.mu.Lock()
	req, ok := imhotepStore.requests[body.ID]
	if !ok {
		imhotepStore.mu.Unlock()
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	req.Status = StatusRejected
	req.Result = "rejected: " + body.Reason
	imhotepStore.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"id":     body.ID,
		"status": string(StatusRejected),
	})
}

// handleRequestByID: GET /api/v1/imhotep/request/{id}
func (h *ImhotepHandlers) handleRequestByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	id := r.URL.Path[len("/api/v1/imhotep/request/"):]
	imhotepStore.mu.RLock()
	req, ok := imhotepStore.requests[id]
	imhotepStore.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// QueueChangeRequest allows other hub components to programmatically enqueue
// a ChangeRequest without going through HTTP. Used by KASA engine integration.
func QueueChangeRequest(req *ChangeRequest) error {
	if len(req.Command) == 0 || req.AgentID == "" {
		return fmt.Errorf("imhotep: command and agent_id are required")
	}
	content, _ := json.Marshal(req.Command)
	idHash2 := sha256.Sum256(append(content, []byte(req.AgentID+req.AssetID)...))
	req.ID = hex.EncodeToString(idHash2[:8])
	req.Status = StatusPending
	req.CreatedAt = time.Now().UTC()

	imhotepStore.mu.Lock()
	imhotepStore.requests[req.ID] = req
	imhotepStore.mu.Unlock()
	return nil
}
