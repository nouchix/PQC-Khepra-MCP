// handlers_scan.go — Fleet Scan REST handlers for ASAF Stargate Hub
//
// Routes:
//   POST /api/v1/fleet/scan           — trigger async fleet STIG scan
//   GET  /api/v1/fleet/scan/status    — check if scan is in progress
//   GET  /api/v1/fleet/scan/last      — last completed scan summary
//   GET  /api/v1/fleet/scan/stream    — SSE: live progress per host
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package stargate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/asaf/scanner"
)

// FleetScanHandlers exposes the fleet scanner over REST + SSE.
type FleetScanHandlers struct {
	scanner *scanner.FleetScanner
}

// NewFleetScanHandlers constructs the scan handler group.
func NewFleetScanHandlers(s *scanner.FleetScanner) *FleetScanHandlers {
	return &FleetScanHandlers{scanner: s}
}

// Register mounts the scan routes onto mux.
func (h *FleetScanHandlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/fleet/scan", h.handleScan)
	mux.HandleFunc("/api/v1/fleet/scan/status", h.handleScanStatus)
	mux.HandleFunc("/api/v1/fleet/scan/last", h.handleScanLast)
	mux.HandleFunc("/api/v1/fleet/scan/stream", h.handleScanStream)
}

// POST /api/v1/fleet/scan
// Body: { "enclave_id": "", "stig_profile": "rhel9" }
func (h *FleetScanHandlers) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		EnclaveID   string `json:"enclave_id"`
		STIGProfile string `json:"stig_profile"`
	}
	if err := readScanJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.STIGProfile == "" {
		req.STIGProfile = "rhel9"
	}

	// Use env-based credential store for now; PR 4 replaces with AES-256-GCM vault
	credStore := &scanner.EnvCredentialStore{
		DefaultUser:     "root",
		DefaultPassword: "", // will error per-asset if not set; scan continues
	}

	err := h.scanner.ScanFleet(r.Context(), req.EnclaveID, req.STIGProfile, credStore)
	if errors.Is(err, scanner.ErrScanInProgress) {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":  "scan already in progress",
			"stream": "/api/v1/fleet/scan/stream",
		})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	active := h.scanner.ActiveScan()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"run_id":  active.RunID,
		"stream":  "/api/v1/fleet/scan/stream",
		"started": active.StartedAt,
		"message": fmt.Sprintf("scanning %d assets with profile=%s", active.TotalAssets, req.STIGProfile),
	})
}

// GET /api/v1/fleet/scan/status
func (h *FleetScanHandlers) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	active := h.scanner.ActiveScan()
	if active == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"running": false,
			"last":    h.scanner.LastSummary(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"running": true,
		"scan":    active,
		"stream":  "/api/v1/fleet/scan/stream",
	})
}

// GET /api/v1/fleet/scan/last
func (h *FleetScanHandlers) handleScanLast(w http.ResponseWriter, r *http.Request) {
	last := h.scanner.LastSummary()
	if last == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "no scan has been run yet",
		})
		return
	}
	writeJSON(w, http.StatusOK, last)
}

// GET /api/v1/fleet/scan/stream
// Server-Sent Events: emits one FleetScanResult JSON per host as it completes.
// Client closes when scan finishes (stream ends with "event: done").
func (h *FleetScanHandlers) handleScanStream(w http.ResponseWriter, r *http.Request) {
	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Subscribe to live results
	ch := h.scanner.Subscribe()

	active := h.scanner.ActiveScan()
	if active != nil {
		fmt.Fprintf(w, "event: start\ndata: {\"run_id\":%q,\"total\":%d}\n\n", active.RunID, active.TotalAssets)
		flusher.Flush()
	}

	for {
		select {
		case result, open := <-ch:
			if !open {
				// Scan finished
				last := h.scanner.LastSummary()
				if last != nil {
					writeSSEJSON(w, "done", last)
					flusher.Flush()
				}
				return
			}
			writeSSEJSON(w, "result", result)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// writeSSEJSON emits a single SSE event with JSON data.
func writeSSEJSON(w http.ResponseWriter, event string, v any) {
	data := mustMarshalScanJSON(v)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
}

// readJSON decodes the JSON request body into v.
func readScanJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// mustMarshalScanJSON marshals v to JSON, returning "{}" on error.
func mustMarshalScanJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
