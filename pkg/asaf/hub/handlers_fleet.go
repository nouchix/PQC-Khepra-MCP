// Package hub — REST API handlers for the ASAF Fleet Manager.
// Mounted at /api/v1/fleet/* by cmd/asaf-hub/main.go.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/asaf/fleet"
)

// FleetHandlers wraps the FleetRegistry and implements http.Handler routes.
type FleetHandlers struct {
	registry *fleet.FleetRegistry
}

// NewFleetHandlers creates handler wrappers around the given registry.
func NewFleetHandlers(registry *fleet.FleetRegistry) *FleetHandlers {
	return &FleetHandlers{registry: registry}
}

// Register mounts all fleet routes onto mux.
func (h *FleetHandlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/fleet/enclaves", h.handleEnclaves)
	mux.HandleFunc("/api/v1/fleet/assets", h.handleAssets)
	mux.HandleFunc("/api/v1/fleet/assets/import", h.handleImport)
	mux.HandleFunc("/api/v1/fleet/assets/discover", h.handleDiscover)
	mux.HandleFunc("/api/v1/fleet/scan", h.handleScan)
	mux.HandleFunc("/api/v1/fleet/boundary/attest", h.handleAttest)
	mux.HandleFunc("/api/v1/fleet/boundary/declaration", h.handleDeclaration)
	mux.HandleFunc("/api/v1/fleet/sprs", h.handleSPRS)
	mux.HandleFunc("/api/v1/fleet/sprs/simulate", h.handleSimulate)
	mux.HandleFunc("/api/v1/fleet/assets/", h.handleAssetByID) // /api/v1/fleet/assets/{id}/*
}

// ── Enclaves ──────────────────────────────────────────────────────────────────

// handleEnclaves: GET → list enclaves | POST → create enclave
func (h *FleetHandlers) handleEnclaves(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		enclaves := h.registry.ListEnclaves()
		writeJSON(w, http.StatusOK, map[string]any{
			"enclaves": enclaves,
			"count":    len(enclaves),
		})

	case http.MethodPost:
		var e fleet.Enclave
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if err := h.registry.AddEnclave(&e); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, e)

	default:
		methodNotAllowed(w)
	}
}

// ── Assets ────────────────────────────────────────────────────────────────────

// handleAssets: GET → list assets (query: enclave_id, category)
//               POST → enroll single asset
func (h *FleetHandlers) handleAssets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		enclaveID := r.URL.Query().Get("enclave_id")
		category := fleet.CMMCCategory(r.URL.Query().Get("category"))
		assets := h.registry.ListAssets(enclaveID, category)
		writeJSON(w, http.StatusOK, map[string]any{
			"assets": assets,
			"count":  len(assets),
		})

	case http.MethodPost:
		var a fleet.Asset
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if err := h.registry.AddAsset(&a); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, a)

	default:
		methodNotAllowed(w)
	}
}

// handleAssetByID: PUT /api/v1/fleet/assets/{id}/category
//                  POST /api/v1/fleet/assets/{id}/test
//                  DELETE /api/v1/fleet/assets/{id}
func (h *FleetHandlers) handleAssetByID(w http.ResponseWriter, r *http.Request) {
	// Parse path: /api/v1/fleet/assets/{id}/{action}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/fleet/assets/")
	parts := strings.SplitN(trimmed, "/", 2)
	assetID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	if assetID == "" {
		writeError(w, http.StatusBadRequest, "asset id required")
		return
	}

	switch action {
	case "category":
		if r.Method != http.MethodPut {
			methodNotAllowed(w)
			return
		}
		var body struct {
			Category fleet.CMMCCategory `json:"category"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if err := h.registry.UpdateCategory(assetID, body.Category); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case "test":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		a, ok := h.registry.GetAsset(assetID)
		if !ok {
			writeError(w, http.StatusNotFound, "asset not found")
			return
		}
		// Attempt TCP connect to management port
		result := testConnectivity(a)
		writeJSON(w, http.StatusOK, map[string]string{
			"asset_id": assetID,
			"status":   result,
		})

	case "":
		if r.Method == http.MethodDelete {
			if err := h.registry.DeleteAsset(assetID); err != nil {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
			return
		}
		if r.Method == http.MethodGet {
			a, ok := h.registry.GetAsset(assetID)
			if !ok {
				writeError(w, http.StatusNotFound, "asset not found")
				return
			}
			writeJSON(w, http.StatusOK, a)
			return
		}
		methodNotAllowed(w)

	default:
		writeError(w, http.StatusNotFound, "unknown action: "+action)
	}
}

// handleImport: POST /api/v1/fleet/assets/import
// Accepts multipart/form-data with file field "csv" OR raw CSV body.
func (h *FleetHandlers) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	enclaveID := r.URL.Query().Get("enclave_id")

	// Accept both multipart and raw CSV body
	var reader = r.Body
	if strings.Contains(r.Header.Get("Content-Type"), "multipart") {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			writeError(w, http.StatusBadRequest, "multipart parse failed: "+err.Error())
			return
		}
		f, _, err := r.FormFile("csv")
		if err != nil {
			writeError(w, http.StatusBadRequest, "missing csv file field")
			return
		}
		defer f.Close()
		reader = f
	}

	result, err := h.registry.ImportCSV(reader, enclaveID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CSV import failed: "+err.Error())
		return
	}

	// Auto-enroll imported assets
	enrolled := 0
	for _, a := range result.Assets {
		if addErr := h.registry.AddAsset(a); addErr == nil {
			enrolled++
		} else {
			result.Errors = append(result.Errors, fleet.ImportError{
				Message: fmt.Sprintf("enroll failed for %s: %v", a.IP, addErr),
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"imported": enrolled,
		"skipped":  result.Skipped,
		"errors":   result.Errors,
	})
}

// handleDiscover: POST /api/v1/fleet/assets/discover
// Body: { "cidr": "10.0.1.0/24", "enclave_id": "..." }
func (h *FleetHandlers) handleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var body struct {
		CIDR      string `json:"cidr"`
		EnclaveID string `json:"enclave_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.CIDR == "" {
		writeError(w, http.StatusBadRequest, "cidr is required")
		return
	}

	// Stream progress via SSE if client accepts it
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")

		progressCh := make(chan string, 256)
		go func() {
			assets, err := h.registry.DiscoverSubnet(body.CIDR, body.EnclaveID, progressCh)
			if err != nil {
				progressCh <- "error:" + err.Error()
			} else {
				for _, a := range assets {
					_ = h.registry.AddAsset(a)
				}
				progressCh <- fmt.Sprintf("done:%d", len(assets))
			}
			close(progressCh)
		}()

		flusher, _ := w.(http.Flusher)
		for msg := range progressCh {
			fmt.Fprintf(w, "data: %s\n\n", msg)
			if flusher != nil {
				flusher.Flush()
			}
		}
		return
	}

	// Synchronous response
	assets, err := h.registry.DiscoverSubnet(body.CIDR, body.EnclaveID, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "discovery failed: "+err.Error())
		return
	}
	enrolled := 0
	for _, a := range assets {
		if h.registry.AddAsset(a) == nil {
			enrolled++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"discovered": len(assets),
		"enrolled":   enrolled,
		"assets":     assets,
	})
}

// ── SPRS ──────────────────────────────────────────────────────────────────────

// handleSPRS: GET /api/v1/fleet/sprs
// Returns the aggregate SPRS score from the last scan results.
func (h *FleetHandlers) handleSPRS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	assets := h.registry.ListAssets("", "")
	sprs := computeSPRSFromRegistry(assets)
	writeJSON(w, http.StatusOK, map[string]any{
		"sprs":        sprs,
		"max_score":   110,
		"asset_count": len(assets),
		"computed_at": time.Now().UTC(),
	})
}

// handleSimulate: POST /api/v1/fleet/sprs/simulate
// Body: { "add_asset_ids": [...], "remove_asset_ids": [...] }
func (h *FleetHandlers) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var body struct {
		AddAssetIDs    []string `json:"add_asset_ids"`
		RemoveAssetIDs []string `json:"remove_asset_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	assets := h.registry.ListAssets("", "")
	currentReports := assetsToReports(assets)

	// For add: look up by ID from registry
	addReports := make([]*fleet.HostReport, 0)
	for _, id := range body.AddAssetIDs {
		if a, ok := h.registry.GetAsset(id); ok {
			addReports = append(addReports, assetToReport(a))
		}
	}

	sim := fleet.SimulateBoundaryCost(currentReports, addReports, body.RemoveAssetIDs)
	writeJSON(w, http.StatusOK, sim)
}

// ── Boundary Attestation ──────────────────────────────────────────────────────

// handleAttest: POST /api/v1/fleet/boundary/attest
// Body: { "org_name": "...", "cage_code": "...", "declared_by": "..." }
// Returns a signed BoundaryDeclaration (Signature = SHA-256 placeholder;
// production callers wrap with full ML-DSA-65 via adinkra.Sign).
func (h *FleetHandlers) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var body struct {
		OrgName     string `json:"org_name"`
		CAGECode    string `json:"cage_code"`
		DeclaredBy  string `json:"declared_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.OrgName == "" || body.DeclaredBy == "" {
		writeError(w, http.StatusBadRequest, "org_name and declared_by are required")
		return
	}

	decl, err := h.registry.AttestBoundary(body.OrgName, body.CAGECode, body.DeclaredBy, nil, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "attestation failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, decl)
}

// handleDeclaration: GET /api/v1/fleet/boundary/declaration
// Returns the most recent boundary declaration (TODO: persist across restarts).
func (h *FleetHandlers) handleDeclaration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "no declaration on file — POST /api/v1/fleet/boundary/attest first",
	})
}

// handleScan: POST /api/v1/fleet/scan
// Placeholder — triggers BulkScanner; wired in PR 2 when pkg/remote is integrated.
func (h *FleetHandlers) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	assets := h.registry.ListAssets("", "")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":      "scan_queued",
		"asset_count": len(assets),
		"message":     "BulkScanner integration pending (PR 2). Assets enrolled and ready.",
	})
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func testConnectivity(a *fleet.Asset) string {
	import_net := "net"
	_ = import_net
	// Use stdlib net to avoid import cycles — same probe used in DiscoverSubnet
	addr := fmt.Sprintf("%s:%d", a.IP, a.ConnProfile.Port)
	conn, err := dialTimeout(addr)
	if err != nil {
		return "unreachable"
	}
	conn.Close()
	return "ok"
}

func computeSPRSFromRegistry(assets []*fleet.Asset) int {
	reports := assetsToReports(assets)
	sprs, _ := fleet.AggregateFleetSPRS(reports)
	return sprs
}

func assetsToReports(assets []*fleet.Asset) []*fleet.HostReport {
	out := make([]*fleet.HostReport, 0, len(assets))
	for _, a := range assets {
		out = append(out, assetToReport(a))
	}
	return out
}

func assetToReport(a *fleet.Asset) *fleet.HostReport {
	return &fleet.HostReport{
		AssetID:          a.ID,
		CMMCCategory:     a.CMMCCategory,
		FailingPractices: map[string]bool{},
		PassingPractices: map[string]bool{},
	}
}
