// Package hub — REST API handlers for the ASAF Fleet Manager.
// Mounted at /api/v1/fleet/* by cmd/asaf-hub/main.go.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package hub

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/asaf/fleet"
)

// ConnectorConfig is the Hub-side representation of a saved connector template.
// Mirrors pkg/asaf/connector.ConnectorConfig on the desktop client.
type ConnectorConfig struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Protocol    string    `json:"protocol"`
	Host        string    `json:"host,omitempty"`
	CIDRRange   string    `json:"cidr,omitempty"`
	Port        int       `json:"port,omitempty"`
	AuthMethod  string    `json:"auth_method"`
	Username    string    `json:"username,omitempty"`
	CredRef     string    `json:"cred_ref,omitempty"`
	APIEndpoint string    `json:"api_endpoint,omitempty"`
	Region      string    `json:"region,omitempty"`
	EnclaveID   string    `json:"enclave_id"`
	Schedule    string    `json:"schedule,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used,omitempty"`
}

// FleetHandlers wraps the FleetRegistry and implements http.Handler routes.
type FleetHandlers struct {
	registry   *fleet.FleetRegistry
	connMu     sync.RWMutex
	connectors map[string]ConnectorConfig // keyed by ConnectorConfig.ID
}

// NewFleetHandlers creates handler wrappers around the given registry.
func NewFleetHandlers(registry *fleet.FleetRegistry) *FleetHandlers {
	return &FleetHandlers{
		registry:   registry,
		connectors: make(map[string]ConnectorConfig),
	}
}

// Register mounts all fleet routes onto mux.
// Exact-match patterns are registered before the /assets/ catch-all so that
// /assets/import, /assets/discover, and /assets/test are never swallowed by
// the prefix handler.
func (h *FleetHandlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/fleet/enclaves", h.handleEnclaves)
	mux.HandleFunc("/api/v1/fleet/assets", h.handleAssets)
	mux.HandleFunc("/api/v1/fleet/assets/import", h.handleImport)
	mux.HandleFunc("/api/v1/fleet/assets/discover", h.handleDiscover)
	mux.HandleFunc("/api/v1/fleet/assets/test", h.handleTestPreEnroll) // pre-enrollment test (no asset ID)
	mux.HandleFunc("/api/v1/fleet/scan", h.handleScan)
	mux.HandleFunc("/api/v1/fleet/boundary/attest", h.handleAttest)
	mux.HandleFunc("/api/v1/fleet/boundary/declaration", h.handleDeclaration)
	mux.HandleFunc("/api/v1/fleet/sprs", h.handleSPRS)
	mux.HandleFunc("/api/v1/fleet/sprs/simulate", h.handleSimulate)
	mux.HandleFunc("/api/v1/fleet/discover", h.handleDiscoverSSE)  // GET SSE: ?cidr=
	mux.HandleFunc("/api/v1/fleet/connectors", h.handleConnectors) // GET list / POST save
	mux.HandleFunc("/api/v1/fleet/assets/", h.handleAssetByID)     // /api/v1/fleet/assets/{id}/*
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
//
//	POST → enroll single asset (accepts fleet.Asset JSON OR AddAssetRequest JSON)
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
		// Accept both native fleet.Asset JSON and the desktop client's AddAssetRequest format.
		// We use a raw map to support both field naming conventions (ip vs ip_address, etc.).
		var raw map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		a := &fleet.Asset{
			CMMCCategory: fleet.Unclassified,
			ConnStatus:   "untested",
			CreatedAt:    time.Now().UTC(),
		}
		jsonStr := func(key string) string {
			if v, ok := raw[key]; ok {
				var s string
				_ = json.Unmarshal(v, &s)
				return s
			}
			return ""
		}
		// Accept both naming conventions.
		a.ID = jsonStr("id")
		a.EnclaveID = firstNonEmpty(jsonStr("enclave_id"), "default")
		a.Name = firstNonEmpty(jsonStr("name"), jsonStr("hostname"))
		a.Hostname = jsonStr("hostname")
		a.IP = firstNonEmpty(jsonStr("ip"), jsonStr("ip_address"))
		a.OS = jsonStr("os")
		a.STIGProfile = jsonStr("stig_profile")
		if a.IP == "" && a.Hostname == "" {
			writeError(w, http.StatusBadRequest, "ip or hostname required")
			return
		}
		if a.ID == "" {
			a.ID = assetIDFromFields(a.Hostname, a.IP)
		}
		if err := h.registry.AddAsset(a); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, a)

	default:
		methodNotAllowed(w)
	}
}

// handleAssetByID: PUT /api/v1/fleet/assets/{id}/category
//
//	POST /api/v1/fleet/assets/{id}/test
//	DELETE /api/v1/fleet/assets/{id}
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
//
// Accepts three body formats:
//  1. JSON  {"rows":[{hostname,ip_address,os,stig_profile,enclave},...], "enclave_id":"..."}
//     — used by the desktop HubClient (pre-parsed rows)
//  2. multipart/form-data with file field "csv"
//  3. raw CSV body
func (h *FleetHandlers) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	ct := r.Header.Get("Content-Type")

	// ── Path 1: JSON pre-parsed rows (desktop HubClient) ──────────────────────
	if strings.Contains(ct, "application/json") {
		var body struct {
			Rows []struct {
				Hostname    string `json:"hostname"`
				IPAddress   string `json:"ip_address"`
				OS          string `json:"os"`
				STIGProfile string `json:"stig_profile"`
				Enclave     string `json:"enclave"`
			} `json:"rows"`
			EnclaveID string `json:"enclave_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		enclaveID := firstNonEmpty(body.EnclaveID, r.URL.Query().Get("enclave_id"), "default")
		total := len(body.Rows)
		enrolled, skipped := 0, 0
		var errs []string
		for _, row := range body.Rows {
			if row.Hostname == "" && row.IPAddress == "" {
				skipped++
				errs = append(errs, "row missing hostname and ip — skipped")
				continue
			}
			a := &fleet.Asset{
				ID:           assetIDFromFields(row.Hostname, row.IPAddress),
				EnclaveID:    enclaveID,
				Name:         firstNonEmpty(row.Hostname, row.IPAddress),
				Hostname:     row.Hostname,
				IP:           row.IPAddress,
				OS:           row.OS,
				STIGProfile:  row.STIGProfile,
				CMMCCategory: fleet.Unclassified,
				ConnStatus:   "untested",
				CreatedAt:    time.Now().UTC(),
			}
			if err := h.registry.AddAsset(a); err != nil {
				skipped++
				errs = append(errs, fmt.Sprintf("%s: %v", firstNonEmpty(row.Hostname, row.IPAddress), err))
			} else {
				enrolled++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"total":    total,
			"enrolled": enrolled,
			"skipped":  skipped,
			"errors":   errs,
		})
		return
	}

	// ── Path 2 & 3: CSV (multipart or raw body) ───────────────────────────────
	enclaveID := r.URL.Query().Get("enclave_id")
	var reader = r.Body
	if strings.Contains(ct, "multipart") {
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

	enrolled := 0
	var importErrs []string
	for _, a := range result.Assets {
		if addErr := h.registry.AddAsset(a); addErr == nil {
			enrolled++
		} else {
			importErrs = append(importErrs, fmt.Sprintf("enroll failed for %s: %v", a.IP, addErr))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":    enrolled + result.Skipped + len(importErrs),
		"enrolled": enrolled,
		"skipped":  result.Skipped,
		"errors":   importErrs,
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
		OrgName    string `json:"org_name"`
		CAGECode   string `json:"cage_code"`
		DeclaredBy string `json:"declared_by"`
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

// ── New connector/discovery/test handlers ──────────────────────────────────────

// handleTestPreEnroll: POST /api/v1/fleet/assets/test
// Tests connectivity to a host before it is enrolled as an asset.
// Body: { "host": "10.0.0.5", "port": 22, "protocol": "ssh" }
func (h *FleetHandlers) handleTestPreEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var body struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		// Also accept nested config/credential from desktop client
		Config struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	host := firstNonEmpty(body.Host, body.Config.Host)
	port := body.Port
	if port == 0 {
		port = body.Config.Port
	}
	if host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}
	if port == 0 {
		port = 22 // SSH default
	}

	start := time.Now()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"success":    false,
			"message":    fmt.Sprintf("unreachable: %v", err),
			"latency_ms": latencyMs,
		})
		return
	}
	// Grab SSH banner if port 22.
	remoteOS, stigProfile := "", ""
	if port == 22 {
		banner := readFirstLine(conn, 2*time.Second)
		if banner != "" {
			remoteOS = parseBannerOSHub(banner)
			stigProfile = autoSTIG(remoteOS)
		}
	} else if port == 5985 || port == 5986 {
		remoteOS = "Windows"
		stigProfile = "windows-server-2022"
	}
	conn.Close()

	writeJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"latency_ms":   latencyMs,
		"remote_os":    remoteOS,
		"stig_profile": stigProfile,
		"message":      fmt.Sprintf("reachable in %dms", latencyMs),
	})
}

// handleDiscoverSSE: GET /api/v1/fleet/discover?cidr=10.0.0.0/24&enclave_id=...
// Streams discovered hosts as SSE events containing DiscoveredHost-compatible JSON.
// Matches the HubClient.DiscoverSubnet() GET request format.
func (h *FleetHandlers) handleDiscoverSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	cidr := r.URL.Query().Get("cidr")
	enclaveID := r.URL.Query().Get("enclave_id")
	if cidr == "" {
		writeError(w, http.StatusBadRequest, "cidr query parameter required")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	progressCh := make(chan string, 256)
	var discovered []*fleet.Asset

	go func() {
		assets, err := h.registry.DiscoverSubnet(cidr, enclaveID, progressCh)
		if err != nil {
			progressCh <- "error:" + err.Error()
		} else {
			discovered = assets
		}
		close(progressCh)
	}()

	for msg := range progressCh {
		if strings.HasPrefix(msg, "found:") {
			// "found:IP:port" → emit a DiscoveredHost SSE event for that IP.
			parts := strings.SplitN(strings.TrimPrefix(msg, "found:"), ":", 2)
			ip := parts[0]
			port := 0
			if len(parts) == 2 {
				fmt.Sscanf(parts[1], "%d", &port)
			}
			hostEvent := map[string]any{
				"ip":         ip,
				"reachable":  true,
				"open_ports": []int{port},
			}
			b, _ := json.Marshal(hostEvent)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		} else if strings.HasPrefix(msg, "error:") {
			fmt.Fprintf(w, "data: {\"error\":%q}\n\n", strings.TrimPrefix(msg, "error:"))
			flusher.Flush()
		}
	}

	// Emit complete asset records as final events.
	for _, a := range discovered {
		hostEvent := map[string]any{
			"ip":           a.IP,
			"hostname":     a.Hostname,
			"os":           a.OS,
			"stig_profile": a.STIGProfile,
			"reachable":    true,
			"open_ports":   []int{a.ConnProfile.Port},
			"services":     []string{string(a.ConnProfile.Protocol)},
		}
		b, _ := json.Marshal(hostEvent)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
}

// handleConnectors: GET /api/v1/fleet/connectors → list saved connector configs
//
//	POST /api/v1/fleet/connectors → save a connector config
func (h *FleetHandlers) handleConnectors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.connMu.RLock()
		out := make([]ConnectorConfig, 0, len(h.connectors))
		for _, c := range h.connectors {
			out = append(out, c)
		}
		h.connMu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"connectors": out,
			"count":      len(out),
		})

	case http.MethodPost:
		var body struct {
			Config     ConnectorConfig  `json:"config"`
			Credential *json.RawMessage `json:"credential,omitempty"` // accepted but not persisted server-side
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		cfg := body.Config
		if cfg.ID == "" {
			cfg.ID = fmt.Sprintf("conn-%x", time.Now().UnixNano())
		}
		if cfg.CreatedAt.IsZero() {
			cfg.CreatedAt = time.Now().UTC()
		}
		h.connMu.Lock()
		h.connectors[cfg.ID] = cfg
		h.connMu.Unlock()
		writeJSON(w, http.StatusCreated, cfg)

	default:
		methodNotAllowed(w)
	}
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
	addr := net.JoinHostPort(a.IP, strconv.Itoa(a.ConnProfile.Port))
	conn, err := dialTimeout(addr)
	if err != nil {
		return "unreachable"
	}
	conn.Close()
	return "ok"
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// assetIDFromFields builds a stable asset ID from hostname + IP (mirrors fleet.assetID).
func assetIDFromFields(hostname, ip string) string {
	h := firstNonEmpty(hostname, ip)
	return fmt.Sprintf("asset-%x", hashStr(h+ip))
}

// hashStr returns a cheap non-cryptographic hash for ID generation.
func hashStr(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// readFirstLine reads one line from conn with the given deadline (for SSH banner grab).
func readFirstLine(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

// parseBannerOSHub extracts an OS name from an SSH server banner string.
func parseBannerOSHub(banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ubuntu"):
		return "Ubuntu Linux"
	case strings.Contains(lower, "debian"):
		return "Debian Linux"
	case strings.Contains(lower, "rhel") || strings.Contains(lower, "red hat"):
		return "Red Hat Enterprise Linux"
	case strings.Contains(lower, "centos"):
		return "CentOS Linux"
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "openssh"):
		return "Linux"
	}
	return ""
}

// autoSTIG maps an OS string to a STIG profile key.
func autoSTIG(os string) string {
	lower := strings.ToLower(os)
	switch {
	case strings.Contains(lower, "rhel") || strings.Contains(lower, "red hat") || strings.Contains(lower, "centos"):
		return "rhel9"
	case strings.Contains(lower, "ubuntu"):
		return "ubuntu"
	case strings.Contains(lower, "windows server 2022"):
		return "windows-server-2022"
	case strings.Contains(lower, "windows server 2019"):
		return "windows-server-2019"
	case strings.Contains(lower, "windows"):
		return "windows-server-2022"
	case strings.Contains(lower, "linux"):
		return "rhel9"
	}
	return "generic"
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
