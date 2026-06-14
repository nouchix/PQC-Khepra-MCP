package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/billing"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
)

// Constants for shared literals
const (
	ErrTelemetryNotInitialized = "telemetry client not initialized"
	ErrInvalidRequest          = "invalid request"
)

// LicensingAPI handles HTTP requests for license management
type LicensingAPI struct {
	clientManager      *license.Manager
	registryManager    *license.LicenseManager
	dagLicenseEnforcer *license.DAGLicenseEnforcer
	billingCalculator  *billing.HybridBillingCalculator
	telemetryClient    *license.TelemetryClient
	dagStore           dag.Store
	systemIsAirGapped  bool
	machineID          string
}

// LicensingDeps holds dependencies for the Licensing API
type LicensingDeps struct {
	ClientManager      *license.Manager
	RegistryManager    *license.LicenseManager
	DagLicenseEnforcer *license.DAGLicenseEnforcer
	BillingCalculator  *billing.HybridBillingCalculator
	TelemetryClient    *license.TelemetryClient
	DagStore           dag.Store
	IsAirGapped        bool
	MachineID          string
}

// NewLicensingAPI creates a new API handler
func NewLicensingAPI(deps LicensingDeps) *LicensingAPI {
	return &LicensingAPI{
		clientManager:      deps.ClientManager,
		registryManager:    deps.RegistryManager,
		dagLicenseEnforcer: deps.DagLicenseEnforcer,
		billingCalculator:  deps.BillingCalculator,
		telemetryClient:    deps.TelemetryClient,
		dagStore:           deps.DagStore,
		systemIsAirGapped:  deps.IsAirGapped,
		machineID:          deps.MachineID,
	}
}

func (api *LicensingAPI) RegisterEndpoints(mux *http.ServeMux) {
	// License
	mux.HandleFunc("POST /license/create", api.HandleCreateLicense)
	mux.HandleFunc("GET /license/{license_id}", api.HandleGetLicense)
	mux.HandleFunc("POST /license/{license_id}/upgrade", api.HandleUpgradeLicense)
	mux.HandleFunc("GET /license/{license_id}/usage", api.HandleGetLicenseUsage)

	// Node
	mux.HandleFunc("POST /dag/node", api.HandleCreateNode)
	mux.HandleFunc("DELETE /dag/node/{node_id}", api.HandleDeleteNode)
	mux.HandleFunc("GET /dag/node/{node_id}/license", api.HandleGetNodeLicense)
	mux.HandleFunc("GET /license/{license_id}/nodes", api.HandleListNodesByLicense)

	// Billing
	mux.HandleFunc("GET /billing/{license_id}/monthly", api.HandleGetMonthlyCost)
	mux.HandleFunc("GET /billing/{license_id}/history", api.HandleBillingHistory)

	// Admin
	mux.HandleFunc("GET /admin/ammit-alerts", api.HandleAmmitAlerts)
	mux.HandleFunc("GET /admin/verify-air-gap", api.HandleVerifyAirGap)
	mux.HandleFunc("POST /admin/{license_id}/renew-offline-license", api.HandleRenewOfflineLicense)
	mux.HandleFunc("GET /admin/dashboard", api.HandleDashboard)

	// Telemetry
	mux.HandleFunc("POST /telemetry/enroll", api.HandleEnrollWithToken)
	mux.HandleFunc("POST /telemetry/validate", api.HandleValidateLicense)
	mux.HandleFunc("POST /telemetry/heartbeat", api.HandleHeartbeat)
	mux.HandleFunc("GET /telemetry/status", api.HandleTelemetryStatus)
}

func (api *LicensingAPI) HandleCreateLicense(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LicenseID string               `json:"license_id"`
		Tier      license.EgyptianTier `json:"tier"`
		Duration  int                  `json:"duration_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	l, err := api.registryManager.CreateLicense(req.LicenseID, req.Tier, req.Duration)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(l)
}

func (api *LicensingAPI) HandleGetLicense(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("license_id")
	l, err := api.registryManager.GetLicense(id)
	if err != nil {
		http.Error(w, "license not found", http.StatusNotFound)
		return
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(l)
}

func (api *LicensingAPI) HandleUpgradeLicense(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("license_id")
	var req struct {
		Tier license.EgyptianTier `json:"tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if err := api.registryManager.UpgradeLicense(id, req.Tier); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	l, _ := api.registryManager.GetLicense(id)
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(l)
}

func (api *LicensingAPI) HandleGetLicenseUsage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("license_id")
	stats := api.dagLicenseEnforcer.GetLicenseUsageStats(id)
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(stats)
}

func (api *LicensingAPI) HandleCreateNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LicenseID string `json:"license_id"`
		NodeID    string `json:"node_id"`
		Type      string `json:"type"`
		Level     int    `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if err := api.dagLicenseEnforcer.CanCreateNode(req.LicenseID, req.NodeID, req.Type, req.Level); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if err := api.dagLicenseEnforcer.RegisterNodeCreation(req.LicenseID, req.NodeID, req.Level); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"status":"created","node_id":"%s"}`, req.NodeID)
}

func (api *LicensingAPI) HandleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("node_id")
	if err := api.dagLicenseEnforcer.CanRemoveNode(id); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *LicensingAPI) HandleGetNodeLicense(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("node_id")
	binding, err := api.dagLicenseEnforcer.GetNodeLicense(id)
	if err != nil {
		http.Error(w, "node binding not found", http.StatusNotFound)
		return
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(binding)
}

func (api *LicensingAPI) HandleListNodesByLicense(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("license_id")
	nodes := api.dagLicenseEnforcer.ListNodesByLicense(id)
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(nodes)
}

func (api *LicensingAPI) HandleGetMonthlyCost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("license_id")
	_, err := api.registryManager.GetLicense(id)
	if err != nil {
		http.Error(w, "license not found", http.StatusNotFound)
		return
	}

	cost := api.billingCalculator.CalculateMonthlyCost()

	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(cost)
}

func (api *LicensingAPI) HandleBillingHistory(w http.ResponseWriter, r *http.Request) {
	history := []map[string]interface{}{
		{"month": "January", "amount": 50.0},
		{"month": "February", "amount": 50.0},
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(history)
}

func (api *LicensingAPI) HandleAmmitAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := api.dagLicenseEnforcer.GetAmmitAlertStatus()
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(alerts)
}

func (api *LicensingAPI) HandleVerifyAirGap(w http.ResponseWriter, _ *http.Request) {
	status := map[string]interface{}{
		"is_air_gapped": api.systemIsAirGapped,
		"machine_id":    api.machineID,
		"verified_at":   time.Now(),
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(status)
}

func (api *LicensingAPI) HandleRenewOfflineLicense(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("license_id")
	sig, err := api.dagLicenseEnforcer.RekeyOfflineLicense(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(map[string]string{"new_signature": sig})
}

func (api *LicensingAPI) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_licenses": api.registryManager.GetLicenseCount(),
		"by_tier": map[string]int{
			"khepri": api.registryManager.CountByTier(license.TierKhepri),
			"ra":     api.registryManager.CountByTier(license.TierRa),
			"atum":   api.registryManager.CountByTier(license.TierAtum),
			"osiris": api.registryManager.CountByTier(license.TierOsiris),
		},
		"total_nodes":   api.dagLicenseEnforcer.GetNodeCount(),
		"active_alerts": len(api.dagLicenseEnforcer.GetAmmitAlertStatus()),
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(stats)
}

func (api *LicensingAPI) HandleEnrollWithToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if api.telemetryClient == nil {
		http.Error(w, ErrTelemetryNotInitialized, http.StatusServiceUnavailable)
		return
	}

	resp, err := api.telemetryClient.RegisterWithEnrollmentToken(api.machineID, "standard", "khepri")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(resp)
}

func (api *LicensingAPI) HandleValidateLicense(w http.ResponseWriter, _ *http.Request) {
	if api.telemetryClient == nil {
		http.Error(w, ErrTelemetryNotInitialized, http.StatusServiceUnavailable)
		return
	}

	resp, err := api.telemetryClient.ValidateLicense(api.machineID, "sig", "v1", "inst")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(resp)
}

func (api *LicensingAPI) HandleHeartbeat(w http.ResponseWriter, _ *http.Request) {
	if api.telemetryClient == nil {
		http.Error(w, ErrTelemetryNotInitialized, http.StatusServiceUnavailable)
		return
	}

	resp, err := api.telemetryClient.HeartbeatLicense("lic", api.machineID, "sig", 0, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(resp)
}

func (api *LicensingAPI) HandleTelemetryStatus(w http.ResponseWriter, _ *http.Request) {
	if api.telemetryClient == nil {
		http.Error(w, ErrTelemetryNotInitialized, http.StatusServiceUnavailable)
		return
	}

	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "connected",
		"ts":     time.Now().String(),
	})
}
