package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/scada"
)

// ── Audit types ───────────────────────────────────────────────────────────────

type auditChannel struct {
	Name   string `json:"name"`
	Status string `json:"status"` // EXPOSED | SIGNED | NONE
	MITRE  string `json:"mitre"`
	Note   string `json:"note"`
}

type mitreFinding struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

type auditResponse struct {
	RiskLevel string         `json:"risk_level"`
	Channels  []auditChannel `json:"channels"`
	Findings  []mitreFinding `json:"findings"`
}

// globalPoller is started once by initSCADAPoller and used by all handlers.
var globalPoller *scada.Poller

// initSCADAPoller starts the background Modbus poller and wires the HTTP endpoints.
func initSCADAPoller(mux *http.ServeMux) {
	host   := getenv("SCADA_HOST", "10.187.242.136")
	port   := getenvInt("SCADA_PORT", 502)
	unitID := byte(getenvInt("SCADA_UNIT_ID", 2))

	globalPoller = scada.NewPoller(scada.Config{
		Host:   host,
		Port:   port,
		UnitID: unitID,
	})
	go globalPoller.Run(context.Background())

	mux.HandleFunc("/api/scada/live",  scadaLiveHandler)
	mux.HandleFunc("/api/scada/audit", scadaAuditHandler)
	mux.HandleFunc("/api/scada/coil",  scadaCoilHandler)
}

// GET /api/scada/live — latest sensor snapshot
func scadaLiveHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalPoller.State()) //nolint:errcheck
}

// GET /api/scada/audit — static OT channel security posture
func scadaAuditHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}
	w.Header().Set("Content-Type", "application/json")

	resp := auditResponse{
		RiskLevel: "HIGH",
		Channels: []auditChannel{
			{
				Name:   "Modbus TCP :502",
				Status: "EXPOSED",
				MITRE:  "T0855",
				Note:   "No auth — any LAN device can issue FC05 coil writes to physical outputs",
			},
			{
				Name:   "MQTT :1883",
				Status: "EXPOSED",
				MITRE:  "T0859",
				Note:   "Plaintext broker — credentials and sensor telemetry visible on network",
			},
			{
				Name:   "SCORPION Channel",
				Status: "SIGNED",
				MITRE:  "",
				Note:   "HMAC-Argon2ID signed — integrity verified by AdinKhepra",
			},
			{
				Name:   "TLS / Encryption",
				Status: "NONE",
				MITRE:  "T0830",
				Note:   "No TLS on any OT channel — full MitM exposure across all sensors",
			},
		},
		Findings: []mitreFinding{
			{ID: "T0855", Name: "Unauthorized Command", Severity: "HIGH"},
			{ID: "T0859", Name: "Valid Accounts (eavesdrop)", Severity: "HIGH"},
			{ID: "T0830", Name: "Man-in-the-Middle", Severity: "CRITICAL"},
			{ID: "T0862", Name: "Supply Chain Compromise", Severity: "HIGH"},
		},
	}
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// POST /api/scada/coil — write a single coil (Buzzer or LED alarm).
// Body: { "coil": 0, "value": true }
// Coil 0 = Buzzer (Pin 25), Coil 1 = RGB LED alarm (Pin 26/27).
func scadaCoilHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Coil  uint16 `json:"coil"`
		Value bool   `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	if req.Coil > 1 {
		http.Error(w, `{"error":"coil must be 0 (buzzer) or 1 (led)"}`, http.StatusBadRequest)
		return
	}

	if err := globalPoller.WriteCoilNow(req.Coil, req.Value); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
