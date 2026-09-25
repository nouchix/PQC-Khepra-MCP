// cmd/licensemock/main.go — Sovereign dev license mock server
//
// Replaces the Cloudflare Wrangler dependency in local development.
// Serves a single /validate endpoint that mimics the production
// license validation response from nouchix.com.
//
// Usage:
//   go run ./cmd/licensemock              # default port 8787
//   go run ./cmd/licensemock -port 9000   # custom port
//
// Set in environment before running adinkhepra.py:
//   KHEPRA_LICENSE_SERVER=http://localhost:8787
//
// No Node.js. No npm. No Cloudflare dependency in dev.
// Zero external calls. Sovereign by default.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

const banner = `
  ┌─────────────────────────────────────────────────┐
  │  KHEPRA License Mock Server                     │
  │  Sovereign dev replacement for Cloudflare Wrangler│
  │  No Node.js · No npm · No external calls        │
  └─────────────────────────────────────────────────┘
`

// LicenseResponse mirrors the production nouchix.com /validate response.
type LicenseResponse struct {
	Valid     bool   `json:"valid"`
	Plan      string `json:"plan"`
	ExpiresAt string `json:"expires_at"`
	NodeID    string `json:"node_id,omitempty"`
	Message   string `json:"message"`
	Mock      bool   `json:"mock"` // always true — signals this is a dev mock
}

// LicenseRequest is the optional body sent by the agent on validation.
type LicenseRequest struct {
	LicenseKey string `json:"license_key,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	Version    string `json:"version,omitempty"`
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-License-Source", "khepra-licensemock")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var req LicenseRequest
	if r.Body != nil {
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	// Mock response: always valid, sovereign plan, expires far in the future.
	// The agent treats this identically to a real validation response.
	resp := LicenseResponse{
		Valid:     true,
		Plan:      "sovereign-dev",
		ExpiresAt: time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339),
		NodeID:    req.NodeID,
		Message:   "Dev mock — sovereign license granted. Replace with real key for production.",
		Mock:      true,
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Printf("[licensemock] /validate  node=%q plan=%s mock=true", req.NodeID, resp.Plan)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","service":"khepra-licensemock","mock":true}`)
}

func main() {
	port := flag.Int("port", 8787, "Port to listen on (default: 8787, same as wrangler dev)")
	flag.Parse()

	fmt.Print(banner)

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", handleValidate)
	mux.HandleFunc("/healthz", handleHealthz)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("[licensemock] Listening on http://%s", addr)
	log.Printf("[licensemock] Set KHEPRA_LICENSE_SERVER=http://%s in your environment", addr)
	log.Printf("[licensemock] Use 'go run ./cmd/licensemock' — no Node.js, no Wrangler required")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[licensemock] Server error: %v", err)
	}
}
