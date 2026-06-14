package license

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestGenerateMachineID ensures the ID is consistent and follows format
func TestGenerateMachineID(t *testing.T) {
	id1 := GenerateMachineID()
	id2 := GenerateMachineID()

	if id1 == "" {
		t.Error("Machine ID should not be empty")
	}

	if id1 != id2 {
		t.Errorf("Machine ID should be stable. Got %s and %s", id1, id2)
	}

	if len(id1) < 10 {
		t.Errorf("Machine ID mostly likely too short: %s", id1)
	}
}

// TestManager_Initialize verifies the manager behaves correctly with a mock server
func TestManager_Initialize(t *testing.T) {
	// 1. Mock Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Request
		if r.URL.Path != "/license/validate" {
			t.Errorf("Expected path /license/validate, got %s", r.URL.Path)
		}

		// Mock Response
		resp := ValidateResponse{
			Valid:        true,
			Organization: "Test Corp",
			LicenseTier:  "enterprise",
			ExpiresAt:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Features:     []string{"advanced_reporting", "ai_defense"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// 2. Initialize Manager
	manager, err := NewManager(server.URL)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Generate and set valid private key for signing
	_, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	// We need the hex string of the PRIVATE key
	privBytes, _ := priv.MarshalBinary()
	manager.SetPrivateKey(hex.EncodeToString(privBytes))

	// Note: In a real test we'd verify the signature on the server side causing issues if pub key isn't known
	// But our mock server ignores signature validation, just returns valid json.

	// 3. Run Initialize
	err = manager.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// 4. Verify State
	if manager.GetTier() != "enterprise" {
		t.Errorf("Expected tier enterprise, got %s", manager.GetTier())
	}

	if !manager.HasFeature("ai_defense") {
		t.Error("Expected feature ai_defense to be present")
	}

	if manager.HasFeature("missing_feature") {
		t.Error("Expected missing_feature to be false")
	}
}

// TestManager_OfflineFallback verifies community fallback on error
func TestManager_OfflineFallback(t *testing.T) {
	// 1. Mock Server that fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Offline", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// 2. Initialize Manager
	manager, err := NewManager(server.URL)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// 3. Run Initialize -> Should error but allow inspection (or be nil if loose fallback)
	// Current implementation: Returns error if online validation fails and no cached grace period
	err = manager.Initialize()
	if err == nil {
		t.Error("Expected error when server is offline and no cache exists")
	}

	// 4. Verify Community Fallback State (Safe Default)
	if manager.GetTier() != "community" {
		t.Errorf("Expected tier community (safemode), got %s", manager.GetTier())
	}
}
