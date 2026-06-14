package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/agi"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/config"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

func TestDagAdd(t *testing.T) {
	// Setup
	cfg := config.Load()
	store := dag.NewMemory()
	arch := agi.NewEngine(store)
	s := &server{cfg: cfg, store: store, agi: arch}

	// Create Request
	payload := map[string]interface{}{
		"action":  "test-action",
		"symbol":  "TestSymbol",
		"parents": []string{},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/dag/add", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	// Execute
	s.dagAdd(w, req)

	// Assert
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
		// debug body
		t.Logf("Response Body: %s", w.Body.String())
	}

	var respData map[string]string
	if err := json.NewDecoder(w.Body).Decode(&respData); err != nil {
		t.Fatal(err)
	}

	if respData["node_id"] == "" {
		t.Error("Expected node_id to be set")
	}
}

func TestHealth(t *testing.T) {
	cfg := config.Load()
	s := &server{cfg: cfg}

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	s.health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if status, exists := resp["status"]; !exists || status != "ok" {
		t.Error("Expected status: ok")
	}
}
