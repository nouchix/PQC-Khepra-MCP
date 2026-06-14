package main

import (
	"os"
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/gateway"
)

func TestLoadConfig_NoFile(t *testing.T) {
	// When no config file, should return defaults
	cfg := loadConfig("")

	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	// Should have default values
	if cfg.ListenAddr == "" {
		t.Error("expected default listen address")
	}
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	// When config file doesn't exist, should return defaults
	cfg := loadConfig("/nonexistent/config.json")

	if cfg == nil {
		t.Fatal("expected non-nil config from fallback")
	}
}

func TestLoadConfig_ValidFile(t *testing.T) {
	// Create temporary config file
	tmpFile, err := os.CreateTemp("", "gateway-config-*.json")
	if err != nil {
		t.Skipf("could not create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write valid JSON config (only fields that parse correctly)
	// Note: time.Duration doesn't unmarshal from JSON strings by default,
	// so we only test string fields
	configJSON := `{
		"listen_addr": ":9443"
	}`
	tmpFile.WriteString(configJSON)
	tmpFile.Close()

	cfg := loadConfig(tmpFile.Name())

	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	// The config should have the custom listen_addr
	if cfg.ListenAddr != ":9443" {
		t.Errorf("expected listen addr ':9443', got '%s'", cfg.ListenAddr)
	}
}

func TestCreateUpstreamHandler(t *testing.T) {
	handler := createUpstreamHandler()

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := gateway.DefaultConfig()

	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}

	if cfg.ListenAddr == "" {
		t.Error("expected non-empty listen address")
	}

	if cfg.ReadTimeout == 0 {
		t.Error("expected non-zero read timeout")
	}
}

func TestPrintBanner(t *testing.T) {
	// Verify doesn't panic
	printBanner()
}
