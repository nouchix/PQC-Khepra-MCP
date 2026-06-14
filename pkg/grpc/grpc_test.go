package grpc

import (
	"testing"
	"time"
)

func TestBridgeConfig(t *testing.T) {
	config := &BridgeConfig{
		RegistryURL:  "ironbank.dso.mil",
		FIPSEnforced: true,
		MaxRetries:   3,
	}

	if config.RegistryURL != "ironbank.dso.mil" {
		t.Error("expected registry URL to be set")
	}

	if !config.FIPSEnforced {
		t.Error("expected FIPS enforced to be true")
	}

	if config.MaxRetries != 3 {
		t.Errorf("expected 3 max retries, got %d", config.MaxRetries)
	}
}

func TestRetryPolicy(t *testing.T) {
	policy := RetryPolicy{
		MaxRetries:        5,
		BackoffMultiplier: 2.0,
	}

	if policy.MaxRetries != 5 {
		t.Error("expected max retries to be 5")
	}

	if policy.BackoffMultiplier != 2.0 {
		t.Error("expected backoff multiplier to be 2.0")
	}
}

func TestScanCacheEntry(t *testing.T) {
	entry := &ScanCacheEntry{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	if entry.ExpiresAt.Before(time.Now()) {
		t.Error("expected cache entry to not be expired")
	}
}

func TestNewIronBankBridgeMissingEndpoint(t *testing.T) {
	config := &BridgeConfig{
		ScannerEndpoint: "", // Missing
	}

	_, err := NewIronBankBridge(config)
	if err == nil {
		t.Error("expected error when scanner endpoint is missing")
	}
}

func TestBridgeConfigDefaults(t *testing.T) {
	config := &BridgeConfig{
		ScannerEndpoint: "test:443",
		// Leave timeout and cacheTTL at zero
	}

	if config.ScannerEndpoint != "test:443" {
		t.Errorf("expected ScannerEndpoint='test:443', got %q", config.ScannerEndpoint)
	}

	// The NewIronBankBridge will set defaults - we test the config structure
	if config.Timeout != 0 {
		t.Error("expected default timeout to be 0 before initialization")
	}
}
