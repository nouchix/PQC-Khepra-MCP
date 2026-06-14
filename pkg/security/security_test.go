//go:build saas

package security

import (
	"testing"
)

// ─── DefaultBootstrapConfig ──────────────────────────────────────────────────

func TestDefaultBootstrapConfig_Defaults(t *testing.T) {
	cfg := DefaultBootstrapConfig()
	if cfg == nil {
		t.Fatal("DefaultBootstrapConfig returned nil")
	}
	if !cfg.EnableThreatDetection {
		t.Error("EnableThreatDetection should default to true")
	}
	if !cfg.EnableAutoResponse {
		t.Error("EnableAutoResponse should default to true")
	}
	if !cfg.EnableMetrics {
		t.Error("EnableMetrics should default to true")
	}
	if cfg.ThreatThreshold <= 0 || cfg.ThreatThreshold > 1.0 {
		t.Errorf("ThreatThreshold should be in (0,1], got %f", cfg.ThreatThreshold)
	}
}

// ─── GetSecurityMetrics ──────────────────────────────────────────────────────

func TestGetSecurityMetrics_UninitializedState(t *testing.T) {
	// Reset global state for isolated test
	securityMetrics = nil

	metrics := GetSecurityMetrics()
	if metrics == nil {
		t.Fatal("GetSecurityMetrics should not return nil")
	}
	initialized, ok := metrics["initialized"].(bool)
	if !ok || initialized {
		t.Error("expected initialized=false before Bootstrap")
	}
}

func TestGetSecurityMetrics_AfterInitMetrics(t *testing.T) {
	initializeMetrics()
	defer func() { securityMetrics = nil }()

	metrics := GetSecurityMetrics()
	if _, ok := metrics["uptime_seconds"]; !ok {
		t.Error("expected uptime_seconds in metrics after initialization")
	}
	if _, ok := metrics["threats_detected"]; !ok {
		t.Error("expected threats_detected in metrics")
	}
}

// ─── Increment counters ──────────────────────────────────────────────────────

func TestIncrementCounters_Safe(t *testing.T) {
	// Should not panic when called with nil securityMetrics
	securityMetrics = nil
	IncrementEncryptions()
	IncrementDecryptions()
	IncrementThreatsDetected()
	IncrementThreatsBlocked()
}

func TestIncrementCounters_WithMetrics(t *testing.T) {
	initializeMetrics()
	defer func() { securityMetrics = nil }()

	IncrementEncryptions()
	IncrementEncryptions()
	IncrementThreatsDetected()

	if securityMetrics.TotalEncryptions != 2 {
		t.Errorf("expected 2 encryptions, got %d", securityMetrics.TotalEncryptions)
	}
	if securityMetrics.ThreatsDetected != 1 {
		t.Errorf("expected 1 threat detected, got %d", securityMetrics.ThreatsDetected)
	}
}

// ─── HealthCheck ─────────────────────────────────────────────────────────────

func TestHealthCheck_UninitialisedKeys(t *testing.T) {
	// With GlobalKeys nil the result should reflect unhealthy state
	health := HealthCheck()
	if health == nil {
		t.Fatal("HealthCheck returned nil")
	}
	if _, ok := health["status"]; !ok {
		t.Error("expected status key in HealthCheck result")
	}
	if _, ok := health["timestamp"]; !ok {
		t.Error("expected timestamp key in HealthCheck result")
	}
}
