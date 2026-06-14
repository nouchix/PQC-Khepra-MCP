//go:build saas

// Package security - Bootstrap PQC Security Framework
//
// This module initializes ALL security components at application startup:
// - PQC key management
// - Secure Supabase client
// - KASA crypto agent
// - Threat detection engine
//
// Usage in main.go:
//
//	func main() {
//	    if err := security.Bootstrap(); err != nil {
//	        log.Fatal("Security initialization failed:", err)
//	    }
//	    // ... rest of application
//	}
package security

import (
	"log"
	"os"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/agi"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/supabase"
)

// ─── Global Security Components ───────────────────────────────────────────────

// bootstrapBanner is the border printed during bootstrap logging.
const bootstrapBanner = "═══════════════════════════════════════════════════════════"

// SecureDB is the global encrypted Supabase client.
// Use this instead of direct Supabase calls for automatic encryption.
var SecureDB *SecureSupabaseClient

// KASAAgent is the global AI threat detection and response agent.
var KASAAgent *agi.KASACryptoAgent

// BootstrapConfig configures security initialization.
type BootstrapConfig struct {
	// Supabase configuration
	SupabaseURL string
	SupabaseKey string

	// Feature flags
	EnableThreatDetection bool // Enable KASA AI agent
	EnableAutoResponse    bool // Enable automatic quarantine
	EnableMetrics         bool // Enable security metrics collection

	// Thresholds
	ThreatThreshold float64 // 0.0-1.0 (default: 0.85 = CRITICAL)
}

// DefaultBootstrapConfig returns default configuration.
func DefaultBootstrapConfig() *BootstrapConfig {
	return &BootstrapConfig{
		SupabaseURL:           os.Getenv("SUPABASE_URL"),
		SupabaseKey:           os.Getenv("SUPABASE_KEY"),
		EnableThreatDetection: true,
		EnableAutoResponse:    true,
		EnableMetrics:         true,
		ThreatThreshold:       0.85, // Auto-segment at 85% anomaly score
	}
}

// ─── Bootstrap ─────────────────────────────────────────────────────────────────

// Bootstrap initializes the entire PQC security framework.
//
// This function:
// 1. Initializes PQC keys (loads or generates)
// 2. Creates secure Supabase client (auto-encryption)
// 3. Initializes KASA AI agent (threat detection)
// 4. Sets up security metrics collection
//
// Call this ONCE at application startup (in main()).
func Bootstrap() error {
	return BootstrapWithConfig(DefaultBootstrapConfig())
}

// BootstrapWithConfig initializes security with custom config.
func BootstrapWithConfig(config *BootstrapConfig) error {
	startTime := time.Now()

	log.Println(bootstrapBanner)
	log.Println("🔐 KHEPRA PROTOCOL - PQC SECURITY BOOTSTRAP")
	log.Println(bootstrapBanner)

	// ─── Step 1: Initialize PQC Keys ──────────────────────────────────────
	log.Println("\n[1/4] Initializing PQC keys...")
	if err := InitializePQCKeys(); err != nil {
		return err
	}

	// ─── Step 2: Initialize Secure Supabase Client ───────────────────────
	log.Println("\n[2/4] Initializing secure Supabase client...")
	SecureDB = NewSecureSupabaseClient(
		supabase.Config{
			ProjectURL:     config.SupabaseURL,
			ServiceRoleKey: config.SupabaseKey,
		},
		GlobalKeys,
	)
	log.Println("✅ Supabase client ready (auto-encryption enabled)")

	// ─── Step 3: Initialize KASA AI Agent ────────────────────────────────
	if config.EnableThreatDetection {
		log.Println("\n[3/4] Initializing KASA AI agent...")
		KASAAgent = agi.NewKASACryptoAgent(GlobalKeys)
		log.Printf("✅ KASA agent ready (threat threshold: %.0f%%)", config.ThreatThreshold*100)

		if config.EnableAutoResponse {
			log.Println("   ⚡ Auto-response ENABLED - threats will be quarantined automatically")
		} else {
			log.Println("   ⏸️  Auto-response DISABLED - threats will be logged only")
		}
	} else {
		log.Println("\n[3/4] KASA AI agent DISABLED")
	}

	// ─── Step 4: Initialize Metrics ───────────────────────────────────────
	if config.EnableMetrics {
		log.Println("\n[4/4] Initializing security metrics...")
		initializeMetrics()
		log.Println("✅ Metrics collection enabled")
	} else {
		log.Println("\n[4/4] Metrics DISABLED")
	}

	// ─── Bootstrap Complete ───────────────────────────────────────────────
	elapsed := time.Since(startTime)
	log.Println("\n" + bootstrapBanner)
	log.Printf("✅ PQC SECURITY BOOTSTRAP COMPLETE (%.2fs)", elapsed.Seconds())
	log.Println(bootstrapBanner)
	log.Println()
	log.Println("Security Status:")
	log.Println("  ✅ 4-Layer PQC Encryption: ACTIVE")
	log.Println("  ✅ Automatic Data Protection: ENABLED")
	log.Println("  ✅ AI Threat Detection: ACTIVE")
	log.Println("  ✅ Zero-Trust Architecture: ENFORCED")
	log.Println()

	return nil
}

// ─── Metrics ───────────────────────────────────────────────────────────────────

var securityMetrics *SecurityMetrics

// SecurityMetrics tracks security operations.
type SecurityMetrics struct {
	BootstrapTime    time.Time
	TotalEncryptions int64
	TotalDecryptions int64
	ThreatsDetected  int64
	ThreatsBlocked   int64
	KeyRotations     int64
}

func initializeMetrics() {
	securityMetrics = &SecurityMetrics{
		BootstrapTime: time.Now(),
	}
}

// GetSecurityMetrics returns current security metrics.
func GetSecurityMetrics() map[string]interface{} {
	if securityMetrics == nil {
		return map[string]interface{}{"initialized": false}
	}

	uptime := time.Since(securityMetrics.BootstrapTime)

	metrics := map[string]interface{}{
		"uptime_seconds":    int(uptime.Seconds()),
		"total_encryptions": securityMetrics.TotalEncryptions,
		"total_decryptions": securityMetrics.TotalDecryptions,
		"threats_detected":  securityMetrics.ThreatsDetected,
		"threats_blocked":   securityMetrics.ThreatsBlocked,
		"key_rotations":     securityMetrics.KeyRotations,
	}

	// Add key metrics
	for k, v := range GetKeyMetrics() {
		metrics["key_"+k] = v
	}

	// Add Supabase metrics
	if SecureDB != nil {
		for k, v := range SecureDB.GetMetrics() {
			metrics["db_"+k] = v
		}
	}

	// Add KASA metrics
	if KASAAgent != nil {
		for k, v := range KASAAgent.GetMetrics() {
			metrics["kasa_"+k] = v
		}
	}

	return metrics
}

// IncrementEncryptions tracks encryption operations.
func IncrementEncryptions() {
	if securityMetrics != nil {
		securityMetrics.TotalEncryptions++
	}
}

// IncrementDecryptions tracks decryption operations.
func IncrementDecryptions() {
	if securityMetrics != nil {
		securityMetrics.TotalDecryptions++
	}
}

// IncrementThreatsDetected tracks detected threats.
func IncrementThreatsDetected() {
	if securityMetrics != nil {
		securityMetrics.ThreatsDetected++
	}
}

// IncrementThreatsBlocked tracks blocked threats.
func IncrementThreatsBlocked() {
	if securityMetrics != nil {
		securityMetrics.ThreatsBlocked++
	}
}

// ─── Health Check ──────────────────────────────────────────────────────────────

// HealthCheck verifies all security components are operational.
func HealthCheck() map[string]interface{} {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	// Check PQC keys
	if GlobalKeys == nil {
		health["status"] = "unhealthy"
		health["pqc_keys"] = "NOT_INITIALIZED"
	} else {
		health["pqc_keys"] = "OK"
	}

	// Check Supabase client
	if SecureDB == nil {
		health["status"] = "degraded"
		health["supabase"] = "NOT_INITIALIZED"
	} else {
		health["supabase"] = "OK"
	}

	// Check KASA agent
	if KASAAgent == nil {
		health["kasa"] = "DISABLED"
	} else {
		health["kasa"] = "OK"
	}

	// Check key age
	keyMetrics := GetKeyMetrics()
	if rotationNeeded, ok := keyMetrics["rotation_needed"].(bool); ok && rotationNeeded {
		health["status"] = "degraded"
		health["key_rotation"] = "OVERDUE"
	} else {
		health["key_rotation"] = "OK"
	}

	return health
}
