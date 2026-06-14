package license

import (
	"fmt"
	"testing"
	"time"
)

// ─── Key Generation Tests ──────────────────────────────────────────────────────

func TestGenerateProtectionKeys(t *testing.T) {
	keys, err := GenerateProtectionKeys("Eban")
	if err != nil {
		t.Fatalf("Failed to generate protection keys: %v", err)
	}

	// Verify Kyber keys
	if len(keys.KyberPublicKey) == 0 {
		t.Error("Kyber public key is empty")
	}
	if len(keys.KyberPrivateKey) == 0 {
		t.Error("Kyber private key is empty")
	}

	// Verify Dilithium keys
	if len(keys.DilithiumPublicKey) == 0 {
		t.Error("Dilithium public key is empty")
	}
	if len(keys.DilithiumPrivateKey) == 0 {
		t.Error("Dilithium private key is empty")
	}

	// Verify AES key
	if len(keys.AESKey) != 32 {
		t.Errorf("AES key should be 32 bytes, got %d", len(keys.AESKey))
	}

	// Verify symbol
	if keys.Symbol != "Eban" {
		t.Errorf("Expected symbol 'Eban', got '%s'", keys.Symbol)
	}
}

// ─── Basic Protection/Unprotection Tests ──────────────────────────────────────

func TestProtectUnprotectData(t *testing.T) {
	keys, err := GenerateProtectionKeys("Fawohodie")
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Test data
	testData := map[string]interface{}{
		"license_id": "test-001",
		"tier":       "Osiris",
		"features":   []string{"all-features", "air-gap"},
		"quota":      -1,
	}

	// Protect data
	protected, err := ProtectData(testData, "license", ContextAtRest, keys, nil, time.Time{})
	if err != nil {
		t.Fatalf("Failed to protect data: %v", err)
	}

	// Verify protected structure
	if protected.DataType != "license" {
		t.Errorf("Expected data type 'license', got '%s'", protected.DataType)
	}
	if protected.Context != ContextAtRest {
		t.Errorf("Expected context 'at_rest', got '%s'", protected.Context)
	}
	if protected.EncryptionScheme != "ADINKHEPRA_AES256GCM_KYBER1024_MLDSA65" {
		t.Error("Unexpected encryption scheme")
	}
	if len(protected.DilithiumSignature) == 0 {
		t.Error("Dilithium signature is empty")
	}
	if len(protected.EncryptedPayload) == 0 {
		t.Error("Encrypted payload is empty")
	}

	// Unprotect data
	decrypted, err := UnprotectData(protected, keys, nil)
	if err != nil {
		t.Fatalf("Failed to unprotect data: %v", err)
	}

	// Verify decrypted data matches original
	if decrypted["license_id"] != testData["license_id"] {
		t.Error("License ID mismatch after decryption")
	}
	if decrypted["tier"] != testData["tier"] {
		t.Error("Tier mismatch after decryption")
	}
}

// ─── Transit Encryption Tests ──────────────────────────────────────────────────

func TestProtectUnprotectTransit(t *testing.T) {
	// Generate sender and recipient keys
	senderKeys, _ := GenerateProtectionKeys("Eban")
	recipientKeys, _ := GenerateProtectionKeys("Sankofa")

	testData := map[string]interface{}{
		"message": "Sensitive license transfer",
		"from":    "authority-001",
		"to":      "node-42",
	}

	// Protect for transit with recipient's Kyber public key
	protected, err := ProtectForTransit(testData, "transfer", senderKeys, recipientKeys.KyberPublicKey)
	if err != nil {
		t.Fatalf("Failed to protect for transit: %v", err)
	}

	// Verify Kyber capsule is present
	if len(protected.KyberCapsule) == 0 {
		t.Error("Kyber capsule should be present for transit encryption")
	}

	// Verify expiration is set
	if protected.ExpiresAt.IsZero() {
		t.Error("Transit data should have expiration set")
	}

	// Recipient decrypts using their private key
	decrypted, err := UnprotectFromTransit(protected, recipientKeys, senderKeys.DilithiumPublicKey)
	if err != nil {
		t.Fatalf("Failed to unprotect from transit: %v", err)
	}

	// Verify decrypted data
	if decrypted["message"] != testData["message"] {
		t.Error("Message mismatch after transit decryption")
	}
}

// ─── License Storage Tests ─────────────────────────────────────────────────────

func TestProtectUnprotectLicense(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Eban")

	// Create test license
	license := &License{
		ID:        "pharaoh-001",
		Tier:      TierOsiris,
		NodeQuota: -1,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(1, 0, 0),
		Features: []string{
			"all-features",
			"air-gap-licensing",
		},
		DeityAuthorities: TierConfigurations[TierOsiris].DeityAuthorities,
		SephirotAccess:   TierConfigurations[TierOsiris].SephirotAccess,
	}

	// Protect license for storage
	protected, err := ProtectLicenseForStorage(license, keys)
	if err != nil {
		t.Fatalf("Failed to protect license: %v", err)
	}

	// Verify context
	if protected.Context != ContextAtRest {
		t.Error("License storage should use ContextAtRest")
	}

	// Unprotect license
	decryptedLicense, err := UnprotectLicenseFromStorage(protected, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect license: %v", err)
	}

	// Verify license data
	if decryptedLicense.ID != license.ID {
		t.Error("License ID mismatch")
	}
	if decryptedLicense.Tier != license.Tier {
		t.Error("License tier mismatch")
	}
	if len(decryptedLicense.Features) != len(license.Features) {
		t.Error("Features count mismatch")
	}
}

// ─── Audit Log Tests ───────────────────────────────────────────────────────────

func TestProtectUnprotectAuditLog(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Fawohodie")

	auditEntry := map[string]interface{}{
		"timestamp":  time.Now().Format(time.RFC3339),
		"user":       "admin@example.com",
		"action":     "LICENSE_CREATED",
		"license_id": "pharaoh-042",
		"ip_address": "10.0.1.5",
	}

	// Protect audit log
	protected, err := ProtectAuditLog(auditEntry, keys)
	if err != nil {
		t.Fatalf("Failed to protect audit log: %v", err)
	}

	// Verify context
	if protected.Context != ContextAuditLog {
		t.Error("Expected audit_log context")
	}

	// Verify no expiration (permanent retention)
	if !protected.ExpiresAt.IsZero() {
		t.Error("Audit logs should not have expiration")
	}

	// Unprotect audit log
	decrypted, err := UnprotectAuditLog(protected, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect audit log: %v", err)
	}

	// Verify data
	if decrypted["action"] != auditEntry["action"] {
		t.Error("Audit action mismatch")
	}
}

// ─── Telemetry Tests ───────────────────────────────────────────────────────────

func TestProtectUnprotectTelemetry(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Sankofa")
	recipientKeys, _ := GenerateProtectionKeys("Eban")

	telemetryData := map[string]interface{}{
		"node_id":      "node-001",
		"cpu_usage":    45.2,
		"memory_usage": 2048,
		"active_licenses": []string{
			"license-001",
			"license-002",
		},
	}

	// Protect telemetry (can be sent to external collector)
	protected, err := ProtectTelemetry(telemetryData, keys, recipientKeys.KyberPublicKey)
	if err != nil {
		t.Fatalf("Failed to protect telemetry: %v", err)
	}

	// Verify context
	if protected.Context != ContextTelemetry {
		t.Error("Expected telemetry context")
	}

	// Verify expiration (24 hours)
	expectedExpiration := time.Now().Add(24 * time.Hour)
	timeDiff := protected.ExpiresAt.Sub(expectedExpiration).Abs()
	if timeDiff > time.Second {
		t.Errorf("Telemetry expiration should be ~24 hours, got %v", protected.ExpiresAt)
	}

	// Unprotect telemetry (recipient decrypts with own keys, verifies with sender's public key)
	decrypted, err := UnprotectData(protected, recipientKeys, keys.DilithiumPublicKey)
	if err != nil {
		t.Fatalf("Failed to unprotect telemetry: %v", err)
	}

	// Verify data
	if decrypted["node_id"] != telemetryData["node_id"] {
		t.Error("Node ID mismatch")
	}
}

// ─── Backup Tests ──────────────────────────────────────────────────────────────

func TestProtectUnprotectBackup(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Eban")

	backupData := map[string]interface{}{
		"backup_id":      "backup-20260216-001",
		"license_count":  42,
		"config_version": "2.1.0",
		"timestamp":      time.Now().Format(time.RFC3339),
	}

	// Protect backup
	protected, err := ProtectBackup(backupData, "backup_snapshot", keys)
	if err != nil {
		t.Fatalf("Failed to protect backup: %v", err)
	}

	// Verify context
	if protected.Context != ContextBackup {
		t.Error("Expected backup context")
	}

	// Verify expiration (3 years)
	expectedExpiration := time.Now().AddDate(3, 0, 0)
	timeDiff := protected.ExpiresAt.Sub(expectedExpiration).Abs()
	if timeDiff > time.Hour {
		t.Errorf("Backup expiration should be ~3 years, got %v", protected.ExpiresAt)
	}

	// Unprotect backup
	decrypted, err := UnprotectBackup(protected, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect backup: %v", err)
	}

	// Verify data
	if decrypted["backup_id"] != backupData["backup_id"] {
		t.Error("Backup ID mismatch")
	}
}

// ─── Archive Tests ─────────────────────────────────────────────────────────────

func TestProtectUnprotectArchive(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Fawohodie")

	archiveData := map[string]interface{}{
		"archive_id":     "archive-2026-Q1",
		"compliance":     "CMMC-L1",
		"license_count":  150,
		"retention_date": time.Now().AddDate(7, 0, 0).Format(time.RFC3339),
	}

	// Protect archive
	protected, err := ProtectArchive(archiveData, "compliance_archive", keys)
	if err != nil {
		t.Fatalf("Failed to protect archive: %v", err)
	}

	// Verify context
	if protected.Context != ContextArchive {
		t.Error("Expected archive context")
	}

	// Verify expiration (7 years)
	expectedExpiration := time.Now().AddDate(7, 0, 0)
	timeDiff := protected.ExpiresAt.Sub(expectedExpiration).Abs()
	if timeDiff > time.Hour {
		t.Errorf("Archive expiration should be ~7 years, got %v", protected.ExpiresAt)
	}

	// Unprotect archive
	decrypted, err := UnprotectArchive(protected, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect archive: %v", err)
	}

	// Verify data
	if decrypted["archive_id"] != archiveData["archive_id"] {
		t.Error("Archive ID mismatch")
	}
}

// ─── In-Use Data Tests ─────────────────────────────────────────────────────────

func TestProtectUnprotectInUse(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Sankofa")

	inUseData := map[string]interface{}{
		"session_id":    "sess-42",
		"user_id":       "user-001",
		"active_since":  time.Now().Format(time.RFC3339),
		"license_cache": []string{"license-001", "license-002"},
	}

	// Protect in-use data
	protected, err := ProtectInUse(inUseData, "session_data", keys)
	if err != nil {
		t.Fatalf("Failed to protect in-use data: %v", err)
	}

	// Verify context
	if protected.Context != ContextInUse {
		t.Error("Expected in_use context")
	}

	// Verify expiration (5 minutes)
	expectedExpiration := time.Now().Add(5 * time.Minute)
	timeDiff := protected.ExpiresAt.Sub(expectedExpiration).Abs()
	if timeDiff > time.Second {
		t.Errorf("In-use data expiration should be ~5 minutes, got %v", protected.ExpiresAt)
	}

	// Unprotect in-use data
	decrypted, err := UnprotectInUse(protected, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect in-use data: %v", err)
	}

	// Verify data
	if decrypted["session_id"] != inUseData["session_id"] {
		t.Error("Session ID mismatch")
	}
}

// ─── Config Protection Tests ───────────────────────────────────────────────────

func TestProtectUnprotectConfig(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Eban")

	configData := map[string]interface{}{
		"api_key":      "secret-api-key-12345",
		"db_password":  "super-secret-password",
		"vault_token":  "hvs.XXXXXXXX",
		"feature_flags": []string{"air-gap", "telemetry"},
	}

	// Protect config
	protected, err := ProtectConfig(configData, keys)
	if err != nil {
		t.Fatalf("Failed to protect config: %v", err)
	}

	// Verify data type
	if protected.DataType != "config" {
		t.Error("Expected config data type")
	}

	// Unprotect config
	decrypted, err := UnprotectConfig(protected, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect config: %v", err)
	}

	// Verify data
	if decrypted["api_key"] != configData["api_key"] {
		t.Error("API key mismatch")
	}
}

// ─── Expiration Tests ──────────────────────────────────────────────────────────

func TestExpiredDataRejection(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Eban")

	testData := map[string]interface{}{
		"test": "expired data",
	}

	// Protect data with past expiration
	expiresAt := time.Now().Add(-1 * time.Hour)
	protected, err := ProtectData(testData, "test", ContextInTransit, keys, nil, expiresAt)
	if err != nil {
		t.Fatalf("Failed to protect data: %v", err)
	}

	// Try to unprotect (should fail due to expiration)
	_, err = UnprotectData(protected, keys, nil)
	if err == nil {
		t.Error("Expected expiration error, got nil")
	}

	if err != nil && err.Error() != fmt.Sprintf("protected data expired at %s", protected.ExpiresAt.Format(time.RFC3339)) {
		t.Logf("Got expected expiration error: %v", err)
	}
}

// ─── Forgery Detection Tests ───────────────────────────────────────────────────

func TestDataForgeryDetection(t *testing.T) {
	keys1, _ := GenerateProtectionKeys("Eban")
	keys2, _ := GenerateProtectionKeys("Fawohodie")

	testData := map[string]interface{}{
		"data": "sensitive information",
	}

	// Protect with keys1
	protected, err := ProtectData(testData, "test", ContextAtRest, keys1, nil, time.Time{})
	if err != nil {
		t.Fatalf("Failed to protect data: %v", err)
	}

	// Try to verify with keys2's public key (should fail)
	_, err = UnprotectData(protected, keys2, keys2.DilithiumPublicKey)
	if err == nil {
		t.Error("Expected forgery detection error, got nil")
	}
}

// ─── Export/Import Tests ───────────────────────────────────────────────────────

func TestExportImportProtectedData(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Sankofa")

	testData := map[string]interface{}{
		"id":    "test-001",
		"value": 42,
	}

	// Protect data
	protected, err := ProtectData(testData, "test", ContextAtRest, keys, nil, time.Time{})
	if err != nil {
		t.Fatalf("Failed to protect data: %v", err)
	}

	// Export to string
	exported, err := ExportProtectedData(protected)
	if err != nil {
		t.Fatalf("Failed to export protected data: %v", err)
	}

	if len(exported) == 0 {
		t.Error("Exported string is empty")
	}

	// Import from string
	imported, err := ImportProtectedData(exported)
	if err != nil {
		t.Fatalf("Failed to import protected data: %v", err)
	}

	// Verify imported data matches original
	if imported.DataID != protected.DataID {
		t.Error("Data ID mismatch after import")
	}
	if imported.LatticeHash != protected.LatticeHash {
		t.Error("Lattice hash mismatch after import")
	}

	// Verify imported data can be decrypted
	decrypted, err := UnprotectData(imported, keys, nil)
	if err != nil {
		t.Fatalf("Failed to unprotect imported data: %v", err)
	}

	if decrypted["value"].(float64) != 42 {
		t.Error("Value mismatch after import/decrypt")
	}
}

// ─── Multi-Layer Verification Tests ────────────────────────────────────────────

func TestAllLayersIntegrity(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Eban")

	testData := map[string]interface{}{
		"critical": "data",
	}

	// Protect data
	protected, err := ProtectData(testData, "test", ContextAtRest, keys, nil, time.Time{})
	if err != nil {
		t.Fatalf("Failed to protect data: %v", err)
	}

	// Test 1: Tamper with lattice hash
	originalHash := protected.LatticeHash
	protected.LatticeHash = "tampered-hash"
	_, err = UnprotectData(protected, keys, nil)
	if err == nil {
		t.Error("Should detect lattice hash tampering")
	}
	protected.LatticeHash = originalHash // Restore

	// Test 2: Tamper with signature
	originalSig := make([]byte, len(protected.DilithiumSignature))
	copy(originalSig, protected.DilithiumSignature)
	protected.DilithiumSignature[0] ^= 0xFF // Flip bits
	_, err = UnprotectData(protected, keys, nil)
	if err == nil {
		t.Error("Should detect signature tampering")
	}
	copy(protected.DilithiumSignature, originalSig) // Restore

	// Test 3: Tamper with encrypted payload
	originalPayload := make([]byte, len(protected.EncryptedPayload))
	copy(originalPayload, protected.EncryptedPayload)
	if len(protected.EncryptedPayload) > 0 {
		protected.EncryptedPayload[0] ^= 0xFF
		_, err = UnprotectData(protected, keys, nil)
		if err == nil {
			t.Error("Should detect payload tampering (GCM authentication)")
		}
	}
}

// ─── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkProtectData(b *testing.B) {
	keys, _ := GenerateProtectionKeys("Eban")

	testData := map[string]interface{}{
		"license_id": "bench-001",
		"tier":       "Osiris",
		"features":   []string{"all-features"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ProtectData(testData, "license", ContextAtRest, keys, nil, time.Time{})
		if err != nil {
			b.Fatalf("Protect failed: %v", err)
		}
	}
}

func BenchmarkUnprotectData(b *testing.B) {
	keys, _ := GenerateProtectionKeys("Eban")

	testData := map[string]interface{}{
		"license_id": "bench-001",
		"tier":       "Osiris",
	}

	protected, _ := ProtectData(testData, "license", ContextAtRest, keys, nil, time.Time{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnprotectData(protected, keys, nil)
		if err != nil {
			b.Fatalf("Unprotect failed: %v", err)
		}
	}
}

// ─── Helper Functions ──────────────────────────────────────────────────────────
// (bytesEqual is defined in pqc_signing.go)
