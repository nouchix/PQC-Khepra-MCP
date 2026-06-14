//go:build saas

package license

import (
	"testing"
	"time"
)

// ─── Supabase Record Protection Tests ─────────────────────────────────────────

func TestProtectUnprotectSupabaseRecord(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Eban")

	// Test data (generic map)
	testData := map[string]interface{}{
		"user_id":   "user-123",
		"email":     "test@example.com",
		"full_name": "John Doe",
		"ssn":       "123-45-6789", // Sensitive data
	}

	// Protect for Supabase
	row, err := ProtectSupabaseRecord(testData, "user_profile", keys, time.Time{})
	if err != nil {
		t.Fatalf("Failed to protect record: %v", err)
	}

	// Verify row structure
	if row.DataType != "user_profile" {
		t.Error("DataType mismatch")
	}
	if len(row.EncryptedPayload) == 0 {
		t.Error("Encrypted payload is empty")
	}
	if len(row.DilithiumSignature) == 0 {
		t.Error("Dilithium signature is empty")
	}
	if row.EncryptionScheme != "ADINKHEPRA_AES256GCM_KYBER1024_MLDSA65" {
		t.Error("Incorrect encryption scheme")
	}

	// Unprotect from Supabase
	decrypted, err := UnprotectSupabaseRecord(row, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect record: %v", err)
	}

	// Verify decrypted data
	if decrypted["email"] != testData["email"] {
		t.Error("Email mismatch")
	}
	if decrypted["ssn"] != testData["ssn"] {
		t.Error("SSN mismatch")
	}
}

// ─── User Profile Protection Tests ────────────────────────────────────────────

func TestProtectUnprotectUserProfile(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Fawohodie")

	// Test user profile
	profile := &UserProfileData{
		Email:       "alice@example.com",
		FullName:    "Alice Smith",
		PhoneNumber: "+1-555-0123",
		Address:     "123 Main St, Anytown, USA",
		SSN:         "987-65-4321",
		Metadata: map[string]interface{}{
			"account_type": "premium",
			"verified":     true,
		},
		Preferences: map[string]interface{}{
			"theme":         "dark",
			"notifications": true,
		},
	}

	// Protect
	row, err := ProtectUserProfile(profile, keys)
	if err != nil {
		t.Fatalf("Failed to protect user profile: %v", err)
	}

	// Verify it's a Supabase row
	if row.DataType != "user_profile" {
		t.Error("DataType should be user_profile")
	}

	// Unprotect
	decryptedProfile, err := UnprotectUserProfile(row, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect user profile: %v", err)
	}

	// Verify data integrity
	if decryptedProfile.Email != profile.Email {
		t.Error("Email mismatch")
	}
	if decryptedProfile.SSN != profile.SSN {
		t.Error("SSN mismatch")
	}
	if decryptedProfile.Metadata["account_type"] != profile.Metadata["account_type"] {
		t.Error("Metadata mismatch")
	}
}

// ─── Configuration Protection Tests ───────────────────────────────────────────

func TestProtectUnprotectConfigData(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Sankofa")

	// Test config
	config := &ConfigData{
		APIKey:      "sk-test-1234567890",
		DatabaseURL: "postgresql://user:pass@localhost:5432/db",
		SecretKey:   "super-secret-key-12345",
		FeatureFlags: map[string]bool{
			"enable_pqc":     true,
			"enable_telemetry": false,
		},
		ServiceConfig: map[string]interface{}{
			"timeout": 30,
			"retries": 3,
		},
		IntegrationKeys: map[string]string{
			"stripe": "sk_live_xxxxx",
			"aws":    "AKIAIOSFODNN7EXAMPLE",
		},
	}

	// Protect
	row, err := ProtectConfigData(config, keys)
	if err != nil {
		t.Fatalf("Failed to protect config: %v", err)
	}

	// Verify
	if row.DataType != "platform_config" {
		t.Error("DataType should be platform_config")
	}

	// Unprotect
	decryptedConfig, err := UnprotectConfigData(row, keys)
	if err != nil {
		t.Fatalf("Failed to unprotect config: %v", err)
	}

	// Verify sensitive data
	if decryptedConfig.APIKey != config.APIKey {
		t.Error("API key mismatch")
	}
	if decryptedConfig.SecretKey != config.SecretKey {
		t.Error("Secret key mismatch")
	}
	if decryptedConfig.IntegrationKeys["stripe"] != config.IntegrationKeys["stripe"] {
		t.Error("Integration key mismatch")
	}
}

// ─── Transport Envelope Tests ─────────────────────────────────────────────────

func TestProtectUnprotectHTTPTransport(t *testing.T) {
	senderKeys, _ := GenerateProtectionKeys("Eban")
	recipientKeys, _ := GenerateProtectionKeys("Fawohodie")

	// Test transport envelope
	envelope := &TransportEnvelope{
		SenderID:    "api-server-001",
		RecipientID: "client-app-123",
		MessageType: "scan_result",
		Payload: map[string]interface{}{
			"scan_id": "scan-42",
			"status":  "completed",
			"findings": []string{
				"CVE-2023-1234",
				"CVE-2023-5678",
			},
		},
		Timestamp: time.Now(),
	}

	// Protect for transport
	protected, err := ProtectForHTTPTransport(envelope, senderKeys, recipientKeys.KyberPublicKey)
	if err != nil {
		t.Fatalf("Failed to protect for transport: %v", err)
	}

	// Verify encryption
	if len(protected.KyberCapsule) == 0 {
		t.Error("Kyber capsule should be present for transport")
	}
	if protected.Context != ContextInTransit {
		t.Error("Context should be in_transit")
	}

	// Verify expiration (1 hour TTL)
	expectedExpiration := time.Now().Add(1 * time.Hour)
	timeDiff := protected.ExpiresAt.Sub(expectedExpiration).Abs()
	if timeDiff > time.Second {
		t.Error("Transport data should expire in ~1 hour")
	}

	// Recipient decrypts
	decryptedEnvelope, err := UnprotectFromHTTPTransport(protected, recipientKeys, senderKeys.DilithiumPublicKey)
	if err != nil {
		t.Fatalf("Failed to unprotect from transport: %v", err)
	}

	// Verify data
	if decryptedEnvelope.SenderID != envelope.SenderID {
		t.Error("Sender ID mismatch")
	}
	if decryptedEnvelope.MessageType != envelope.MessageType {
		t.Error("Message type mismatch")
	}
	if decryptedEnvelope.Payload["scan_id"] != envelope.Payload["scan_id"] {
		t.Error("Payload mismatch")
	}
}

// ─── Batch Operations Tests ────────────────────────────────────────────────────

func TestProtectSupabaseBatch(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Eban")

	// Create batch of test records
	users := []interface{}{
		map[string]interface{}{
			"email": "user1@example.com",
			"name":  "User One",
		},
		map[string]interface{}{
			"email": "user2@example.com",
			"name":  "User Two",
		},
		map[string]interface{}{
			"email": "user3@example.com",
			"name":  "User Three",
		},
	}

	// Protect batch
	rows, errors := ProtectSupabaseBatch(users, "user_profile", keys)

	// Verify all succeeded
	for i, err := range errors {
		if err != nil {
			t.Errorf("Batch item %d failed: %v", i, err)
		}
	}

	// Verify row count
	if len(rows) != len(users) {
		t.Errorf("Expected %d rows, got %d", len(users), len(rows))
	}

	// Verify each row is encrypted
	for i, row := range rows {
		if len(row.EncryptedPayload) == 0 {
			t.Errorf("Row %d has empty encrypted payload", i)
		}
		if len(row.DilithiumSignature) == 0 {
			t.Errorf("Row %d has empty signature", i)
		}
	}
}

func TestUnprotectSupabaseBatch(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Fawohodie")

	// Create and protect batch
	users := []interface{}{
		map[string]interface{}{"email": "user1@example.com"},
		map[string]interface{}{"email": "user2@example.com"},
	}

	rows, _ := ProtectSupabaseBatch(users, "user_profile", keys)

	// Unprotect batch
	decrypted, errors := UnprotectSupabaseBatch(rows, keys)

	// Verify all succeeded
	for i, err := range errors {
		if err != nil {
			t.Errorf("Batch item %d failed: %v", i, err)
		}
	}

	// Verify data integrity
	if len(decrypted) != len(users) {
		t.Error("Decrypted count mismatch")
	}

	for i, record := range decrypted {
		originalEmail := users[i].(map[string]interface{})["email"]
		if record["email"] != originalEmail {
			t.Errorf("Row %d email mismatch", i)
		}
	}
}

// ─── Expiration Tests ──────────────────────────────────────────────────────────

func TestSupabaseRecordExpiration(t *testing.T) {
	keys, _ := GenerateProtectionKeys("Eban")

	testData := map[string]interface{}{
		"temp_token": "12345",
	}

	// Protect with past expiration
	expiresAt := time.Now().Add(-1 * time.Hour)
	row, err := ProtectSupabaseRecord(testData, "temp_data", keys, expiresAt)
	if err != nil {
		t.Fatalf("Failed to protect: %v", err)
	}

	// Try to unprotect (should fail due to expiration)
	_, err = UnprotectSupabaseRecord(row, keys)
	if err == nil {
		t.Error("Expected expiration error")
	}
}

// ─── Forgery Detection Tests ───────────────────────────────────────────────────

func TestSupabaseRecordForgeryDetection(t *testing.T) {
	keys1, _ := GenerateProtectionKeys("Eban")
	keys2, _ := GenerateProtectionKeys("Fawohodie")

	testData := map[string]interface{}{
		"data": "sensitive",
	}

	// Protect with keys1
	row, err := ProtectSupabaseRecord(testData, "test", keys1, time.Time{})
	if err != nil {
		t.Fatalf("Failed to protect: %v", err)
	}

	// Try to unprotect with keys2 (should fail)
	_, err = UnprotectSupabaseRecord(row, keys2)
	if err == nil {
		t.Error("Should detect forgery (wrong keys)")
	}
}

// ─── Schema Generation Tests ───────────────────────────────────────────────────

func TestGenerateSupabaseSchema(t *testing.T) {
	sql := GenerateSupabaseSchema("users_encrypted", "user_profile")

	// Verify SQL contains required elements
	requiredStrings := []string{
		"CREATE TABLE",
		"users_encrypted",
		"encrypted_payload",
		"dilithium_signature",
		"lattice_hash",
		"ADINKHEPRA_AES256GCM_KYBER1024_MLDSA65",
		"CREATE INDEX",
	}

	for _, required := range requiredStrings {
		if len(sql) > 0 && !contains(sql, required) {
			t.Errorf("Generated SQL missing: %s", required)
		}
	}

	// Verify length (should be substantial DDL)
	if len(sql) < 500 {
		t.Error("Generated SQL too short, likely incomplete")
	}
}

// ─── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkProtectSupabaseRecord(b *testing.B) {
	keys, _ := GenerateProtectionKeys("Eban")

	testData := map[string]interface{}{
		"email": "test@example.com",
		"name":  "Test User",
		"ssn":   "123-45-6789",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ProtectSupabaseRecord(testData, "user_profile", keys, time.Time{})
		if err != nil {
			b.Fatalf("Protect failed: %v", err)
		}
	}
}

func BenchmarkUnprotectSupabaseRecord(b *testing.B) {
	keys, _ := GenerateProtectionKeys("Eban")

	testData := map[string]interface{}{
		"email": "test@example.com",
		"name":  "Test User",
	}

	row, _ := ProtectSupabaseRecord(testData, "user_profile", keys, time.Time{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnprotectSupabaseRecord(row, keys)
		if err != nil {
			b.Fatalf("Unprotect failed: %v", err)
		}
	}
}

// ─── Helper Functions ──────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != "" && substr != "" &&
		   len(s) >= len(substr) && s[:len(substr)] == substr ||
		   len(s) > len(substr) && s[len(s)-len(substr):] == substr ||
		   len(s) > len(substr) && anySubstr(s, substr)
}

func anySubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
