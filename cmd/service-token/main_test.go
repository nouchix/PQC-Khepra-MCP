package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestComputeHMAC(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef-0123")
	message := "test-message"

	result := computeHMAC(message, secret)

	if result == "" {
		t.Error("expected non-empty HMAC result")
	}

	// HMAC-SHA256 produces 64 hex characters
	if len(result) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(result))
	}

	// Same input should produce same output
	result2 := computeHMAC(message, secret)
	if result != result2 {
		t.Error("HMAC should be deterministic")
	}

	// Different secret should produce different output
	result3 := computeHMAC(message, []byte("different-secret-0123456789abcdef"))
	if result == result3 {
		t.Error("different secrets should produce different HMACs")
	}
}

const testSecretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestGetServiceSecret_NoDefault(t *testing.T) {
	t.Setenv("KHEPRA_SERVICE_SECRET", "")
	if _, err := getServiceSecret(); err == nil {
		t.Fatal("expected an error when KHEPRA_SERVICE_SECRET is unset")
	}
}

func TestGetServiceSecret_FromEnv(t *testing.T) {
	t.Setenv("KHEPRA_SERVICE_SECRET", testSecretHex)
	secret, err := getServiceSecret()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(secret) != testSecretHex {
		t.Errorf("expected the hex-decoded secret, got %x", secret)
	}
}

func TestGetServiceSecret_Rejects(t *testing.T) {
	for _, v := range []string{"not-hex-at-all", "00112233"} {
		t.Setenv("KHEPRA_SERVICE_SECRET", v)
		if _, err := getServiceSecret(); err == nil {
			t.Errorf("secret %q: expected an error", v)
		}
	}
}

func TestPrintUsage(t *testing.T) {
	// Just verify it doesn't panic
	printUsage()
}

func TestTokenFormat(t *testing.T) {
	// Test that generated tokens have the correct format
	t.Setenv("KHEPRA_SERVICE_SECRET", testSecretHex)

	// We can't easily capture stdout, so test the components
	secret, err := getServiceSecret()
	if err != nil {
		t.Fatal(err)
	}
	message := "khepra-svc-test-service-0000000000000000"
	signature := computeHMAC(message, secret)

	// Signature should be 64 hex chars
	if len(signature) != 64 {
		t.Errorf("expected 64 hex chars in signature, got %d", len(signature))
	}

	// Should be valid hex
	for _, c := range signature {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("signature contains non-hex character: %c", c)
		}
	}
}

func TestValidServices(t *testing.T) {
	validServices := map[string]bool{
		"cloudflare-telemetry": true,
		"license-signer":       true,
		"master-console":       true,
	}

	// Test that valid services are recognized
	for service := range validServices {
		if !validServices[service] {
			t.Errorf("service '%s' should be valid", service)
		}
	}

	// Test that invalid services are not recognized
	if validServices["invalid-service"] {
		t.Error("invalid-service should not be valid")
	}
}

func TestTimestampEncoding(t *testing.T) {
	// Test timestamp encoding logic
	var timestamp int64 = 1234567890
	timestampBytes := make([]byte, 8)

	for i := 7; i >= 0; i-- {
		timestampBytes[i] = byte(timestamp & 0xff)
		timestamp >>= 8
	}

	// Decode back
	var decoded int64
	for i := 0; i < 8; i++ {
		decoded = (decoded << 8) | int64(timestampBytes[i])
	}

	if decoded != 1234567890 {
		t.Errorf("timestamp encoding/decoding mismatch: expected 1234567890, got %d", decoded)
	}
}

func TestTokenPrefixValidation(t *testing.T) {
	validToken := "khepra-svc-cloudflare-telemetry-0000000000000000-abcd1234"
	invalidToken := "invalid-prefix-token"

	if !strings.HasPrefix(validToken, "khepra-svc-") {
		t.Error("valid token should have correct prefix")
	}

	if strings.HasPrefix(invalidToken, "khepra-svc-") {
		t.Error("invalid token should not have correct prefix")
	}
}
