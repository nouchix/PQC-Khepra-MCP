package mobile

import (
	"strings"
	"testing"
)

// Each test calls Destroy() after to reset the package-level singleton state.

func TestInitPhantom_ValidSymbol(t *testing.T) {
	defer Destroy()

	keyID, err := InitPhantom("Eban")
	if err != nil {
		t.Fatalf("InitPhantom failed: %v", err)
	}
	if keyID == "" {
		t.Error("expected non-empty key ID")
	}
}

func TestInitPhantom_SetsSymbol(t *testing.T) {
	defer Destroy()

	_, err := InitPhantom("Sankofa")
	if err != nil {
		t.Fatalf("InitPhantom failed: %v", err)
	}
	sym, err := GetSymbol()
	if err != nil {
		t.Fatalf("GetSymbol failed: %v", err)
	}
	if sym != "Sankofa" {
		t.Errorf("expected symbol=Sankofa, got %s", sym)
	}
}

func TestGetSymbol_NotInitialized(t *testing.T) {
	Destroy() // ensure clean state
	_, err := GetSymbol()
	if err == nil {
		t.Error("expected error when not initialized")
	}
}

func TestSignAndVerify_Roundtrip(t *testing.T) {
	defer Destroy()

	if _, err := InitPhantom("Dwennimmen"); err != nil {
		t.Fatalf("InitPhantom failed: %v", err)
	}

	msg := "Khepra PQC message integrity test"
	sigHex, err := SignMessage(msg)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	if sigHex == "" {
		t.Fatal("expected non-empty signature hex")
	}

	valid, err := VerifySignature(msg, sigHex)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !valid {
		t.Error("signature verification failed for valid message")
	}
}

func TestSignAndVerify_TamperedMessage(t *testing.T) {
	defer Destroy()

	if _, err := InitPhantom("Nkyinkyim"); err != nil {
		t.Fatalf("InitPhantom failed: %v", err)
	}

	sigHex, err := SignMessage("original message")
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	valid, err := VerifySignature("tampered message", sigHex)
	if err != nil {
		t.Fatalf("VerifySignature error: %v", err)
	}
	if valid {
		t.Error("tampered message should not verify")
	}
}

func TestSealUnseal_Roundtrip(t *testing.T) {
	defer Destroy()

	if _, err := InitPhantom("Fawohodie"); err != nil {
		t.Fatalf("InitPhantom failed: %v", err)
	}

	plaintext := "Sovereign PQC Mobile Binding Test — Khepra v1"
	sealed, err := SealData(plaintext)
	if err != nil {
		t.Fatalf("SealData failed: %v", err)
	}
	if sealed == "" || sealed == plaintext {
		t.Error("sealed ciphertext should be non-empty and differ from plaintext")
	}

	recovered, err := UnsealData(sealed)
	if err != nil {
		t.Fatalf("UnsealData failed: %v", err)
	}
	if recovered != plaintext {
		t.Errorf("roundtrip failed: want %q got %q", plaintext, recovered)
	}
}

func TestGetPhantomAddress_IPv6Range(t *testing.T) {
	defer Destroy()

	if _, err := InitPhantom("Eban"); err != nil {
		t.Fatalf("InitPhantom failed: %v", err)
	}

	addr, err := GetPhantomAddress()
	if err != nil {
		t.Fatalf("GetPhantomAddress failed: %v", err)
	}
	// Phantom addresses are in the fc00::/8 range (unique local)
	if !strings.HasPrefix(addr, "fc00:") {
		t.Errorf("expected fc00:: prefix, got %s", addr)
	}
}

func TestGetSpectralFingerprint_NonEmpty(t *testing.T) {
	fp := GetSpectralFingerprint("Eban")
	if fp == "" {
		t.Error("expected non-empty spectral fingerprint")
	}
	// Should be hex-encoded
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			t.Errorf("fingerprint contains non-hex char: %c", c)
			break
		}
	}
}

func TestGetStatus_JSON(t *testing.T) {
	defer Destroy()

	if _, err := InitPhantom("Eban"); err != nil {
		t.Fatalf("InitPhantom failed: %v", err)
	}

	status, err := GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	// Should contain the symbol
	if !strings.Contains(status, "Eban") {
		t.Errorf("status JSON should contain symbol 'Eban', got: %s", status)
	}
	// Should be valid JSON (contains braces)
	if !strings.HasPrefix(status, "{") {
		t.Errorf("expected JSON object, got: %s", status)
	}
}

func TestRotateKeys_NewKeyID(t *testing.T) {
	defer Destroy()

	if _, err := InitPhantom("Sankofa"); err != nil {
		t.Fatalf("InitPhantom failed: %v", err)
	}

	newID, err := RotateKeys()
	if err != nil {
		t.Fatalf("RotateKeys failed: %v", err)
	}
	if newID == "" {
		t.Error("expected non-empty new key ID after rotation")
	}
}

func TestOperations_NotInitialized(t *testing.T) {
	Destroy()

	if _, err := SignMessage("test"); err == nil {
		t.Error("SignMessage: expected error when not initialized")
	}
	if _, err := VerifySignature("test", "sig"); err == nil {
		t.Error("VerifySignature: expected error when not initialized")
	}
	if _, err := SealData("test"); err == nil {
		t.Error("SealData: expected error when not initialized")
	}
	if _, err := UnsealData("test"); err == nil {
		t.Error("UnsealData: expected error when not initialized")
	}
	if _, err := GetPhantomAddress(); err == nil {
		t.Error("GetPhantomAddress: expected error when not initialized")
	}
	if _, err := GetStatus(); err == nil {
		t.Error("GetStatus: expected error when not initialized")
	}
	if _, err := RotateKeys(); err == nil {
		t.Error("RotateKeys: expected error when not initialized")
	}
	if _, err := GetComplianceMapping(); err == nil {
		t.Error("GetComplianceMapping: expected error when not initialized")
	}
}
