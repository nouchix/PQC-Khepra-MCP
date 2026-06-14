package kms

import (
	"os"
	"testing"
)

func TestRootOfTrustCeremony(t *testing.T) {
	password := "Sup3rS3cur3P@ssw0rd!"
	entropySource := "HardwareRNG"

	// 1. Perform Ceremony
	result, err := BootstrapTier0(entropySource, password)
	if err != nil {
		t.Fatalf("BootstrapTier0 failed: %v", err)
	}

	if result.Salt == "" {
		t.Error("Salt should not be empty")
	}

	// 2. Perform second ceremony to ensure salts are random
	result2, _ := BootstrapTier0(entropySource, password)
	if result.Salt == result2.Salt {
		t.Error("Salts must be unique per operation")
	}

	// 3. Save to temp file
	tmpFile := "test_root.json"
	defer os.Remove(tmpFile)
	err = EncodeTier0(result, tmpFile)
	if err != nil {
		t.Fatalf("EncodeTier0 failed: %v", err)
	}

	// 4. Load and Unlock
	recoveredSeed, err := LoadMasterSeed(tmpFile, password)
	if err != nil {
		t.Fatalf("LoadMasterSeed failed: %v", err)
	}

	if len(recoveredSeed) != 64 {
		t.Errorf("Expected 64 bytes seed, got %d", len(recoveredSeed))
	}

	// 5. Test wrong password
	_, err = LoadMasterSeed(tmpFile, "WrongPassword")
	if err == nil {
		t.Error("LoadMasterSeed should fail with wrong password")
	}
}
