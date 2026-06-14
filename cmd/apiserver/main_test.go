//go:build saas

package main

import (
	"os"
	"testing"
)

func TestGetSecretStatus_NotSet(t *testing.T) {
	// Clear environment
	os.Unsetenv("KHEPRA_SERVICE_SECRET")

	status := getSecretStatus()
	expected := "NOT SET (using development default)"

	if status != expected {
		t.Errorf("expected '%s', got '%s'", expected, status)
	}
}

func TestGetSecretStatus_Set(t *testing.T) {
	// Set environment
	os.Setenv("KHEPRA_SERVICE_SECRET", "test-secret-value")
	defer os.Unsetenv("KHEPRA_SERVICE_SECRET")

	status := getSecretStatus()
	expected := "configured (HMAC-SHA256)"

	if status != expected {
		t.Errorf("expected '%s', got '%s'", expected, status)
	}
}

func TestPrintBanner(t *testing.T) {
	// Just verify it doesn't panic
	// We can't easily capture stdout in a unit test
	printBanner()
}
