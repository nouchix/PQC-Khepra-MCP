package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Ensure clean env
	os.Unsetenv("ADINKHEPRA_USER")

	cfg := Load()
	if cfg.Username != "adinkhepra" {
		t.Errorf("Expected default username 'adinkhepra', got '%s'", cfg.Username)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	os.Setenv("ADINKHEPRA_USER", "testuser")
	defer os.Unsetenv("ADINKHEPRA_USER")

	cfg := Load()
	if cfg.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", cfg.Username)
	}
}
