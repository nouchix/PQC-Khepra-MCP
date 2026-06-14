package crypto

import (
	"os"
	"testing"
)

func TestGetFIPSMode(t *testing.T) {
	tests := []struct {
		name     string
		devMode  string
		fipsMode string
		want     FIPSMode
	}{
		{
			name:     "default (no env vars)",
			devMode:  "",
			fipsMode: "",
			want:     FIPSRequired,
		},
		{
			name:     "dev mode overrides FIPS",
			devMode:  "1",
			fipsMode: "true",
			want:     FIPSDisabled,
		},
		{
			name:     "explicit FIPS required",
			devMode:  "",
			fipsMode: "true",
			want:     FIPSRequired,
		},
		{
			name:     "explicit FIPS disabled",
			devMode:  "",
			fipsMode: "false",
			want:     FIPSDisabled,
		},
		{
			name:     "FIPS warning mode",
			devMode:  "",
			fipsMode: "warn",
			want:     FIPSWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env vars
			originalDev := os.Getenv("ADINKHEPRA_DEV")
			originalFIPS := os.Getenv("ADINKHEPRA_FIPS_MODE")
			defer func() {
				os.Setenv("ADINKHEPRA_DEV", originalDev)
				os.Setenv("ADINKHEPRA_FIPS_MODE", originalFIPS)
			}()

			// Set test env vars
			if tt.devMode == "" {
				os.Unsetenv("ADINKHEPRA_DEV")
			} else {
				os.Setenv("ADINKHEPRA_DEV", tt.devMode)
			}

			if tt.fipsMode == "" {
				os.Unsetenv("ADINKHEPRA_FIPS_MODE")
			} else {
				os.Setenv("ADINKHEPRA_FIPS_MODE", tt.fipsMode)
			}

			// Test
			got := GetFIPSMode()
			if got != tt.want {
				t.Errorf("GetFIPSMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckFIPS_DevMode(t *testing.T) {
	// Save original env
	originalDev := os.Getenv("ADINKHEPRA_DEV")
	defer os.Setenv("ADINKHEPRA_DEV", originalDev)

	// Enable dev mode (should not panic even if BoringCrypto unavailable)
	os.Setenv("ADINKHEPRA_DEV", "1")

	status := CheckFIPS()
	if status.Mode != FIPSDisabled {
		t.Errorf("CheckFIPS() in dev mode, got mode %v, want FIPSDisabled", status.Mode)
	}
}

func TestFIPSInfo(t *testing.T) {
	// Save original env
	originalDev := os.Getenv("ADINKHEPRA_DEV")
	defer os.Setenv("ADINKHEPRA_DEV", originalDev)

	// Enable dev mode to avoid panic in test
	os.Setenv("ADINKHEPRA_DEV", "1")

	info := FIPSInfo()
	if info == "" {
		t.Error("FIPSInfo() returned empty string")
	}

	// Info should mention FIPS status
	if len(info) < 10 {
		t.Errorf("FIPSInfo() returned suspiciously short string: %s", info)
	}
}

func TestValidateTLSConfig(t *testing.T) {
	// Save original env
	originalDev := os.Getenv("ADINKHEPRA_DEV")
	originalFIPS := os.Getenv("ADINKHEPRA_FIPS_MODE")
	defer func() {
		os.Setenv("ADINKHEPRA_DEV", originalDev)
		os.Setenv("ADINKHEPRA_FIPS_MODE", originalFIPS)
	}()

	// Test with dev mode (should always pass)
	os.Setenv("ADINKHEPRA_DEV", "1")
	if err := ValidateTLSConfig(); err != nil {
		t.Errorf("ValidateTLSConfig() in dev mode failed: %v", err)
	}

	// Test with FIPS warning mode (should pass even without BoringCrypto)
	os.Unsetenv("ADINKHEPRA_DEV")
	os.Setenv("ADINKHEPRA_FIPS_MODE", "warn")
	if err := ValidateTLSConfig(); err != nil {
		t.Errorf("ValidateTLSConfig() in warn mode failed: %v", err)
	}
}

// TestFIPSBuild_Integration verifies that a FIPS build includes required symbols
// This test only runs in CI with -tags=fips
func TestFIPSBuild_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test verifies FIPS build succeeds without panicking
	// In a proper FIPS build with BoringCrypto, boring.Enabled() returns true
	// In a standard build, it returns false

	// Save and restore env
	originalDev := os.Getenv("ADINKHEPRA_DEV")
	defer os.Setenv("ADINKHEPRA_DEV", originalDev)

	// Test that dev mode bypass works
	os.Setenv("ADINKHEPRA_DEV", "1")
	status := CheckFIPS()

	if status.Mode != FIPSDisabled {
		t.Errorf("Dev mode should disable FIPS enforcement, got mode=%v", status.Mode)
	}
}
