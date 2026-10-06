package crypto

import (
	"crypto/fips140"
	"fmt"
	"log"
	"os"
	"runtime"
)

// FIPSMode represents the FIPS 140-3 enforcement level
type FIPSMode int

const (
	// FIPSDisabled - No FIPS enforcement (development only)
	FIPSDisabled FIPSMode = iota

	// FIPSWarning - FIPS preferred but not required (logs warning if disabled)
	FIPSWarning

	// FIPSRequired - FIPS mandatory (panics if not enabled)
	// This is the default for DoD deployments
	FIPSRequired
)

// FIPSStatus contains runtime FIPS 140-3 information
type FIPSStatus struct {
	Enabled       bool // Go Cryptographic Module running in FIPS mode
	Enforced      bool // non-approved algorithms disabled (GODEBUG=fips140=only)
	Mode          FIPSMode
	ModuleVersion string // Go Cryptographic Module version, e.g. "v1.26.0"
	GOVersion     string
}

// GetFIPSMode returns the configured FIPS enforcement level from environment.
//
// Environment Variables:
//
//	ADINKHEPRA_FIPS_MODE=true     -> FIPSRequired (DoD default)
//	ADINKHEPRA_FIPS_MODE=warn     -> FIPSWarning
//	ADINKHEPRA_FIPS_MODE=false    -> FIPSDisabled (dev mode only)
//	ADINKHEPRA_DEV=1              -> FIPSDisabled (overrides FIPS_MODE)
func GetFIPSMode() FIPSMode {
	// Development mode bypasses FIPS
	if os.Getenv("ADINKHEPRA_DEV") == "1" {
		return FIPSDisabled
	}

	fipsEnv := os.Getenv("ADINKHEPRA_FIPS_MODE")
	switch fipsEnv {
	case "false", "0", "disabled":
		return FIPSDisabled
	case "warn", "warning":
		return FIPSWarning
	case "true", "1", "required", "":
		// Empty string defaults to required for DoD compliance
		return FIPSRequired
	default:
		log.Printf("WARNING: Unknown ADINKHEPRA_FIPS_MODE value '%s', defaulting to FIPSRequired", fipsEnv)
		return FIPSRequired
	}
}

func currentFIPSStatus() FIPSStatus {
	status := FIPSStatus{
		Enabled:   fips140.Enabled(),
		Mode:      GetFIPSMode(),
		GOVersion: runtime.Version(),
	}
	if status.Enabled {
		status.Enforced = fips140.Enforced()
		status.ModuleVersion = fips140.Version()
	}
	return status
}

// CheckFIPS verifies FIPS 140-3 mode at application boot. It panics when FIPS
// is required and the Go Cryptographic Module is not running in FIPS mode.
func CheckFIPS() FIPSStatus {
	status := currentFIPSStatus()

	switch status.Mode {
	case FIPSRequired:
		if !status.Enabled {
			panic(fmt.Sprintf(
				"CRITICAL: FIPS 140-3 mode required but not enabled\n\n"+
					"To fix this error:\n"+
					"1. Build with GOFIPS140=inprocess (Go Cryptographic Module v1.26.0)\n"+
					"2. Run with GODEBUG=fips140=on (or fips140=only)\n"+
					"3. For development/testing only, set: ADINKHEPRA_DEV=1\n\n"+
					"Current Build:\n"+
					"  Go Version: %s\n",
				status.GOVersion,
			))
		}
		log.Printf("SYSTEM: FIPS 140-3 mode enabled (Go Cryptographic Module %s, enforced=%v)",
			status.ModuleVersion, status.Enforced)

	case FIPSWarning:
		if !status.Enabled {
			log.Println("WARNING: FIPS 140-3 mode NOT enabled")
			log.Println("WARNING: Build with GOFIPS140=inprocess and run with GODEBUG=fips140=on")
		} else {
			log.Printf("SYSTEM: FIPS 140-3 mode enabled (Go Cryptographic Module %s)", status.ModuleVersion)
		}

	case FIPSDisabled:
		log.Println("DEVELOPMENT: FIPS 140-3 enforcement DISABLED")
		log.Println("DEVELOPMENT: This configuration is NOT approved for production or DoD use")
	}

	return status
}

// AssertFIPS is a convenience function that panics if FIPS is required but not enabled.
func AssertFIPS() {
	_ = CheckFIPS()
}

// FIPSInfo returns a human-readable string describing the FIPS 140-3 status.
func FIPSInfo() string {
	status := currentFIPSStatus()
	if status.Enabled {
		return fmt.Sprintf(
			"FIPS 140-3 mode: ENABLED (Go Cryptographic Module %s, enforced=%v)\n"+
				"Algorithms: ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), AES-256-GCM, SHA-384\n"+
				"Build: %s",
			status.ModuleVersion, status.Enforced, status.GOVersion,
		)
	}
	return fmt.Sprintf(
		"FIPS 140-3 mode: DISABLED\n"+
			"Build: %s\n"+
			"WARNING: Not suitable for DoD deployment",
		status.GOVersion,
	)
}

// ValidateTLSConfig ensures the process can meet FIPS requirements for TLS.
func ValidateTLSConfig() error {
	if GetFIPSMode() == FIPSRequired && !fips140.Enabled() {
		return fmt.Errorf("TLS validation failed: FIPS 140-3 required but the Go Cryptographic Module is not in FIPS mode")
	}
	return nil
}
