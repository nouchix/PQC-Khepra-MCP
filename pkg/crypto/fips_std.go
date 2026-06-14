//go:build !boringcrypto

package crypto

import (
	"fmt"
	"log"
	"runtime"
)

// CheckFIPS verifies FIPS 140-3 compliance at application boot.
func CheckFIPS() FIPSStatus {
	mode := GetFIPSMode()
	status := FIPSStatus{
		Enabled:       false,
		Mode:          mode,
		BoringVersion: "not available",
		GOVersion:     runtime.Version(),
		CGOEnabled:    false, // Assumption for standard build, or can't determine easily
	}

	switch mode {
	case FIPSRequired:
		// Panic because we cannot satisfy the requirement
		panic(fmt.Sprintf(
			"CRITICAL: FIPS 140-3 mode required but BoringCrypto not available\n\n"+
				"This binary was built with the standard Go compiler, which does not support FIPS validation.\n\n"+
				"To fix this error:\n"+
				"1. Rebuild binary with a FIPS-aware toolchain (GOEXPERIMENT=boringcrypto)\n"+
				"2. For development/testing only, set environment: ADINKHEPRA_DEV=1\n\n"+
				"Current Build:\n"+
				"  Go Version: %s\n"+
				"  BoringCrypto: Not Available\n",
			status.GOVersion,
		))

	case FIPSWarning:
		log.Println("WARNING: FIPS 140-3 mode NOT enabled (Standard Go Build)")

	case FIPSDisabled:
		log.Println("DEVELOPMENT: FIPS 140-3 enforcement DISABLED")
	}

	return status
}

// AssertFIPS is a convenience function that panics if FIPS is required but not enabled.
func AssertFIPS() {
	_ = CheckFIPS()
}

// FIPSInfo returns a human-readable string describing the FIPS compliance status.
func FIPSInfo() string {
	return fmt.Sprintf(
		"FIPS 140-3: DISABLED (Standard Build)\n"+
			"Build: %s\n"+
			"WARNING: Not suitable for DoD deployment",
		runtime.Version(),
	)
}

// ValidateTLSConfig ensures TLS configuration meets FIPS requirements.
func ValidateTLSConfig() error {
	if GetFIPSMode() == FIPSRequired {
		return fmt.Errorf("TLS validation failed: FIPS required but BoringCrypto not available in this build")
	}
	return nil
}
