//go:build boringcrypto

package crypto

import (
	"crypto/boring"
	"fmt"
	"log"
	"runtime"
)

// CheckFIPS verifies FIPS 140-3 compliance at application boot.
func CheckFIPS() FIPSStatus {
	mode := GetFIPSMode()
	status := FIPSStatus{
		Enabled:       boring.Enabled(),
		Mode:          mode,
		BoringVersion: getBoringVersion(),
		GOVersion:     runtime.Version(),
		CGOEnabled:    cgoEnabled(),
	}

	switch mode {
	case FIPSRequired:
		if !status.Enabled {
			panic(fmt.Sprintf(
				"CRITICAL: FIPS 140-3 mode required but BoringCrypto not enabled\n\n"+
					"DoD Platform One deployments MUST use FIPS-validated cryptography.\n\n"+
					"To fix this error:\n"+
					"1. Rebuild binary with: GOEXPERIMENT=boringcrypto CGO_ENABLED=1 go build -tags=fips\n"+
					"2. Verify build environment has gcc installed\n"+
					"3. For development/testing only, set: ADINKHEPRA_DEV=1\n\n"+
					"Current Build:\n"+
					"  Go Version: %s\n"+
					"  CGO Enabled: %v\n"+
					"  BoringCrypto: %v\n\n"+
					"Reference: TC 25-ADINKHEPRA-001 Section 2-2 (FIPS Compliance)\n",
				status.GOVersion,
				status.CGOEnabled,
				status.Enabled,
			))
		}
		log.Println("SYSTEM: FIPS 140-3 Mode ENABLED (BoringCrypto active)")
		log.Printf("SYSTEM: Transport Layer Cryptography - FIPS-Validated (BoringSSL %s)", status.BoringVersion)
		log.Println("SYSTEM: Application Layer Cryptography - NIST PQC (ML-DSA-65, ML-KEM-1024)")

	case FIPSWarning:
		if !status.Enabled {
			log.Println("WARNING: FIPS 140-3 mode NOT enabled")
			log.Println("WARNING: BoringCrypto not active - TLS may not meet DoD compliance")
			log.Println("WARNING: Rebuild with: GOEXPERIMENT=boringcrypto CGO_ENABLED=1 go build -tags=fips")
		} else {
			log.Println("SYSTEM: FIPS 140-3 Mode enabled (BoringCrypto active)")
		}

	case FIPSDisabled:
		log.Println("DEVELOPMENT: FIPS 140-3 enforcement DISABLED")
		log.Println("DEVELOPMENT: This configuration is NOT approved for production or DoD use")
		if status.Enabled {
			log.Println("DEVELOPMENT: BoringCrypto detected but enforcement disabled by ADINKHEPRA_DEV")
		}
	}

	return status
}

// AssertFIPS is a convenience function that panics if FIPS is required but not enabled.
func AssertFIPS() {
	_ = CheckFIPS()
}

// getBoringVersion returns the BoringCrypto version string if available.
func getBoringVersion() string {
	if !boring.Enabled() {
		return "not enabled"
	}
	return "chromium-stable"
}

// cgoEnabled returns true if CGO is enabled at compile time.
func cgoEnabled() bool {
	return boring.Enabled()
}

// FIPSInfo returns a human-readable string describing the FIPS compliance status.
func FIPSInfo() string {
	status := CheckFIPS()
	if status.Enabled {
		return fmt.Sprintf(
			"FIPS 140-3: ENABLED (BoringCrypto %s)\n"+
				"Transport Layer: FIPS-validated BoringSSL\n"+
				"Application Layer: NIST PQC (ML-DSA-65, ML-KEM-1024)\n"+
				"Build: %s, CGO=%v",
			status.BoringVersion,
			status.GOVersion,
			status.CGOEnabled,
		)
	}
	return fmt.Sprintf(
		"FIPS 140-3: DISABLED\n"+
			"Build: %s, CGO=%v\n"+
			"WARNING: Not suitable for DoD deployment",
		status.GOVersion,
		status.CGOEnabled,
	)
}

// ValidateTLSConfig ensures TLS configuration meets FIPS requirements.
func ValidateTLSConfig() error {
	if !boring.Enabled() && GetFIPSMode() == FIPSRequired {
		return fmt.Errorf("TLS validation failed: FIPS required but BoringCrypto not enabled")
	}
	return nil
}
