// Package crypto provides FIPS 140-3 compliance verification for DoD deployments.
package crypto

import (
	"log"
	"os"
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

// FIPSStatus contains runtime FIPS compliance information
type FIPSStatus struct {
	Enabled       bool
	Mode          FIPSMode
	BoringVersion string
	GOVersion     string
	CGOEnabled    bool
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
