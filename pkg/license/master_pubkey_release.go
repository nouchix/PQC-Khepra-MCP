//go:build !devroot

package license

// devRootOverride is disabled in release builds. Offline verification trusts
// only the compiled-in MasterPublicKey.
func devRootOverride() ([]byte, bool, error) {
	return nil, false, nil
}

// DevOverridesEnabled reports whether development-only license overrides
// (ADINKHEPRA_DEV, explicit root key paths) are compiled in. They are not in
// release builds.
func DevOverridesEnabled() bool {
	return false
}
