//go:build !devroot

package license

// devRootOverride is disabled in release builds. Offline verification trusts
// only the compiled-in MasterPublicKey.
func devRootOverride() ([]byte, bool, error) {
	return nil, false, nil
}
