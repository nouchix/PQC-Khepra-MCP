//go:build devroot

package license

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// devRootOverride lets a development build verify licenses against a test
// root instead of MasterPublicKey. It is compiled in only with -tags devroot
// and must never be used for a binary that ships.
//
// Sources, in priority order:
//  1. KHEPRA_MASTER_PUBLIC_KEY env var (hex)
//  2. KHEPRA_MASTER_PUBLIC_KEY_PATH env var
//  3. ~/.khepra/master.pub
//
// An empty or undecodable override is an error, never a silent fallback:
// an empty key used to let a license verify against its own signer key.
func devRootOverride() ([]byte, bool, error) {
	if raw := strings.TrimSpace(os.Getenv("KHEPRA_MASTER_PUBLIC_KEY")); raw != "" {
		key, err := decodeDevRoot(raw)
		return key, true, err
	}

	var paths []string
	if p := os.Getenv("KHEPRA_MASTER_PUBLIC_KEY_PATH"); p != "" {
		paths = append(paths, p)
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".khepra", "master.pub"))
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		key, err := decodeDevRoot(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, true, fmt.Errorf("devroot %s: %w", p, err)
		}
		return key, true, nil
	}
	return nil, false, nil
}

func decodeDevRoot(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode master public key: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("master public key override is empty")
	}
	return key, nil
}
