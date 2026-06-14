package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"
)

// Baseline represents a FIM baseline snapshot
type Baseline struct {
	CreatedAt time.Time         `json:"created_at"`
	Hostname  string            `json:"hostname"`
	Hashes    map[string]string `json:"hashes"` // filepath -> SHA256
	Metadata  map[string]FileMeta `json:"metadata,omitempty"`
}

// FileMeta contains metadata about a monitored file
type FileMeta struct {
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"mod_time"`
	Permissions  string    `json:"permissions"`
	Owner        string    `json:"owner,omitempty"`
	Group        string    `json:"group,omitempty"`
}

// ComputeSHA256 computes SHA256 hash of a file (exported helper)
// This is used by cmd_fim.go for the verify command
func ComputeSHA256(path string) (string, error) {
	// Use the same algorithm as FIMWatcher
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}
