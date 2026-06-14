package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// ValidateStoragePath ensures the configured storage path is writable.
// This implements ECR-01 fail-fast requirement for DoD deployments.
//
// Behavior:
// - If path doesn't exist, attempts to create it
// - If path exists but is not writable, panics immediately
// - Returns absolute path for use in application
//
// Kubernetes StatefulSet deployments should set ADINKHEPRA_STORAGE_PATH=/var/lib/adinkhepra/data
// and mount a PersistentVolumeClaim at that path.
func ValidateStoragePath(cfg Config) (string, error) {
	storagePath := cfg.StoragePath

	// Convert to absolute path
	absPath, err := filepath.Abs(storagePath)
	if err != nil {
		return "", fmt.Errorf("invalid storage path '%s': %w", storagePath, err)
	}

	// Check if path exists
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Attempt to create directory
			if err := os.MkdirAll(absPath, 0750); err != nil {
				return "", fmt.Errorf("cannot create storage directory '%s': %w", absPath, err)
			}
			// Verify creation succeeded
			if _, err := os.Stat(absPath); err != nil {
				return "", fmt.Errorf("storage directory creation failed for '%s': %w", absPath, err)
			}
		} else {
			return "", fmt.Errorf("cannot access storage path '%s': %w", absPath, err)
		}
	} else {
		// Path exists, verify it's a directory
		if !info.IsDir() {
			return "", fmt.Errorf("storage path '%s' exists but is not a directory", absPath)
		}
	}

	// Test write permissions by creating a temporary file
	testFile := filepath.Join(absPath, ".adinkhepra_write_test")
	f, err := os.Create(testFile)
	if err != nil {
		return "", fmt.Errorf("storage path '%s' is not writable: %w (DoD StatefulSet deployments must mount PVC)", absPath, err)
	}
	f.Close()
	os.Remove(testFile)

	return absPath, nil
}

// MustValidateStoragePath is a fail-fast wrapper around ValidateStoragePath.
// If storage validation fails, the application panics immediately per ECR-01 requirements.
//
// This prevents containers from starting successfully but silently losing data on restart.
func MustValidateStoragePath(cfg Config) string {
	absPath, err := ValidateStoragePath(cfg)
	if err != nil {
		panic(fmt.Sprintf("CRITICAL STORAGE FAILURE: %v\n\nDoD Deployment Note: Ensure StatefulSet has PersistentVolumeClaim mounted at ADINKHEPRA_STORAGE_PATH", err))
	}
	return absPath
}
