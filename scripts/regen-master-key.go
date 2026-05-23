//go:build ignore

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	// Generate ML-DSA-65 key pair (FIPS 204 standardized)
	fmt.Println("[KEYGEN] Generating ML-DSA-65 Master Key Pair...")

	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key: %v\n", err)
		os.Exit(1)
	}

	// Get key bytes
	pubKeyBytes, err := pk.MarshalBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal public key: %v\n", err)
		os.Exit(1)
	}

	privKeyBytes, err := sk.MarshalBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal private key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[KEYGEN] Public key size: %d bytes\n", len(pubKeyBytes))
	fmt.Printf("[KEYGEN] Private key size: %d bytes (expected: %d)\n", len(privKeyBytes), mldsa65.PrivateKeySize)

	// Create output directory
	outDir := "keys/offline"
	if err := os.MkdirAll(outDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create directory: %v\n", err)
		os.Exit(1)
	}

	// Backup existing keys if they exist
	secretPath := filepath.Join(outDir, "OFFLINE_ROOT_KEY.secret")
	pubPath := filepath.Join(outDir, "OFFLINE_ROOT_KEY.pub")

	if _, err := os.Stat(secretPath); err == nil {
		backupPath := secretPath + ".backup"
		fmt.Printf("[KEYGEN] Backing up existing key to %s\n", backupPath)
		os.Rename(secretPath, backupPath)
	}

	// Write private key (hex-encoded)
	privKeyHex := hex.EncodeToString(privKeyBytes)
	if err := os.WriteFile(secretPath, []byte(privKeyHex), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[KEYGEN] ✅ Private key written to: %s\n", secretPath)

	// Write public key (hex-encoded)
	pubKeyHex := hex.EncodeToString(pubKeyBytes)
	if err := os.WriteFile(pubPath, []byte(pubKeyHex), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write public key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[KEYGEN] ✅ Public key written to: %s\n", pubPath)

	fmt.Println("\n[KEYGEN] ML-DSA-65 Master Key Pair generated successfully!")
	fmt.Println("[KEYGEN] The private key is your SOVEREIGN MASTER KEY.")
	fmt.Println("[KEYGEN] Keep it secure and never share it.")
}
