package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// LicenseBlob is the signed license structure (matching license-signer.go)
type LicenseBlob struct {
	Version      string   `json:"version"`
	MachineID    string   `json:"machine_id"`
	Organization string   `json:"organization"`
	Tier         string   `json:"tier"`
	Features     []string `json:"features"`
	IssuedAt     int64    `json:"issued_at"`
	ExpiresAt    int64    `json:"expires_at,omitempty"` // 0 for perpetual
	Issuer       string   `json:"issuer"`
	SignedWith   string   `json:"signed_with"`
}

// SignedLicense is the complete license file format
type SignedLicense struct {
	License   LicenseBlob `json:"license"`
	Signature string      `json:"signature"` // Hex-encoded ML-DSA-65 signature
}

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║       KHEPRA Protocol - Offline License Generator         ║")
	fmt.Println("║              ML-DSA-65 Post-Quantum Signatures            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")

	machineID := flag.String("id", "", "Target Machine ID (required)")
	org := flag.String("org", "Internal Command", "Organization Name")
	tier := flag.String("tier", "osiris", "License Tier (khepri, ra, atum, osiris)")
	days := flag.Int("days", 365, "Validity in days (0 for perpetual)")
	privKeyPath := flag.String("key", "OFFLINE_ROOT_KEY.secret", "Path to ML-DSA-65 Private Key")
	outFile := flag.String("out", "license.khepra", "Output filename")
	flag.Parse()

	if *machineID == "" {
		fmt.Println("❌ Error: -id (Machine ID) is required.")
		flag.Usage()
		os.Exit(1)
	}

	// 1. Load Private Key
	privData, err := os.ReadFile(*privKeyPath)
	if err != nil {
		fmt.Printf("❌ Error reading private key: %v\n", err)
		os.Exit(1)
	}

	keyBytes, err := hex.DecodeString(string(privData))
	if err != nil {
		fmt.Printf("❌ Error decoding private key (must be hex): %v\n", err)
		os.Exit(1)
	}

	if len(keyBytes) != mldsa65.PrivateKeySize {
		fmt.Printf("❌ Error: Invalid key size (got %d, expected %d)\n", len(keyBytes), mldsa65.PrivateKeySize)
		os.Exit(1)
	}

	var keyBuf [mldsa65.PrivateKeySize]byte
	copy(keyBuf[:], keyBytes)
	var privateKey mldsa65.PrivateKey
	privateKey.Unpack(&keyBuf)

	// 2. Prepare License Blob
	now := time.Now().Unix()
	var expiresAt int64
	if *days > 0 {
		expiresAt = now + int64(*days*86400)
	}

	features := []string{"pqc-all", "offline-mode", "white-box"}
	if *tier == "osiris" {
		features = append(features, "air-gap-unlimited", "hsm-support")
	}

	blob := LicenseBlob{
		Version:      "1.5",
		MachineID:    *machineID,
		Organization: *org,
		Tier:         *tier,
		Features:     features,
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
		Issuer:       "NouchiX SecRed Knowledge Inc.",
		SignedWith:   "ML-DSA-65",
	}

	// 3. Sign the Blob
	blobJSON, _ := json.Marshal(blob)
	signature := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(&privateKey, blobJSON, nil, false, signature)

	// 4. Wrap and Save
	signed := SignedLicense{
		License:   blob,
		Signature: hex.EncodeToString(signature),
	}

	signedJSON, _ := json.MarshalIndent(signed, "", "  ")
	if err := os.WriteFile(*outFile, signedJSON, 0644); err != nil {
		fmt.Printf("❌ Error saving license: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✅ License generated successfully!")
	fmt.Printf("   Target ID:  %s\n", *machineID)
	fmt.Printf("   Org:        %s\n", *org)
	fmt.Printf("   Tier:       %s\n", *tier)
	fmt.Printf("   Expires:    %v\n", time.Unix(expiresAt, 0).Format(time.RFC3339))
	fmt.Printf("   Filename:   %s\n", *outFile)
	fmt.Println("\n⚠️  DEPLOYMENT INSTRUCTIONS:")
	fmt.Printf("   Move '%s' to the target machine's ~/.khepra/ directory.\n", *outFile)
}
