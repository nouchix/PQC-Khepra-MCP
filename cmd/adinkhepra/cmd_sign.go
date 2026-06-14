package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

func signCmd(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "Path to Dilithium3 private key (required)")
	inputFile := fs.String("input", "", "File to sign (required)")
	outputFile := fs.String("output", "", "Signature output file (default: <input>.sig)")
	fs.Parse(args)

	if *keyPath == "" || *inputFile == "" {
		fmt.Println("Error: --key and --input are required")
		printSignUsage()
		return
	}

	// Default output file
	if *outputFile == "" {
		*outputFile = *inputFile + ".sig"
	}

	// Read private key
	privKeyData, err := os.ReadFile(*keyPath)
	if err != nil {
		fatal("failed to read private key", err)
	}

	// Read input file
	inputData, err := os.ReadFile(*inputFile)
	if err != nil {
		fatal("failed to read input file", err)
	}

	// Compute SHA256 hash of input (for Git compatibility)
	hash := sha256.Sum256(inputData)
	hashHex := hex.EncodeToString(hash[:])

	// Sign the hash using Dilithium3
	signature, err := adinkra.Sign(privKeyData, hash[:])
	if err != nil {
		fatal("failed to sign", err)
	}

	// Create Git-style signature format
	gitSig := fmt.Sprintf(`-----BEGIN DILITHIUM3 SIGNATURE-----
Hash: SHA256
Algorithm: Dilithium3 (NIST FIPS 204)

%s

-----BEGIN SIGNATURE-----
%s
-----END DILITHIUM3 SIGNATURE-----
`, hashHex, hex.EncodeToString(signature))

	// Write signature to output
	if err := os.WriteFile(*outputFile, []byte(gitSig), 0644); err != nil {
		fatal("failed to write signature", err)
	}

	fmt.Printf("[SIGN] Signature created: %s\n", *outputFile)
}

func printSignUsage() {
	fmt.Println(`adinkhepra sign - Sign files with Dilithium3

Usage:
  adinkhepra sign --key <private-key> --input <file> [--output <signature-file>]

Examples:
  # Sign a Git commit
  adinkhepra sign --key .khepra/dag-signing-key --input commit-msg.txt

  # Sign DAG snapshot
  adinkhepra sign --key .khepra/dag-signing-key --input snapshot.json --output snapshot.sig`)
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keyPath := fs.String("key", "", "Path to Dilithium3 public key (required)")
	inputFile := fs.String("input", "", "File to verify (required)")
	sigFile := fs.String("signature", "", "Signature file (default: <input>.sig)")
	fs.Parse(args)

	if *keyPath == "" || *inputFile == "" {
		fmt.Println("Error: --key and --input are required")
		printVerifyUsage()
		return
	}

	// Default signature file
	if *sigFile == "" {
		*sigFile = *inputFile + ".sig"
	}

	// Read public key
	pubKeyData, err := os.ReadFile(*keyPath + ".pub")
	if err != nil {
		fatal("failed to read public key", err)
	}

	// Read input file
	inputData, err := os.ReadFile(*inputFile)
	if err != nil {
		fatal("failed to read input file", err)
	}

	// Read signature
	sigData, err := os.ReadFile(*sigFile)
	if err != nil {
		fatal("failed to read signature", err)
	}

	// Extract signature from Git format
	// (Parse the -----BEGIN SIGNATURE----- block)
	sigHex := extractSignatureHex(string(sigData))
	signature, err := hex.DecodeString(sigHex)
	if err != nil {
		fatal("failed to decode signature", err)
	}

	// Compute hash
	hash := sha256.Sum256(inputData)

	// Verify signature
	valid, err := adinkra.Verify(pubKeyData, hash[:], signature)
	if err != nil {
		fatal("verification failed", err)
	}
	if !valid {
		fmt.Println("[VERIFY] ❌ INVALID SIGNATURE")
		os.Exit(1)
	}

	fmt.Println("[VERIFY] ✅ VALID SIGNATURE")
	fmt.Printf("   - Algorithm: Dilithium3 (NIST FIPS 204)\n")
	fmt.Printf("   - File Hash: %x\n", hash)
	fmt.Println("   - Status: Post-quantum secure")
}

func printVerifyUsage() {
	fmt.Println(`adinkhepra verify - Verify Dilithium3 signatures

Usage:
  adinkhepra verify --key <public-key> --input <file> [--signature <sig-file>]

Examples:
  # Verify a signed file
  adinkhepra verify --key .khepra/dag-signing-key.pub --input snapshot.json

  # Verify with custom signature file
  adinkhepra verify --key .khepra/dag-signing-key.pub --input snapshot.json --signature custom.sig`)
}

// Helper to extract hex signature from Git-style format
func extractSignatureHex(sigText string) string {
	lines := []string{}
	inSigBlock := false

	for _, line := range splitLines(sigText) {
		if line == "-----BEGIN SIGNATURE-----" {
			inSigBlock = true
			continue
		}
		if line == "-----END DILITHIUM3 SIGNATURE-----" {
			break
		}
		if inSigBlock && line != "" {
			lines = append(lines, line)
		}
	}

	// Join all hex lines
	result := ""
	for _, line := range lines {
		result += line
	}
	return result
}

func splitLines(s string) []string {
	lines := []string{}
	current := ""
	for _, ch := range s {
		if ch == '\n' || ch == '\r' {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
