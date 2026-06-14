package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

func csrCmd(args []string) {
	fs := flag.NewFlagSet("csr", flag.ExitOnError)
	cn := fs.String("cn", "", "Common Name (CN) for the certificate (Required)")
	org := fs.String("org", "SouHimBou.AI", "Organization Name")
	out := fs.String("out", "cloudflare", "Output filename prefix (default: cloudflare)")
	pass := fs.String("pass", "", "Passphrase for encrypted .khepra backup (Required for cloud upload)")
	fs.Parse(args)

	if *cn == "" {
		fmt.Println("Error: --cn (Common Name) is required")
		printCSRUsage()
		return
	}

	// Password check
	passphrase := *pass
	if passphrase == "" {
		fmt.Println("⚠️  WARNING: No passphrase provided via --pass.")
		fmt.Println("   The '.khepra' backup will be encrypted with the DEFAULT DEVELOPMENT PASSPHRASE ('khepra-dev').")
		fmt.Println("   DO NOT UPLOAD THIS TO PUBLIC CLOUDS unless you change the password later.")
		passphrase = "khepra-dev"
		// In interactive mode, we would prompt here using terminal.ReadPassword
	}

	fmt.Println("🛡️  Generating Khepra Hybrid Key Pair...")
	// 1. Generate Hybrid Key
	// We use 'Fawohodie' (Independence) for client certificates (FIG. 10 - Privilege Management).
	keyPair, err := adinkra.GenerateHybridKeyPair("client-cert", "Fawohodie", 12)
	if err != nil {
		fatal("failed to generate hybrid key", err)
	}

	// 2. Generate CSR (from ECDSA layer)
	csrPEM, err := adinkra.GenerateCSR(keyPair, *cn, *org)
	if err != nil {
		fatal("failed to generate CSR", err)
	}

	// 3. Export Private Key (for Browser/OS import)
	keyPEM, err := adinkra.ExportECDSAPrivateKeyPEM(keyPair)
	if err != nil {
		fatal("failed to export private key", err)
	}

	// 4. Generate Encrypted Backup (.khepra)
	fmt.Println("🔒 Encrypting Backup Artifact (Argon2id + Kyber + AES-GCM)...")
	backup, err := adinkra.EncryptBackup(keyPair, passphrase)
	if err != nil {
		fatal("failed to encrypt backup", err)
	}
	backupHelpers, _ := json.MarshalIndent(backup, "", "  ")

	// 5. Save Artifacts
	csrFile := *out + ".csr"
	keyFile := *out + ".key"
	backupFile := *out + ".khepra"

	// Write CSR
	if err := os.WriteFile(csrFile, csrPEM, 0644); err != nil {
		fatal("failed to write CSR file", err)
	}

	// Write Key
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		fatal("failed to write Key file", err)
	}

	// Write Backup
	if err := os.WriteFile(backupFile, backupHelpers, 0644); err != nil {
		fatal("failed to write Backup file", err)
	}

	fmt.Printf("[CSR] Successfully generated artifacts:\n")
	fmt.Printf("   1. CSR Request:   %s (Upload this to Cloudflare)\n", csrFile)
	fmt.Printf("   2. Private Key:   %s (Import this to Browser)\n", keyFile)
	fmt.Printf("   3. Secure Backup: %s (Safe for Cloud Storage)\n", backupFile)
	fmt.Println()
	fmt.Println("👉 Next Step: Copy the content of " + csrFile + " and paste it into the 'Certificate Signing Request (CSR)' box.")
}

func printCSRUsage() {
	fmt.Println(`adinkhepra csr - Generate Cloudflare-compatible CSR and PQC Backup

Usage:
  adinkhepra csr --cn <name> [--org <org>] [--out <filename>] [--pass <password>]

Examples:
  adinkhepra csr --cn "SouHimBou Admin" --pass "CorrectHorseBatteryStaple"
  adinkhepra csr --cn "Khepra Agent 001" --out agent_01`)
}
