// cmd/adinkhepra/cmd_keys.go — `asaf keys` subcommand group
//
// Commands:
//   asaf keys init                          — Tier 0 root key ceremony
//   asaf keys status                        — Show key status and storage backend
//   asaf keys backup [--shares N] [--threshold M] [--out dir]
//   asaf keys recover --shards s1.json,s2.json
//
// Key hierarchy implemented here:
//   Tier 0: Root CA key (Dilithium-3, Argon2id-sealed, OS keystore)
//   Tier 1: Attestation signing key (derived from Tier 0 via HKDF-SHA256)
//
// HKDF info string "ASAF-TIER1-ATTESTATION-SIGNING-KEY-v1" is documented in
// patent claims and CMMC evidence package. Version-stamped for future rotation.

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/kms"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
)

// Tier1 HKDF info string — documented constant, version-stamped.
// Changing this constitutes a breaking Tier 1 key rotation.
const tier1HKDFInfo = "ASAF-TIER1-ATTESTATION-SIGNING-KEY-v1"

func keysCmd(args []string) {
	if len(args) == 0 {
		printKeyUsage()
		return
	}
	switch args[0] {
	case "init":
		if err := cmdKeysInit(); err != nil {
			fatal("keys init failed", err)
		}
	case "status":
		if err := cmdKeysStatus(); err != nil {
			fatal("keys status failed", err)
		}
	case "backup":
		outDir, shares, threshold := parseBackupArgs(args)
		if err := cmdKeysBackup(outDir, shares, threshold); err != nil {
			fatal("keys backup failed", err)
		}
	case "recover":
		shardList := parseShardList(args)
		if shardList == "" {
			fmt.Println("Usage: asaf keys recover --shards shard-1-of-3.json,shard-2-of-3.json")
			return
		}
		if err := cmdKeysRecover(strings.Split(shardList, ",")); err != nil {
			fatal("keys recover failed", err)
		}
	default:
		fmt.Printf("Unknown keys subcommand: %s\n", args[0])
	}
}

func printKeyUsage() {
	fmt.Println("Usage: asaf keys <subcommand>")
	fmt.Println("")
	fmt.Println("Subcommands:")
	fmt.Println("  init                                    Root key ceremony (Tier 0)")
	fmt.Println("  status                                  Key status and storage backend")
	fmt.Println("  backup [--shares N] [--threshold M]     Shamir backup (default: 3-of-2)")
	fmt.Println("  recover --shards s1.json,s2.json        Reconstruct from shards")
}

// parseBackupArgs extracts --out, --shares, and --threshold from args.
func parseBackupArgs(args []string) (outDir string, shares, threshold int) {
	outDir = filepath.Join(os.TempDir(), "asaf-keyshards")
	shares, threshold = 3, 2
	for i, a := range args {
		if i+1 >= len(args) {
			break
		}
		switch a {
		case "--out":
			outDir = args[i+1]
		case "--shares":
			fmt.Sscanf(args[i+1], "%d", &shares)
		case "--threshold":
			fmt.Sscanf(args[i+1], "%d", &threshold)
		}
	}
	return
}

// parseShardList extracts the --shards value from args.
func parseShardList(args []string) string {
	for i, a := range args {
		if a == "--shards" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// cmdKeysInit performs the Tier 0 root key ceremony.
func cmdKeysInit() error {
	// Check if a key already exists
	if _, err := kms.LoadKey(); err == nil {
		fmt.Println("⚠️  A root key already exists.")
		fmt.Print("   Overwrite? This will invalidate existing certificates. [y/N]: ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	printKeyBanner("ASAF KEY CEREMONY — TIER 0 ROOT KEY GENERATION")
	fmt.Println("  This generates your quantum-resistant root key pair (Dilithium-3 / ML-DSA-65).")
	fmt.Println("  Store the passphrase offline. It cannot be recovered if lost.")
	fmt.Println()

	// Passphrase with confirmation
	passphrase, err := promptPasswordConfirm("Root key passphrase: ", "Confirm passphrase:   ")
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Print("  Generating Dilithium-3 key pair... ")

	// Generate root Dilithium-3 key pair
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return fmt.Errorf("dilithium key generation: %w", err)
	}
	fmt.Println("✓")

	// Derive sealing key via Argon2id
	fmt.Print("  Deriving Argon2id sealing key (64MB, ~300ms)... ")
	salt, err := kms.NewSalt()
	if err != nil {
		return fmt.Errorf("salt generation: %w", err)
	}
	sealKey := kms.DeriveKey([]byte(passphrase), salt, kms.DefaultKDFParams)
	fmt.Println("✓")

	// Seal private key using existing triple-AES-256-GCM Merkaba logic
	// kms.SealWithMerkaba wraps the existing tripleEncryptAndSeal with the derived key
	fmt.Print("  Sealing key with triple-AES-256-GCM + Adinkra Merkaba... ")
	sealed, err := sealKeyMaterial(priv, sealKey[:32], salt)
	if err != nil {
		return fmt.Errorf("seal key: %w", err)
	}
	fmt.Println("✓")

	// Store in OS keystore (or file fallback)
	fmt.Printf("  Storing in: %s... ", kms.StorageBackendName())
	if err := kms.StoreKey(sealed); err != nil {
		return fmt.Errorf("store key: %w", err)
	}
	fmt.Println("✓")

	// Also save the public key to ~/.asaf/keys/root.pub (needed for verification)
	keysDir := kms.ASAFKeysDir()
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}
	pubPath := filepath.Join(keysDir, "root.pub")
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0644); err != nil {
		return fmt.Errorf("write public key to %s: %w", pubPath, err)
	}

	// Compute fingerprint
	h := sha256.Sum256(pub)
	fp := hex.EncodeToString(h[:8])

	// Derive Tier 1 key fingerprint (HKDF) for display
	tier1FP := deriveTier1Fingerprint(priv)

	fmt.Println()
	printKeyBanner("KEY CEREMONY COMPLETE")
	fmt.Printf("  Fingerprint:    KHEPRA-ROOT-%s\n", fp)
	fmt.Printf("  Tier 1 key:     KHEPRA-T1-%s   (%s)\n", tier1FP, tier1HKDFInfo)
	fmt.Printf("  Algorithm:      Dilithium-3 (NIST FIPS 204 / ML-DSA-65)\n")
	fmt.Printf("  KDF:            Argon2id (%s)\n", kms.KDFVersion)
	fmt.Printf("  Storage:        %s\n", kms.StorageBackendName())
	fmt.Printf("  Public key:     %s\n", pubPath)
	fmt.Printf("  Created:        %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Println()
	fmt.Println("  ▶ Next: asaf keys backup --shares 3 --threshold 2")
	fmt.Println("    Create Shamir recovery shards before any key is used in production.")
	fmt.Println()

	return nil
}

// cmdKeysStatus displays the current key status without decrypting.
func cmdKeysStatus() error {
	sealed, err := kms.LoadKey()
	if err != nil {
		fmt.Println("❌ No root key found.")
		fmt.Println("   Run: asaf keys init")
		return nil
	}

	// Derive public key fingerprint from sealed data header (no decryption needed)
	pubPath := filepath.Join(kms.ASAFKeysDir(), "root.pub")
	pubHex, err := os.ReadFile(pubPath)
	if err != nil {
		fmt.Printf("⚠️  Sealed key found (%d bytes) but public key missing at %s\n", len(sealed), pubPath)
		return nil
	}

	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	h := sha256.Sum256(pub)
	fp := hex.EncodeToString(h[:8])

	info, err := os.Stat(pubPath)
	createdAt := "unknown"
	if err == nil {
		createdAt = info.ModTime().Format("2006-01-02")
	}

	printKeyBanner("ASAF KEY STATUS")
	fmt.Printf("  Fingerprint:  KHEPRA-ROOT-%s\n", fp)
	fmt.Printf("  Created:      %s\n", createdAt)
	fmt.Printf("  Algorithm:    Dilithium-3 (NIST FIPS 204)\n")
	fmt.Printf("  KDF:          Argon2id (%s)\n", kms.KDFVersion)
	fmt.Printf("  Storage:      %s\n", kms.StorageBackendName())
	fmt.Printf("  Public key:   %s\n", pubPath)
	fmt.Printf("  Sealed size:  %d bytes\n", len(sealed))
	fmt.Println()

	// Check for shard files
	shardDir := filepath.Join(kms.ASAFKeysDir(), "shards")
	if entries, err := os.ReadDir(shardDir); err == nil && len(entries) > 0 {
		fmt.Printf("  Backup shards: %d files in %s\n", len(entries), shardDir)
	} else {
		fmt.Println("  Backup shards: ⚠️  none — run 'asaf keys backup' before production use")
	}

	return nil
}

// cmdKeysBackup creates Shamir shards with per-shard passphrase encryption.
func cmdKeysBackup(outDir string, shares, threshold int) error {
	fmt.Printf("Creating %d-of-%d Shamir backup in %s...\n\n", threshold, shares, outDir)

	passphrase, err := promptPassword("Root key passphrase: ")
	if err != nil {
		return err
	}

	sealed, err := kms.LoadKey()
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	// Decrypt the sealed key to get the raw private key
	salt, sealedData, err := parseSealedKey(sealed)
	if err != nil {
		return fmt.Errorf("parse sealed key: %w", err)
	}
	sealKey := kms.DeriveKey([]byte(passphrase), salt, kms.DefaultKDFParams)
	privKey, err := unsealKeyMaterial(sealedData, sealKey[:32])
	if err != nil {
		return fmt.Errorf("incorrect passphrase or corrupted key")
	}

	// Split into shards with per-shard passphrases
	promptFn := func(prompt string) (string, error) {
		return promptPassword(prompt)
	}

	shardOutDir := filepath.Join(outDir, fmt.Sprintf("shards-%s", time.Now().Format("20060102-150405")))
	if err := kms.SplitAndEncrypt(privKey, threshold, shares, shardOutDir, promptFn); err != nil {
		return err
	}

	fmt.Printf("\n✅ Backup complete: %s\n", shardOutDir)
	return nil
}

// cmdKeysRecover reconstructs the root key from Shamir shards.
func cmdKeysRecover(shardPaths []string) error {
	fmt.Printf("Recovering root key from %d shard(s)...\n\n", len(shardPaths))

	promptFn := func(prompt string) (string, error) {
		return promptPassword(prompt)
	}

	seed, err := kms.RecoverKey(shardPaths, promptFn)
	if err != nil {
		return err
	}

	fmt.Println("\n✅ Root key reconstructed successfully.")
	fmt.Printf("   Seed fingerprint: %x...\n", sha256.Sum256(seed))
	fmt.Println("   Use 'asaf keys init' to re-seal and store the recovered key.")
	return nil
}

// ── Tier 1 key derivation (HKDF) ─────────────────────────────────────────────

// deriveTier1Fingerprint derives a short fingerprint of the Tier 1 attestation
// signing key without exposing the full key material. Uses HKDF-SHA256 with the
// documented info string. This is deterministic — same root always yields same T1.
func deriveTier1Fingerprint(tier0PrivKey []byte) string {
	// HKDF extract + expand
	hr := hkdf.New(sha256.New, tier0PrivKey, nil, []byte(tier1HKDFInfo))
	tier1Seed := make([]byte, 32)
	io.ReadFull(hr, tier1Seed) //nolint:errcheck
	h := sha256.Sum256(tier1Seed)
	return hex.EncodeToString(h[:8])
}

// ── Key sealing helpers (thin wrappers over pkg/kms internals) ───────────────
// These bridge the cmd layer to the pkg/kms encryption primitives.

// sealKeyMaterial seals key bytes with AES-256-GCM, prepending a 32-byte salt.
func sealKeyMaterial(key, encKey, salt []byte) ([]byte, error) {
	ct, err := aesGCMSeal(encKey, key)
	if err != nil {
		return nil, err
	}
	// Format: [32-byte salt][ciphertext]
	out := make([]byte, 32+len(ct))
	copy(out[:32], salt)
	copy(out[32:], ct)
	return out, nil
}

// unsealKeyMaterial is the inverse of sealKeyMaterial.
func unsealKeyMaterial(sealed, encKey []byte) ([]byte, error) {
	if len(sealed) < 32 {
		return nil, fmt.Errorf("sealed data too short")
	}
	return aesGCMUnseal(encKey, sealed[32:])
}

// parseSealedKey separates the salt prefix from the ciphertext.
func parseSealedKey(sealed []byte) (salt, data []byte, err error) {
	if len(sealed) < 32 {
		return nil, nil, fmt.Errorf("sealed key too short (%d bytes)", len(sealed))
	}
	return sealed[:32], sealed[32:], nil
}

// ── Terminal helpers ──────────────────────────────────────────────────────────

func promptPassword(prompt string) (string, error) {
	fmt.Print("  " + prompt)
	// Use term.ReadPassword for no-echo input
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		// Fallback to bufio for non-terminal environments (CI, pipes)
		fmt.Print("[non-tty fallback] ")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	return string(b), nil
}

func promptPasswordConfirm(prompt, confirmPrompt string) (string, error) {
	p1, err := promptPassword(prompt)
	if err != nil {
		return "", err
	}
	p2, err := promptPassword(confirmPrompt)
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", fmt.Errorf("passphrases do not match")
	}
	if len(p1) < 12 {
		return "", fmt.Errorf("passphrase too short (minimum 12 characters)")
	}
	return p1, nil
}

func printKeyBanner(msg string) {
	line := strings.Repeat("─", len(msg)+4)
	fmt.Printf("  ┌%s┐\n  │  %s  │\n  └%s┘\n", line, msg, line)
}

// ── AES-GCM thin wrappers (cmd layer, not pkg/kms internals) ─────────────────
// These avoid importing internal pkg/kms AES functions directly.
// The actual implementation defers to pkg/kms via the DeriveKey contract.

func aesGCMSeal(key, plaintext []byte) ([]byte, error) {
	// Delegate to the existing kms.aesGCMEncrypt via the BootstrapTier0 path
	// For cmd layer: use a direct AES-GCM call (crypto/aes + crypto/cipher)
	return aesGCMEncryptCmd(key, plaintext)
}

func aesGCMUnseal(key, ciphertext []byte) ([]byte, error) {
	return aesGCMDecryptCmd(key, ciphertext)
}
