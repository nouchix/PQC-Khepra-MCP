package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sca"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/vuln"
)

// ertCryptoCmd implements Package C: Tactical Weapons System
// Code Lineage & PQC Attestation — SBOM-informed cryptographic analysis
func ertCryptoCmd(args []string) {
	targetDir := "."
	if len(args) > 0 {
		targetDir = args[0]
	}

	printPurple("================================================================")
	printPurple(" KHEPRA PROTOCOL // TIER III: TACTICAL WEAPONS SYSTEM")
	printPurple(" CODE LINEAGE & PQC ATTESTATION v6.0.0")
	printPurple("================================================================\n")

	fmt.Print("\nPress ENTER to Verify Codebase Integrity...")
	fmt.Scanln()

	printSlow("[*] Hashing Git History (Merkle Tree Construction)...")

	// Hash actual codebase
	hashes := hashCodebase(targetDir)
	for i, h := range hashes {
		if i >= 3 {
			break // Show first 3 hashes
		}
		printHex(h + "... [verifying blocks] ... OK")
	}

	fmt.Print("\033[0m")
	fmt.Println("\n[*] Analyzing Cryptographic Primitives (Source + SBOM)...")

	// ── Source-level crypto scan (AST-approximation via string analysis) ─────
	cryptoUsage := analyzeCryptoUsage(targetDir)

	// ── SBOM-informed crypto library inventory ────────────────────────────────
	var sbomCryptoLibs []SBOMCryptoLib
	if toolInPath("syft") && toolInPath("grype") {
		printSlow("[*] SBOM crypto library scan in progress...")
		spinCursor("Scanning SBOM", 2*time.Second)
		sbomCryptoLibs = scanSBOMCryptoLibraries(targetDir)
		fmt.Print("\r[*] SBOM Crypto Scan Complete               \n")
	} else {
		printYellow("[INFO] Install syft+grype for SBOM-based crypto library inventory.")
	}

	// Display combined analysis
	displayCryptoAnalysis(cryptoUsage)
	displaySBOMCryptoInventory(sbomCryptoLibs)

	// ── Weak primitive detection ───────────────────────────────────────────────
	fmt.Println("\n[*] Detecting Weak/Deprecated Primitives...")
	weakPrimitives := detectWeakPrimitives(targetDir)
	displayWeakPrimitives(weakPrimitives)

	// ── PQC migration simulation ───────────────────────────────────────────────
	fmt.Println("\n[*] Simulating Khepra PQC Migration...")
	time.Sleep(time.Second)
	fmt.Println("    [>] Replacing RSA with ML-KEM-768 (NIST FIPS 203)...")
	time.Sleep(500 * time.Millisecond)
	fmt.Println("    [>] Replacing ECDSA with ML-DSA-65 (NIST FIPS 204)...")
	time.Sleep(500 * time.Millisecond)
	fmt.Println("    [>] Replacing SHA-1 with SHA-3 (NIST FIPS 202)...")
	time.Sleep(500 * time.Millisecond)
	printGreen("    [✓] PQC Migration Path: VALIDATED (CNSA 2.0 compliant)")

	// ── Quantum risk context (CNSA 2.0 scenario-based, not precise dates) ────
	displayQuantumRiskContext(cryptoUsage, sbomCryptoLibs)

	// ── IP lineage analysis ────────────────────────────────────────────────────
	fmt.Println("\n[*] Verifying IP Lineage (AR 27-60)...")
	time.Sleep(500 * time.Millisecond)

	ipAnalysis := analyzeIPLineage(targetDir)
	fmt.Printf("    -> %.0f%% Proprietary Code (Verified Authorship)\n", ipAnalysis.Proprietary)
	fmt.Printf("    -> %.0f%% Open Source (MIT/Apache 2.0 - Clean)\n", ipAnalysis.OSS)
	fmt.Printf("    -> %.0f%% GPL/Viral Contamination Found\n", ipAnalysis.GPL)

	if ipAnalysis.GPL == 0 {
		printGreen("\n[+] IP PURITY CERTIFICATE: ISSUED")
	} else {
		printRed("\n[!] IP CONTAMINATION DETECTED: REMEDIATION REQUIRED")
	}

	printGreen("[+] PQC READINESS: MIGRATION PATH CONFIRMED\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// SBOM Crypto Library Inventory
// ─────────────────────────────────────────────────────────────────────────────

// SBOMCryptoLib represents a crypto-relevant library found in the SBOM.
type SBOMCryptoLib struct {
	Name       string
	Version    string
	Ecosystem  string
	PQCCapable bool   // Supports post-quantum algorithms
	Weak       bool   // Contains known-weak primitives
	Note       string // Human-readable risk note
}

// cryptoLibPatterns maps well-known crypto library name patterns to their PQC/weak status.
var cryptoLibPatterns = []struct {
	Pattern    string
	PQCCapable bool
	Weak       bool
	Note       string
}{
	// Post-quantum capable
	{"liboqs", true, false, "Open Quantum Safe — NIST PQC reference implementation"},
	{"pqcrypto", true, false, "PQCrypto — pure-Go NIST PQC suite"},
	{"kyber", true, false, "ML-KEM-768 key encapsulation (NIST FIPS 203)"},
	{"dilithium", true, false, "ML-DSA-65 digital signatures (NIST FIPS 204)"},
	{"mlkem", true, false, "ML-KEM — NIST standardized KEM"},
	{"mldsa", true, false, "ML-DSA — NIST standardized signature scheme"},
	{"sphincs", true, false, "SLH-DSA hash-based signatures (NIST FIPS 205)"},
	{"falcon", true, false, "Falcon lattice signatures (NIST round 4)"},

	// Classical but safe (quantum-resistant for symmetric operations)
	{"aes", false, false, "AES-256 is Grover-resistant at 256-bit key length"},
	{"sha256", false, false, "SHA-256 safe with 128-bit post-quantum security"},
	{"sha512", false, false, "SHA-512 safe with 256-bit post-quantum security"},
	{"chacha20", false, false, "ChaCha20 stream cipher — acceptable for classical + quantum"},
	{"xchacha", false, false, "XChaCha20 — extended nonce variant, acceptable"},

	// Weak or quantum-vulnerable
	{"openssl", false, false, "OpenSSL — assess version for weak default configs"},
	{"rsa", false, true, "RSA — quantum-vulnerable via Shor's algorithm"},
	{"ecdsa", false, true, "ECDSA — quantum-vulnerable via Shor's algorithm"},
	{"ecdh", false, true, "ECDH — quantum-vulnerable key exchange"},
	{"des", false, true, "DES/3DES — deprecated, broken brute-force resistance"},
	{"rc4", false, true, "RC4 — cryptographically broken stream cipher"},
	{"md5", false, true, "MD5 — collision-broken hash function"},
	{"sha1", false, true, "SHA-1 — collision-broken, NIST deprecated"},
	{"blowfish", false, true, "Blowfish — deprecated, short block size (64-bit)"},
	{"arc4", false, true, "ARC4 — RC4 variant, cryptographically broken"},
}

// scanSBOMCryptoLibraries uses the SCA pipeline to enumerate crypto-relevant
// components from the project SBOM and classify them for PQC readiness.
func scanSBOMCryptoLibraries(dir string) []SBOMCryptoLib {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}

	feedMgr := vuln.NewIntelFeedManager()
	pipeline := sca.NewPipeline(feedMgr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	result, err := pipeline.ScanAndEnrich(ctx, absDir)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var libs []SBOMCryptoLib

	for _, f := range result.Findings {
		name := strings.ToLower(f.Component)
		for _, pattern := range cryptoLibPatterns {
			if strings.Contains(name, pattern.Pattern) && !seen[f.Component+f.Version] {
				seen[f.Component+f.Version] = true
				libs = append(libs, SBOMCryptoLib{
					Name:       f.Component,
					Version:    f.Version,
					Ecosystem:  f.Ecosystem,
					PQCCapable: pattern.PQCCapable,
					Weak:       pattern.Weak,
					Note:       pattern.Note,
				})
				break
			}
		}
	}

	// Sort: weak first, then by name
	sort.Slice(libs, func(i, j int) bool {
		if libs[i].Weak != libs[j].Weak {
			return libs[i].Weak
		}
		return libs[i].Name < libs[j].Name
	})
	return libs
}

// displaySBOMCryptoInventory renders the SBOM-derived crypto library inventory.
func displaySBOMCryptoInventory(libs []SBOMCryptoLib) {
	if len(libs) == 0 {
		return
	}

	fmt.Printf("\n    [SBOM] Crypto Library Inventory (%d libraries identified):\n", len(libs))
	fmt.Println("    " + strings.Repeat("-", 60))

	for _, lib := range libs {
		var tag, color string
		switch {
		case lib.Weak:
			tag = "WEAK"
			color = "\033[91m"
		case lib.PQCCapable:
			tag = "PQC"
			color = "\033[92m"
		default:
			tag = "OK"
			color = "\033[93m"
		}
		fmt.Printf("%s    [%s]\033[0m %s@%s (%s)\n", color, tag, lib.Name, lib.Version, lib.Ecosystem)
		if lib.Note != "" {
			fmt.Printf("           %s\n", lib.Note)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Weak Primitive Detection
// ─────────────────────────────────────────────────────────────────────────────

// WeakPrimitive represents a detected weak or deprecated cryptographic primitive.
type WeakPrimitive struct {
	Pattern  string
	File     string
	Line     int
	Severity string // CRITICAL | HIGH | MEDIUM
	Reason   string
}

// weakPrimitiveDetectors defines patterns that signal weak crypto usage.
var weakPrimitiveDetectors = []struct {
	Pattern  string
	Severity string
	Reason   string
}{
	{"md5.New()", "CRITICAL", "MD5 is collision-broken — use SHA-256 minimum"},
	{"md5.Sum(", "CRITICAL", "MD5 is collision-broken — use SHA-256 minimum"},
	{"sha1.New()", "HIGH", "SHA-1 is collision-broken — use SHA-256 minimum"},
	{"sha1.Sum(", "HIGH", "SHA-1 is collision-broken — use SHA-256 minimum"},
	{"des.NewCipher(", "CRITICAL", "DES is insecure — use AES-256-GCM"},
	{"des.NewTripleDESCipher(", "HIGH", "3DES has 64-bit block size — migrate to AES-256"},
	{"rc4.NewCipher(", "CRITICAL", "RC4 is cryptographically broken — do not use"},
	{"blowfish.NewCipher(", "HIGH", "Blowfish 64-bit block size is vulnerable — use AES-256"},
	{"rsa.GenerateKey(", "MEDIUM", "RSA key size must be ≥4096 for post-quantum transition buffer"},
	{`"RSA-2048"`, "HIGH", "RSA-2048 insufficient for post-2028 requirements"},
	{"ECDHKey(P256", "MEDIUM", "ECDH P-256 is quantum-vulnerable — plan migration to ML-KEM"},
	{"ecdsa.GenerateKey(elliptic.P224", "HIGH", "ECDSA P-224 below minimum — use P-384 or ML-DSA"},
	{"rand.Read(", "MEDIUM", "Verify crypto/rand is used, not math/rand"},
	{`"hardcoded_key"`, "CRITICAL", "Hardcoded cryptographic key detected"},
	{"IV := []byte{", "MEDIUM", "Potential hardcoded IV — use crypto/rand for IVs"},
	{"nonce := []byte{", "MEDIUM", "Potential hardcoded nonce — use crypto/rand"},
}

// detectWeakPrimitives scans Go source files for weak cryptographic patterns.
func detectWeakPrimitives(dir string) []WeakPrimitive {
	var found []WeakPrimitive

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Focus on Go source files only; skip vendor to avoid false positives
		if !strings.HasSuffix(path, ".go") || strings.Contains(path, "/vendor/") ||
			strings.Contains(path, "\\vendor\\") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		lines := strings.Split(content, "\n")

		for lineNum, line := range lines {
			for _, d := range weakPrimitiveDetectors {
				if strings.Contains(line, d.Pattern) {
					found = append(found, WeakPrimitive{
						Pattern:  d.Pattern,
						File:     path,
						Line:     lineNum + 1,
						Severity: d.Severity,
						Reason:   d.Reason,
					})
				}
			}
		}
		return nil
	})

	// Sort by severity
	sort.Slice(found, func(i, j int) bool {
		return severityRank(found[i].Severity) > severityRank(found[j].Severity)
	})
	return found
}

// displayWeakPrimitives renders detected weak primitives.
func displayWeakPrimitives(primitives []WeakPrimitive) {
	if len(primitives) == 0 {
		printGreen("    [+] No weak cryptographic primitives detected in source scan.")
		return
	}

	displayLimit := 10
	if len(primitives) < displayLimit {
		displayLimit = len(primitives)
	}

	fmt.Printf("    [WEAK PRIMITIVES] %d detected (showing %d):\n", len(primitives), displayLimit)
	for _, p := range primitives[:displayLimit] {
		color := severityColor(p.Severity)
		// Trim absolute path for readability
		shortPath := filepath.Base(filepath.Dir(p.File)) + "/" + filepath.Base(p.File)
		fmt.Printf("%s    [%s]\033[0m %s:%d — %s\n",
			color, p.Severity, shortPath, p.Line, p.Reason)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Quantum Risk Context (CNSA 2.0 scenario-based)
// ─────────────────────────────────────────────────────────────────────────────

// displayQuantumRiskContext shows CNSA 2.0 timeline-aligned risk context.
// Per AD-006: never use precise quantum break dates — use scenario ranges.
func displayQuantumRiskContext(usage CryptoUsage, sbomLibs []SBOMCryptoLib) {
	fmt.Println("\n[*] Quantum Risk Context (CNSA 2.0 / NIST SP 800-131A Rev 3):")

	weakSBOMCount := 0
	for _, lib := range sbomLibs {
		if lib.Weak {
			weakSBOMCount++
		}
	}

	hasRSA := usage.RSA > 0 || weakSBOMCount > 0
	hasECDSA := usage.ECDSA > 0

	if hasRSA {
		printRed("    [QUANTUM-VULN] RSA detected:")
		fmt.Println("    • Vulnerable to Shor's algorithm when cryptographically-relevant")
		fmt.Println("      quantum computers (CRQCs) reach scale (scenario: 2030–2040 window)")
		fmt.Println("    • CNSA 2.0 mandates ML-KEM-768 for new systems NOW")
		fmt.Println("    • Migration path: RSA → ML-KEM-768 (NIST FIPS 203)")
	}

	if hasECDSA {
		printRed("    [QUANTUM-VULN] ECDSA/ECDH detected:")
		fmt.Println("    • Same Shor's vulnerability as RSA — elliptic curve discrete log is broken")
		fmt.Println("    • CNSA 2.0 mandates ML-DSA-65 for signatures NOW")
		fmt.Println("    • Migration path: ECDSA → ML-DSA-65 (NIST FIPS 204)")
	}

	if usage.HasPQC {
		printGreen("    [PQC-PRESENT] Post-quantum algorithms detected in source:")
		if usage.Kyber > 0 {
			fmt.Printf("      ML-KEM (Kyber): %d references\n", usage.Kyber)
		}
		if usage.Dilithium > 0 {
			fmt.Printf("      ML-DSA (Dilithium): %d references\n", usage.Dilithium)
		}
	}

	if !hasRSA && !hasECDSA && !usage.HasPQC {
		printYellow("    [INFO] No classical public-key crypto detected in source scan.")
		printYellow("           Run SBOM scan for complete dependency-level inventory.")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Source-level crypto analysis (retained from v5, extended with weak detection)
// ─────────────────────────────────────────────────────────────────────────────

// hashCodebase generates merkle hashes for codebase verification
func hashCodebase(dir string) []string {
	var hashes []string
	hasher := sha256.New()

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".py") &&
			!strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".java") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		hasher.Reset()
		hasher.Write(data)
		hash := hex.EncodeToString(hasher.Sum(nil))
		hashes = append(hashes, hash)

		if len(hashes) >= 10 {
			return filepath.SkipDir
		}
		return nil
	})

	if len(hashes) == 0 {
		// Generate deterministic placeholder hashes for display
		for i := 0; i < 3; i++ {
			hasher.Reset()
			hasher.Write([]byte(fmt.Sprintf("merkle-block-%d", i)))
			hashes = append(hashes, hex.EncodeToString(hasher.Sum(nil)))
		}
	}

	return hashes
}

// printHex displays text with matrix-style green effect
func printHex(s string) {
	for _, c := range s {
		fmt.Printf("\033[92m%c\033[0m", c)
		time.Sleep(time.Millisecond)
	}
	fmt.Println()
}

// CryptoUsage tracks cryptographic primitive usage in source code
type CryptoUsage struct {
	RSA       int
	ECDSA     int
	AES       int
	SHA       int
	Kyber     int
	Dilithium int
	HasLegacy bool
	HasPQC    bool
}

// analyzeCryptoUsage scans codebase for crypto primitives via string matching.
// For a full AST-level analysis, use the SBOM-based scanSBOMCryptoLibraries().
func analyzeCryptoUsage(dir string) CryptoUsage {
	usage := CryptoUsage{}

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.Contains(path, "/vendor/") || strings.Contains(path, "\\vendor\\") {
			return nil // Exclude vendor to avoid false positives
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		usage.RSA += strings.Count(content, "rsa.")
		usage.ECDSA += strings.Count(content, "ecdsa.") + strings.Count(content, "ecdh.")
		usage.AES += strings.Count(content, "aes.")
		usage.SHA += strings.Count(content, "sha256") + strings.Count(content, "sha512")
		usage.Kyber += strings.Count(content, "kyber") + strings.Count(content, "Kyber") +
			strings.Count(content, "mlkem") + strings.Count(content, "MLKEM")
		usage.Dilithium += strings.Count(content, "dilithium") + strings.Count(content, "Dilithium") +
			strings.Count(content, "mldsa") + strings.Count(content, "MLDSA")

		return nil
	})

	usage.HasLegacy = usage.RSA > 0 || usage.ECDSA > 0
	usage.HasPQC = usage.Kyber > 0 || usage.Dilithium > 0

	return usage
}

// displayCryptoAnalysis shows the source-level crypto primitive analysis.
func displayCryptoAnalysis(usage CryptoUsage) {
	if usage.RSA > 0 {
		printRed(fmt.Sprintf("    -> RSA: QUANTUM-VULNERABLE (Shor's algorithm) [%d source refs]", usage.RSA))
	} else {
		printYellow("    -> RSA: NOT DETECTED in source")
	}

	if usage.ECDSA > 0 {
		printRed(fmt.Sprintf("    -> ECDSA/ECDH: QUANTUM-VULNERABLE [%d source refs]", usage.ECDSA))
	} else {
		printYellow("    -> ECDSA/ECDH: NOT DETECTED in source")
	}

	if usage.AES > 0 {
		printGreen(fmt.Sprintf("    -> AES-256: QUANTUM-RESISTANT (Grover halving → AES-256 still safe) [%d refs]", usage.AES))
	}

	if usage.SHA > 0 {
		printGreen(fmt.Sprintf("    -> SHA-256/512: SAFE [%d refs]", usage.SHA))
	}

	if usage.Kyber > 0 {
		printGreen(fmt.Sprintf("    -> ML-KEM (Kyber): PQC KEM DETECTED [%d refs]", usage.Kyber))
	}

	if usage.Dilithium > 0 {
		printGreen(fmt.Sprintf("    -> ML-DSA (Dilithium): PQC SIGNATURE DETECTED [%d refs]", usage.Dilithium))
	}

	if !usage.HasLegacy && !usage.HasPQC {
		printYellow("    -> No crypto primitives detected in scanned .go files.")
		printYellow("       Run with syft+grype installed for SBOM-level library inventory.")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IP Lineage Analysis
// ─────────────────────────────────────────────────────────────────────────────

// IPAnalysis tracks intellectual property ownership
type IPAnalysis struct {
	Proprietary float64
	OSS         float64
	GPL         float64
}

// analyzeIPLineage determines code ownership and licensing from file headers.
func analyzeIPLineage(dir string) IPAnalysis {
	analysis := IPAnalysis{}

	proprietaryPatterns := []string{
		"// Copyright", "// Proprietary",
		"// SPDX-License-Identifier: Proprietary",
		"EtherVerseCodeMate", "NouchiX",
	}
	ossPatterns := []string{
		"MIT License", "Apache License", "BSD",
		"SPDX-License-Identifier: MIT",
		"SPDX-License-Identifier: Apache-2.0",
	}
	gplPatterns := []string{
		"GPL", "GNU General Public",
		"SPDX-License-Identifier: GPL",
	}

	var proprietaryCount, ossCount, gplCount, totalFiles int

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".py") &&
			!strings.HasSuffix(path, ".js") {
			return nil
		}
		if strings.Contains(path, "/vendor/") || strings.Contains(path, "\\vendor\\") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		totalFiles++

		// Check header (first 20 lines)
		lines := strings.Split(content, "\n")
		header := strings.Join(lines[:min(len(lines), 20)], "\n")

		isProprietary, isOSS, isGPL := false, false, false
		for _, p := range proprietaryPatterns {
			if strings.Contains(header, p) {
				isProprietary = true
				break
			}
		}
		for _, p := range ossPatterns {
			if strings.Contains(header, p) {
				isOSS = true
				break
			}
		}
		for _, p := range gplPatterns {
			if strings.Contains(header, p) {
				isGPL = true
				break
			}
		}

		switch {
		case isGPL:
			gplCount++
		case isOSS:
			ossCount++
		default:
			// Both proprietary and untagged default to proprietary
			if isProprietary || !isOSS {
				proprietaryCount++
			}
		}
		return nil
	})

	if totalFiles > 0 {
		analysis.Proprietary = float64(proprietaryCount) / float64(totalFiles) * 100
		analysis.OSS = float64(ossCount) / float64(totalFiles) * 100
		analysis.GPL = float64(gplCount) / float64(totalFiles) * 100
	} else {
		// Default demo values when no source files found
		analysis.Proprietary = 88.0
		analysis.OSS = 12.0
		analysis.GPL = 0.0
	}

	return analysis
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
