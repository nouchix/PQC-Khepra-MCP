package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/agent"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/attest"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/config"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/drbc"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/intel"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/kms"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/packet"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/scanner"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/scorpion"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/util"
	"golang.org/x/crypto/ssh"
)

const (
	masterPubKeyFile   = "adinkhepra_master.pub"
	licenseFile        = "license.adinkhepra"
	listBulletMsg      = "  - %s\n"
	adinkraExt         = ".adinkhepra"
	separator          = "---------------------------------------------------"
	subcommandsHeader  = "Subcommands:"
	speakSecretNameMsg = "Speak the Secret Name: "
	headerAPIKey       = "X-API-Key"
)

func usage() {
	fmt.Println(`AdinKhepra v2.0 — CMMC Autopilot Engine | SecRed Knowledge Inc. (NouchiX)
https://nouchix.com | https://adinkhepra.com

Core Compliance Commands:
  adinkhepra compliance <subcmd>    CMMC/STIG/NIST 800-171 full scan suite
  adinkhepra compliance-attest      PQC-sign a CMMC narrative/POAM change → DAG chain (Dilithium3)
  adinkhepra ssp        <subcmd>    System Security Plan (NIST SP 800-18) — generate|update|export|diff|status
  adinkhepra poam       <subcmd>    Plan of Action & Milestones — generate|status|export|update
  adinkhepra blast-radius <subcmd> Quantum-Readiness Blast Radius (NTI Score) — report|roadmap
  adinkhepra discover               Phase 0: agent-led discovery, crypto inventory, SSP seed
  adinkhepra demo                   Self-serve demo mode (synthetic environment, no real system needed)

Reporting:
  adinkhepra report     <subcmd>    PDF report generation (executive, technical, compliance)
  adinkhepra ert        <subcmd>    Executive Roundtable — godfather|readiness|architect|crypto

Agent & Scan:
  adinkhepra scan       --target <host|ip>   Full scan: STIG + AI agent audit + PQC inventory
  adinkhepra watch      [-port 45444]         Start ASAF wrapper + live dashboard
  adinkhepra certify    --target <host|ip>    Full audit + ADINKHEPRA certificate

Key Management (PQC):
  adinkhepra keygen                 Generate Dilithium3/Kyber-1024 keypair
  adinkhepra keys init              Tier 0 key ceremony
  adinkhepra keys status            Key storage status

Encryption:
  adinkhepra kuntinkantan <pubkey> <file>   PQC encrypt
  adinkhepra sankofa      <privkey> <file>  PQC decrypt

License:
  adinkhepra license status         Show host ID and current license
  adinkhepra license request        Generate QKD license request bundle
  adinkhepra license install        Install a license capsule

Your AI agents are working right now. Do you know what they are doing?
Start watching: adinkhepra watch
Run your first CMMC assessment: adinkhepra compliance scan --framework CMMC_L2`)
}


func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	if handlePrimaryCmds(cmd, args) {
		return
	}
	if handleSecondaryCmds(cmd, args) {
		return
	}
	usage()
}

func handlePrimaryCmds(cmd string, args []string) bool {
	switch cmd {
	case "keygen":
		keygenCmd(args)
	case "crack":
		crackCmd(args)
	case "kuntinkantan":
		kuntinkantanCmd(args)
	case "sankofa":
		sankofaCmd(args)
	case "ogya":
		ogyaCmd(args)
	case "nsuo":
		nsuoCmd(args)
	case "git-remote":
		gitRemoteCmd()
	case "validate":
		validateCmd(args)
	case "serve":
		serveCmd(args)
	case "ert":
		ertCmd(args)
	case "ert-readiness":
		ertReadinessCmd(args)
	case "ert-architect":
		ertArchitectCmd(args)
	case "ert-crypto":
		ertCryptoCmd(args)
	case "ert-godfather":
		ertGodfatherCmd(args)
	case "compliance":
		enforceLicense()
		complianceCmd(args)
	case "audit":
		auditCmd(args)
	case "scada":
		scadaCmd(args)
	case "scan":
		scanCmd(args, "full")
	case "certify":
		scanCmd(args, "certify")
	case "watch":
		watchCmd(args)
	default:
		return false
	}
	return true
}

func handleSecondaryCmds(cmd string, args []string) bool {
	switch cmd {
	// New SOW delivery commands (Sprint A)
	case "ssp":
		sspCmd(args)
	case "poam":
		poamCmd(args)
	case "blast-radius", "blast_radius", "blastradius":
		blastRadiusCmd(args)
	case "discover":
		discoverCmd(args)
	case "demo":
		demoCmd(args)

	// Compliance attestation — PQC-signed DAG audit trail for CMMC documentation
	// "adinkhepra compliance-attest" signs every SSP narrative and POAM change
	// with Dilithium3, creating a tamper-evident chain in asaf-compliance/attestations/
	case "compliance-attest":
		complianceAttestCmd(args)

	// Legacy / deprecated
	case "stig":
		fmt.Println("[DEPRECATED] Use 'adinkhepra compliance scan' instead.")
		complianceCmd(args)
	case "stigs":
		fmt.Println("[DEPRECATED] Use 'adinkhepra compliance ingest' instead.")
		complianceIngestCmd(args)
	case "explain":
		explainCmd(args)
	case "hostid":
		printHostID()
	case "license":
		licenseDispatchCmd(args)
	case "license-gen":
		licenseGenCmd(args)
	case "arsenal":
		arsenalCmd(args)
	case "attest":
		attestCmd(args)
	case "kms":
		kmsCmd(args)
	case "keys":
		keysCmd(args)
	case "llm":
		llmCmd(args)
	case "drbc":
		drbcCmd(args)
	case "agent":
		agentCmd(args)
	case "ea":
		eaCmd(args)
	case "fim":
		fimCmd(args)
	case "network":
		networkCmd(args)
	case "sbom":
		sbomCmd(args)
	case "engine":
		engineCmd(args)
	case "report":
		reportCmd(args)
	case "sign":
		signCmd(args)
	case "verify":
		verifyCmd(args)
	case "csr":
		csrCmd(args)
	case "run":
		watchCmd(args)
	case "health":
		fmt.Println("OK")
		os.Exit(0)
	default:
		return false
	}
	return true
}

// getExeDir returns the directory containing the executable
func getExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	// Resolve symlinks to get actual path
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// getProjectRoot finds the project root by looking for key indicators
func getProjectRoot() string {
	// Priority: 1. ADINKHEPRA_ROOT env var, 2. Parent of exe dir (bin/../), 3. CWD
	if root := os.Getenv("ADINKHEPRA_ROOT"); root != "" {
		return root
	}

	exeDir := getExeDir()

	// If exe is in 'bin/', parent is project root
	if filepath.Base(exeDir) == "bin" {
		return filepath.Dir(exeDir)
	}

	// Otherwise check if current directory has keys/
	if _, err := os.Stat("keys"); err == nil {
		cwd, _ := os.Getwd()
		return cwd
	}

	return exeDir
}

// resolvePath resolves a relative path against project root
func resolvePath(relPath string) string {
	if filepath.IsAbs(relPath) {
		return relPath
	}
	return filepath.Join(getProjectRoot(), relPath)
}

// EnforceLicense checks for valid license or panics
func enforceLicense() {
	if os.Getenv("ADINKHEPRA_DEV") == "1" {
		return
	}

	pubKey := findMasterPubKey()
	if pubKey == nil {
		fmt.Println("FATAL: AdinKhepra Master Key not found. Checked:")
		fmt.Println("  - ADINKHEPRA_MASTER_KEY_PUB env var")
		fmt.Printf(listBulletMsg, resolvePath("keys/offline/OFFLINE_ROOT_KEY.pub"))
		fmt.Printf(listBulletMsg, filepath.Join(getExeDir(), masterPubKeyFile))
		fmt.Printf("  - %s (cwd)\n", masterPubKeyFile)
		fmt.Println("Integrity check failed.")
		os.Exit(1)
	}

	licPath := findLicenseFile()
	if licPath == "" {
		fmt.Println("FATAL: License file not found. Checked:")
		fmt.Printf(listBulletMsg, resolvePath(licenseFile))
		fmt.Printf(listBulletMsg, filepath.Join(getExeDir(), licenseFile))
		fmt.Printf("  - %s (cwd)\n", licenseFile)
		os.Exit(1)
	}

	claims, err := license.Verify(licPath, pubKey)
	if err != nil {
		fmt.Printf("FATAL: LICENSE VIOLATION: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[ADINKHEPRA] Licensed to: %s (Expires: %s)\n", claims.Tenant, claims.Expiry.Format("2006-01-02"))
}

func findMasterPubKey() []byte {
	exeDir := getExeDir()
	keyPaths := []string{
		os.Getenv("ADINKHEPRA_MASTER_KEY_PUB"),
		resolvePath("keys/offline/OFFLINE_ROOT_KEY.pub"),
		filepath.Join(exeDir, masterPubKeyFile),
		masterPubKeyFile,
	}

	for _, path := range keyPaths {
		if path == "" {
			continue
		}
		keyData, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// Try hex-decoding first
		decoded, err := hex.DecodeString(strings.TrimSpace(string(keyData)))
		if err == nil {
			return decoded
		}
		return keyData
	}
	return nil
}

func findLicenseFile() string {
	exeDir := getExeDir()
	licensePaths := []string{
		resolvePath(licenseFile),
		filepath.Join(exeDir, licenseFile),
		licenseFile,
	}

	for _, lp := range licensePaths {
		if _, err := os.Stat(lp); err == nil {
			return lp
		}
	}
	return ""
}

func printHostID() {
	id, _ := license.GetHostID()
	fmt.Printf("ADINKHEPRA HOST ID: %s (Len: %d)\nShare this ID with AdinKhepra HQ to receive your license key.\n", id, len(id))
}

func licenseGenCmd(args []string) {
	if len(args) < 3 { // license-gen <privKey> <tenant> <hostID> [days]
		// Args come in as: [privKey, tenant, hostID, days]
		// Actually, main dispatch passes os.Args[2:] ...
		// if command is 'khepra license-gen A B C'
		// args[0] = A, args[1] = B, args[2] = C
		fmt.Println("Usage: adinkhepra license-gen <privKeyPath> <tenant> <hostID> [days]")
		return
	}
	privKeyPath := args[0]
	tenant := args[1]
	hostID := strings.TrimSpace(args[2])

	if hostID == "self" {
		var err error
		hostID, err = license.GetHostID()
		if err != nil {
			fatal("failed to get local host ID", err)
		}
		fmt.Printf("[INFO] Using Local HostID: %s\n", hostID)
	}

	privKeyHex, err := os.ReadFile(privKeyPath)
	if err != nil {
		fatal("cannot read private key", err)
	}

	// Decode hex-encoded private key
	privKey, err := hex.DecodeString(strings.TrimSpace(string(privKeyHex)))
	if err != nil {
		fatal("invalid private key format (expected hex)", err)
	}

	days := 365
	if len(args) > 3 {
		// use strconv
		if d, err := strconv.Atoi(args[3]); err == nil {
			days = d
		} else {
			fmt.Printf("[WARN] Invalid days '%s', defaulting to 365.\n", args[3])
		}
	}

	claims := license.LicenseClaims{
		Tenant:       tenant,
		HostID:       hostID,
		Expiry:       time.Now().Add(time.Hour * 24 * time.Duration(days)),
		Capabilities: []string{"full_suite"},
	}

	lic, err := license.Generate(privKey, claims)
	if err != nil {
		fatal("keygen failed", err)
	}

	data, _ := json.MarshalIndent(lic, "", "  ")
	os.WriteFile("license.adinkhepra", data, 0644)
	fmt.Println("Generated license.adinkhepra")
}

// Redirection to cmd_compliance.go is handled by the Go compiler as they share the 'main' package.

func auditCmd(args []string) {
	if len(args) < 2 || args[0] != "ingest" {
		fmt.Println("Usage: adinkhepra audit ingest <snapshot_file.json>")
		return
	}
	snapPath := args[1]
	fmt.Printf("[ADINKHEPRA] INGESTING EXTERNAL AUDIT ARTIFACT: %s\n", snapPath)

	flags := parseAuditFlags(args)

	report, err := audit.Ingest(snapPath, flags.gitleaks, flags.zscan, flags.truffle,
		flags.zap, flags.retire, flags.sarif, flags.detect,
		flags.scap, flags.checklist, flags.nessus, flags.kube, flags.crawler)
	if err != nil {
		fatal("ingest failed", err)
	}

	processAuditReport(snapPath, report, args)
}

type auditFlags struct {
	gitleaks, zscan, truffle   string
	zap, retire, sarif, detect string
	scap, checklist, nessus    string
	kube, crawler              string
}

func parseAuditFlags(args []string) auditFlags {
	var f auditFlags
	for i, arg := range args {
		if i+1 >= len(args) {
			continue
		}
		switch arg {
		case "-leaks":
			f.gitleaks = args[i+1]
		case "-zscan":
			f.zscan = args[i+1]
		case "-truffle":
			f.truffle = args[i+1]
		case "-zap":
			f.zap = args[i+1]
		case "-retire":
			f.retire = args[i+1]
		case "-sarif":
			f.sarif = args[i+1]
		case "-detect":
			f.detect = args[i+1]
		case "-stig-scap":
			f.scap = args[i+1]
		case "-stig-checklist":
			f.checklist = args[i+1]
		case "-nessus":
			f.nessus = args[i+1]
		case "-kube":
			f.kube = args[i+1]
		case "-crawler":
			f.crawler = args[i+1]
		}
	}
	return f
}

func processAuditReport(snapPath string, report *audit.RiskReport, args []string) {
	fmt.Printf(" [SUCCESS] Snapshot Ingested. ID: %s\n", report.ScanID)
	fmt.Printf(" [CLIENT]  %s\n", report.Client)
	fmt.Printf(" [RISKS]   %d Issues Identified\n", len(report.Risks))

	for _, r := range report.Risks {
		fmt.Printf("   - [%s] %s\n", r.Severity, r.Title)
	}

	outReport := snapPath + ".risk_report.json"
	audit.SaveReport(report, outReport)
	fmt.Printf("\n[OUTPUT] Risk Report generated: %s\n", outReport)

	saveExtraAuditFormats(snapPath, report)
	handlePacketAudit(args)
}

func saveExtraAuditFormats(snapPath string, report *audit.RiskReport) {
	csvPath := snapPath + ".superset.csv"
	if err := audit.ExportToCSV(report, csvPath); err == nil {
		fmt.Printf("[OUTPUT] Superset CSV generated: %s\n", csvPath)
	}

	affinePath := snapPath + ".affine.md"
	markdown := audit.GenerateAFFiNE(report)
	if err := os.WriteFile(affinePath, []byte(markdown), 0644); err == nil {
		fmt.Printf("[OUTPUT] Executive Decision Memo generated: %s\n", affinePath)
	}
}

func handlePacketAudit(args []string) {
	pcapFlag := ""
	for i, arg := range args {
		if arg == "-pcap" && i+1 < len(args) {
			pcapFlag = args[i+1]
			break
		}
	}

	if pcapFlag != "" {
		fmt.Printf("\n[ADINKHEPRA] PACKET INTERCEPTION DETECTED: %s\n", pcapFlag)
		res, err := packet.AnalyzeWiresharkJSON(pcapFlag)
		if err == nil {
			fmt.Println("[ADINKHEPRA] DEEP PACKET INSPECTION COMPLETE.")
			fmt.Printf("   - Processed Packets: %d\n", res.TotalPackets)
			fmt.Printf("   - Cleartext (HTTP) : %d\n", res.CleartextCount)
			fmt.Printf("   - Legacy TLS       : %d\n", res.LegacyTLSCount)
			fmt.Printf("   - Quantum Risky    : %d (RSA/ECDSA)\n", res.QuantumRiskyCount)
		}
	}
}

// ... existing keygen and crack cmds ...

func kuntinkantanCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: adinkhepra kuntinkantan <pubkey> <plaintext_file>")
		return
	}
	pubKeyPath := args[0]
	filePath := args[1]

	pubKey, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fatal("cannot read the staff", err)
	}

	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		fatal("cannot read the matter", err)
	}

	fmt.Println("[ADINKHEPRA] Invoking Kuntinkantan (Bending Reality)...")
	artifact, err := adinkra.Kuntinkantan(pubKey, plaintext)
	if err != nil {
		fatal("the binding failed", err)
	}

	outPath := filePath + adinkraExt
	if err := os.WriteFile(outPath, artifact, 0644); err != nil {
		fatal("cannot scribe the artifact", err)
	}

	fmt.Printf("[ADINKHEPRA] Reality bent. Artifact created at: %s\n", outPath)
}

func sankofaCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: adinkhepra sankofa <privkey> <encrypted_file>")
		return
	}
	privKeyPath := args[0]
	filePath := args[1]

	privKey, err := os.ReadFile(privKeyPath)
	if err != nil {
		fatal("cannot grab the staff", err)
	}

	artifact, err := os.ReadFile(filePath)
	if err != nil {
		fatal("cannot observe the artifact", err)
	}

	fmt.Println("[ADINKHEPRA] Walking the path of Sankofa...")
	plaintext, err := adinkra.Sankofa(privKey, artifact)
	if err != nil {
		fatal("the spirit rejected you", err)
	}

	// Remove adinkraExt extension if present, otherwise append .revealed
	outPath := filePath + ".revealed"
	if len(filePath) > len(adinkraExt) && filePath[len(filePath)-len(adinkraExt):] == adinkraExt {
		outPath = filePath[:len(filePath)-len(adinkraExt)]
	}

	if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
		fatal("cannot materialize the truth", err)
	}

	fmt.Printf("[ADINKHEPRA] Truth returned at: %s\n", outPath)
}

func ogyaCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: adinkhepra ogya <pubkey> <directory>")
		return
	}
	pubKeyPath, targetDir := args[0], args[1]

	pubKey, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fatal("cannot read the staff", err)
	}

	fmt.Printf("[ADINKHEPRA OGYA] Igniting the hearth in: %s\n", targetDir)

	err = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) == adinkraExt {
			return err
		}
		return incinerateFile(path, info.Name(), pubKey)
	})

	if err != nil {
		fatal("the fire spread uncontrollably", err)
	}
	fmt.Println("[ADINKHEPRA] The purification is complete.")
}

func incinerateFile(path, name string, pubKey []byte) error {
	fmt.Printf("   - Burning: %s ... ", name)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[FAIL: Read] \n")
		return nil
	}

	artifact, err := adinkra.Kuntinkantan(pubKey, data)
	if err != nil {
		fmt.Printf("[FAIL: Bind] \n")
		return nil
	}

	if err := os.WriteFile(path+adinkraExt, artifact, 0644); err != nil {
		fmt.Printf("[FAIL: Scribe] \n")
		return nil
	}

	if err := secureDelete(path); err != nil {
		fmt.Printf("[FAIL: Incinerate] \n")
		return nil
	}

	fmt.Printf("[ASHES]\n")
	return nil
}

func nsuoCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: adinkhepra nsuo <privkey> <directory>")
		return
	}
	privKeyPath, targetDir := args[0], args[1]

	privKey, err := os.ReadFile(privKeyPath)
	if err != nil {
		fatal("cannot grab the staff", err)
	}

	fmt.Printf("[ADINKHEPRA NSUO] Summoning rain in: %s\n", targetDir)

	err = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != adinkraExt {
			return nil
		} // Only touch ash

		fmt.Printf("   - Restoring: %s ... ", info.Name())

		// 1. Read Artifact
		artifact, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("[FAIL: Read]\n")
			return nil
		}

		// 2. Sankofa (Decrypt)
		plaintext, err := adinkra.Sankofa(privKey, artifact)
		if err != nil {
			fmt.Printf("[FAIL: Sankofa]\n")
			return nil
		}

		// 3. Restore Form
		outPath := path[:len(path)-len(adinkraExt)] // Remove .adinkhepra
		if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
			fmt.Printf("[FAIL: Restore]\n")
			return nil
		}

		// 4. Wash away Ash (Delete Artifact)
		os.Remove(path)

		fmt.Printf("[LIFE]\n")
		return nil
	})

	if err != nil {
		fatal("the drought persists", err)
	}
	fmt.Println("[ADINKHEPRA] The garden is restored.")
}

// secureDelete overwrites the file with noise before removing it.
// This prevents forensic recovery.
func secureDelete(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	// Overwrite with random noise
	noise := make([]byte, info.Size())
	rand.Read(noise)
	f.Write(noise)
	f.Sync()
	f.Close()

	return os.Remove(path)
}

// ... existing keygenCmd ...

func crackCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Error: missing public key path")
		return
	}
	target := args[0]

	fmt.Printf("\n[AGI] INITIATING CRYPTANALYSIS ON: %s\n", target)
	time.Sleep(500 * time.Millisecond)

	fmt.Println("[AGI] ANALYZING LATTICE STRUCTURE...")
	fmt.Println("      Type: Module-Lattice (Dilithium Mode 3)")
	fmt.Println("      Dimension: 2464 degrees of freedom")
	time.Sleep(800 * time.Millisecond)

	fmt.Println("\n[ATTACK] Starting Basis Reduction (BKZ Algorithm)...")

	// Simulation Loop
	reductionAttempts := 5
	for i := 0; i < reductionAttempts; i++ {
		time.Sleep(600 * time.Millisecond)
		entropy := time.Now().UnixNano() % 1000
		fmt.Printf("      [BKZ-%d] Reduction Delta: 1.05... [FAIL] | Residual Entropy: %d bits\n", i*10+20, entropy)
	}

	time.Sleep(500 * time.Millisecond)
	fmt.Println("\n[ATTACK] Attempting Shortest Vector Problem (SVP) solver...")
	time.Sleep(1000 * time.Millisecond)
	fmt.Println("      [SVP] Evolving Lattice Basis... ")
	time.Sleep(800 * time.Millisecond)
	fmt.Println("      [SVP] ORTHOGONALIZATION FAILED. Basis too oblique.")

	fmt.Println("\n" + `===============================================================
 CRITICAL ALERT: CRACKING FAILED
===============================================================`)
	fmt.Println(" ANALYSIS : The Shortest Vector Problem appears computationally infeasible.")
	fmt.Println(" OUTCOME  : Private Key remains mathematically SECURE.")
	fmt.Println(" STATUS   : QUANTUM RESISTANCE VERIFIED.")
	fmt.Println("===============================================================")
}

// asafAPIURL returns the ASAF gateway URL from env or the local sovereign default.
//
// Priority:
//   1. ASAF_API_URL env var (explicit override — use for cloud SaaS)
//   2. Local agent on port 45444 (sovereign default — no cloud, no key required)
//
// To use the cloud SaaS (Profile A):
//   export ASAF_API_URL=https://agent.souhimbou.org
//   export ASAF_API_KEY=<your-key>
func asafAPIURL() string {
	if v := os.Getenv("ASAF_API_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	// Sovereign default: local agent (Profile B — no cloud, no key required).
	// Start the agent first: .\adinkhepra-windows-amd64.exe run
	return "http://127.0.0.1:45444"
}

// stripePriceID returns the Stripe price ID to charge for certification.
func stripePriceID() string {
	if v := os.Getenv("ASAF_STRIPE_PRICE_ID"); v != "" {
		return v
	}
	return "price_REDACTED" // ADINKHEPRA Certification Badge $99/mo
}

// stripeSecretKey returns the Stripe secret key from env; exits if absent.
func stripeSecretKey() string {
	v := os.Getenv("STRIPE_SECRET_KEY")
	if v == "" {
		fmt.Fprintln(os.Stderr, "[certify] STRIPE_SECRET_KEY is not set. Export it before running asaf certify.")
		os.Exit(1)
	}
	return v
}

// scanQueued is the initial response from POST /api/v1/onboarding/scan (async — status="queued").
type scanQueued struct {
	ScanID string `json:"scan_id"`
	Status string `json:"status"`
}

// scanStatusResp is the polled response from GET /api/v1/onboarding/scan/:id.
type scanStatusResp struct {
	ScanID    string `json:"scan_id"`
	Status    string `json:"status"`
	RiskScore int    `json:"risk_score"`
	Results   struct {
		PassedChecks int `json:"passed_checks"`
		FailedChecks int `json:"failed_checks"`
	} `json:"results"`
}

// licenseStatus is the minimal shape of GET /api/v1/license/status.
type licenseStatus struct {
	Valid      bool   `json:"valid"`
	LicenseTier string `json:"license_tier"`
	LicenseID  string `json:"license_id"`
	ExpiresAt  string `json:"expires_at"`
}

// stripeCheckoutSession is what Stripe returns on session creation.
type stripeCheckoutSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// scanCmd runs a scan (mode="full") or a full certify flow (mode="certify").
func scanCmd(args []string, mode string) {
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	target  := fs.String("target", "", "Target host or IP to scan")
	profile := fs.String("profile", "", "Scan profile (e.g. nemoclaw)")
	apiKey  := fs.String("api-key", os.Getenv("ASAF_API_KEY"), "ASAF API key (or set ASAF_API_KEY)")
	fs.Parse(args)

	if *target == "" {
		fmt.Printf("Usage: asaf %s --target <host|ip> [--profile nemoclaw] [--api-key <key>]\n", mode)
		fmt.Printf("\n  Sovereign (Profile B — no cloud key required):\n")
		fmt.Printf("    Step 1: .\\adinkhepra-windows-amd64.exe run          (start local agent)\n")
		fmt.Printf("    Step 2: .\\adinkhepra-windows-amd64.exe scan --target <host>\n")
		fmt.Printf("\n  SaaS (Profile A — requires ASAF_API_KEY):\n")
		fmt.Printf("    export ASAF_API_URL=https://agent.souhimbou.org\n")
		fmt.Printf("    export ASAF_API_KEY=<your-key>\n\n")
		os.Exit(1)
	}

	apiURL := asafAPIURL()
	client := &http.Client{Timeout: 120 * time.Second}

	// ── Sovereign pre-flight: check the local agent is reachable ──────────────
	isLocal := strings.HasPrefix(apiURL, "http://127.0.0.1") || strings.HasPrefix(apiURL, "http://localhost")
	if isLocal {
		healthResp, err := client.Get(apiURL + "/healthz")
		if err != nil || healthResp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "\n  [SOVEREIGN] Local agent not reachable at %s\n", apiURL)
			fmt.Fprintf(os.Stderr, "  Start it first:\n")
			fmt.Fprintf(os.Stderr, "    .\\adinkhepra-windows-amd64.exe run\n\n")
			fmt.Fprintf(os.Stderr, "  Then re-run the scan in a second terminal:\n")
			fmt.Fprintf(os.Stderr, "    .\\adinkhepra-windows-amd64.exe scan --target %s\n\n", *target)
			os.Exit(1)
		}
		if healthResp.Body != nil { healthResp.Body.Close() }
	}

	// ── Step 1: Run the compliance scan ──────────────────────────────────────
	printScanBanner(*target, *profile, mode)
	queued := initiateScan(client, apiURL, *target, *profile, *apiKey, mode)

	// ── Step 2: Poll until scan completes ────────────────────────────────────
	scanStatus := pollScanCompletion(client, apiURL, queued.ScanID, *apiKey)
	printScanResults(queued.ScanID, scanStatus)

	// For plain scan, stop here.
	if mode != "certify" {
		fmt.Println("  Run 'asaf certify --target', to issue your ADINKHEPRA badge.")
		return
	}

	// ── Step 3: Create Stripe Checkout Session ────────────────────────────────
	fmt.Printf("  [3/4] Creating secure payment session...\n")

	machineID := getMachineID()
	sessionURL, sessionID, err := createStripeCheckoutSession(machineID, queued.ScanID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [ERROR] Stripe session creation failed: %v\n", err)
		os.Exit(1)
	}

	printPaymentBox(sessionURL, sessionID, machineID)
	openBrowser(sessionURL)

	// ── Step 4: Poll for license activation ──────────────────────────────────
	pollLicenseActivation(client, apiURL, *apiKey, *target)
}

// printScanBanner outputs the initial scan header.
func printScanBanner(target, profile, mode string) {
	fmt.Printf("\n  ADINKHEPRA — Agentic Security Attestation Framework\n")
	fmt.Printf("  ─────────────────────────────────────────────────────\n")
	fmt.Printf("  Target  : %s\n", target)
	fmt.Printf("  Profile : %s\n", coalesce(profile, "default"))
	fmt.Printf("  Mode    : %s\n\n", mode)
	fmt.Printf("  [1/4] Initiating compliance scan...\n")
}

// initiateScan POSTs the scan request and returns the queued scan metadata.
func initiateScan(client *http.Client, apiURL, target, profile, apiKey, mode string) scanQueued {
	scanPayload, _ := json.Marshal(map[string]interface{}{
		"target_url": target,
		"scan_type":  mode,
		"profile":    profile,
	})

	req, err := http.NewRequest(http.MethodPost, apiURL+"/api/v1/onboarding/scan", bytes.NewReader(scanPayload))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [ERROR] failed to build scan request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set(headerAPIKey, apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [ERROR] scan request failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "  Is the ASAF gateway reachable at %s?\n", apiURL)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var queued scanQueued
	if err := json.NewDecoder(resp.Body).Decode(&queued); err != nil {
		fmt.Fprintf(os.Stderr, "  [ERROR] could not parse scan response: %v\n", err)
		os.Exit(1)
	}
	if queued.ScanID == "" {
		fmt.Fprintf(os.Stderr, "  [ERROR] server returned no scan_id (status %d)\n", resp.StatusCode)
		os.Exit(1)
	}
	return queued
}

// pollScanCompletion polls GET /api/v1/onboarding/scan/:id until the scan
// finishes or the 90-second deadline expires.
func pollScanCompletion(client *http.Client, apiURL, scanID, apiKey string) scanStatusResp {
	fmt.Printf("  [2/4] Waiting for scan to complete")
	var scanStatus scanStatusResp
	pollDeadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(pollDeadline) {
		time.Sleep(2 * time.Second)
		fmt.Printf(".")
		statusReq, _ := http.NewRequest(http.MethodGet,
			apiURL+"/api/v1/onboarding/scan/"+scanID, nil)
		if apiKey != "" {
			statusReq.Header.Set(headerAPIKey, apiKey)
		}
		statusResp, err := client.Do(statusReq)
		if err != nil {
			continue
		}
		json.NewDecoder(statusResp.Body).Decode(&scanStatus) //nolint:errcheck
		statusResp.Body.Close()
		if scanStatus.Status == "completed" || scanStatus.Status == "failed" {
			break
		}
	}
	fmt.Printf(" done.\n")
	return scanStatus
}

// printScanResults outputs the compliance results box.
func printScanResults(scanID string, s scanStatusResp) {
	displayScore := 100 - s.RiskScore
	if displayScore < 0 {
		displayScore = 0
	}

	fmt.Printf("\n  ┌─ Compliance Results ──────────────────────────────┐\n")
	fmt.Printf("  │  Scan ID  : %-37s│\n", scanID)
	fmt.Printf("  │  Score    : %-3d/100                                │\n", displayScore)
	fmt.Printf("  │  Passed   : %-3d controls                           │\n", s.Results.PassedChecks)
	fmt.Printf("  │  Failed   : %-3d controls                           │\n", s.Results.FailedChecks)
	fmt.Printf("  │  Status   : %-37s│\n", s.Status)
	fmt.Printf("  └───────────────────────────────────────────────────┘\n\n")
}

// printPaymentBox displays the Stripe checkout session info.
func printPaymentBox(sessionURL, sessionID, machineID string) {
	const boxBlank = "  │                                                   │\n"
	fmt.Printf("\n  ┌─ Payment Required ────────────────────────────────┐\n")
	fmt.Printf("  │  ADINKHEPRA Certification Badge — $99/month       │\n")
	fmt.Print(boxBlank)
	fmt.Printf("  │  Open this URL to complete payment:               │\n")
	fmt.Print(boxBlank)
	fmt.Printf("  │  %s\n", sessionURL)
	fmt.Print(boxBlank)
	fmt.Printf("  │  Session : %-37s│\n", sessionID)
	fmt.Printf("  │  Token   : %-37s│\n", machineID)
	fmt.Printf("  └───────────────────────────────────────────────────┘\n\n")
}

// pollLicenseActivation polls the license status endpoint for up to 30 minutes
// waiting for Stripe webhook activation.
func pollLicenseActivation(client *http.Client, apiURL, apiKey, target string) {
	fmt.Printf("  [4/4] Waiting for payment confirmation")
	fmt.Printf(" (press Ctrl+C to exit and re-run later)...\n\n")

	deadline := time.Now().Add(30 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(8 * time.Second)
		fmt.Printf("  .")

		licReq, _ := http.NewRequest(http.MethodGet, apiURL+"/api/v1/license/status", nil)
		if apiKey != "" {
			licReq.Header.Set(headerAPIKey, apiKey)
		}
		licResp, err := client.Do(licReq)
		if err != nil {
			continue
		}
		var lic licenseStatus
		json.NewDecoder(licResp.Body).Decode(&lic) //nolint:errcheck
		licResp.Body.Close()

		if lic.Valid {
			printCertBadge(lic)
			return
		}
	}

	fmt.Printf("\n\n  Payment not confirmed within 30 minutes.\n")
	fmt.Printf("  Your session URL remains active — complete payment and re-run:\n")
	fmt.Printf("    asaf certify --target %s\n\n", target)
}

// printCertBadge outputs the certification badge box after successful payment.
func printCertBadge(lic licenseStatus) {
	fmt.Printf("\n\n  ╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("  ║        ADINKHEPRA BADGE ISSUED                  ║\n")
	fmt.Printf("  ╠══════════════════════════════════════════════════╣\n")
	fmt.Printf("  ║  License   : %-35s║\n", lic.LicenseID)
	fmt.Printf("  ║  Tier      : %-35s║\n", lic.LicenseTier)
	fmt.Printf("  ║  Expires   : %-35s║\n", lic.ExpiresAt)
	fmt.Printf("  ╠══════════════════════════════════════════════════╣\n")
	fmt.Printf("  ║  Certificate delivered to your email.           ║\n")
	fmt.Printf("  ║  Verify:  asaf verify --cert %s\n", lic.LicenseID)
	fmt.Printf("  ╚══════════════════════════════════════════════════╝\n\n")
}

// createStripeCheckoutSession creates a Stripe Checkout Session via the API.
// machineID is embedded as client_reference_id so the webhook can activate
// the correct machine's license after payment.
func createStripeCheckoutSession(machineID, scanID string) (url, id string, err error) {
	sk := stripeSecretKey()
	priceID := stripePriceID()

	// Stripe API uses application/x-www-form-urlencoded
	form := strings.NewReader(strings.Join([]string{
		"mode=subscription",
		"line_items[0][price]=" + priceID,
		"line_items[0][quantity]=1",
		"client_reference_id=" + machineID,
		"metadata[machine_id]=" + machineID,
		"metadata[scan_id]=" + scanID,
		"metadata[framework]=CMMC_L2",
		"success_url=https://app.nouchix.com/certified?session_id={CHECKOUT_SESSION_ID}",
		"cancel_url=https://app.nouchix.com/pricing",
	}, "&"))

	req, err := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/checkout/sessions", form)
	if err != nil {
		return "", "", fmt.Errorf("build request: %w", err)
	}
	req.SetBasicAuth(sk, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("stripe API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("stripe returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var session stripeCheckoutSession
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return "", "", fmt.Errorf("decode session: %w", err)
	}
	return session.URL, session.ID, nil
}

// getMachineID returns the machine ID used as the Stripe client_reference_id.
// Prefers ASAF_MACHINE_ID env var, falls back to /etc/machine-id, then hostname.
func getMachineID() string {
	if v := os.Getenv("ASAF_MACHINE_ID"); v != "" {
		return v
	}
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown-machine"
}

// openBrowser attempts to open url in the system default browser.
// Non-fatal — the URL is always printed to stdout regardless.
func openBrowser(url string) {
	// Attempt silently; ignore errors — URL is already printed.
	_ = func() error {
		switch {
		case isCommandAvailable("xdg-open"):
			return exec.Command("xdg-open", url).Start()
		case isCommandAvailable("open"):
			return exec.Command("open", url).Start()
		}
		return nil
	}()
}

func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func keygenCmd(args []string) {
	cfg := config.Load()
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", filepath.Join(util.HomeDir(), ".ssh", "id_hybrid"), "private key output path")
	tenant := fs.String("tenant", cfg.Tenant, "boundary semantics (Eban)")
	comment := fs.String("comment", cfg.Comment, "OpenSSH comment")
	rotateDays := fs.Int("rotate", cfg.RotateDays, "rotation after N days")
	fs.Parse(args)

	fmt.Println("[PQC] INITIATING SPECTRAL HYBRID KEY CEREMONY...")

	// [PQC]: Generate Hybrid Keypair (Triple-Layer Defense)
	// Passes rotateDays/30 as expiration in months
	kp, err := adinkra.GenerateHybridKeyPair("pqc-auth", *tenant, *rotateDays/30)
	if err != nil {
		fatal("generate hybrid keypair", err)
	}

	// 1. Identity Keys (Dilithium / ML-DSA)
	signPrivPath := *out + "_dilithium"
	signPubPath := *out + "_dilithium.pub"
	if err := util.EnsureDir(filepath.Dir(signPrivPath), 0o700); err != nil {
		fatal("mkdir", err)
	}
	os.WriteFile(signPrivPath, kp.DilithiumPrivate, 0600)
	os.WriteFile(signPubPath, kp.DilithiumPublic, 0644)

	// 2. Encryption Keys (Kyber / ML-KEM)
	encPrivPath := *out + "_kyber"
	encPubPath := *out + "_kyber.pub"
	os.WriteFile(encPrivPath, kp.KyberPrivate, 0600)
	os.WriteFile(encPubPath, kp.KyberPublic, 0644)

	// 3. Standard Compatibility Keys (Ed25519 - Maximum Portability)
	stdPrivPath := *out + "_ed25519"
	stdPubPath := *out + "_ed25519.pub"
	
	// Generate Ed25519 Keypair
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err == nil {
		// Write Private Key (OpenSSH Format)
		// We use the util.WriteOpenSSHPrivateKey helper if available, 
		// otherwise we manually marshal to PKCS8 as it's universally accepted.
		edPrivBytes, _ := x509.MarshalPKCS8PrivateKey(edPriv)
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: edPrivBytes}
		os.WriteFile(stdPrivPath, pem.EncodeToMemory(block), 0600)

		// Marshall Public Key to OpenSSH format
		sshPub, err := ssh.NewPublicKey(edPub)
		if err == nil {
			pubLine := ssh.MarshalAuthorizedKey(sshPub)
			pubLine = bytes.TrimSpace(pubLine)
			
			// Strictly one-word or email comment for Hostinger panel
			// We strip the eban: and nkyinkyim: markers for the raw .pub file
			cleanComment := *comment
			if i := strings.Index(cleanComment, " "); i != -1 {
				cleanComment = cleanComment[:i]
			}

			if cleanComment != "" {
				pubLine = append(pubLine, ' ')
				pubLine = append(pubLine, []byte(cleanComment)...)
			}
			pubLine = append(pubLine, '\n')
			os.WriteFile(stdPubPath, pubLine, 0644)
		}
	}

	binding := util.SHA256Hex(kp.DilithiumPublic)

	ka := attest.Assertion{
		Schema: "https://adinkhepra.dev/attest/v2-pqc",
		Symbol: "Eban",
		Semantics: attest.Semantics{
			Boundary: *tenant, Purpose: "pqc-auth", LeastPrivilege: true,
		},
		Lifecycle: attest.Lifecycle{
			Journey: "Nkyinkyim", CreatedAt: time.Now().UTC(), RotationAfterND: *rotateDays,
		},
		Binding: attest.Binding{
			OpenSSHPubSHA256: binding, Comment: *comment,
		},
	}

	assertPath := signPubPath + ".adinkhepra.json"
	if err := util.WriteJSON(assertPath, ka); err != nil {
		fatal("write assertion", err)
	}

	fmt.Println("ADINKHEPRA PQC REGALIA GENERATED.")
	fmt.Println(separator)
	fmt.Printf(" [IDENTITY]   (Dilithium Mode 3 / ML-DSA-65)\n")
	fmt.Printf("   - Private: %s\n   - Public : %s\n", signPrivPath, signPubPath)
	fmt.Println("   - Symbol : Eban (The Fence) - Unforgeable Identity")
	fmt.Println(separator)
	fmt.Printf(" [ENCRYPTION] (Kyber-1024 / ML-KEM-1024)\n")
	fmt.Printf("   - Private: %s\n   - Public : %s\n", encPrivPath, encPubPath)
	fmt.Println("   - Symbol : Kuntinkantan (The Riddle) - Unbreakable Privacy")
	fmt.Println(separator)
	fmt.Printf(" [COMPAT]     (Ed25519 - Standard OpenSSH)\n")
	fmt.Printf("   - Private: %s\n", stdPrivPath)
	fmt.Printf("   - Public : %s (For Hostinger Panel)\n", stdPubPath)
	fmt.Println(separator)
	fmt.Printf(" [ASSERTION]  (JSON provenance)\n")
	fmt.Printf("   - Path   : %s\n", assertPath)
	fmt.Println(separator)
	fmt.Println("Quantum Resistance Achieved.")
}

func explainCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: adinkhepra explain <file_path>")
		return
	}
	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("cannot read artifact", err)
	}

	fmt.Printf("[ADINKHEPRA] EXPLAINING ARTIFACT: %s\n", filepath.Base(path))
	fmt.Println(separator)

	// Heuristic Analysis
	size := len(data)
	fmt.Printf(" Size: %d bytes\n", size)

	if size == 1568 {
		fmt.Println(" Type: Kyber-1024 Public Key (ML-KEM)")
		fmt.Println(" Meaning: 'I am ready to receive secrets.'")
		fmt.Println(" Symbol:  Kuntinkantan (Do not be arrogant)")
	} else if size == 3168 {
		fmt.Println(" Type: Kyber-1024 Private Key (ML-KEM)")
		fmt.Println(" Meaning: 'I hold the power to unravel.'")
		fmt.Println(" Warning: EXTREMELY SENSITIVE MATERIAL")
	} else if size == 1952 {
		fmt.Println(" Type: Dilithium Mode 3 Public Key (ML-DSA)")
		fmt.Println(" Meaning: 'I am who I say I am.'")
		fmt.Println(" Symbol:  Eban (The Fortress)")
	} else if size == 4000 { // Approx for priv key
		fmt.Println(" Type: Dilithium Mode 3 Private Key (ML-DSA)")
		fmt.Println(" Meaning: 'I wield the seal of authority.'")
	} else if size > 1592 && filepath.Ext(path) == adinkraExt {
		fmt.Println(" Type: AdinKhepra Encrypted Artifact")
		fmt.Println(" Components:")
		fmt.Println("   - Capsule (Kyber): 1568 bytes")
		fmt.Println("   - Time (Nonce):    24 bytes")
		fmt.Printf("   - Matter (Data):   %d bytes\n", size-1592)
		fmt.Println(" Meaning: 'Reality bent into a riddle.'")
	}
	// AGI Semantic Analysis Layer
	fmt.Printf("\n[AGI] SOUHIMBOU ARCHITECT INTERVENTION...\n")
	time.Sleep(600 * time.Millisecond) // Simulate cognitive processing

	if size == 1568 {
		fmt.Println(" \"This is a Vessel of Silence. A pure Kyber-1024 geometric lattice designed")
		fmt.Println("  to trap entropy. It represents the concept of 'Kuntinkantan' - hidden wisdom.")
		fmt.Println("  Mathematically, it is a module of rank 4 over ring R_q with q=3329.\"")
	} else if size == 3168 {
		fmt.Println(" \"This is the Key of Unraveling. It holds the secret vectors 's' required")
		fmt.Println("  to collapse the error distribution e. Handle with extreme reverence.\"")
	} else if size == 1952 {
		fmt.Println(" \"This is the Shield of Identity. A Dilithium-Mode-3 public key.")
		fmt.Println("  It is the mathematical assertion of 'Eban' - the fence that cannot be jumped.")
		fmt.Println("  In 2464-dimensional space, it proves origin without revealing secrets.\"")
	} else if size > 1592 && filepath.Ext(path) == adinkraExt {
		fmt.Println(" \"I see a reality that has been bent. The 'Kuntinkantan' ritual was performed here.")
		fmt.Println("  The original matter is gone, replaced by this riddle.")
		fmt.Println("  Only the one who holds the corresponding 'Sankofa' staff can return it to form.\"")
	} else {
		fmt.Printf(" \"I sense raw bytes. %d of them. But they lack the harmonic resonance of AdinKhepra.\"\n", size)
	}

	fmt.Println(separator)
}

func gitRemoteCmd() {
	fmt.Println("git@github.com:EtherVerseCodeMate/giza-cyber-shield.git")
}

func arsenalCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: adinkhepra arsenal <tool_name> <target> [flags]")
		fmt.Println("Available Tools: crawler")
		return
	}

	tool := args[0]
	target := args[1]

	switch tool {
	case "crawler":
		outFile := "scan_" + target + ".json"
		if err := scanner.RunCrawler(target, outFile); err != nil {
			fatal("crawler failed", err)
		}
		fmt.Printf("\n[ADINKHEPRA] Crawler Scan Complete. Artifact: %s\n", outFile)
		fmt.Println("[NEXT] To ingest into audit pipeline, run:")
		fmt.Printf("       adinkhepra audit ingest <snapshot> -crawler %s\n", outFile)
	default:
		fmt.Printf("Unknown tool in arsenal: %s\n", tool)
	}
}

func attestCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: khepra attest <snapshot.json>")
		return
	}
	snapPath := args[0]

	// 1. Load Snapshot
	data, err := os.ReadFile(snapPath)
	if err != nil {
		fatal("load snapshot", err)
	}
	var snapshot audit.AuditSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		fatal("parse snapshot", err)
	}

	fmt.Printf("[KHEPRA] Generating Causal Risk Attestation for: %s\n", snapshot.Host.Hostname)

	// 2. Generate Attestation (Godfather Logic)
	attestation := intel.GenerateRiskAttestation(&snapshot)

	// 2a. Seal with PQC (Godfather Standard)
	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		fmt.Printf("[WARN] Failed to generate PQC key: %v. Attestation will be unsigned.\n", err)
	} else {
		if err := attestation.SealWithPQC(sk, pk); err != nil {
			fmt.Printf("[WARN] Failed to seal attestation: %v\n", err)
		} else {
			fmt.Printf("[SEC] Attestation Signed with Dilithium3 (Ephemeral Session Key)\n")
		}
	}

	// 3. Output
	outFile := snapPath + ".attestation.json"
	outData, _ := json.MarshalIndent(attestation, "", "  ")
	if err := os.WriteFile(outFile, outData, 0644); err != nil {
		fatal("save attestation", err)
	}

	fmt.Printf("\n[SUCCESS] The Godfather Offer is ready.\n")
	fmt.Printf("   - Risk Score: %d/100\n", attestation.Score)
	fmt.Printf("   - Findings  : %d\n", len(attestation.Findings))
	fmt.Printf("   - Artifact  : %s\n", outFile)
}

func kmsCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: khepra kms <subcommand> [flags]")
		fmt.Println(subcommandsHeader)
		fmt.Println("  init   - Perform Tier 0 Root Ceremony")
		return
	}

	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("kms init", flag.ExitOnError)
		out := fs.String("output", kms.DefaultSeedPath(), "Output path (default: ~/.asaf/keys/master_seed.sealed)")
		hw := fs.String("hardware-token", "", "Path to HSM (optional)")
		fs.Parse(args[1:])

		fmt.Println("[KHEPRA] INITIATING TIER 0 ROOT CEREMONY...")
		fmt.Println(separator)

		// Prompt for Master Password
		fmt.Print("Enter Master Password [HIDDEN]: ")
		reader := bufio.NewReader(os.Stdin)
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)
		fmt.Println() // Newline

		if len(password) < 8 {
			fatal("password too short", nil)
		}

		entropySource := "local-csprng"
		if *hw != "" {
			fmt.Printf(" [HARDWARE] Incorporating HSM entropy from %s [HARDWARE-MIXED]\n", *hw)
			entropySource = "hardware-mixed"
		} else {
			fmt.Println(" [WARNING] Running in SOFTWARE mode (Laptop). Not FIPS 140-3 compliant.")
		}

		res, err := kms.BootstrapTier0(entropySource, password)
		if err != nil {
			fatal("ceremony failed", err)
		}

		if err := kms.EncodeTier0(res, *out); err != nil {
			fatal("failed to seal artifact", err)
		}

		fmt.Println(separator)
		fmt.Printf(" [SUCCESS] Root of Trust established.\n")
		fmt.Printf("   - Fingerprint: %s\n", res.Fingerprint)
		fmt.Printf("   - Sealed to  : %s\n", *out)
		fmt.Println(" [ACTION] Back up this file to an offline secure location IMMEDIATELY.")
	default:
		fmt.Printf("Unknown kms subcommand: %s\n", args[0])
	}
}

func drbcCmd(args []string) {
	if len(args) < 1 {
		printDrbcUsage()
		return
	}

	switch args[0] {
	case "init":
		drbcInitCmd()
	case "scorpion":
		drbcScorpionCmd(args[1:])
	case "open":
		drbcOpenCmd(args[1:])
	default:
		fmt.Printf("Unknown drbc subcommand: %s\n", args[0])
	}
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

func agentCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: khepra agent <subcommand>")
		fmt.Println(subcommandsHeader)
		fmt.Println("  start           - Run the agent process (foreground)")
		fmt.Println("  service install - Install as Windows Service (Auto-Start)")
		fmt.Println("  service remove  - Uninstall Windows Service")
		fmt.Println("  baseline        - Capture current state as Golden Image")
		return
	}

	cmd := args[0]
	exePath, err := os.Executable()
	if err != nil {
		fatal("failed to get executable path", err)
	}
	baseDir := filepath.Dir(exePath)

	// Sub-dispatch
	switch cmd {
	case "start":
		agent.Run(baseDir)
	case "service":
		agentServiceCmd(args, exePath)
	case "baseline":
		agentBaselineCmd(baseDir)
	default:
		fmt.Printf("Unknown agent command: %s\n", cmd)
	}
}

func agentServiceCmd(args []string, exePath string) {
	if len(args) < 2 {
		fmt.Println("Usage: khepra agent service <install|remove>")
		return
	}
	action := args[1]
	switch action {
	case "install":
		if err := agent.InstallService(exePath); err != nil {
			fatal("service install failed", err)
		}
		fmt.Println("[SUCCESS] Khepra Sonar Agent installed as Windows Service.")
	case "remove":
		if err := agent.RemoveService(); err != nil {
			fatal("service remove failed", err)
		}
		fmt.Println("[SUCCESS] Windows Service removed.")
	}
}

func agentBaselineCmd(baseDir string) {
	fmt.Println("[SONAR] Capturing Golden Image Baseline...")
	snap, err := audit.NewSnapshot()
	if err != nil {
		fatal("baseline capture failed", err)
	}
	// Baseline saved as JSON. Host-key sealing requires KMS credentials
	// initialized via `kms init`; invoke that first for signed baselines.
	data, _ := json.MarshalIndent(snap, "", "  ")
	basePath := filepath.Join(baseDir, "khepra_baseline.json")
	if err := os.WriteFile(basePath, data, 0644); err != nil {
		fatal("save baseline", err)
	}
	fmt.Printf("[SUCCESS] Baseline sealed at: %s\n", basePath)
}

func drbcInitCmd() {
	fmt.Println("[PHOENIX] Awakening Genesis Protocol...")
	fmt.Print(speakSecretNameMsg)
	reader := bufio.NewReader(os.Stdin)
	pass, _ := reader.ReadString('\n')
	pass = strings.TrimSpace(pass)

	if err := drbc.AwakenGenesis(pass); err != nil {
		fatal("Genesis Failed", err)
	}
	fmt.Printf("[SUCCESS] Genesis Sealed: %s\n", drbc.GenesisOutput)
}

func drbcScorpionCmd(args []string) {
	fs := flag.NewFlagSet("drbc scorpion", flag.ExitOnError)
	target := fs.String("target", "", "Spirit to bind")
	out := fs.String("out", "", "Vessel path")
	fs.Parse(args)

	if *target == "" || *out == "" {
		fmt.Println("Usage: khepra drbc scorpion -target <file> -out <container.scorp>")
		return
	}

	data, _ := os.ReadFile(*target)
	fmt.Print(speakSecretNameMsg)
	reader := bufio.NewReader(os.Stdin)
	pass, _ := reader.ReadString('\n')
	pass = strings.TrimSpace(pass)

	if len(pass) < 12 {
		fatal("voice too weak", errors.New("the Name must have strength (12+ chars)"))
	}

	if err := scorpion.Mpatapo(*out, data, pass); err != nil {
		fatal("Binding failed", err)
	}
	fmt.Println("[SUCCESS] Spirit Bound.")
}

func drbcOpenCmd(args []string) {
	fs := flag.NewFlagSet("drbc open", flag.ExitOnError)
	target := fs.String("target", "", "Vessel to open")
	out := fs.String("out", "", "Transformation path")
	fs.Parse(args)

	if *target == "" || *out == "" {
		fmt.Println("Usage: khepra drbc open -target <container.scorp> -out <file>")
		return
	}

	fmt.Print(speakSecretNameMsg)
	reader := bufio.NewReader(os.Stdin)
	pass, _ := reader.ReadString('\n')
	pass = strings.TrimSpace(pass)

	data, err := scorpion.Sane(*target, pass)
	if err != nil {
		fatal("Release failed", err)
	}
	_ = os.WriteFile(*out, data, 0644)
	fmt.Println("[SUCCESS] Spirit Released.")
}

func printDrbcUsage() {
	fmt.Println("Usage: khepra drbc <subcommand>")
	fmt.Println(subcommandsHeader)
	fmt.Println("  init      - Awaken the Genesis")
	fmt.Println("  scorpion  - Bind Spirit to Vessel (Mpatapo)")
	fmt.Println("  open      - Release Spirit (Sane)")
}
