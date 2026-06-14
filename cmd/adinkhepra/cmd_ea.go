package main

// cmd_ea.go — CLI commands for the Evolutionary Agent kernel.
//
// Commands exposed:
//   adinkhepra agent start     — start continuous EA evolution loop (foreground)
//   adinkhepra agent status    — show current EA generation + fitness scores
//   adinkhepra agent evolve    — run one evolution cycle manually, print result
//   adinkhepra license request — generate QKD license request bundle
//   adinkhepra license install — install a QKD license capsule from master authority

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/ea"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
)

// ─── CLI dispatch shim ────────────────────────────────────────────────────────
// These functions are called from handleSecondaryCmds in main.go.
// `agentCmd` already exists in main.go for the old agent sub-commands.
// The EA sub-commands are dispatched here from the "ea" top-level command,
// and the new license sub-commands extend the existing "license" path.

// eaCmd is the top-level dispatcher for `adinkhepra ea <subcommand>`.
func eaCmd(args []string) {
	if len(args) < 1 {
		printEAUsage()
		return
	}
	switch args[0] {
	case "start":
		eaStartCmd(args[1:])
	case "status":
		eaStatusCmd(args[1:])
	case "evolve":
		eaEvolveCmd(args[1:])
	default:
		fmt.Printf("[EA] Unknown subcommand: %s\n", args[0])
		printEAUsage()
	}
}

func printEAUsage() {
	fmt.Println(`AdinKhepra EA — Evolutionary Agent Kernel

Usage:
  adinkhepra ea start   [-generations N] [-pop N]   Start continuous evolution loop
  adinkhepra ea status                               Show current generation + fitness
  adinkhepra ea evolve  [-n N]                       Run N evolution cycles manually`)
}

// ─── EA Start ─────────────────────────────────────────────────────────────────

func eaStartCmd(args []string) {
	generations := 0 // 0 = run forever
	popSize := ea.DefaultPopulationSize

	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-generations":
			fmt.Sscanf(args[i+1], "%d", &generations)
		case "-pop":
			fmt.Sscanf(args[i+1], "%d", &popSize)
		}
	}

	fmt.Println("[EA] Initialising AdinkraEAEngine...")

	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		fatal("EA keygen", err)
	}

	dagStore := dag.NewMemory()
	eng, err := ea.NewAdinkraEAEngine(dagStore, sk, pk)
	if err != nil {
		fatal("EA engine init", err)
	}

	fmt.Printf("[EA] Population: %d  |  Running %s\n",
		popSize, generationsLabel(generations))
	fmt.Println(separator)

	gen := 0
	for {
		best, err := eng.Evolve()
		if err != nil {
			fatal("EA evolve", err)
		}
		gen++
		fmt.Printf("[EA] Gen %4d | Fitness: %.4f | Symbol: %-12s | DAG: %s\n",
			gen, best.Fitness, best.Symbol, truncate(best.DAGNodeID, 12))

		if generations > 0 && gen >= generations {
			break
		}
	}

	printEAStatus(eng)
}

// ─── EA Status ────────────────────────────────────────────────────────────────

func eaStatusCmd(_ []string) {
	stateFile := eaStateFile()
	data, err := os.ReadFile(stateFile)
	if err != nil {
		fmt.Printf("[EA] No saved EA state found at %s\n", stateFile)
		fmt.Println("     Run 'adinkhepra ea start' to begin evolution.")
		return
	}

	var status ea.EngineStatus
	if err := json.Unmarshal(data, &status); err != nil {
		fatal("parse EA state", err)
	}

	fmt.Println("[EA] EVOLUTIONARY AGENT STATUS")
	fmt.Println(separator)
	fmt.Printf("  Generation    : %d\n", status.Generation)
	fmt.Printf("  Population    : %d\n", status.PopulationSize)
	fmt.Printf("  Best Fitness  : %.4f\n", status.BestFitness)
	fmt.Printf("  Mean Fitness  : %.4f\n", status.MeanFitness)
	fmt.Printf("  Worst Fitness : %.4f\n", status.WorstFitness)
	fmt.Printf("  Best Symbol   : %s\n", status.BestSymbol)
	fmt.Printf("  Agent ID      : %s\n", status.AgentID)
	fmt.Println(separator)
}

// ─── EA Evolve ────────────────────────────────────────────────────────────────

func eaEvolveCmd(args []string) {
	n := 1
	if len(args) > 1 && args[0] == "-n" {
		fmt.Sscanf(args[1], "%d", &n)
	}

	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		fatal("EA keygen", err)
	}

	eng, err := ea.NewAdinkraEAEngine(dag.NewMemory(), sk, pk)
	if err != nil {
		fatal("EA engine", err)
	}

	fmt.Printf("[EA] Running %d evolution cycle(s)...\n", n)
	var best *ea.Individual
	for i := 0; i < n; i++ {
		best, err = eng.Evolve()
		if err != nil {
			fatal("EA evolve", err)
		}
	}

	fmt.Println(separator)
	fmt.Printf("  Generations run : %d\n", n)
	fmt.Printf("  Best Fitness    : %.4f\n", best.Fitness)
	fmt.Printf("  Best Symbol     : %s\n", best.Symbol)
	fmt.Printf("  DAG Node        : %s\n", best.DAGNodeID)
	fmt.Println(separator)

	// Export best genome as JSON
	exportJSON, err := eng.ExportBestAsJSON()
	if err != nil {
		fmt.Printf("[EA] WARN: export failed: %v\n", err)
		return
	}
	outPath := fmt.Sprintf("ea_best_gen%d_%s.json", n, time.Now().Format("20060102_150405"))
	if err := os.WriteFile(outPath, exportJSON, 0644); err != nil {
		fmt.Printf("[EA] WARN: write export: %v\n", err)
	} else {
		fmt.Printf("[EA] Best genome exported to: %s\n", outPath)
	}
}

// ─── License Dispatch ─────────────────────────────────────────────────────────

// licenseDispatchCmd is the top-level handler for `adinkhepra license <subcommand>`.
func licenseDispatchCmd(args []string) {
	if len(args) < 1 {
		printLicenseUsage()
		return
	}
	switch args[0] {
	case "status":
		printHostID()
	case "request":
		licenseRequestCmd(args[1:])
	case "install":
		licenseInstallCmd(args[1:])
	default:
		fmt.Printf("[LICENSE] Unknown subcommand: %s\n", args[0])
		printLicenseUsage()
	}
}

func printLicenseUsage() {
	fmt.Println(`AdinKhepra License Management

Usage:
  adinkhepra license status                        Show host ID and current license
  adinkhepra license request [-tenant T] [-tier T] Generate QKD license request bundle
  adinkhepra license install -capsule F -session F Install a license capsule from master authority`)
}

func licenseRequestCmd(args []string) {
	tenant := "unknown"
	tier := license.TierPilot
	out := "license_request.json"

	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-tenant":
			tenant = args[i+1]
		case "-tier":
			tier = args[i+1]
		case "-out":
			out = args[i+1]
		}
	}

	fmt.Println("[LICENSE] Generating QKD license request bundle...")

	summary, _, err := license.DeviceFingerprintSummary()
	if err != nil {
		fatal("device fingerprint", err)
	}
	fmt.Println(separator)
	fmt.Println(summary)
	fmt.Println(separator)

	req, session, err := license.GenerateLicenseRequestBundle(tenant, tier)
	if err != nil {
		fatal("generate request", err)
	}

	if err := license.SaveLicenseRequest(req, out); err != nil {
		fatal("save request", err)
	}

	// Save ephemeral session key alongside request (client must keep this)
	sessionFile := out + ".session.kyber"
	sessionData, _ := json.MarshalIndent(session, "", "  ")
	if err := os.WriteFile(sessionFile, sessionData, 0600); err != nil {
		fatal("save session key", err)
	}

	fmt.Printf("\n[LICENSE] Request bundle generated.\n")
	fmt.Println(separator)
	fmt.Printf("  Request file  : %s\n", out)
	fmt.Printf("  Session key   : %s\n", sessionFile)
	fmt.Printf("  Request ID    : %s\n", req.RequestID)
	fmt.Printf("  Device ID     : %s\n", req.DeviceID[:16]+"...")
	fmt.Printf("  Tenant        : %s\n", req.Tenant)
	fmt.Printf("  Tier          : %s\n", req.RequestedTier)
	fmt.Println(separator)
	fmt.Println("\n[NEXT] Send the request file to AdinKhepra HQ (email / Signal / physical media).")
	fmt.Printf("[NEXT] Keep '%s' safe — it's the only way to open your license capsule.\n", sessionFile)
}

func licenseInstallCmd(args []string) {
	capsulePath := ""
	sessionPath := ""
	outputPath := licenseFile
	masterPubKeyPath := ""

	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-capsule":
			capsulePath = args[i+1]
		case "-session":
			sessionPath = args[i+1]
		case "-out":
			outputPath = args[i+1]
		case "-master-pub":
			masterPubKeyPath = args[i+1]
		}
	}

	if capsulePath == "" || sessionPath == "" {
		fmt.Println("Usage: adinkhepra license install -capsule <file> -session <file> [-out <file>] [-master-pub <key>]")
		os.Exit(1)
	}

	fmt.Println("[LICENSE] Installing QKD license capsule...")

	capsule, err := license.LoadLicenseCapsule(capsulePath)
	if err != nil {
		fatal("load capsule", err)
	}

	sessionData, err := os.ReadFile(sessionPath)
	if err != nil {
		fatal("read session key", err)
	}
	var session license.EphemeralKyberSession
	if err := json.Unmarshal(sessionData, &session); err != nil {
		fatal("parse session key", err)
	}

	var masterPubKey []byte
	if masterPubKeyPath != "" {
		masterPubKey = findMasterPubKey()
		// Override with explicit path if provided
		data, err := os.ReadFile(masterPubKeyPath)
		if err != nil {
			fatal("read master pub key", err)
		}
		masterPubKey = data
	} else {
		masterPubKey = findMasterPubKey()
	}

	lic, err := license.InstallLicenseCapsule(capsule, &session, masterPubKey, outputPath, sessionPath)
	if err != nil {
		fatal("install capsule", err)
	}

	fmt.Println(separator)
	fmt.Printf("  [SUCCESS] License installed at: %s\n", outputPath)
	fmt.Printf("  License ID  : %s\n", lic.LicenseID)
	fmt.Printf("  Tenant      : %s\n", lic.Tenant)
	fmt.Printf("  Tier        : %s\n", lic.Tier)
	fmt.Printf("  Expires     : %s\n", lic.ExpiresAt.Format("2006-01-02"))
	fmt.Printf("  Capabilities: %v\n", lic.Capabilities)
	fmt.Println(separator)
	fmt.Println("[LICENSE] The Shu Breath has carried your license across the air gap.")
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func printEAStatus(eng *ea.AdinkraEAEngine) {
	status := eng.Status()
	data, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(data))

	// Persist status for `adinkhepra ea status`
	if err := os.WriteFile(eaStateFile(), data, 0644); err != nil {
		fmt.Printf("[EA] WARN: could not save status: %v\n", err)
	}
}

func eaStateFile() string {
	return filepath.Join(getProjectRoot(), ".ea_state.json")
}

func generationsLabel(n int) string {
	if n <= 0 {
		return "indefinitely (Ctrl+C to stop)"
	}
	return fmt.Sprintf("%d generations", n)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
