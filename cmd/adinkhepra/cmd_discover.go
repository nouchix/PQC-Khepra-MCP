package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/enumerate"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

func discoverCmd(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	target := fs.String("target", "127.0.0.1/32", "Target CIDR or IP (e.g., 192.168.1.0/24)")
	output := fs.String("output", "discovery.json", "Output file for discovery snapshot")
	cryptoInventory := fs.Bool("crypto-inventory", true, "Enumerate cryptographic assets")
	sspSeed := fs.Bool("ssp-seed", true, "Generate SSP skeleton from discovery")
	blastRadiusRun := fs.Bool("blast-radius", true, "Run Quantum Blast Radius on discovered crypto assets")
	company := fs.String("company", "", "Client system/company name")
	isso := fs.String("isso", "ISSM", "ISSO contact name")
	fs.Parse(args)

	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║     KHEPRA PROTOCOL // PHASE 0 — AGENT-LED DISCOVERY            ║")
	fmt.Println("║     Environment mapping · Crypto inventory · SSP seeding         ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("[*] Target: %s\n", *target)
	fmt.Printf("[*] Started: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	// ── Step 1: System enumeration ──────────────────────────────────────────
	fmt.Println("[1/4] System enumeration...")
	sysInfo, err := enumerate.CollectSystemIntelligence()
	if err != nil {
		fmt.Printf("[WARN] Partial system enumeration: %v\n", err)
	}
	fmt.Printf("      Processes: %d running\n", len(sysInfo.Processes))
	fmt.Printf("      Services:  %d discovered\n", len(sysInfo.Services))
	fmt.Printf("      Software:  %d packages\n", len(sysInfo.InstalledSoftware))
	fmt.Printf("      Users:     %d accounts\n", len(sysInfo.Users))

	// ── Step 2: Network enumeration ─────────────────────────────────────────
	fmt.Println("\n[2/4] Network enumeration...")
	netInfo, err := enumerate.CollectNetworkIntelligence()
	if err != nil {
		fmt.Printf("[WARN] Partial network enumeration: %v\n", err)
	}
	fmt.Printf("      Interfaces: %d\n", len(netInfo.Interfaces))
	fmt.Printf("      Open ports: %d\n", len(netInfo.Ports))

	// ── Step 3: Crypto inventory ─────────────────────────────────────────────
	var cryptoAssets map[string]int
	hostname := "unknown"
	osVersion := "unknown"

	if *cryptoInventory {
		fmt.Println("\n[3/4] Cryptographic asset inventory...")
		v := stig.NewValidator(".")
		// Run only PQC framework for the crypto inventory scan — G-1 fix means
		// validatePQCReadiness() now populates PQCMetrics with real asset counts.
		v.DisableFramework(stig.FrameworkRHEL09STIG)
		v.DisableFramework(stig.FrameworkCISL1)
		v.DisableFramework(stig.FrameworkCISL2)
		v.DisableFramework(stig.FrameworkNIST53)
		v.DisableFramework(stig.FrameworkNIST171)
		v.DisableFramework(stig.FrameworkCMMC)
		report, _ := v.Validate()

		hostname = report.Hostname
		osVersion = report.OSVersion

		if pqcResult, ok := report.Results[stig.FrameworkPQC]; ok && pqcResult.PQCMetrics != nil {
			cryptoAssets = pqcResult.PQCMetrics.CryptoInventory
			fmt.Printf("      X.509 certs:       %d\n", cryptoAssets["X509_certificates"])
			fmt.Printf("      SSH host keys:     %d\n", cryptoAssets["SSH_connections"])
			fmt.Printf("      TLS endpoints:     %d\n", cryptoAssets["TLS_connections"])
			fmt.Printf("      VPN tunnels:       %d\n", cryptoAssets["VPN_tunnels"])
			fmt.Printf("      Code-signed bins:  %d\n", cryptoAssets["signed_binaries"])
		} else {
			fmt.Println("      [INFO] Crypto inventory completed")
		}
	} else {
		fmt.Println("\n[3/4] Crypto inventory skipped (--crypto-inventory=false)")
	}

	// ── Step 4: Build output ─────────────────────────────────────────────────
	fmt.Println("\n[4/4] Building discovery snapshot...")

	if *company == "" {
		*company = hostname
	}

	snapshot := map[string]interface{}{
		"generated_at":  time.Now().UTC().Format(time.RFC3339),
		"target":        *target,
		"company":       *company,
		"isso":          *isso,
		"hostname":      hostname,
		"os_version":    osVersion,
		"processes":     len(sysInfo.Processes),
		"services":      len(sysInfo.Services),
		"software":      len(sysInfo.InstalledSoftware),
		"users":         len(sysInfo.Users),
		"interfaces":    len(netInfo.Interfaces),
		"open_ports":    len(netInfo.Ports),
		"crypto_assets": cryptoAssets,
	}

	data, _ := json.MarshalIndent(snapshot, "", "  ")
	if err := os.WriteFile(*output, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing discovery: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n✓ Discovery snapshot: %s\n", *output)

	// ── Step 5: SSP skeleton ─────────────────────────────────────────────────
	if *sspSeed {
		skeletonPath := "ssp_skeleton.json"
		skeleton := &SSPDocument{
			SystemName:     *company,
			ResponsibleOrg: *company,
			ISSO:           *isso,
			ImpactLevel:    "Moderate",
			CUICategories:  []string{"Controlled Technical Information (CTI)"},
			SystemDescription: fmt.Sprintf(
				"Auto-generated from Phase 0 discovery on %s. Environment: %s.",
				time.Now().Format("2006-01-02"), osVersion,
			),
			SystemEnvironment:    osVersion,
			ComponentsInBoundary: []string{hostname},
		}

		skeletonData, _ := json.MarshalIndent(skeleton, "", "  ")
		os.WriteFile(skeletonPath, skeletonData, 0644)
		fmt.Printf("✓ SSP skeleton:       %s\n", skeletonPath)
		fmt.Println("  → Next: adinkhepra ssp generate --skeleton ssp_skeleton.json --output ssp_v1.json")
	}

	// ── Step 6: Blast Radius ──────────────────────────────────────────────────
	if *blastRadiusRun {
		fmt.Println("\n[*] Generating Quantum Blast Radius report (Day 14 deliverable)...")
		blastRadiusReportCmd([]string{"--output", "blast_radius_v1.pdf"})
	}

	fmt.Println("\n╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Phase 0 COMPLETE                                                ║")
	fmt.Printf("║    ✓ %s\n", *output)
	if *sspSeed {
		fmt.Println("║    ✓ ssp_skeleton.json  (SSP seed)                               ║")
	}
	if *blastRadiusRun {
		fmt.Println("║    ✓ blast_radius_v1_blast_radius.md  (Day 14 deliverable)        ║")
	}
	fmt.Println("║                                                                  ║")
	fmt.Println("║  Next: adinkhepra compliance scan --framework CMMC_L2            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}
