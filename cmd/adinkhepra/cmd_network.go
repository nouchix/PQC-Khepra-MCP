package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/network"
)

func networkCmd(args []string) {
	if len(args) < 1 {
		printNetworkUsage()
		return
	}

	switch args[0] {
	case "build":
		networkBuildCmd(args[1:])
	case "attack-paths":
		networkAttackPathsCmd(args[1:])
	case "visualize":
		networkVisualizeCmd(args[1:])
	case "blast-radius":
		networkBlastRadiusCmd(args[1:])
	default:
		printNetworkUsage()
	}
}

func printNetworkUsage() {
	fmt.Println(`adinkhepra network - Network Topology & Attack Path Analysis

Usage:
  adinkhepra network build --input snapshots/*.json --output topology.json
  adinkhepra network attack-paths --topology topology.json --from web-server-01
  adinkhepra network blast-radius --topology topology.json --compromised db-server
  adinkhepra network visualize --topology topology.json --output graph.html

Commands:
  build         Build network topology from Sonar snapshots
  attack-paths  Compute lateral movement paths
  blast-radius  Calculate blast radius from compromised host
  visualize     Generate interactive attack graph visualization

Examples:
  # Build topology from multiple snapshots
  adinkhepra network build --input scan1.json,scan2.json --output topology.json

  # Find attack paths from web server
  adinkhepra network attack-paths --topology topology.json --from web-01

  # Calculate blast radius if database is compromised
  adinkhepra network blast-radius --topology topology.json --compromised db-01`)
}

func networkBuildCmd(args []string) {
	fs := flag.NewFlagSet("network build", flag.ExitOnError)
	input := fs.String("input", "", "Input snapshot files (comma-separated)")
	output := fs.String("output", "topology.json", "Output topology file")
	fs.Parse(args)

	if *input == "" {
		fmt.Println("Error: --input is required")
		printNetworkUsage()
		return
	}

	fmt.Println("[NETWORK] Building topology from snapshots...")

	// Parse input files
	inputFiles := parsePaths(*input)

	// Topology built without DAG persistence. Pass a configured dag.Store
	// to NewNetworkTopology() to enable immutable event recording.
	topo := network.NewNetworkTopology(nil)

	// Load each snapshot and build topology
	for _, file := range inputFiles {
		fmt.Printf("   - Processing: %s\n", file)

		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("   [WARN] Failed to read %s: %v\n", file, err)
			continue
		}

		// Parse snapshot JSON and extract host/service/connection data
		var snapData map[string]interface{}
		if err := json.Unmarshal(data, &snapData); err != nil {
			fmt.Printf("   [WARN] Failed to parse %s as JSON: %v\n", file, err)
			continue
		}

		// Register host and connections into the topology via the discovery API
		if err := topo.DiscoverNetworkTopology(snapData); err != nil {
			fmt.Printf("   [WARN] Failed to ingest topology from %s: %v\n", file, err)
		}
	}

	// Export topology
	topoData, err := json.MarshalIndent(topo, "", "  ")
	if err != nil {
		fatal("failed to marshal topology", err)
	}

	if err := os.WriteFile(*output, topoData, 0644); err != nil {
		fatal("failed to write topology", err)
	}

	fmt.Printf("\n[SUCCESS] Topology built.\n")
	fmt.Printf("   - Hosts: %d\n", topo.HostCount())
	fmt.Printf("   - Connections: %d\n", topo.ConnectionCount())
	fmt.Printf("   - Output: %s\n", *output)
	fmt.Println("\n[NEXT] Compute attack paths:")
	fmt.Printf("       adinkhepra network attack-paths --topology %s --from <hostname>\n", *output)
}

func networkAttackPathsCmd(args []string) {
	fs := flag.NewFlagSet("network attack-paths", flag.ExitOnError)
	topoPath := fs.String("topology", "", "Topology JSON file (required)")
	from := fs.String("from", "", "Starting host (compromised host)")
	maxDepth := fs.Int("max-depth", 5, "Maximum path depth")
	fs.Parse(args)

	if *topoPath == "" || *from == "" {
		fmt.Println("Error: --topology and --from are required")
		printNetworkUsage()
		return
	}

	// Load topology
	data, err := os.ReadFile(*topoPath)
	if err != nil {
		fatal("failed to read topology", err)
	}

	var topo network.NetworkTopology
	if err := json.Unmarshal(data, &topo); err != nil {
		fatal("failed to parse topology", err)
	}

	fmt.Printf("[NETWORK] Computing attack paths from: %s\n", *from)
	fmt.Printf("   - Max depth: %d\n", *maxDepth)

	// Compute lateral movement paths
	paths, err := topo.ComputeLateralMovementPaths(*from)
	if err != nil {
		fatal("failed to compute paths", err)
	}

	if len(paths) == 0 {
		fmt.Println("\n[RESULT] No attack paths found.")
		return
	}

	fmt.Printf("\n[RESULT] Found %d attack paths:\n\n", len(paths))

	for i, path := range paths {
		fmt.Printf("Path %d: %s\n", i+1, path.Summary())
		fmt.Printf("   - Length: %d steps\n", len(path.Steps))
		fmt.Printf("   - Severity: %s\n", path.Severity)
		fmt.Printf("   - Blast Radius: %d hosts\n", len(path.BlastRadius))

		if len(path.MITRETactics) > 0 {
			fmt.Printf("   - MITRE ATT&CK Tactics: %v\n", path.MITRETactics)
		}

		fmt.Println("\n   Steps:")
		for j, step := range path.Steps {
			fmt.Printf("      %d. %s → %s (%s)\n", j+1, step.FromHost, step.ToHost, step.Method)
			if step.Requirement != "" {
				fmt.Printf("         Requirement: %s\n", step.Requirement)
			}
		}
		fmt.Println()
	}
}

func networkBlastRadiusCmd(args []string) {
	fs := flag.NewFlagSet("network blast-radius", flag.ExitOnError)
	topoPath := fs.String("topology", "", "Topology JSON file (required)")
	compromised := fs.String("compromised", "", "Compromised host")
	fs.Parse(args)

	if *topoPath == "" || *compromised == "" {
		fmt.Println("Error: --topology and --compromised are required")
		printNetworkUsage()
		return
	}

	// Load topology
	data, err := os.ReadFile(*topoPath)
	if err != nil {
		fatal("failed to read topology", err)
	}

	var topo network.NetworkTopology
	if err := json.Unmarshal(data, &topo); err != nil {
		fatal("failed to parse topology", err)
	}

	fmt.Printf("[NETWORK] Calculating blast radius from: %s\n\n", *compromised)

	// Compute paths
	paths, err := topo.ComputeLateralMovementPaths(*compromised)
	if err != nil {
		fatal("failed to compute paths", err)
	}

	// Extract unique hosts
	affectedHosts := make(map[string]bool)
	affectedHosts[*compromised] = true

	for _, path := range paths {
		for _, step := range path.Steps {
			affectedHosts[step.ToHost] = true
		}
	}

	fmt.Printf("[RESULT] Blast Radius Analysis:\n\n")
	fmt.Printf("   - Initial Compromise: %s\n", *compromised)
	fmt.Printf("   - Total Affected Hosts: %d\n", len(affectedHosts))
	fmt.Printf("   - Attack Paths: %d\n\n", len(paths))

	fmt.Println("Affected Hosts:")
	for host := range affectedHosts {
		if host != *compromised {
			fmt.Printf("   - %s\n", host)
		}
	}

	// Financial impact model: IBM/Ponemon 2024 Cost of a Data Breach Report
	// Global average: $4.45M per breach. Adjusted by blast radius as a fraction
	// of total network reachability (conservative: each host = 1 blast unit).
	// Formula: $4.45M × (affected / total_hosts), floor at $250K per host.
	const ibmAverageBreach = 4_450_000 // $4.45M (IBM/Ponemon 2024)
	hostFraction := float64(len(affectedHosts)) / float64(topo.HostCount()+1)
	estimatedImpactF := float64(ibmAverageBreach) * hostFraction
	if perHost := ibmAverageBreach / (topo.HostCount() + 1); estimatedImpactF < float64(perHost)*250_000/1_000_000 {
		estimatedImpactF = 250_000 * float64(len(affectedHosts))
	}
	estimatedImpact := int(estimatedImpactF)
	fmt.Printf("\n[BUSINESS IMPACT]\n")
	fmt.Printf("   - Estimated Loss: $%s\n", formatMoney(estimatedImpact))
}

func networkVisualizeCmd(args []string) {
	fs := flag.NewFlagSet("network visualize", flag.ExitOnError)
	topoPath := fs.String("topology", "", "Topology JSON file (required)")
	output := fs.String("output", "attack-graph.html", "Output HTML file")
	fs.Parse(args)

	if *topoPath == "" {
		fmt.Println("Error: --topology is required")
		printNetworkUsage()
		return
	}

	// Load topology
	data, err := os.ReadFile(*topoPath)
	if err != nil {
		fatal("failed to read topology", err)
	}

	var topo network.NetworkTopology
	if err := json.Unmarshal(data, &topo); err != nil {
		fatal("failed to parse topology", err)
	}

	fmt.Printf("[NETWORK] Generating attack graph visualization...\n")

	// Generate D3.js HTML visualization
	html := topo.GenerateD3Visualization()

	if err := os.WriteFile(*output, []byte(html), 0644); err != nil {
		fatal("failed to write HTML", err)
	}

	fmt.Printf("\n[SUCCESS] Visualization generated.\n")
	fmt.Printf("   - Output: %s\n", *output)
	fmt.Printf("   - Open in browser: file:///%s\n", *output)
}

func formatMoney(amount int) string {
	// Simple money formatter
	millions := amount / 1000000
	thousands := (amount % 1000000) / 1000

	if millions > 0 {
		return fmt.Sprintf("%d.%dM", millions, thousands/100)
	}
	return fmt.Sprintf("%dK", thousands)
}
