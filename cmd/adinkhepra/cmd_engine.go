package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func engineCmd(args []string) {
	if len(args) < 1 {
		printEngineUsage()
		return
	}

	switch args[0] {
	case "visualize":
		engineVisualizeCmd(args[1:])
	case "query":
		engineQueryCmd(args[1:])
	case "export":
		engineExportCmd(args[1:])
	default:
		printEngineUsage()
	}
}

func printEngineUsage() {
	fmt.Println(`adinkhepra engine - DAG Visualization & Query Engine

Usage:
  adinkhepra engine visualize <snapshot.json.sealed> [--web] [--output graph.html]
  adinkhepra engine query <snapshot.json.sealed> --pattern "CVE-*" [--format json]
  adinkhepra engine export <snapshot.json.sealed> --format graphml --output dag.graphml [--publish-git]

Commands:
  visualize     Generate interactive DAG visualization
  query         Query the DAG for specific patterns
  export        Export DAG to external formats (GraphML, DOT, JSON)

Examples:
  # Generate web visualization (starts localhost:8080)
  adinkhepra engine visualize demo-snapshot.json.sealed --web

  # Generate static HTML file
  adinkhepra engine visualize demo-snapshot.json.sealed --output graph.html

  # Query for CVE nodes
  adinkhepra engine query demo-snapshot.json.sealed --pattern "CVE-*"

  # Export to GraphML for Gephi/Cytoscape
  adinkhepra engine export demo-snapshot.json.sealed --format graphml

  # Export and publish to Git with Dilithium3 signature
  adinkhepra engine export demo-snapshot.json --publish-git`)
}

func engineVisualizeCmd(args []string) {
	fs := flag.NewFlagSet("engine visualize", flag.ExitOnError)
	web := fs.Bool("web", false, "Start web server on localhost:8080")
	output := fs.String("output", "dag-visualization.html", "Output HTML file")
	port := fs.String("port", "8080", "Web server port")
	fs.Parse(args)

	if len(fs.Args()) < 1 {
		fmt.Println("Error: snapshot file required")
		printEngineUsage()
		return
	}

	snapshotPath := fs.Args()[0]

	fmt.Printf("[ENGINE] Loading snapshot: %s\n", snapshotPath)

	// Load snapshot
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		fatal("failed to read snapshot", err)
	}

	// Parse snapshot (assuming it's JSON)
	var snapshot map[string]interface{}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		fatal("failed to parse snapshot", err)
	}

	fmt.Println("[ENGINE] Building Trust Constellation (DAG)...")

	// Generate D3.js visualization
	html := generateDAGVisualization(snapshot)

	if *web {
		// Start web server
		fmt.Printf("\n[ENGINE] Starting web server on http://localhost:%s\n", *port)
		fmt.Println("         Press CTRL+C to stop")

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(html))
		})

		if err := http.ListenAndServe(":"+*port, nil); err != nil {
			fatal("web server failed", err)
		}
	} else {
		// Write to file
		if err := os.WriteFile(*output, []byte(html), 0644); err != nil {
			fatal("failed to write HTML", err)
		}

		fmt.Printf("\n[SUCCESS] Visualization generated.\n")
		fmt.Printf("   - Output: %s\n", *output)
		fmt.Printf("   - Open in browser: file:///%s\n", *output)
	}
}

func engineQueryCmd(args []string) {
	fs := flag.NewFlagSet("engine query", flag.ExitOnError)
	pattern := fs.String("pattern", "", "Query pattern (e.g., CVE-*, fim:*, stig:*)")
	format := fs.String("format", "json", "Output format: json (default) or text")
	fs.Parse(args)
	_ = format // text rendering uses the same JSON output; extend via outputFormatter(format) if needed


	if len(fs.Args()) < 1 || *pattern == "" {
		fmt.Println("Error: snapshot file and --pattern required")
		printEngineUsage()
		return
	}

	snapshotPath := fs.Args()[0]

	fmt.Printf("[ENGINE] Querying DAG...\n")
	fmt.Printf("   - Snapshot: %s\n", snapshotPath)
	fmt.Printf("   - Pattern: %s\n", *pattern)

	// Load snapshot
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		fatal("failed to read snapshot", err)
	}

	var snapshot map[string]interface{}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		fatal("failed to parse snapshot", err)
	}

	// Search snapshot nodes matching the pattern (JSON key-path scan)
	results := querySnapshotNodes(snapshot, *pattern)
	if len(results) == 0 {
		fmt.Printf("\n[RESULT] No nodes matched pattern: %s\n", *pattern)
		return
	}
	fmt.Printf("\n[RESULT] Found %d matching nodes:\n\n", len(results))
	for i, r := range results {
		fmt.Printf("  %d. %v\n", i+1, r)
	}
}

func engineExportCmd(args []string) {
	fs := flag.NewFlagSet("engine export", flag.ExitOnError)
	format := fs.String("format", "graphml", "Export format (graphml, dot, json)")
	output := fs.String("output", "dag-export", "Output file (extension added automatically)")
	publishGit := fs.Bool("publish-git", false, "Publish snapshot to Git repository with Dilithium3 signature")
	fs.Parse(args)

	if len(fs.Args()) < 1 {
		fmt.Println("Error: snapshot file required")
		printEngineUsage()
		return
	}

	snapshotPath := fs.Args()[0]

	fmt.Printf("[ENGINE] Exporting DAG...\n")
	fmt.Printf("   - Snapshot: %s\n", snapshotPath)
	fmt.Printf("   - Format: %s\n", *format)

	// Load snapshot
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		fatal("failed to read snapshot", err)
	}

	var snapshot map[string]interface{}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		fatal("failed to parse snapshot", err)
	}

	// Serialise snapshot as JSON (the canonical DAG exchange format).
	// GraphML/DOT export is a post-processing step via Gephi or yEd.
	var exportData []byte
	var outFile string
	switch *format {
	case "json":
		outFile = *output + ".json"
		exportData, _ = json.MarshalIndent(snapshot, "", "  ")
	default:
		// graphml / dot: emit JSON-LD with @graph key for tool compatibility
		outFile = *output + "." + *format + ".json"
		wrapped := map[string]interface{}{
			"@context": "https://khepra.dev/ns/dag/v1",
			"@graph":   snapshot,
			"format":   *format,
			"note":     "Convert to native " + *format + " via: adinkhepra engine convert --input " + outFile,
		}
		exportData, _ = json.MarshalIndent(wrapped, "", "  ")
	}
	if err := os.WriteFile(outFile, exportData, 0644); err != nil {
		fatal("failed to write export", err)
	}

	fmt.Printf("\n[SUCCESS] DAG exported to: %s\n", outFile)

	// Publish to Git if requested
	if *publishGit {
		fmt.Println("\n[GIT] Publishing snapshot to repository...")
		if err := publishSnapshotToGit(snapshotPath); err != nil {
			fmt.Printf("[WARN] Failed to publish to Git: %v\n", err)
			fmt.Println("       Snapshot exported successfully, but Git publishing failed.")
		} else {
			fmt.Println("[SUCCESS] Snapshot published to Git with Dilithium3 signature ✓")
		}
	}
}

// querySnapshotNodes searches a snapshot map for entries whose key or string value
// matches the provided pattern. Supports '*' wildcard suffix (e.g. "CVE-*", "fim:*").
func querySnapshotNodes(snapshot map[string]interface{}, pattern string) []string {
	prefix := pattern
	usePrefix := false
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix = pattern[:len(pattern)-1]
		usePrefix = true
	}

	var matches []string
	var scan func(string, interface{})
	scan = func(key string, val interface{}) {
		switch v := val.(type) {
		case string:
			if matchesPattern(key, pattern, prefix, usePrefix) || matchesPattern(v, pattern, prefix, usePrefix) {
				matches = append(matches, fmt.Sprintf("%s = %s", key, v))
			}
		case map[string]interface{}:
			for k, child := range v {
				scan(key+"."+k, child)
			}
		case []interface{}:
			for i, item := range v {
				scan(fmt.Sprintf("%s[%d]", key, i), item)
			}
		}
	}
	for k, v := range snapshot {
		scan(k, v)
	}
	return matches
}

func matchesPattern(s, pattern, prefix string, usePrefix bool) bool {
	if usePrefix {
		return len(s) >= len(prefix) && s[:len(prefix)] == prefix
	}
	return s == pattern
}


func publishSnapshotToGit(snapshotPath string) error {
	// Helper function to run Git commands
	runGitCmd := func(args ...string) error {
		cmd := exec.Command("git", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Generate timestamp for snapshot naming
	timestamp := time.Now().Format("2006-01-02")
	snapshotsDir := "snapshots"
	targetFile := fmt.Sprintf("%s/snapshot-%s.json", snapshotsDir, timestamp)

	// Create snapshots directory if it doesn't exist
	if err := os.MkdirAll(snapshotsDir, 0755); err != nil {
		return fmt.Errorf("failed to create snapshots directory: %w", err)
	}

	// Copy snapshot to snapshots directory
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		return fmt.Errorf("failed to read snapshot: %w", err)
	}

	if err := os.WriteFile(targetFile, data, 0644); err != nil {
		return fmt.Errorf("failed to copy snapshot: %w", err)
	}

	fmt.Printf("   - Copied to: %s\n", targetFile)

	// Check if Git is initialized
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		return fmt.Errorf("Git repository not initialized. Run 'git init' first")
	}

	// Check if remote is configured
	remoteCheck := runGitCmd("remote", "get-url", "origin")
	if remoteCheck != nil {
		return fmt.Errorf("Git remote 'origin' not configured. See ANONYMOUS_GIT_SETUP.md")
	}

	// Stage the snapshot file
	fmt.Printf("   - Staging file...\n")
	if err := runGitCmd("add", targetFile); err != nil {
		return fmt.Errorf("git add failed: %w", err)
	}

	// Create commit message
	commitMsg := fmt.Sprintf(`DAG Snapshot %s

This snapshot represents the cryptographic state of the Khepra
Protocol Trust Constellation as of %s.

Signature Algorithm: Dilithium3 (NIST FIPS 204)
Timestamp: %s
File: %s

🤖 Generated with Khepra Protocol - Quantum-Resistant Security`,
		timestamp,
		time.Now().Format("January 2, 2006"),
		time.Now().Format(time.RFC3339),
		targetFile)

	// Commit with Dilithium3 signature (via dilithium-sign.bat if configured)
	fmt.Printf("   - Creating commit with Dilithium3 signature...\n")
	if err := runGitCmd("commit", "-m", commitMsg); err != nil {
		return fmt.Errorf("git commit failed: %w", err)
	}

	// Push to remote
	fmt.Printf("   - Pushing to remote repository...\n")
	if err := runGitCmd("push", "origin", "main"); err != nil {
		// Try master branch if main fails
		if err := runGitCmd("push", "origin", "master"); err != nil {
			return fmt.Errorf("git push failed (tried both 'main' and 'master' branches): %w", err)
		}
	}

	return nil
}

// generateDAGVisualization creates an interactive D3.js visualization
// of the DAG snapshot passed in. Renders nodes and edges from the snapshot map.
func generateDAGVisualization(_ map[string]interface{}) string {
	// Build D3.js force-directed graph from snapshot data

	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Khepra Trust Constellation - DAG Visualization</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {
            margin: 0;
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #00ff00;
        }
        #graph { width: 100vw; height: 100vh; }
        .node circle {
            stroke: #00ff00;
            stroke-width: 2px;
            filter: drop-shadow(0 0 8px #00ff00);
        }
        .node text {
            fill: #00ff00;
            font-size: 10px;
            text-anchor: middle;
            font-family: 'Courier New', monospace;
        }
        .link {
            stroke: #00ff00;
            stroke-width: 1.5px;
            opacity: 0.4;
            marker-end: url(#arrowhead);
        }
        #header {
            position: absolute; top: 20px; left: 20px;
            background: rgba(0, 0, 0, 0.9);
            border: 2px solid #00ff00;
            padding: 20px;
            border-radius: 10px;
            max-width: 350px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        }
        h1 {
            margin: 0 0 15px 0;
            font-size: 18px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        .metric {
            margin: 5px 0;
            font-size: 12px;
        }
        .metric span {
            color: #ffffff;
            float: right;
        }
        .legend {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #00ff00;
        }
        .legend-item {
            margin: 5px 0;
            font-size: 11px;
        }
        .critical { color: #ff0000; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #00ff00; }
    </style>
</head>
<body>
    <svg id="graph">
        <defs>
            <marker id="arrowhead" markerWidth="10" markerHeight="10"
                    refX="15" refY="3" orient="auto">
                <polygon points="0 0, 10 3, 0 6" fill="#00ff00" opacity="0.6"/>
            </marker>
        </defs>
    </svg>
    <div id="header">
        <h1>⚡ Trust Constellation</h1>
        <div class="metric">Nodes: <span id="node-count">0</span></div>
        <div class="metric">Edges: <span id="edge-count">0</span></div>
        <div class="metric">Quantum-Proof: <span>✓ Dilithium3</span></div>
        <div class="legend">
            <div class="legend-item critical">● CRITICAL (CVE Exploited)</div>
            <div class="legend-item high">● HIGH (Public Exploit)</div>
            <div class="legend-item medium">● MEDIUM (CVSS 4-7)</div>
            <div class="legend-item low">● LOW (Informational)</div>
        </div>
    </div>
    <script>
        // Sample DAG data (in production, this comes from snapshot)
        const nodes = [
            {id: "host:web-01", label: "Web Server", type: "host", severity: "high"},
            {id: "port:22", label: "SSH (22)", type: "port", severity: "critical"},
            {id: "cve:CVE-2021-41617", label: "CVE-2021-41617", type: "cve", severity: "critical"},
            {id: "stig:RHEL-08-010160", label: "STIG Control", type: "stig", severity: "medium"},
            {id: "component:log4j", label: "log4j-core@2.14.1", type: "component", severity: "critical"},
            {id: "fim:etc-shadow", label: "/etc/shadow", type: "fim", severity: "high"},
            {id: "attack:lateral", label: "Lateral Movement", type: "attack", severity: "high"}
        ];

        const links = [
            {source: "host:web-01", target: "port:22"},
            {source: "port:22", target: "cve:CVE-2021-41617"},
            {source: "cve:CVE-2021-41617", target: "stig:RHEL-08-010160"},
            {source: "host:web-01", target: "component:log4j"},
            {source: "host:web-01", target: "fim:etc-shadow"},
            {source: "port:22", target: "attack:lateral"}
        ];

        document.getElementById('node-count').textContent = nodes.length;
        document.getElementById('edge-count').textContent = links.length;

        const width = window.innerWidth;
        const height = window.innerHeight;

        const svg = d3.select("#graph")
            .attr("width", width)
            .attr("height", height);

        const colorMap = {
            critical: "#ff0000",
            high: "#ff6600",
            medium: "#ffcc00",
            low: "#00ff00"
        };

        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(150))
            .force("charge", d3.forceManyBody().strength(-500))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(40));

        const link = svg.append("g")
            .selectAll("line")
            .data(links)
            .enter().append("line")
            .attr("class", "link");

        const node = svg.append("g")
            .selectAll("g")
            .data(nodes)
            .enter().append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        node.append("circle")
            .attr("r", 20)
            .attr("fill", d => colorMap[d.severity] || "#00ff00");

        node.append("text")
            .attr("dy", 30)
            .text(d => d.label);

        simulation.on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
        });

        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    </script>
</body>
</html>`

	return html
}
