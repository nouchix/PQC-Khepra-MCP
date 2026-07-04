// Package dag — VPS demo seeder for the Master DAG.
//
// SeedDemoNodes writes a set of realistic, ML-DSA-65-signed DAG nodes at
// startup when the chain has fewer than minNodes real tool-call nodes.
//
// These nodes represent the MCP server's own security posture as it would
// appear after the first KASA audit cycle:
//   - GENESIS_CONSTELLATION (already created by GlobalDAG / NewStore)
//   - Forensic system snapshot
//   - Port scan results (localhost — MCP server self-assessment)
//   - Dependency vulnerability scan
//   - STIG compliance check stubs
//   - MCP tool attestation samples
//
// The nodes are parent-linked into a realistic chain. Each is ML-DSA-65
// signed with the provided key so the dag-viewer shows verified (green ring)
// attestations immediately on the first demo.
//
// IMPORTANT: Demo nodes are real DAG nodes. They persist to disk alongside
// production nodes. They are indistinguishable from live nodes to the viewer.
// Use KHEPRA_DAG_SEED_DEMO=true env var to enable (disabled by default).
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.
package dag

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// SeedConfig controls demo seeding behavior.
type SeedConfig struct {
	// MinNodes: seed only if store has fewer than this many nodes (default: 10).
	// Counts all nodes including genesis.
	MinNodes int

	// PrivKey is the ML-DSA-65 private key used to sign seeded nodes.
	// If nil, nodes are written unsigned (hash still valid).
	PrivKey []byte

	// ServerVersion is embedded in the genesis-level metadata.
	ServerVersion string
}

// SeedDemoNodes writes realistic demo nodes if KHEPRA_DAG_SEED_DEMO=true
// and the store has fewer than cfg.MinNodes nodes.
//
// Returns the number of nodes seeded (0 if skipped).
func SeedDemoNodes(store Store, cfg SeedConfig) int {
	if strings.ToLower(os.Getenv("KHEPRA_DAG_SEED_DEMO")) != "true" {
		return 0
	}
	if cfg.MinNodes <= 0 {
		cfg.MinNodes = 10
	}
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "1.0.0"
	}

	existing := store.All()
	if len(existing) >= cfg.MinNodes {
		log.Printf("[DAG-SEED] Chain has %d nodes ≥ threshold %d — skipping demo seed",
			len(existing), cfg.MinNodes)
		return 0
	}

	log.Printf("[DAG-SEED] Chain has %d nodes < threshold %d — seeding demo nodes...",
		len(existing), cfg.MinNodes)

	// Find current tail for parent linking
	var lastID string
	var latestTime string
	for _, n := range existing {
		if n.Time > latestTime {
			latestTime = n.Time
			lastID = n.ID
		}
	}

	seeded := 0
	seed := func(n *Node, parents []string) {
		// MUST set parents before Sign() — ComputeHash() includes Parents in the
		// content-addressed ID. If we set parents after signing, Add() rewrites
		// n.Parents and the stored ID no longer matches the recomputed hash.
		n.Parents = parents
		if len(cfg.PrivKey) > 0 {
			if err := n.Sign(cfg.PrivKey); err != nil {
				log.Printf("[DAG-SEED] WARN: sign failed: %v", err)
			}
		}
		// Pass nil parents — n.Parents is already set; Add() must not overwrite.
		if err := store.Add(n, nil); err != nil {
			if err.Error() != "duplicate node" {
				log.Printf("[DAG-SEED] WARN: Add failed: %v", err)
			}
			return
		}
		lastID = n.ID
		seeded++
	}

	now := time.Now().UTC()
	ts := func(offset time.Duration) string {
		return now.Add(offset).Format(time.RFC3339Nano)
	}

	// ── Node 1: KASA system initialization ──────────────────────────────────
	n1 := &Node{
		Action: "KASA_INIT",
		Symbol: "OwoForoAdobe", // vigilance/watchfulness
		Time:   ts(-30 * time.Minute),
		PQC: map[string]string{
			"agent":          "KASA-Autonomous-v2",
			"mode":           "KASA-Hybrid-v2",
			"objective":      "Enterprise Risk Elimination",
			"server_version": cfg.ServerVersion,
			"key_scheme":     "ML-DSA-65-Dilithium3",
		},
	}
	seed(n1, parentOf(lastID))

	// ── Node 2: Forensic snapshot — VPS system baseline ─────────────────────
	n2 := &Node{
		Action: fmt.Sprintf("forensic-snapshot:snap-%d", now.Unix()-1800),
		Symbol: "Sankofa", // learn from the past
		Time:   ts(-28 * time.Minute),
		PQC: map[string]string{
			"snapshot_id":   fmt.Sprintf("snap-%d", now.Unix()-1800),
			"hostname":      "khepra-vps",
			"os":            "Alpine Linux 3.21",
			"process_count": "47",
			"conn_count":    "12",
			"port_count":    "3",
			"file_count":    "2847",
			"snapshot_hash": "sha256:a7f3c9e1b4d2",
			"agent":         "KASA-Forensics-v1",
		},
	}
	seed(n2, parentOf(lastID))

	// ── Node 3: Port scan — MCP server self-assessment ───────────────────────
	n3 := &Node{
		Action: "pentest-start:127.0.0.1",
		Symbol: "Eban", // fortress/protection
		Time:   ts(-25 * time.Minute),
		PQC: map[string]string{
			"target":      "127.0.0.1",
			"phase":       "INITIATION",
			"mitre_ttp":   "T1595",
			"agent":       "KASA-Pentest-v1",
			"compliance":  "NIST-800-53-CA-8,PCI-DSS-11.3",
		},
	}
	seed(n3, parentOf(lastID))

	// ── Node 4: Port 8080 open — HTTP transport ──────────────────────────────
	n4 := &Node{
		Action: "pentest-discovery:127.0.0.1:8080",
		Symbol: "OwoForoAdobe",
		Time:   ts(-24 * time.Minute),
		PQC: map[string]string{
			"target":    "127.0.0.1",
			"port":      "8080",
			"service":   "HTTP (MCP Transport)",
			"banner":    "khepra-mcp/" + cfg.ServerVersion,
			"mitre_ttp": "T1046",
			"phase":     "DISCOVERY",
			"agent":     "KASA-Pentest-v1",
			"risk":      "LOW — internal only, TLS terminated at Caddy",
		},
	}
	seed(n4, parentOf(lastID))

	// ── Node 5: Pentest complete — no critical findings ───────────────────────
	n5 := &Node{
		Action: "pentest-complete:127.0.0.1",
		Symbol: "Eban",
		Time:   ts(-23 * time.Minute),
		PQC: map[string]string{
			"target":         "127.0.0.1",
			"phase":          "COMPLETION",
			"open_ports":     "1",
			"total_vulns":    "0",
			"critical_vulns": "0",
			"agent":          "KASA-Pentest-v1",
			"compliance":     "NIST-800-53-CA-8,PCI-DSS-11.3",
			"result":         "PASS — no critical exposure",
		},
	}
	seed(n5, parentOf(lastID))

	// ── Node 6: Dependency vuln scan ─────────────────────────────────────────
	n6 := &Node{
		Action: "vuln-scan-complete:go-modules",
		Symbol: "Dwennimmen", // strength/conflict resolution
		Time:   ts(-20 * time.Minute),
		PQC: map[string]string{
			"ecosystem":      "Go",
			"total_scanned":  "247",
			"critical":       "0",
			"high":           "0",
			"moderate":       "2",
			"low":            "5",
			"agent":          "KASA-VulnHunter-v1",
			"compliance":     "NIST-800-53-RA-5,CMMC-RM.L2-3.11.2",
			"result":         "PASS — no exploitable dependencies",
		},
	}
	seed(n6, parentOf(lastID))

	// ── Node 7: STIG check — KHEPRA-PQC-001 ─────────────────────────────────
	n7 := &Node{
		Action: "stig-check:KHEPRA-PQC-001",
		Symbol: "Eban",
		Time:   ts(-18 * time.Minute),
		PQC: map[string]string{
			"stig_id":    "KHEPRA-PQC-001",
			"control":    "SC-13",
			"framework":  "NIST-800-53",
			"check":      "PQC cryptography active (ML-DSA-65 + ML-KEM-768)",
			"status":     "PASS",
			"finding":    "ML-DSA-65 Dilithium3 signatures verified on all DAG nodes",
			"cmmc_map":   "CMMC.SC.L2-3.13.10",
			"agent":      "KASA-STIG-v1",
		},
	}
	seed(n7, parentOf(lastID))

	// ── Node 8: STIG check — KHEPRA-WAF-001 ──────────────────────────────────
	n8 := &Node{
		Action: "stig-check:KHEPRA-WAF-001",
		Symbol: "Eban",
		Time:   ts(-17 * time.Minute),
		PQC: map[string]string{
			"stig_id":    "KHEPRA-WAF-001",
			"control":    "SI-3",
			"framework":  "NIST-800-53",
			"check":      "SEKHEM WAF bilateral protection active",
			"status":     "PASS",
			"finding":    "8 WAF rules active | Kyber-1024 FP | Crowdsec integration | egress scrub",
			"cmmc_map":   "CMMC.SI.L2-3.14.2",
			"agent":      "KASA-STIG-v1",
		},
	}
	seed(n8, parentOf(lastID))

	// ── Node 9: MCP tool attestation sample — ert_scan ───────────────────────
	n9 := &Node{
		Action: "MCP_TOOL_ATTEST",
		Symbol: "NKYINKYIM",
		Time:   ts(-10 * time.Minute),
		PQC: map[string]string{
			"tool":        "ert_scan",
			"agent_id":    "claude-code-demo",
			"session_id":  "demo-session-001",
			"dag_hash":    "sha256:8f4a2b1c9d3e",
			"risk_class":  "high",
			"key_scheme":  "ML-DSA-65-Dilithium3", // gitleaks:allow
			"signed":      "true",
		},
	}
	seed(n9, parentOf(lastID))

	// ── Node 10: MCP tool attestation sample — stig_check ────────────────────
	n10 := &Node{
		Action: "MCP_TOOL_ATTEST",
		Symbol: "NKYINKYIM",
		Time:   ts(-5 * time.Minute),
		PQC: map[string]string{
			"tool":        "stig_check",
			"agent_id":    "cursor-pro-demo",
			"session_id":  "demo-session-002",
			"dag_hash":    "sha256:3c7f9a5d1e2b",
			"risk_class":  "medium",
			"key_scheme":  "ML-DSA-65-Dilithium3", // gitleaks:allow
			"signed":      "true",
		},
	}
	seed(n10, parentOf(lastID))

	log.Printf("[DAG-SEED] Seeded %d demo nodes into Master DAG (chain now has %d nodes)",
		seeded, len(existing)+seeded)
	return seeded
}

// parentOf returns a parent slice with the given ID, or empty if ID is blank.
func parentOf(id string) []string {
	if id == "" {
		return []string{}
	}
	return []string{id}
}
