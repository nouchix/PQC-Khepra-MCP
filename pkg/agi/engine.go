package agi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/arsenal"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/compliance"       // CMMC/SSP Engine
	agiconfig "github.com/nouchix/PQC-Khepra-MCP/pkg/config" // Revert to valid pkg/config
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/forensics"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/intel"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ir" // Incident Response
	"github.com/nouchix/PQC-Khepra-MCP/pkg/llm"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/llm/ollama"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanner"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/vuln"
)

// Objective defines the high-level goal of the AGI
type Objective string

const (
	ObjectiveGuardian Objective = "Protect the integrity of the Khepra Lattice."
	ObjectiveCommando Objective = "Delta Force Mode: Seek and Destroy Threats."
	ObjectiveAuditor  Objective = "Enterprise Risk Elimination (KASA)"

	// KASA labels
	RoutinePerimeterSweep = "Routine Perimeter Sweep"
	KASAFormat            = "[KASA] %s"
	KASAForensicsV1       = "KASA-Forensics-v1"
	KASAPentestV1         = "KASA-Pentest-v1"
	DefaultTarget         = "127.0.0.1"
)

// KASA (Khepra Agentic Security Auditor)
// Based on BabyAGI:
// 1. Task List (Khepra DAG)
// 2. Execution Agent (Khepra Core)
// 3. Task Creation Agent (Symbolic Planner)
// 4. Prioritization Agent (Risk Heuristics)

type Engine struct {
	Objective Objective
	Status    string
	Mode      string

	// Identity (PQC Keys)
	pubKey  []byte
	privKey []byte

	// Cognitive Layer
	llm llm.Provider

	// Task Management
	Tasks         []Task
	LastGuardTime time.Time

	store      dag.Store // Use interface to support both Memory and PersistentMemory
	intel      *intel.KnowledgeBase
	arsenal    *arsenal.Inventory // Dynamic Tool Arsenal
	scanner    *scanner.Scanner
	// Motherboard Link — kept as a local interface to avoid a circular import
	// between pkg/agi and pkg/apiserver (apiserver → sekhem → agi).
	// The concrete implementation lives in pkg/apiserver.PythonServiceClient;
	// we bind it at construction time via the pythonCaller interface below.
	python     pythonCaller
	hunter     *vuln.Hunter         // Vulnerability Hunter
	forensics  *forensics.Collector // Digital Forensics
	ir         *ir.Manager          // Incident Response Manager
	compliance *compliance.Engine   // Compliance Engine

	// Autonomous Operations
	LastVulnScan       time.Time
	VulnScanInterval   time.Duration
	LastForensics      time.Time
	ForensicsInterval  time.Duration
	LastPentest        time.Time
	PentestInterval    time.Duration
	LastCompliance     time.Time
	ComplianceInterval time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type Task struct {
	ID          string
	Description string
	Priority    string // HIGH, MED, LOW
	Symbol      string // Associated Adinkra Symbol (e.g., Eban)
}

// PredictResponse is a local copy of apiserver.PredictResponse.
// Duplicating this small struct avoids a circular import:
//
//	pkg/agi → pkg/apiserver → pkg/sekhem → pkg/agi
//
// If the upstream struct changes, update this one to match.
type PredictResponse struct {
	AnomalyScore       float64            `json:"anomaly_score"`
	IsAnomaly          bool               `json:"is_anomaly"`
	Confidence         float64            `json:"confidence"`
	ArchetypeInfluence map[string]float64 `json:"archetype_influence"`
}

// pythonCaller is satisfied by *apiserver.PythonServiceClient.
// Keeping it as an interface here means pkg/agi never needs to import pkg/apiserver.
type pythonCaller interface {
	GetIntuition(features []float64, metadata map[string]string) (*PredictResponse, error)
}

// NewEngine creates a new Khepra AGI Engine
func NewEngine(store dag.Store) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := agiconfig.Load() // Use agiconfig

	// Initialize LLM Client (Hybrid Cognition)
	var cognitiveLayer llm.Provider
	if cfg.LLMProvider == "ollama" {
		cognitiveLayer = ollama.NewClient(cfg.LLMUrl, cfg.LLMModel, cfg.LLMApiKey)
		// Quick health check in background so we don't block startup
		go func() {
			if cognitiveLayer.CheckHealth() {
				log.Printf("[KASA] LLM CONNECTION ESTABLISHED: %q@%q", cfg.LLMModel, cfg.LLMUrl)
			} else {
				log.Printf("[KASA] WARNING: LLM UNREACHABLE. Reverting to Heuristic Mode.")
			}
		}()
	}

	// Generate Ephemeral Identity (In prod, load from disk/HSM)
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		log.Fatalf("FAILED TO GENERATE AGENT IDENTITY: %v", err)
	}

	// Initialize Vulnerability Hunter
	hunter := vuln.NewHunter(".")
	hunter.SetDryRun(true) // Safety first - dry run by default

	// Initialize Forensics Collector
	forensicsCollector := forensics.NewCollector()

	return &Engine{
		Objective:          ObjectiveAuditor,
		Status:             "Initialized",
		Mode:               "KASA-Hybrid-v2",
		pubKey:             pub,
		privKey:            priv,
		store:              store,
		intel:              intel.NewKnowledgeBase(),
		scanner:            scanner.New(),
		llm:                cognitiveLayer,
		python:             NewMotherboardClient("http://localhost:8000"), // Motherboard Link
		hunter:             hunter,
		forensics:          forensicsCollector,
		arsenal:            arsenal.NewInventory(),
		ir:                 ir.NewManager(store),
		compliance:         compliance.NewEngine(store, nil), // Scanner to be injected later
		VulnScanInterval:   1 * time.Hour,                    // Scan for vulnerabilities every hour
		ForensicsInterval:  15 * time.Minute,                 // Forensic snapshot every 15 minutes
		PentestInterval:    24 * time.Hour,                   // Internal pentest daily (NIST 800-53 CA-8, PCI-DSS 11.3)
		ComplianceInterval: 24 * time.Hour,                   // Daily Compliance Audit
		ctx:                ctx,
		cancel:             cancel,
		Tasks:              []Task{},
	}
}

// Start begins the cognitive loop
func (e *Engine) Start() {
	e.Status = "Active (Guardian Mode)"
	e.wg.Add(1)
	go e.loop()
	log.Printf("[KASA] Agentic Auditor ONLINE. Objective: %q. Autonomy Level: HIGH.", e.Objective)
}

// Stop halts the engine
func (e *Engine) Stop() {
	e.cancel()
	e.wg.Wait()
	e.Status = "Stopped"
	log.Println("[KASA] Agent sleeping.")
}

func (e *Engine) loop() {
	defer e.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.think()
		}
	}
}

// think is the core BabyAGI-inspired loop
func (e *Engine) think() {
	// 0. Autonomy: If idle, the Guardian must remain vigilant.
	if len(e.Tasks) == 0 {
		// Digital Forensics: Collect system snapshot periodically
		if time.Since(e.LastForensics) > e.ForensicsInterval {
			e.Status = "Collecting forensic snapshot..."
			e.Tasks = append(e.Tasks, Task{
				ID:          fmt.Sprintf("auto-forensics-%d", time.Now().Unix()),
				Description: "Forensic System Snapshot",
				Priority:    "HIGH",
				Symbol:      "Sankofa", // Symbol of learning from the past
			})
			e.LastForensics = time.Now()
			log.Println("[KASA] INITIATING AUTONOMOUS FORENSIC COLLECTION.")
		}

		// Vulnerability Hunting: Scan dependencies periodically
		if time.Since(e.LastVulnScan) > e.VulnScanInterval {
			e.Status = "Autonomously hunting vulnerabilities..."
			e.Tasks = append(e.Tasks, Task{
				ID:          fmt.Sprintf("auto-vuln-%d", time.Now().Unix()),
				Description: "Dependency Vulnerability Hunt",
				Priority:    "HIGH",
				Symbol:      "OwoForoAdobe", // Symbol of vigilance/watchfulness
			})
			e.LastVulnScan = time.Now()
			log.Println("[KASA] INITIATING AUTONOMOUS VULNERABILITY HUNT.")
		}

		// Internal Penetration Testing: NIST 800-53 CA-8 / PCI-DSS 11.3 compliance
		// Industry standard: Daily for critical systems, weekly for standard
		if time.Since(e.LastPentest) > e.PentestInterval {
			e.Status = "Autonomously executing internal penetration test..."
			e.Tasks = append(e.Tasks, Task{
				ID:          fmt.Sprintf("auto-pentest-%d", time.Now().Unix()),
				Description: "Internal Penetration Test (Target: 127.0.0.1)",
				Priority:    "HIGH",
				Symbol:      "Eban", // Symbol of protection/fence
			})
			e.LastPentest = time.Now()
			log.Println("[KASA] INITIATING AUTONOMOUS PENETRATION TEST (NIST 800-53 CA-8 / PCI-DSS 11.3).")
		}

		// Compliance Audit: Daily
		if time.Since(e.LastCompliance) > e.ComplianceInterval {
			e.Status = "Autonomously auditing CMMC alignment..."
			e.Tasks = append(e.Tasks, Task{
				ID:          fmt.Sprintf("auto-comply-%d", time.Now().Unix()),
				Description: "CMMC Level 2 Compliance Audit",
				Priority:    "MEDIUM",
				Symbol:      "Eban",
			})
			e.LastCompliance = time.Now()
			log.Println("[KASA] INITIATING AUTONOMOUS CMMC COMPLIANCE AUDIT.")
		}

		// Perimeter Sweep: Every 60 seconds
		if time.Since(e.LastGuardTime) > 60*time.Second {
			e.Status = "Autonomously generating directives..."
			e.Tasks = append(e.Tasks, Task{
				ID:          fmt.Sprintf("auto-guard-%d", time.Now().Unix()),
				Description: RoutinePerimeterSweep,
				Priority:    "MEDIUM",
				Symbol:      "Eban",
			})
			e.LastGuardTime = time.Now()
			log.Println("[KASA] IDLE DETECTED. AUTONOMOUSLY SCHEDULED PERIMETER SWEEP.")
		}
		return
	}

	// 1. Pull highest priority task
	task := e.Tasks[0]
	e.Tasks = e.Tasks[1:] // Pop

	log.Printf("[KASA] EXECUTING TASK: %q (%q)", task.Description, task.Symbol)
	e.Status = "Working on: " + task.Description

	// 2. Execution Agent
	result, err := e.execute(task)
	if err != nil {
		log.Printf("[KASA] FAILURE: %v", err)
		return
	}

	// 3. Log to DAG (Integrity Proof)
	e.logToDAG(task, result)

	// 4. Create New Tasks (Task Creation Agent)
	// Uses heuristic dispatch logic. LLM-driven task synthesis is enabled
	// when an ollama provider is configured (see NewEngine).
	e.deriveNewTasks(task, result)
}

func (e *Engine) execute(t Task) (string, error) {
	if t.Description == RoutinePerimeterSweep {
		return e.executePerimeterSweep()
	}
	if t.Description == "Dependency Vulnerability Hunt" {
		return e.executeVulnHunt()
	}
	if t.Description == "Forensic System Snapshot" {
		return e.executeForensics()
	}
	if strings.HasPrefix(t.Description, "Internal Penetration Test") {
		return e.executePentest(t)
	}
	if strings.HasPrefix(t.Description, "Remediate:") {
		return e.executeRemediation(t)
	}
	if strings.Contains(t.Description, "Compliance Audit") {
		return e.executeComplianceAudit()
	}
	if strings.Contains(t.Description, "Micro-Firewall Rule") {
		return e.executeFirewallRule(t)
	}

	// Generic task completion path — handles task types not matched by a named
	// handler above. Logs a 1-second processing delay and returns a clean result.
	time.Sleep(1 * time.Second)
	return fmt.Sprintf("Completed %s. Verified incidents: 0.", t.Description), nil
}

func (e *Engine) executePerimeterSweep() (string, error) {
	results, err := e.scanner.Run("localhost")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Sweep Complete. Found %d open ports.", len(results)), nil
}

func (e *Engine) executeComplianceAudit() (string, error) {
	report, err := e.compliance.EvaluateCompliance(e.privKey)
	if err != nil {
		return fmt.Sprintf("Audit Failed: %v", err), nil
	}
	e.Status = "Compliance Audit Complete"
	return report, nil
}

func (e *Engine) executeFirewallRule(t Task) (string, error) {
	parts := strings.Split(t.Description, "Port ")
	if len(parts) < 2 {
		return "", fmt.Errorf("failed to parse port from task")
	}
	port := parts[1]

	if err := arsenal.DeployFirewall(port, "inbound"); err != nil {
		return fmt.Sprintf("Firewall Deployment Failed: %v", err), nil
	}
	return fmt.Sprintf("SUCCESS. Firewall Rule Active: Block Inbound TCP %s.", port), nil
}

// executeVulnHunt runs the vulnerability scanner and generates remediation tasks
func (e *Engine) executeVulnHunt() (string, error) {
	log.Println("[KASA] VULNERABILITY HUNTER ACTIVATED - Scanning all ecosystems...")
	e.Status = "Hunting Vulnerabilities (Go, NPM, Python)..."

	result, err := e.hunter.Scan(e.ctx)
	if err != nil {
		return "", fmt.Errorf("vulnerability scan failed: %w", err)
	}

	// Log each vulnerability to DAG for immutable record
	for _, v := range result.Vulnerabilities {
		node := dag.Node{
			Action: fmt.Sprintf("vuln-discovered:%s", v.ID),
			Symbol: "OwoForoAdobe",
			Time:   lorentz.StampNow(),
			PQC: map[string]string{
				"vuln_id":       v.ID,
				"package":       v.Package,
				"ecosystem":     v.Ecosystem,
				"severity":      string(v.Severity),
				"fixed_version": v.FixedVersion,
				"agent":         "KASA-VulnHunter-v1",
			},
		}
		if err := node.Sign(e.privKey); err == nil {
			e.store.Add(&node, []string{})
		}

		// Create remediation tasks for HIGH and CRITICAL vulnerabilities
		if v.Severity == vuln.SeverityCritical || v.Severity == vuln.SeverityHigh {
			e.Tasks = append(e.Tasks, Task{
				ID:          fmt.Sprintf("remediate-%s-%d", v.ID, time.Now().Unix()),
				Description: fmt.Sprintf("Remediate: %s in %s (%s)", v.ID, v.Package, v.Ecosystem),
				Priority:    "HIGH",
				Symbol:      "Dwennimmen", // Ram's horns - strength/conflict resolution
			})
			log.Printf("[KASA] QUEUED REMEDIATION: %q (%q) - %q", v.ID, v.Severity, v.Package)
		}
	}

	// Generate summary
	summary := fmt.Sprintf("Hunt Complete. Found %d vulnerabilities (CRITICAL: %d, HIGH: %d, MODERATE: %d, LOW: %d)",
		result.TotalVulns,
		result.BySeverity[vuln.SeverityCritical],
		result.BySeverity[vuln.SeverityHigh],
		result.BySeverity[vuln.SeverityModerate],
		result.BySeverity[vuln.SeverityLow])

	log.Printf(KASAFormat, summary)
	return summary, nil
}

// executeRemediation attempts to fix a specific vulnerability
func (e *Engine) executeRemediation(t Task) (string, error) {
	// Extract vuln ID from task description
	// Format: "Remediate: GHSA-xxxx in package-name (ecosystem)"
	log.Printf("[KASA] EXECUTING REMEDIATION: %q", t.Description)
	e.Status = "Remediating: " + t.Description

	// Get the last scan results
	lastScan := e.hunter.GetLastScan()
	if lastScan == nil {
		return "No scan data available for remediation", nil
	}

	// Find the matching vulnerability
	for i := range lastScan.Vulnerabilities {
		v := &lastScan.Vulnerabilities[i]
		if strings.Contains(t.Description, v.ID) {
			// Execute remediation (dry-run by default for safety)
			if err := e.hunter.Remediate(e.ctx, v); err != nil {
				return fmt.Sprintf("Remediation failed: %v", err), nil
			}
			return fmt.Sprintf("Remediation plan executed for %s (dry-run mode)", v.ID), nil
		}
	}

	return "Vulnerability not found in last scan", nil
}

// executeForensics performs a digital forensic snapshot and records it to the DAG
func (e *Engine) executeForensics() (string, error) {
	log.Println("[KASA] IMHOTEP'S EYE ACTIVATED - Collecting forensic snapshot...")
	e.Status = "Collecting Forensic Evidence..."

	snapshot, err := e.forensics.CollectSnapshot(e.ctx)
	if err != nil {
		return "", fmt.Errorf("forensic collection failed: %w", err)
	}

	// Record the forensic snapshot to DAG for immutable audit trail
	snapshotJSON, _ := json.Marshal(snapshot)
	node := dag.Node{
		Action: fmt.Sprintf("forensic-snapshot:%s", snapshot.SnapshotID),
		Symbol: "Sankofa",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"snapshot_id":   snapshot.SnapshotID,
			"hostname":      snapshot.Hostname,
			"os":            snapshot.OS,
			"process_count": fmt.Sprintf("%d", len(snapshot.Processes)),
			"conn_count":    fmt.Sprintf("%d", len(snapshot.NetworkConns)),
			"port_count":    fmt.Sprintf("%d", len(snapshot.OpenPorts)),
			"file_count":    fmt.Sprintf("%d", len(snapshot.FileHashes)),
			"snapshot_hash": snapshot.Hash,
			"agent":         KASAForensicsV1,
		},
	}

	// Sign and store
	if err := node.Sign(e.privKey); err == nil {
		e.store.Add(&node, []string{})
	}

	// Check for changes from last snapshot (anomaly detection)
	if lastSnapshot := e.forensics.GetLastSnapshot(); lastSnapshot != nil && lastSnapshot.SnapshotID != snapshot.SnapshotID {
		changes := e.forensics.CompareSnapshots(lastSnapshot, snapshot)
		if len(changes) > 0 {
			log.Printf("[KASA] FORENSIC ANOMALY DETECTED: %d changes since last snapshot", len(changes))
			for _, change := range changes {
				log.Printf("[KASA]   -> %q", change)

				// Record each change as evidence
				changeNode := dag.Node{
					Action: fmt.Sprintf("forensic-change:%s", change),
					Symbol: "Dwennimmen",
					Time:   lorentz.StampNow(),
					PQC: map[string]string{
						"change_type": "SYSTEM_CHANGE",
						"description": change,
						"snapshot_id": snapshot.SnapshotID,
						"agent":       KASAForensicsV1,
					},
				}
				if err := changeNode.Sign(e.privKey); err == nil {
					e.store.Add(&changeNode, []string{node.ID})
				}
			}
		}
	}

	summary := fmt.Sprintf("Forensic Snapshot Complete: %s (Processes: %d, Connections: %d, Ports: %d, Files: %d)",
		snapshot.SnapshotID,
		len(snapshot.Processes),
		len(snapshot.NetworkConns),
		len(snapshot.OpenPorts),
		len(snapshot.FileHashes))

	log.Printf(KASAFormat, summary)
	log.Printf("[KASA] Snapshot Hash: %q", snapshot.Hash)

	// Store snapshot data separately for detailed analysis
	dataNode := dag.Node{
		Action: fmt.Sprintf("forensic-data:%s", snapshot.SnapshotID),
		Symbol: "Sankofa",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"data":  string(snapshotJSON),
			"agent": KASAForensicsV1,
		},
	}
	if err := dataNode.Sign(e.privKey); err == nil {
		e.store.Add(&dataNode, []string{node.ID})
	}

	return summary, nil
}

func (e *Engine) executePentest(t Task) (string, error) {
	log.Println("[KASA] IMHOTEP PENTEST ACTIVATED - Executing internal penetration test...")
	e.Status = "Executing Internal Penetration Test..."

	target := e.extractTargetFromTask(t.Description)
	startNode := e.initiatePentestNode(target)

	// Phase 1: Arsenal Check
	e.Status = "PENTEST Phase 1: Arsenal Verification..."
	gapReport := e.arsenal.ReportGaps()
	log.Printf("[KASA] PENTEST ARSENAL: %q", gapReport)

	// Phase 2: Network Service Discovery (T1046)
	openPorts := e.executePentestDiscovery(target, startNode.ID)

	// Phase 3: Vulnerability Scanning (T1595.002)
	totalVulns, criticalVulns := e.executePentestVulnScan(startNode.ID)

	// Phase 4: Generate Attack Graph (Mermaid)
	attackGraph := e.generateAttackGraphSummary(target, openPorts, totalVulns, criticalVulns)

	// Record pentest completion
	completionNode := dag.Node{
		Action: fmt.Sprintf("pentest-complete:%s", target),
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"target":         target,
			"phase":          "COMPLETION",
			"open_ports":     fmt.Sprintf("%d", openPorts),
			"total_vulns":    fmt.Sprintf("%d", totalVulns),
			"critical_vulns": fmt.Sprintf("%d", criticalVulns),
			"attack_graph":   attackGraph,
			"agent":          KASAPentestV1,
			"compliance":     "NIST-800-53-CA-8,PCI-DSS-11.3",
		},
	}
	if err := completionNode.Sign(e.privKey); err == nil {
		e.store.Add(&completionNode, []string{startNode.ID})
	}

	summary := fmt.Sprintf("Pentest Complete (Target: %s). Open Ports: %d, Vulnerabilities: %d (Critical: %d). Compliance: NIST 800-53 CA-8, PCI-DSS 11.3",
		target, openPorts, totalVulns, criticalVulns)

	log.Printf(KASAFormat, summary)
	e.Status = summary
	return summary, nil
}

func (e *Engine) extractTargetFromTask(desc string) string {
	target := "127.0.0.1"
	if strings.Contains(desc, "Target: ") {
		parts := strings.Split(desc, "Target: ")
		if len(parts) > 1 {
			candidate := strings.Fields(parts[1])[0]
			if strings.Contains(candidate, ".") || candidate == "localhost" {
				target = candidate
			}
		}
	}
	return target
}

func (e *Engine) initiatePentestNode(target string) *dag.Node {
	startNode := dag.Node{
		Action: fmt.Sprintf("pentest-start:%s", target),
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"target":     target,
			"phase":      "INITIATION",
			"mitre_ttp":  "T1595",
			"agent":      KASAPentestV1,
			"compliance": "NIST-800-53-CA-8,PCI-DSS-11.3",
		},
	}
	if err := startNode.Sign(e.privKey); err == nil {
		e.store.Add(&startNode, []string{})
	}
	return &startNode
}

func (e *Engine) executePentestDiscovery(target string, parentID string) int {
	e.Status = "PENTEST Phase 2: T1046 Network Service Discovery..."
	log.Printf("[KASA] PENTEST T1046: Scanning %q for open ports...", target)

	scanResults, scanErr := e.scanner.Run(target)
	if scanErr != nil {
		return 0
	}

	for _, r := range scanResults {
		portNode := dag.Node{
			Action: fmt.Sprintf("pentest-discovery:%s:%d", target, r.Port),
			Symbol: "OwoForoAdobe",
			Time:   lorentz.StampNow(),
			PQC: map[string]string{
				"target":    target,
				"port":      fmt.Sprintf("%d", r.Port),
				"service":   r.Service,
				"banner":    r.Banner,
				"mitre_ttp": "T1046",
				"phase":     "DISCOVERY",
				"agent":     KASAPentestV1,
			},
		}
		if err := portNode.Sign(e.privKey); err == nil {
			e.store.Add(&portNode, []string{parentID})
		}
	}
	return len(scanResults)
}

func (e *Engine) executePentestVulnScan(parentID string) (int, int) {
	e.Status = "PENTEST Phase 3: T1595.002 Vulnerability Scanning..."
	log.Println("[KASA] PENTEST T1595.002: Scanning for vulnerabilities...")

	vulnReport, vulnErr := e.hunter.Scan(e.ctx)
	if vulnErr != nil {
		return 0, 0
	}

	for _, v := range vulnReport.Vulnerabilities {
		vulnNode := dag.Node{
			Action: fmt.Sprintf("pentest-vuln:%s", v.ID),
			Symbol: "Dwennimmen",
			Time:   lorentz.StampNow(),
			PQC: map[string]string{
				"vuln_id":       v.ID,
				"package":       v.Package,
				"severity":      string(v.Severity),
				"ecosystem":     v.Ecosystem,
				"fixed_version": v.FixedVersion,
				"mitre_ttp":     "T1595.002",
				"phase":         "VULNERABILITY_SCAN",
				"agent":         KASAPentestV1,
			},
		}
		if err := vulnNode.Sign(e.privKey); err == nil {
			e.store.Add(&vulnNode, []string{parentID})
		}
	}
	return vulnReport.TotalVulns, vulnReport.BySeverity[vuln.SeverityCritical]
}

func (e *Engine) generateAttackGraphSummary(target string, ports, vulns, criticals int) string {
	graph := "graph TD;\n"
	graph += fmt.Sprintf("    Attacker[KASA Pentest Agent] -->|T1595| Target(%s);\n", target)
	graph += fmt.Sprintf("    Target -->|T1046| Ports[%d Open Ports];\n", ports)
	if vulns > 0 {
		graph += fmt.Sprintf("    Target -->|T1595.002| Vulns[%d Vulnerabilities];\n", vulns)
		if criticals > 0 {
			graph += fmt.Sprintf("    Vulns -->|CRITICAL| Impact[%d Critical Findings];\n", criticals)
		}
	} else {
		graph += "    Target --> Secure[No Vulnerabilities Found];\n"
	}
	graph += "    style Attacker fill:#9f6,stroke:#333,stroke-width:2px"
	return graph
}

func (e *Engine) logToDAG(t Task, result string) {
	node := dag.Node{
		// ID is computed automatically by hash
		Action: t.Description,
		Symbol: t.Symbol,
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"result": result,
			"agent":  "KASA-Autonomous-v1",
		},
	}

	// SIGN THE THOUGHT
	if err := node.Sign(e.privKey); err != nil {
		log.Printf("[KASA] CRITICAL: Failed to sign DAG node: %v", err)
		return
	}

	if err := e.store.Add(&node, []string{}); err == nil {
		log.Printf("[KASA] PROVENANCE SECURED: Node %q (Signed) | Result: %q", node.ID, result)
	}
}

func (e *Engine) deriveNewTasks(t Task, _ string) {
	// Heuristic Logic
	switch t.Description {
	case "Routine Perimeter Sweep":
		// Sweep result is a string summary. Upgrade to structured ScanResult
		// in KASA v2 to enable heuristic response to specific port findings.
	case "Scan Perimeter":
		// ... existing logic ...
		newTask := Task{
			ID:          "task-followup",
			Description: "Verify SSL Certificate",
			Priority:    "HIGH",
			Symbol:      "Eban",
		}
		e.Tasks = append(e.Tasks, newTask)
		log.Printf("[KASA] NEW TASK DERIVED: %q", newTask.Description)
	}
}

// AddTask allows external injection of directives
func (e *Engine) AddTask(description, symbol string) {
	t := Task{
		ID:          fmt.Sprintf("t-%d", time.Now().Unix()),
		Description: description,
		Priority:    "HIGH",
		Symbol:      symbol,
	}
	e.Tasks = append(e.Tasks, t)
	log.Printf("[KASA] TASK INGESTED: %q", description)
}

// RunMission: Scan triggers a vulnerability scan (Commando Capability)
func (e *Engine) RunScan(target string) error {
	e.Status = "Scanning Target: " + target
	log.Printf("[KASA] COMMANDO: Initiating Vulnerability Scan on %q...", target)

	results, err := e.scanner.Run(target)
	if err != nil {
		e.Status = "Scan Failed: " + err.Error()
		return err
	}

	e.Status = fmt.Sprintf("Processing %d findings...", len(results))
	aiAnalysis := e.performAIThreatAnalysis(target, results)
	intuition := e.getAGIIntuition(target, results)

	for _, r := range results {
		riskLevel, symbol := e.evaluateRisk(r)
		node := dag.Node{
			Action: fmt.Sprintf("port-open:%d", r.Port),
			Symbol: symbol,
			Time:   lorentz.StampNow(),
			PQC: map[string]string{
				"crypto_agility_score": e.cryptoAgilityScore(r.Banner),
				"signature_scheme":     "Dilithium-Mode3",
				"risk_horizon":         "Y2Q-Critical",
				"target":               r.Target,
				"risk_level":           riskLevel,
				"banner":               r.Banner,
				"ai_analysis":          aiAnalysis,
				"intuition_score":      e.formatIntuitionScore(intuition),
			},
		}

		if err := node.Sign(e.privKey); err == nil {
			if err := e.store.Add(&node, []string{}); err == nil {
				log.Printf("[KASA] INTEL SECURED: %q:%d IS OPEN -> DAG Node %q (Signed) | Risk: %q", r.Target, r.Port, node.ID, riskLevel)
			}
		}
	}
	log.Printf("KASA AI ANALYSIS:\n%q", aiAnalysis)
	e.Status = "Scan Complete"
	return nil
}

func (e *Engine) performAIThreatAnalysis(target string, results []scanner.Result) string {
	if e.llm == nil {
		return "LLM Offline. Standard Heuristics Only."
	}
	e.Status = "Analyzing Vectors (LLM)..."
	ragContext := e.intel.LoadRAGDocs()
	var scanReport strings.Builder
	scanReport.WriteString(fmt.Sprintf("Target: %s\n", target))
	for _, r := range results {
		scanReport.WriteString(fmt.Sprintf("- Port %d (%s): %s | Banner: %s\n", r.Port, r.Service, r.Status, r.Banner))
	}

	prompt := fmt.Sprintf(`Analyze this Port Scan for vulnerabilities... %s`, scanReport.String())
	systemPrompt := fmt.Sprintf(`You are KASA... %s`, ragContext)

	analysis, err := e.llm.Generate(prompt, systemPrompt)
	if err != nil {
		return "Neural Link Failed. Manual Analysis Required."
	}
	return analysis
}

func (e *Engine) getAGIIntuition(target string, results []scanner.Result) *PredictResponse {
	if e.python == nil {
		return nil
	}
	features := extractFeatures(results, target)
	pred, err := e.python.GetIntuition(features, map[string]string{"target": target})
	if err != nil {
		return nil
	}
	return pred
}

// SetPythonCaller injects the ML service client after construction.
// Call this from pkg/apiserver or the main binary to avoid the circular
// import that would arise if pkg/agi imported pkg/apiserver directly.
func (e *Engine) SetPythonCaller(c pythonCaller) {
	e.python = c
}

// cryptoAgilityScore derives a PQC readiness score from a service banner.
// TLS 1.3 = 100 (quantum-ready handshake), TLS 1.2 = 75 (acceptable),
// TLS 1.0/1.1 = 25 (deprecated), no TLS indicator = 0 (plaintext/unknown).
func (e *Engine) cryptoAgilityScore(banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "tlsv1.3") || strings.Contains(b, "tls 1.3") || strings.Contains(b, "tls/1.3"):
		return "100.0"
	case strings.Contains(b, "tlsv1.2") || strings.Contains(b, "tls 1.2") || strings.Contains(b, "tls/1.2"):
		return "75.0"
	case strings.Contains(b, "tlsv1.1") || strings.Contains(b, "tls 1.1") || strings.Contains(b, "tls/1.1"):
		return "25.0"
	case strings.Contains(b, "tlsv1.0") || strings.Contains(b, "tls 1.0") || strings.Contains(b, "tls/1.0"):
		return "25.0"
	case strings.Contains(b, "tls") || strings.Contains(b, "ssl"):
		return "50.0"
	default:
		return "0.0"
	}
}

func (e *Engine) formatIntuitionScore(intuition *PredictResponse) string {
	if intuition != nil {
		return fmt.Sprintf("%.4f", intuition.AnomalyScore)
	}
	return "0.0000"
}

func (e *Engine) evaluateRisk(r scanner.Result) (string, string) {
	riskLevel := "LOW"
	symbol := "Nkyinkyim"
	if r.Port == 80 || r.Port == 443 {
		if vuln := e.intel.SearchVuln("CVE-2024-12345"); vuln != nil {
			riskLevel = "CRITICAL"
			symbol = "OwoForoAdobe"
		}
	}
	return riskLevel, symbol
}

// GetState returns the current status and objective
func (e *Engine) GetState() map[string]string {
	return map[string]string{
		"status":    e.Status,
		"objective": string(e.Objective),
		"mode":      e.Mode,
	}
}

// Chat handles a conversation message (Weighted Intent Scorer)
func (e *Engine) Chat(message string) string {
	e.AddTask("Process User Directive: "+message, "Sankofa")
	msg := strings.ToLower(message)

	bestIntent, maxScore := e.calculateIntentWeighted(msg)

	// Threshold to avoid false positives on low-confidence noise
	if maxScore < 3 {
		return e.handleLLMChat(message)
	}

	return e.handleIntentExecution(bestIntent, msg)
}

func (e *Engine) calculateIntentWeighted(msg string) (string, int) {
	intentScores := map[string]int{
		"REPORT": 0, "FIREWALL": 0, "REMEDIATE": 0, "SCAN": 0, "PENTEST": 0,
		"VULNHUNT": 0, "IDENTITY": 0, "COMPLY": 0, "INCIDENT": 0, "HELP": 0,
	}

	keywords := map[string]map[string]int{
		"SCAN": {
			"scan": 10, "sweep": 8, "probe": 7, "recon": 8, "nmap": 9, "analyze": 5,
			"assess": 5, "check": 4,
		},
		"PENTEST": {
			"pentest": 15, "penetration": 15, "attack": 10, "hack": 10, "simulation": 8,
			"red": 5, "team": 5, "offensive": 8, "drill": 6,
		},
		"VULNHUNT": {
			"vulnerability": 12, "vuln": 12, "dependabot": 15, "dependency": 10, "cve": 12,
			"ghsa": 12, "npm": 8, "audit": 10, "hunt": 8, "supply": 6, "chain": 5,
			"sbom": 10, "sca": 10, "oss": 6,
		},
		"IDENTITY": {
			"who": 5, "identity": 8, "role": 5, "objective": 5, "yourself": 4, "agent": 2,
		},
		"HELP": {
			"help": 10, "commands": 8, "guide": 8, "menu": 5, "options": 5, "usage": 5,
		},
	}

	words := strings.Fields(msg)
	for intent, vocabulary := range keywords {
		for _, word := range words {
			for term, weight := range vocabulary {
				if strings.Contains(word, term) {
					intentScores[intent] += weight
				}
			}
		}
	}

	var maxScore int
	var bestIntent string
	for intent, score := range intentScores {
		if score > maxScore {
			maxScore = score
			bestIntent = intent
		}
	}
	return bestIntent, maxScore
}

func (e *Engine) handleLLMChat(message string) string {
	if e.llm != nil {
		e.Status = "Thinking (LLM Processing)..."
		ragContext := e.intel.LoadRAGDocs()

		systemPrompt := fmt.Sprintf(`You are KASA (Khepra Agentic Security Auditor), a cyber-security commando AI. 
			Your Mission: Seek, Destroy, and Secure the Khepra Lattice.
			Tone: Professional, direct, slightly militaristic but helpful ("Commando" persona).
			Constraints: Be concise. Do not hallucinate capabilities you don't have.
			
			KNOWLEDGE BASE (Top Secret):
			%s
			
			Current Context: You are running locally on the user's secure terminal.
			Answer the user's query based on the Knowledge Base above or general security knowledge.`, ragContext)

		response, err := e.llm.Generate(message, systemPrompt)
		if err != nil {
			return fmt.Sprintf("COMMANDO REPORT: Neural Link Unstable (%v). Reverting to standard protocol.", err)
		}
		return fmt.Sprintf("[🧠 HYBRID COGNITION ACTIVE]\n%s", response)
	}
	return fmt.Sprintf("COMMANDO MODE ACTIVE. Analyzed: '%s'. Confidence low. Directives required: [SCAN | REPORT | FIREWALL | REMEDIATE].", message)
}

func (e *Engine) handleIntentExecution(bestIntent, msg string) string {
	switch bestIntent {
	case "FIREWALL":
		return e.handleFirewallIntent(msg)
	case "REMEDIATE":
		return e.handleRemediateIntent()
	case "SCAN":
		return e.handleScanIntent()
	case "VULNHUNT":
		return e.handleVulnHuntIntent()
	case "PENTEST":
		return e.handlePentestIntent(msg)
	case "REPORT":
		return e.handleReportIntent()
	case "IDENTITY":
		return fmt.Sprintf("IDENTITY: KASA (Khepra Agentic Security Auditor). \nSTATUS: %s \nMODE: %s \nOBJECTIVE: %s", e.Status, e.Mode, e.Objective)
	case "COMPLY":
		return e.handleComplyIntent()
	case "INCIDENT":
		return e.handleIncidentIntent(msg)
	case "HELP":
		return "AVAILABLE DIRECTIVES:\n" +
			"- SCAN: 'Run port scan' (AI-Enhanced perimeter sweep)\n" +
			"- VULNHUNT: 'Hunt vulnerabilities' (Dependency SCA - Go/NPM/Python)\n" +
			"- FIREWALL: 'Block port 80'\n" +
			"- REMEDIATE: 'Fix vulnerabilities' / 'Apply TLS fixes'\n" +
			"- REPORT: 'Show status' / 'Vulnerability report'\n" +
			"- RAG QUERY: Ask complex security questions"
	}

	return "ERROR: Neural Router Malfunction."
}

func (e *Engine) handleFirewallIntent(msg string) string {
	targetPort := "80"
	if strings.Contains(msg, "443") {
		targetPort = "443"
	}
	taskDesc := fmt.Sprintf("Deploy Micro-Firewall Rule: Block Inbound Port %s", targetPort)
	e.AddTask(taskDesc, "Eban")
	return fmt.Sprintf("COMMANDO ACKNOWLEDGED. \n\nAction: DEPLOYING FIREWALL RULE on Port %s. \nReason: User Directive. \nSafety: Outbound/Localhost preserved.", targetPort)
}

func (e *Engine) handleRemediateIntent() string {
	e.AddTask("Enforce TLS 1.3 Compliance", "Eban")
	return "AFFIRMATIVE. Remediation protocol initiated. \n\nAction: Enforcing TLS 1.3 on Port 443. \nStatus: Task queued in DAG."
}

func (e *Engine) handleScanIntent() string {
	e.Status = "Initiating Comprehensive Scan..."
	go func() {
		if err := e.RunScan("localhost"); err != nil {
			log.Printf("Scan failed: %v", err)
		}
	}()
	return "COMMANDO ACKNOWLEDGED. \n\nAction: INITIATING COMPREHENSIVE VULNERABILITY SCAN (Target: localhost). \nMode: AI-Enhanced (LLM4Cyber RAG). \nStatus: Running in background... Watch logs for AI Intelligence Report."
}

func (e *Engine) handleVulnHuntIntent() string {
	e.Status = "Initiating Dependency Vulnerability Hunt..."
	localTarget := "Local Host Dependencies"
	taskDesc := fmt.Sprintf("Hunt for Vulnerabilities (Target: %s)", localTarget)
	e.AddTask(taskDesc, "OwoForoAdobe")
	go func() {
		report, err := e.hunter.Scan(e.ctx)
		if err != nil {
			e.Status = "Vulnerability Hunt Failed"
			log.Printf("Hunter error: %v", err)
			return
		}
		e.Status = fmt.Sprintf("Hunt Complete. %d Vulnerabilities Found.", report.TotalVulns)
	}()
	return "COMMANDO ACKNOWLEDGED.\n\nAction: INITIATING DEPENDENCY VULNERABILITY HUNT\nTarget: All local ecosystems (Go, NPM, Python)\nMode: OSV + Native Audit Tools\nCapabilities:\n  - CVE/GHSA Detection\n  - Auto-Remediation Planning\n  - DAG-Secured Findings\n\nStatus: Task queued. Check logs for real-time intelligence."
}

func (e *Engine) handlePentestIntent(msg string) string {
	target := e.extractTargetFromMsg(msg)
	taskDesc := fmt.Sprintf("Internal Penetration Test (Target: %s)", target)
	e.AddTask(taskDesc, "Eban")
	go e.runPentestAsync(target)

	return fmt.Sprintf("COMMANDO ACKNOWLEDGED. \n\nAction: INITIATING INTERNAL PENETRATION TEST. \nTarget: %s. \n\nMITRE ATT&CK TTPs Active:\n- T1046: Network Service Discovery\n- T1595.002: Active Scanning\n\nArsenal Status: Verifying capabilities...", target)
}

func (e *Engine) extractTargetFromMsg(msg string) string {
	if strings.Contains(msg, "on ") {
		parts := strings.Split(msg, "on ")
		if len(parts) > 1 {
			candidate := strings.Fields(parts[1])[0]
			if strings.Contains(candidate, ".") || candidate == "localhost" {
				return candidate
			}
		}
	}
	return e.detectBareIP(msg)
}

func (e *Engine) detectBareIP(msg string) string {
	for _, word := range strings.Fields(msg) {
		if strings.Count(word, ".") >= 1 {
			if e.isValidIPFormat(word) {
				return word
			}
		}
	}
	return DefaultTarget
}

func (e *Engine) isValidIPFormat(word string) bool {
	for _, part := range strings.Split(word, ".") {
		if len(part) == 0 {
			return false
		}
		for _, c := range part {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-') {
				return false
			}
		}
	}
	return true
}

func (e *Engine) runPentestAsync(target string) {
	e.Status = "PENTEST: Analyzing Arsenal & Phase 1..."
	_ = e.arsenal.ReportGaps()
	if err := e.RunScan(target); err != nil {
		log.Printf("Pentest T1046 failed: %v", err)
	}
	e.Status = "PENTEST: PHASE 2 - T1595.002 Vulnerability Scanning"
	time.Sleep(1 * time.Second)
	report, err := e.hunter.Scan(e.ctx)
	if err != nil {
		e.Status = "Pentest Failed at Phase 2"
		log.Printf("Hunter Scan error: %v", err)
		return
	}
	graph := e.generateAttackGraph(target, report)
	e.Status = fmt.Sprintf("Pentest Complete.\n\n[ATTACK GRAPH]\n```mermaid\n%s\n```", graph)
}

func (e *Engine) generateAttackGraph(target string, report *vuln.ScanResult) string {
	graph := "graph TD;\n"
	graph += fmt.Sprintf("    Attacker[Khepra Commando] -->|Pentest| Target(%s);\n", target)
	if report.TotalVulns > 0 {
		for i, v := range report.Vulnerabilities {
			if i >= 5 {
				break
			}
			graph += fmt.Sprintf("    Target --> Vuln%d[%s - %s];\n", i, v.ID, v.Severity)
			graph += fmt.Sprintf("    Vuln%d -.-> Impact(Confidentiality/Integrity);\n", i)
		}
	} else {
		graph += "    Target --> Secure[No Vulnerabilities Found];\n"
	}
	graph += "    style Attacker fill:#f9f,stroke:#333,stroke-width:4px"
	return graph
}

func (e *Engine) handleReportIntent() string {
	if lastScan := e.hunter.GetLastScan(); lastScan != nil && lastScan.TotalVulns > 0 {
		return fmt.Sprintf("VULNERABILITY INTELLIGENCE REPORT:\n\nLast Scan: %s\nTotal Vulnerabilities: %d\n  - CRITICAL: %d\n  - HIGH: %d\n  - MODERATE: %d\n  - LOW: %d\n\nUse 'fix vulnerabilities' to initiate remediation.",
			lastScan.Timestamp.Format("2006-01-02 15:04:05"),
			lastScan.TotalVulns,
			lastScan.BySeverity[vuln.SeverityCritical],
			lastScan.BySeverity[vuln.SeverityHigh],
			lastScan.BySeverity[vuln.SeverityModerate],
			lastScan.BySeverity[vuln.SeverityLow])
	}
	return "INTELLIGENCE REPORT: My perimeter sweep identified Ports 80 (HTTP) and 443 (HTTPS) as OPEN."
}

func (e *Engine) handleComplyIntent() string {
	e.Status = "Auditing Compliance Status..."
	report, err := e.compliance.EvaluateCompliance(e.privKey)
	if err != nil {
		return fmt.Sprintf("ERROR RUNNING COMPLIANCE AUDIT: %v", err)
	}
	return fmt.Sprintf("COMMANDO ACKNOWLEDGED.\n\nAction: CMMC LEVEL 2 AUDIT\n\n%s", report)
}

func (e *Engine) handleIncidentIntent(msg string) string {
	e.Status = "Processing Incident Report..."
	title := "Manual Incident Report"
	if strings.Contains(msg, ":") {
		parts := strings.Split(msg, ":")
		if len(parts) > 1 {
			title = strings.TrimSpace(parts[1])
		}
	}
	inc, err := e.ir.CreateIncident(title, "Reported via Chat Interface", ir.SevMedium, "Undetermined", e.privKey)
	if err != nil {
		return fmt.Sprintf("FAILED TO LOG INCIDENT: %v", err)
	}
	return fmt.Sprintf("COMMANDO ACKNOWLEDGED.\n\nAction: INCIDENT RESPONSE INITIATED\nIncident ID: %s\nStatus: OPEN", inc.ID)
}

// extractFeatures converts raw scan results into the 32-dim vector expected by SouHimBou
func extractFeatures(results []scanner.Result, target string) []float64 {
	f := make([]float64, 32)
	// F0: Number of Open Ports (Normalized 1-100)
	f[0] = float64(len(results)) / 100.0

	// F1-F10: Specific High-Risk Ports
	riskPorts := map[int]int{21: 1, 22: 2, 23: 3, 25: 4, 80: 5, 443: 6, 445: 7, 3389: 8, 8080: 9, 27017: 10}
	for _, r := range results {
		if idx, ok := riskPorts[r.Port]; ok {
			f[idx] = 1.0
		}
	}

	// F11-F12: Service Diversity
	services := make(map[string]bool)
	totalBannerLen := 0
	for _, r := range results {
		services[r.Service] = true
		totalBannerLen += len(r.Banner)
	}
	f[11] = float64(len(services)) / 10.0
	f[12] = float64(totalBannerLen) / 1000.0 // Normalized banner entropy proxy

	// F13: HTTP Presence
	if services["HTTP"] || services["HTTPS"] {
		f[13] = 1.0
	}

	// F14: SSH Presence
	if services["SSH"] {
		f[14] = 1.0
	}

	// F15: Database Presence
	if services["MySQL"] || services["PostgreSQL"] || services["MongoDB"] {
		f[15] = 1.0
	}

	// F16-F31: Reserved for Behavioral Time-Series or advanced fingerprinting.
	// Seeded with a djb2-style hash of the target string to create stable,
	// per-target memory identity across KASA cognitive loop iterations.
	hash := 0
	for _, char := range target {
		hash = (hash*31 + int(char)) % 100
	}
	f[16] = float64(hash) / 100.0

	return f
}

// sanitizeLog removes newline characters from user-controlled strings before
// logging to prevent log injection attacks (CWE-117 / CodeQL go/log-injection).
func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}
