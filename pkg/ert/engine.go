package ert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sonar"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

// Engine is the central ERT intelligence coordinator
// It connects the 4 ERT packages to the AdinKhepra ecosystem
type Engine struct {
	dagMemory     dag.Store // Use interface to support both Memory and PersistentMemory
	stigValidator *stig.Validator
	sonarRuntime  *sonar.SonarRuntime
	cveDatabase   *CVEDatabase
	targetPath    string
	tenant        string
}

// NewEngine creates an integrated ERT analysis engine
func NewEngine(targetPath, tenant string, dagStore dag.Store) (*Engine, error) {
	// Initialize CVE database
	cveDB, err := LoadCVEDatabase(filepath.Join(targetPath, "data"))
	if err != nil {
		// Fallback to current directory if data not in target
		cveDB, err = LoadCVEDatabase("data")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: CVE database not loaded: %v\n", err)
			cveDB = NewCVEDatabase() // Empty database
		}
	}

	// Initialize STIG validator
	stigValidator := stig.NewValidator(targetPath)

	// Initialize Sonar (no secrets by default - will use network scanner only)
	sonarRuntime := sonar.NewOrchestrator(nil)

	return &Engine{
		dagMemory:     dagStore,
		stigValidator: stigValidator,
		sonarRuntime:  sonarRuntime,
		cveDatabase:   cveDB,
		targetPath:    targetPath,
		tenant:        tenant,
	}, nil
}

// RunFullAnalysis executes all 4 ERT packages and returns aggregated intelligence
func (e *Engine) RunFullAnalysis() (*AggregatedIntelligence, error) {
	intel := &AggregatedIntelligence{
		Timestamp: time.Now(),
		Tenant:    e.tenant,
	}

	// Package A: Strategic Readiness
	readiness, err := e.AnalyzeReadiness()
	if err != nil {
		return nil, fmt.Errorf("readiness analysis failed: %w", err)
	}
	intel.Readiness = readiness
	e.recordToDAG("ert_readiness", readiness)

	// Package B: Architect (Supply Chain)
	architecture, err := e.AnalyzeArchitecture()
	if err != nil {
		return nil, fmt.Errorf("architecture analysis failed: %w", err)
	}
	intel.Architecture = architecture
	e.recordToDAG("ert_architect", architecture)

	// Package C: Crypto & IP Lineage
	crypto, err := e.AnalyzeCrypto()
	if err != nil {
		return nil, fmt.Errorf("crypto analysis failed: %w", err)
	}
	intel.Crypto = crypto
	e.recordToDAG("ert_crypto", crypto)

	// Package D: Executive Synthesis
	godfather := e.SynthesizeGodfather(readiness, architecture, crypto)
	intel.Godfather = godfather
	e.recordToDAG("ert_godfather", godfather)

	return intel, nil
}

// AnalyzeReadiness runs Package A with real STIG data
func (e *Engine) AnalyzeReadiness() (*ReadinessIntel, error) {
	intel := &ReadinessIntel{}

	// Scan for strategy documents
	intel.StrategyDocs = e.scanStrategyDocuments()

	// Run STIG validation to get real compliance data
	stigReport, err := e.stigValidator.Validate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: STIG validation failed: %v\n", err)
	} else {
		// Extract compliance gaps from STIG report
		intel.ComplianceGaps = e.extractComplianceGaps(stigReport)
		intel.STIGScore = e.calculateSTIGScore(stigReport)
	}

	// Detect regulatory conflicts
	intel.RegulatoryConflicts = e.detectRegulatoryConflicts()

	// Calculate strategic alignment score (0-100)
	intel.AlignmentScore = e.calculateAlignmentScore(intel)

	// Generate prioritized roadmap
	intel.Roadmap = e.generateRoadmap(intel)

	return intel, nil
}

// AnalyzeArchitecture runs Package B with real sonar and CVE data
func (e *Engine) AnalyzeArchitecture() (*ArchitectureIntel, error) {
	intel := &ArchitectureIntel{}

	// Build dependency graph from go.mod
	intel.DependencyGraph = e.buildDependencyGraph()

	// Scan dependencies against CVE database
	intel.VulnerableDeps = e.scanDependenciesForCVEs(intel.DependencyGraph)

	// Analyze codebase structure
	intel.ModuleCount = e.countModules()
	intel.FileCount = e.countFiles()

	// Detect shadow IT (unmanaged dependencies)
	intel.ShadowIT = e.detectShadowIT()

	// Detect architectural friction
	intel.FrictionPoints = e.detectArchitecturalFriction()

	return intel, nil
}

// AnalyzeCrypto runs Package C with real cryptographic scanning
func (e *Engine) AnalyzeCrypto() (*CryptoIntel, error) {
	intel := &CryptoIntel{}

	// Hash all source files (Merkle tree)
	intel.SourceHashes = e.hashSourceFiles()

	// Scan for cryptographic primitives
	intel.CryptoUsage = e.scanCryptoPrimitives()

	// Analyze IP lineage
	intel.IPLineage = e.analyzeIPLineage()

	// PQC readiness assessment
	intel.PQCReadiness = e.assessPQCReadiness(intel.CryptoUsage)

	return intel, nil
}

// SynthesizeGodfather runs Package D with aggregated data
func (e *Engine) SynthesizeGodfather(readiness *ReadinessIntel, arch *ArchitectureIntel, crypto *CryptoIntel) *GodfatherReport {
	report := &GodfatherReport{
		Timestamp: time.Now(),
	}

	// Calculate executive risk level
	report.RiskLevel = e.calculateExecutiveRisk(readiness.AlignmentScore)

	// Build causal chain
	report.CausalChain = e.buildCausalChain(readiness, arch, crypto)

	// Generate executive recommendations
	report.Recommendations = e.generateRecommendations(readiness, arch, crypto)

	// Calculate business impact
	report.BusinessImpact = e.calculateBusinessImpact(readiness, arch, crypto)

	return report
}

// recordToDAG writes ERT findings to the immutable DAG
func (e *Engine) recordToDAG(eventType string, data interface{}) {
	if e.dagMemory == nil {
		return // DAG not initialized
	}

	// Serialize finding to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to serialize %s for DAG: %v\n", eventType, err)
		return
	}

	// Create DAG node
	node := &dag.Node{
		Action: fmt.Sprintf("ERT_ANALYSIS_%s", eventType),
		Symbol: "EXECUTIVE_ROUNDTABLE",
		Time:   time.Now().Format(time.RFC3339),
		PQC: map[string]string{
			"event_type": eventType,
			"tenant":     e.tenant,
			"data_hash":  fmt.Sprintf("%x", jsonData[:32]), // First 32 bytes of data hash
		},
	}

	// Get latest node as parent (or genesis if empty)
	parents := []string{}
	allNodes := e.dagMemory.All()
	if len(allNodes) > 0 {
		// Use the most recent node as parent
		latest := allNodes[len(allNodes)-1]
		parents = []string{latest.ID}
	}

	// Add to DAG
	if err := e.dagMemory.Add(node, parents); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to add %s to DAG: %v\n", eventType, err)
	}
}

// AggregatedIntelligence combines all ERT package outputs
type AggregatedIntelligence struct {
	Timestamp    time.Time         `json:"timestamp"`
	Tenant       string            `json:"tenant"`
	Readiness    *ReadinessIntel   `json:"readiness"`
	Architecture *ArchitectureIntel `json:"architecture"`
	Crypto       *CryptoIntel       `json:"crypto"`
	Godfather    *GodfatherReport   `json:"godfather"`
}

// ReadinessIntel contains Package A output
type ReadinessIntel struct {
	StrategyDocs         []string          `json:"strategy_docs"`
	ComplianceGaps       []ComplianceGap   `json:"compliance_gaps"`
	RegulatoryConflicts  []string          `json:"regulatory_conflicts"`
	STIGScore            int               `json:"stig_score"`
	AlignmentScore       int               `json:"alignment_score"`
	Roadmap              []RoadmapItem     `json:"roadmap"`
}

// ArchitectureIntel contains Package B output
type ArchitectureIntel struct {
	DependencyGraph  map[string][]string  `json:"dependency_graph"`
	VulnerableDeps   []VulnerableDep      `json:"vulnerable_deps"`
	ModuleCount      int                  `json:"module_count"`
	FileCount        int                  `json:"file_count"`
	ShadowIT         []string             `json:"shadow_it"`
	FrictionPoints   []FrictionPoint      `json:"friction_points"`
}

// CryptoIntel contains Package C output
type CryptoIntel struct {
	SourceHashes  []string        `json:"source_hashes"`
	CryptoUsage   CryptoUsage     `json:"crypto_usage"`
	IPLineage     IPLineage       `json:"ip_lineage"`
	PQCReadiness  string          `json:"pqc_readiness"`
}

// GodfatherReport contains Package D output
type GodfatherReport struct {
	Timestamp        time.Time          `json:"timestamp"`
	RiskLevel        string             `json:"risk_level"`
	CausalChain      []CausalLink       `json:"causal_chain"`
	Recommendations  []Recommendation   `json:"recommendations"`
	BusinessImpact   BusinessImpact     `json:"business_impact"`
}

// Supporting types
type ComplianceGap struct {
	Framework   string `json:"framework"`
	Control     string `json:"control"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type RoadmapItem struct {
	Priority    string `json:"priority"`
	Action      string `json:"action"`
	Impact      string `json:"impact"`
	Timeline    string `json:"timeline"`
}

type VulnerableDep struct {
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	CVEs        []string `json:"cves"`
	Severity    string   `json:"severity"`
	Exploitable bool     `json:"exploitable"`
}

type FrictionPoint struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

type CryptoUsage struct {
	RSA       int  `json:"rsa"`
	ECDSA     int  `json:"ecdsa"`
	AES       int  `json:"aes"`
	SHA       int  `json:"sha"`
	Kyber     int  `json:"kyber"`
	Dilithium int  `json:"dilithium"`
	HasLegacy bool `json:"has_legacy"`
	HasPQC    bool `json:"has_pqc"`
}

type IPLineage struct {
	Proprietary float64 `json:"proprietary_pct"`
	OSS         float64 `json:"oss_pct"`
	GPL         float64 `json:"gpl_pct"`
	Clean       bool    `json:"clean"`
}

type CausalLink struct {
	Step        int    `json:"step"`
	Type        string `json:"type"` // "GOAL", "BLOCKER", "CONSEQUENCE"
	Description string `json:"description"`
}

type Recommendation struct {
	Priority string `json:"priority"`
	Action   string `json:"action"`
	Impact   string `json:"impact"`
	Cost     string `json:"cost,omitempty"`
	ROI      string `json:"roi,omitempty"`
}

type BusinessImpact struct {
	RevenueAtRisk string   `json:"revenue_at_risk"`
	ComplianceCost string  `json:"compliance_cost"`
	MitigationCost string  `json:"mitigation_cost"`
	TimeToCompliance string `json:"time_to_compliance"`
	KeyRisks       []string `json:"key_risks"`
}

// GetCVEDatabase exposes the CVE database for external access
func (e *Engine) GetCVEDatabase() *CVEDatabase {
	return e.cveDatabase
}
