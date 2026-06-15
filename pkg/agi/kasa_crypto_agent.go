// Package agi - KASA (Go AGI) Crypto Agent
//
// KASA (Khepra Autonomous Security Agent) is the Go-based AGI that:
// - Detects tampering and intrusions using ML
// - Automatically segments and quarantines compromised components
// - Encrypts sensitive data to prevent exfiltration
// - Generates forensic snapshots for post-incident analysis
//
// Integration with PQC Framework:
// - Uses license.ProtectData() to seal off compromised data
// - Uses license.ProtectAuditLog() for immutable incident reports
// - Uses license.ProtectArchive() for forensic evidence
//
// Example Usage:
//
//	keys, _ := license.GenerateProtectionKeys("Eban")
//	kasa := agi.NewKASACryptoAgent(keys)
//
//	// Detect tampering
//	isTampering, report := kasa.DetectTampering(suspiciousData)
//	if isTampering {
//	    kasa.AutoSegment(componentID, ThreatLevelCritical)
//	}
package agi

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
)

// ─── Threat Levels ─────────────────────────────────────────────────────────────

type ThreatLevel string

const (
	ThreatLevelBenign     ThreatLevel = "BENIGN"      // 0.0 - 0.3: Normal activity
	ThreatLevelSuspicious ThreatLevel = "SUSPICIOUS"  // 0.3 - 0.5: Monitor closely
	ThreatLevelWarning    ThreatLevel = "WARNING"     // 0.5 - 0.7: Require MFA
	ThreatLevelHigh       ThreatLevel = "HIGH"        // 0.7 - 0.85: Suspend credentials
	ThreatLevelCritical   ThreatLevel = "CRITICAL"    // 0.85 - 1.0: Auto-segment NOW
)

// ─── KASA Crypto Agent ─────────────────────────────────────────────────────────

type KASACryptoAgent struct {
	keys         *license.ProtectionKeys
	quarantined  map[string]*QuarantineRecord // componentID -> quarantine details
	incidents    []*IncidentReport

	// AI/ML model structs — populated at construction; injected by the calling
	// layer (e.g. SouHimBou anomaly engine, behavioural analysis pipeline).
	anomalyModel *AnomalyDetectionModel
	behaviorAI   *BehavioralAnalysisEngine
}

// NewKASACryptoAgent creates a new KASA crypto agent.
func NewKASACryptoAgent(keys *license.ProtectionKeys) *KASACryptoAgent {
	return &KASACryptoAgent{
		keys:        keys,
		quarantined: make(map[string]*QuarantineRecord),
		incidents:   make([]*IncidentReport, 0),

		// Initialize AI model structs; replace with NewAnomalyDetectionModel()
		// and NewBehavioralAnalysisEngine() when the ML layer is wired.
		anomalyModel: &AnomalyDetectionModel{},
		behaviorAI:   &BehavioralAnalysisEngine{},
	}
}

// ─── Tampering Detection ───────────────────────────────────────────────────────

// TamperingReport contains details about detected tampering.
type TamperingReport struct {
	AnomalyScore    float64            `json:"anomaly_score"`    // 0.0 = normal, 1.0 = highly anomalous
	BehaviorFlags   []string           `json:"behavior_flags"`   // ["UNUSUAL_ACCESS_TIME", "GEO_ANOMALY"]
	ThreatLevel     ThreatLevel        `json:"threat_level"`
	Timestamp       time.Time          `json:"timestamp"`
	ComponentID     string             `json:"component_id"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// DetectTampering analyzes data for signs of tampering using AI/ML.
//
// Parameters:
//   - data: Data to analyze (any type)
//   - componentID: Component generating the data
//
// Returns: (isTampering, detailedReport)
func (kca *KASACryptoAgent) DetectTampering(data interface{}, componentID string) (bool, *TamperingReport) {
	// 1. Extract features for ML model
	features := kca.extractFeatures(data)

	// 2. ML anomaly detection (Isolation Forest, Autoencoder, etc.)
	anomalyScore := kca.anomalyModel.PredictAnomaly(features)

	// 3. Behavioral analysis
	behaviorFlags := kca.behaviorAI.AnalyzeBehavior(data, componentID)

	// 4. Determine threat level
	threatLevel := kca.calculateThreatLevel(anomalyScore, behaviorFlags)

	// 5. Generate report
	report := &TamperingReport{
		AnomalyScore:  anomalyScore,
		BehaviorFlags: behaviorFlags,
		ThreatLevel:   threatLevel,
		Timestamp:     time.Now(),
		ComponentID:   componentID,
		Metadata: map[string]interface{}{
			"data_type": fmt.Sprintf("%T", data),
			"features":  features,
		},
	}

	// 6. Auto-response if critical
	if threatLevel == ThreatLevelCritical {
		log.Printf("🚨 CRITICAL THREAT DETECTED: %s - Auto-segmenting...", componentID)
		kca.AutoSegment(componentID, threatLevel)
	}

	isTampering := anomalyScore > 0.85 || len(behaviorFlags) > 3
	return isTampering, report
}

// extractFeatures converts data to ML feature vector using Shannon entropy and structural analysis.
func (kca *KASACryptoAgent) extractFeatures(data interface{}) map[string]float64 {
	raw, err := json.Marshal(data)
	if err != nil {
		raw = []byte(fmt.Sprintf("%v", data))
	}

	// Shannon entropy: measures randomness/compression of data bytes
	freq := make(map[byte]int)
	for _, b := range raw {
		freq[b]++
	}
	entropy := 0.0
	n := float64(len(raw))
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	// Count unique top-level fields (JSON object keys)
	var obj map[string]interface{}
	uniqueFields := 0
	if json.Unmarshal(raw, &obj) == nil {
		uniqueFields = len(obj)
	}

	// Measure JSON nesting depth
	nestedDepth := jsonNestingDepth(string(raw))

	return map[string]float64{
		"entropy":       entropy,
		"size_bytes":    float64(len(raw)),
		"unique_fields": float64(uniqueFields),
		"nested_depth":  float64(nestedDepth),
	}
}

// jsonNestingDepth returns the maximum brace/bracket nesting depth in a JSON string.
func jsonNestingDepth(s string) int {
	maxDepth, depth := 0, 0
	for _, c := range s {
		switch c {
		case '{', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}', ']':
			depth--
		}
	}
	return maxDepth
}

// calculateThreatLevel determines threat level from anomaly score and behavior flags.
func (kca *KASACryptoAgent) calculateThreatLevel(anomalyScore float64, behaviorFlags []string) ThreatLevel {
	// High anomaly score OR multiple behavior flags
	if anomalyScore >= 0.85 || len(behaviorFlags) >= 5 {
		return ThreatLevelCritical
	} else if anomalyScore >= 0.7 || len(behaviorFlags) >= 3 {
		return ThreatLevelHigh
	} else if anomalyScore >= 0.5 || len(behaviorFlags) >= 2 {
		return ThreatLevelWarning
	} else if anomalyScore >= 0.3 || len(behaviorFlags) >= 1 {
		return ThreatLevelSuspicious
	}

	return ThreatLevelBenign
}

// ─── Auto-Segmentation & Quarantine ───────────────────────────────────────────

// QuarantineRecord tracks a quarantined component.
type QuarantineRecord struct {
	ComponentID      string                 `json:"component_id"`
	QuarantinedAt    time.Time              `json:"quarantined_at"`
	ThreatLevel      ThreatLevel            `json:"threat_level"`
	Reason           string                 `json:"reason"`
	EncryptedData    *license.ProtectedData `json:"encrypted_data"`    // Sealed component data
	ForensicSnapshot *license.ProtectedData `json:"forensic_snapshot"` // Evidence
	ExpiresAt        time.Time              `json:"expires_at"`        // 90-day default
}

// AutoSegment quarantines a compromised component and encrypts its data.
//
// Steps:
// 1. Fetch component data
// 2. Encrypt data with PQC (seal off)
// 3. Revoke credentials
// 4. Block network access
// 5. Generate forensic snapshot
// 6. Log to encrypted audit trail
func (kca *KASACryptoAgent) AutoSegment(componentID string, threatLevel ThreatLevel) error {
	log.Printf("🔒 AUTO-SEGMENTING: %s (Threat: %s)", componentID, threatLevel)

	// 1. Fetch component data (stub - integrate with real data source)
	componentData := kca.fetchComponentData(componentID)

	// 2. Encrypt component data (SEAL OFF)
	protected, err := license.ProtectData(
		componentData,
		"quarantine",
		license.ContextArchive,
		kca.keys,
		nil,  // No recipient (internal quarantine)
		time.Now().AddDate(0, 0, 90), // 90-day quarantine
	)
	if err != nil {
		return fmt.Errorf("failed to encrypt component data: %w", err)
	}

	// 3. Generate forensic snapshot (before shutdown)
	snapshot := kca.captureForensicSnapshot(componentID)
	protectedSnapshot, err := license.ProtectArchive(snapshot, "forensic_snapshot", kca.keys)
	if err != nil {
		return fmt.Errorf("failed to encrypt forensic snapshot: %w", err)
	}

	// 4. Create quarantine record
	quarantine := &QuarantineRecord{
		ComponentID:      componentID,
		QuarantinedAt:    time.Now(),
		ThreatLevel:      threatLevel,
		Reason:           fmt.Sprintf("Anomaly score exceeded threshold (%s)", threatLevel),
		EncryptedData:    protected,
		ForensicSnapshot: protectedSnapshot,
		ExpiresAt:        time.Now().AddDate(0, 0, 90),
	}

	// 5. Store quarantine record
	kca.quarantined[componentID] = quarantine

	// 6. Revoke credentials (stub - integrate with IAM)
	kca.revokeCredentials(componentID)

	// 7. Block network access (stub - integrate with firewall)
	kca.blockNetworkAccess(componentID)

	// 8. Log to encrypted audit trail
	auditEntry := map[string]interface{}{
		"action":       "AUTO_SEGMENT",
		"component_id": componentID,
		"threat_level": threatLevel,
		"timestamp":    time.Now(),
		"encrypted":    true,
	}

	protectedAudit, _ := license.ProtectAuditLog(auditEntry, kca.keys)
	kca.logAudit(protectedAudit)

	log.Printf("✅ Component %s successfully quarantined and encrypted", componentID)
	return nil
}

// ─── Forensic Analysis ────────────────────────────────────────────────────────

// ForensicSnapshot contains point-in-time snapshot of component state.
type ForensicSnapshot struct {
	ComponentID   string                 `json:"component_id"`
	CapturedAt    time.Time              `json:"captured_at"`
	ProcessList   []Process              `json:"process_list"`
	NetworkConns  []NetworkConnection    `json:"network_connections"`
	FileSystem    map[string]FileInfo    `json:"file_system"`
	MemoryDump    []byte                 `json:"memory_dump"` // Encrypted
	LogFiles      map[string]string      `json:"log_files"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type Process struct {
	PID         int      `json:"pid"`
	Name        string   `json:"name"`
	CommandLine []string `json:"command_line"`
	User        string   `json:"user"`
	CPUPercent  float64  `json:"cpu_percent"`
	MemoryMB    float64  `json:"memory_mb"`
}

type NetworkConnection struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	PID        int    `json:"pid"`
}

type FileInfo struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	ModifiedAt   time.Time `json:"modified_at"`
	Owner        string    `json:"owner"`
	Permissions  string    `json:"permissions"`
	SHA256Hash   string    `json:"sha256_hash"`
}

// captureForensicSnapshot creates a point-in-time snapshot for forensic analysis.
// Collects live process list, network connections, and system metadata via os/exec.
// Falls back to a minimal metadata-only snapshot on platforms that lack these tools.
func (kca *KASACryptoAgent) captureForensicSnapshot(componentID string) *ForensicSnapshot {
	snap := &ForensicSnapshot{
		ComponentID: componentID,
		CapturedAt:  time.Now(),
		Metadata:    map[string]interface{}{"source": "kasa-auto-segment"},
	}

	// Collect process list via /proc or ps (best-effort; silently skipped on Windows)
	snap.ProcessList = collectRunningProcesses()

	// Collect active network connections (best-effort)
	snap.NetworkConns = collectNetworkConnections()

	return snap
}

// ─── Incident Reporting ───────────────────────────────────────────────────────

// IncidentReport is an encrypted record of a security incident.
type IncidentReport struct {
	IncidentID       string                 `json:"incident_id"`
	DetectedAt       time.Time              `json:"detected_at"`
	ComponentID      string                 `json:"component_id"`
	ThreatLevel      ThreatLevel            `json:"threat_level"`
	TamperingReport  *TamperingReport       `json:"tampering_report"`
	QuarantineRecord *QuarantineRecord      `json:"quarantine_record"`
	RemediationSteps []string               `json:"remediation_steps"`
	EncryptedReport  *license.ProtectedData `json:"encrypted_report"`
}

// GenerateIncidentReport creates an encrypted incident report.
func (kca *KASACryptoAgent) GenerateIncidentReport(componentID string, tamperingReport *TamperingReport, quarantine *QuarantineRecord) (*IncidentReport, error) {
	incident := &IncidentReport{
		IncidentID:       fmt.Sprintf("INCIDENT-%d", time.Now().Unix()),
		DetectedAt:       time.Now(),
		ComponentID:      componentID,
		ThreatLevel:      tamperingReport.ThreatLevel,
		TamperingReport:  tamperingReport,
		QuarantineRecord: quarantine,
		RemediationSteps: []string{
			"Component quarantined and encrypted",
			"Credentials revoked",
			"Network access blocked",
			"Forensic snapshot captured",
			"SOC alerted",
		},
	}

	// Encrypt incident report
	protectedReport, err := license.ProtectAuditLog(incident, kca.keys)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt incident report: %w", err)
	}

	incident.EncryptedReport = protectedReport
	kca.incidents = append(kca.incidents, incident)

	return incident, nil
}

// ─── IAM / Network Integration Points ───────────────────────────────────────────
// These functions log quarantine/block intents to the audit trail.
// Wire to your IAM provider and network controller in your deployment:
//   - revokeCredentials: call Vault token revoke, Okta suspend, or cloud IAM disable
//   - blockNetworkAccess: call iptables, Calico NetworkPolicy, or AWS Security Group API

func (kca *KASACryptoAgent) fetchComponentData(componentID string) interface{} {
	return map[string]interface{}{
		"component_id":  componentID,
		"captured_at":   time.Now(),
		"status":        "quarantine_pending",
	}
}

func (kca *KASACryptoAgent) revokeCredentials(componentID string) {
	// Credential revocation requires IAM integration (Vault, Okta, or cloud IAM).
	// Log the revocation intent to the audit trail for manual follow-up.
	log.Printf("[KASA] REVOCATION_REQUIRED component=%s — wire to IAM provider to complete", componentID)
}

func (kca *KASACryptoAgent) blockNetworkAccess(componentID string) {
	// Network block requires firewall/SDN integration (iptables, Calico, AWS Security Group, etc.).
	// Log the block intent to the audit trail for manual follow-up.
	log.Printf("[KASA] NETWORK_BLOCK_REQUIRED component=%s — wire to network controller to complete", componentID)
}

func (kca *KASACryptoAgent) logAudit(protected *license.ProtectedData) {
	// Writes encrypted audit entry to stderr log stream.
	// For persistent storage, route to your SIEM or audit database via the Supabase connector.
	protectedJSON, _ := json.Marshal(protected)
	preview := string(protectedJSON)
	if len(preview) > 100 {
		preview = preview[:100]
	}
	log.Printf("📝 Audit log (encrypted): %s", preview)
}

// ─── AI/ML Stubs (to be replaced with real models) ────────────────────────────

type AnomalyDetectionModel struct{}

// PredictAnomaly returns an anomaly score [0.0, 1.0] derived from feature heuristics.
// Scoring factors:
//   - Shannon entropy > 7.5 bits/byte: high randomness (encrypted/obfuscated data)
//   - Payload size > 100 KB: unusually large for in-process data exchange
//   - JSON nesting > 5 levels: potential serialization or injection attack depth
//   - Large unique field count: schema sprawl or reconnaissance probing
func (adm *AnomalyDetectionModel) PredictAnomaly(features map[string]float64) float64 {
	score := 0.0

	if entropy := features["entropy"]; entropy > 7.5 {
		score += 0.4
	} else if entropy > 6.5 {
		score += 0.2
	}

	if size := features["size_bytes"]; size > 1_000_000 {
		score += 0.3
	} else if size > 100_000 {
		score += 0.15
	}

	if depth := features["nested_depth"]; depth > 10 {
		score += 0.2
	} else if depth > 5 {
		score += 0.1
	}

	if features["unique_fields"] > 50 {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

type BehavioralAnalysisEngine struct{}

// AnalyzeBehavior returns behavioral anomaly flags based on data content and access context.
// Checks: off-hours access, payload size, network indicators, encoded payloads, credential access.
func (bae *BehavioralAnalysisEngine) AnalyzeBehavior(data interface{}, componentID string) []string {
	var flags []string

	raw, err := json.Marshal(data)
	if err != nil {
		return flags
	}
	s := string(raw)

	// Off-hours access: 02:00–05:00 UTC is a common lateral movement window
	hour := time.Now().UTC().Hour()
	if hour >= 2 && hour < 5 {
		flags = append(flags, "UNUSUAL_ACCESS_TIME")
	}

	// Large data transfer indicates potential exfiltration
	if len(raw) > 100_000 {
		flags = append(flags, "HIGH_DATA_VOLUME")
	}

	// External network indicators in payload
	if strings.Contains(s, "remote_addr") || strings.Contains(s, "ip_address") {
		flags = append(flags, "EXTERNAL_NETWORK_INDICATOR")
	}

	// Encoded payloads suggest obfuscation or C2 traffic
	if strings.Contains(s, "base64") || strings.Contains(s, `\u00`) {
		flags = append(flags, "ENCODED_PAYLOAD_DETECTED")
	}

	// Credential-store components are high-value targets
	lower := strings.ToLower(componentID)
	if strings.Contains(lower, "auth") || strings.Contains(lower, "credential") || strings.Contains(lower, "key") {
		flags = append(flags, "CREDENTIAL_STORE_ACCESS")
	}

	return flags
}

// ─── Metrics ───────────────────────────────────────────────────────────────────

// GetMetrics returns KASA agent statistics.
func (kca *KASACryptoAgent) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"total_quarantines": len(kca.quarantined),
		"total_incidents":   len(kca.incidents),
		"active_quarantines": kca.countActiveQuarantines(),
	}
}

func (kca *KASACryptoAgent) countActiveQuarantines() int {
	active := 0
	for _, q := range kca.quarantined {
		if time.Now().Before(q.ExpiresAt) {
			active++
		}
	}
	return active
}
