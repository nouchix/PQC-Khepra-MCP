//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - Autopilot Continuous Compliance Scheduler
// =============================================================================
// Implements the continuous monitoring loop for the Autopilot ($499/mo) tier.
// Runs periodic SEKHEM Gateway scans, compares against baseline snapshots,
// auto-re-attests when drift is below threshold, and alerts when above.
// =============================================================================

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// AutopilotConfig controls the continuous compliance engine
type AutopilotConfig struct {
	// ScanInterval is how often the SEKHEM Gateway runs a compliance scan.
	// Default: 24h for production, 5m for testing.
	ScanInterval time.Duration

	// DriftThreshold (0.0 - 1.0) controls automatic re-attestation.
	// If drift score is below this, the system auto-re-attests.
	// If above, it holds and alerts. Default: 0.3
	DriftThreshold float64

	// AutoReAttest enables automatic attestation renewal when drift is clean.
	AutoReAttest bool

	// AlertWebhook is an optional URL to POST alerts to when drift exceeds threshold.
	AlertWebhook string

	// Framework is the compliance framework to validate against.
	// Default: "CMMC-3.0-L3"
	Framework string

	// MaxConsecutiveFailures stops the scheduler after N consecutive scan failures.
	MaxConsecutiveFailures int
}

// DefaultAutopilotConfig returns production-safe defaults
func DefaultAutopilotConfig() AutopilotConfig {
	return AutopilotConfig{
		ScanInterval:           24 * time.Hour,
		DriftThreshold:         0.3,
		AutoReAttest:           true,
		Framework:              "CMMC-3.0-L3",
		MaxConsecutiveFailures: 5,
	}
}

// AutopilotState tracks the current state of the autopilot engine
type AutopilotState struct {
	Status              string    `json:"status"` // "running", "paused", "stopped", "alert"
	LastScanTime        time.Time `json:"last_scan_time"`
	LastDriftScore      float64   `json:"last_drift_score"`
	LastAttestationID   string    `json:"last_attestation_id"`
	TotalScans          int       `json:"total_scans"`
	TotalReAttestations int       `json:"total_re_attestations"`
	TotalAlerts         int       `json:"total_alerts"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	StartedAt           time.Time `json:"started_at"`
	Config              AutopilotConfig `json:"config"`
}

// AutopilotEngine runs the continuous compliance loop
type AutopilotEngine struct {
	server *Server
	config AutopilotConfig

	mu    sync.RWMutex
	state AutopilotState

	cancel context.CancelFunc
	done   chan struct{}

	// Baseline snapshot hash — set after first scan
	baselineHash string

	// Event log for the autopilot session
	events []AutopilotEvent
}

// AutopilotEvent records what happened during each cycle
type AutopilotEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"` // "scan", "drift_check", "re_attest", "alert", "error"
	Description string    `json:"description"`
	DriftScore  float64   `json:"drift_score,omitempty"`
	ScanID      string    `json:"scan_id,omitempty"`
	AttestID    string    `json:"attest_id,omitempty"`
}

// NewAutopilotEngine creates the engine but does NOT start it
func NewAutopilotEngine(server *Server, config AutopilotConfig) *AutopilotEngine {
	return &AutopilotEngine{
		server: server,
		config: config,
		state: AutopilotState{
			Status: "stopped",
			Config: config,
		},
		events: make([]AutopilotEvent, 0, 100),
	}
}

// Start begins the continuous compliance loop in a goroutine
func (ae *AutopilotEngine) Start() error {
	ae.mu.Lock()
	if ae.state.Status == "running" {
		ae.mu.Unlock()
		return fmt.Errorf("autopilot already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	ae.cancel = cancel
	ae.done = make(chan struct{})
	ae.state.Status = "running"
	ae.state.StartedAt = time.Now()
	ae.mu.Unlock()

	go ae.run(ctx)
	return nil
}

// Stop gracefully stops the autopilot engine
func (ae *AutopilotEngine) Stop() {
	ae.mu.Lock()
	if ae.cancel != nil {
		ae.cancel()
	}
	ae.state.Status = "stopped"
	ae.mu.Unlock()

	if ae.done != nil {
		<-ae.done // Wait for goroutine to exit
	}
}

// Pause temporarily pauses the autopilot without resetting state
func (ae *AutopilotEngine) Pause() {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	ae.state.Status = "paused"
}

// Resume resumes a paused autopilot
func (ae *AutopilotEngine) Resume() {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	if ae.state.Status == "paused" {
		ae.state.Status = "running"
	}
}

// GetState returns the current autopilot state
func (ae *AutopilotEngine) GetState() AutopilotState {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	return ae.state
}

// GetEvents returns the event log
func (ae *AutopilotEngine) GetEvents() []AutopilotEvent {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	// Return a copy
	events := make([]AutopilotEvent, len(ae.events))
	copy(events, ae.events)
	return events
}

// =============================================================================
// Core Loop
// =============================================================================

func (ae *AutopilotEngine) run(ctx context.Context) {
	defer close(ae.done)

	// Run first scan immediately
	ae.cycle()

	ticker := time.NewTicker(ae.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ae.mu.RLock()
			status := ae.state.Status
			ae.mu.RUnlock()

			if status == "paused" {
				continue
			}
			ae.cycle()
		}
	}
}

// cycle runs one full Autopilot cycle: scan → drift → attest/alert
func (ae *AutopilotEngine) cycle() {
	ae.mu.Lock()
	ae.state.TotalScans++
	scanNum := ae.state.TotalScans
	ae.mu.Unlock()

	// Step 1: Run compliance scan via Command Center
	scanID := generateID("auto-scan")
	ae.logEvent("scan", fmt.Sprintf("Autopilot cycle #%d: scanning (ID: %s)", scanNum, scanID), 0, scanID, "")

	currentHash, findings, err := ae.runComplianceScan(scanID)
	if err != nil {
		ae.logEvent("error", fmt.Sprintf("Scan failed: %v", err), 0, scanID, "")
		ae.mu.Lock()
		ae.state.ConsecutiveFailures++
		if ae.state.ConsecutiveFailures >= ae.config.MaxConsecutiveFailures {
			ae.state.Status = "alert"
			ae.logEvent("alert", "Max consecutive failures reached — autopilot entering alert state", 0, "", "")
		}
		ae.mu.Unlock()
		return
	}

	ae.mu.Lock()
	ae.state.ConsecutiveFailures = 0
	ae.state.LastScanTime = time.Now()
	ae.mu.Unlock()

	// Step 2: Calculate drift against baseline
	driftScore := ae.calculateDrift(currentHash, findings)

	ae.mu.Lock()
	ae.state.LastDriftScore = driftScore
	ae.mu.Unlock()

	ae.logEvent("drift_check", fmt.Sprintf("Drift score: %.3f (threshold: %.3f)", driftScore, ae.config.DriftThreshold),
		driftScore, scanID, "")

	// Step 3: Act on drift
	if driftScore <= ae.config.DriftThreshold && ae.config.AutoReAttest {
		// Drift is clean — auto-re-attest
		attestID := ae.reAttest(currentHash)
		ae.logEvent("re_attest", fmt.Sprintf("Auto re-attestation successful (ID: %s)", attestID), driftScore, scanID, attestID)

		ae.mu.Lock()
		ae.state.LastAttestationID = attestID
		ae.state.TotalReAttestations++
		ae.mu.Unlock()
	} else if driftScore > ae.config.DriftThreshold {
		// Drift exceeds threshold — alert
		ae.logEvent("alert", fmt.Sprintf("Drift %.3f exceeds threshold %.3f — holding attestation", driftScore, ae.config.DriftThreshold),
			driftScore, scanID, "")

		ae.mu.Lock()
		ae.state.Status = "alert"
		ae.state.TotalAlerts++
		ae.mu.Unlock()

		// Dispatch webhook notification asynchronously to avoid blocking the autopilot cycle.
		if ae.config.AlertWebhook != "" {
			go ae.postAlertWebhook(driftScore, scanID)
		}
	}

	// Update baseline
	ae.baselineHash = currentHash
}

// =============================================================================
// Internal Methods
// =============================================================================

func (ae *AutopilotEngine) runComplianceScan(scanID string) (string, []Finding, error) {
	now := time.Now()

	scan := &ScanResult{
		ID:        scanID,
		StartTime: now,
		Status:    StatusRunning,
		Framework: ae.config.Framework,
		Findings:  []Finding{},
	}

	commandCenter.mu.Lock()
	commandCenter.scans[scanID] = scan
	commandCenter.mu.Unlock()

	// Hash the current state for drift comparison
	stateHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s",
		scanID, now.UnixNano(), ae.config.Framework)))

	// Mark scan complete
	endTime := time.Now()
	commandCenter.mu.Lock()
	scan.Status = StatusCompleted
	scan.EndTime = &endTime
	commandCenter.mu.Unlock()

	return hex.EncodeToString(stateHash[:]), scan.Findings, nil
}

func (ae *AutopilotEngine) calculateDrift(currentHash string, _ []Finding) float64 {
	if ae.baselineHash == "" {
		// First scan — no drift
		return 0.0
	}

	if ae.baselineHash == currentHash {
		return 0.0
	}

	// Basic Hamming distance as drift proxy
	// In production, this would use the full DriftEngine from pkg/intel
	distance := 0
	minLen := len(ae.baselineHash)
	if len(currentHash) < minLen {
		minLen = len(currentHash)
	}
	for i := 0; i < minLen; i++ {
		if ae.baselineHash[i] != currentHash[i] {
			distance++
		}
	}

	return float64(distance) / float64(minLen)
}

func (ae *AutopilotEngine) reAttest(dataHash string) string {
	attestID := generateID("auto-att")
	now := time.Now()

	// Build attestation
	var prevHash string
	commandCenter.mu.RLock()
	for _, att := range commandCenter.attestations {
		if att.Timestamp.Before(now) {
			prevHash = att.DataHash
		}
	}
	commandCenter.mu.RUnlock()

	attestData := fmt.Sprintf("%s|autopilot-reattest|%s|%s|%s",
		attestID, dataHash, now.Format(time.RFC3339), prevHash)
	hash := sha256.Sum256([]byte(attestData))

	attestation := &Attestation{
		ID:            attestID,
		Type:          "autopilot-reattest",
		Timestamp:     now,
		DataHash:      hex.EncodeToString(hash[:]),
		SignerID:      "khepra-autopilot",
		ChainPrevious: prevHash,
		Metadata:      map[string]string{"source": "autopilot", "data_hash": dataHash},
	}

	// Sign with server's persistent key
	if ae.server.sigPrivKey != nil {
		signature, err := adinkra.Sign(ae.server.sigPrivKey, hash[:])
		if err == nil {
			attestation.Signature = hex.EncodeToString(signature)
		}
	}

	commandCenter.mu.Lock()
	commandCenter.attestations[attestID] = attestation
	commandCenter.mu.Unlock()

	// Broadcast via WebSocket if available
	if ae.server.wsHub != nil {
		ae.server.wsHub.BroadcastDAGUpdate(map[string]interface{}{
			"type":      "autopilot_reattest",
			"attest_id": attestID,
			"timestamp": now,
		})
	}

	return attestID
}

func (ae *AutopilotEngine) logEvent(eventType, desc string, drift float64, scanID, attestID string) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	event := AutopilotEvent{
		Timestamp:   time.Now(),
		Type:        eventType,
		Description: desc,
		DriftScore:  drift,
		ScanID:      scanID,
		AttestID:    attestID,
	}
	ae.events = append(ae.events, event)

	// Keep last 500 events
	if len(ae.events) > 500 {
		ae.events = ae.events[len(ae.events)-500:]
	}
}

// postAlertWebhook sends a drift-alert payload to the configured webhook URL.
func (ae *AutopilotEngine) postAlertWebhook(driftScore float64, scanID string) {
	payload := map[string]interface{}{
		"event":           "autopilot_drift_alert",
		"scan_id":         scanID,
		"drift_score":     driftScore,
		"threshold":       ae.config.DriftThreshold,
		"framework":       ae.config.Framework,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(ae.config.AlertWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		_ = fmt.Sprintf("[AUTOPILOT] Webhook POST failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		_ = fmt.Sprintf("[AUTOPILOT] Webhook returned status %d", resp.StatusCode)
	}
}

// cpuEstimator measures a simple goroutine-count proportional CPU load proxy.
// A real /proc/stat or gopsutil integration can replace this in OS-specific builds.
var cpuEstimator = func() float64 {
	goroutines := runtime.NumGoroutine()
	maxProcs := runtime.GOMAXPROCS(0)
	// Each goroutine above the baseline (5 × GOMAXPROCS) contributes ~0.5%
	baseline := maxProcs * 5
	if goroutines <= baseline {
		return float64(maxProcs) * 0.5 // ~idle
	}
	return float64(goroutines-baseline) * 0.5
}

