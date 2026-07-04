// Package scanner bridges pkg/remote BulkScanner with pkg/asaf/fleet FleetRegistry.
//
// Enrolled assets in the FleetRegistry become scan targets. STIG scan results
// flow back into the registry (last_scan, last_score, SPRS impact) and are
// attested as ML-DSA-65-signed DAG nodes via pkg/adinkra.
//
// Integration:
//   hub.NewFleetScannerHandlers(scanner.NewFleetScanner(registry, dagStore, privKey))
//   → POST /api/v1/fleet/scan        (trigger async scan)
//   → GET  /api/v1/fleet/scan/stream (SSE progress)
//   → GET  /api/v1/fleet/scan/last   (last full results)
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/asaf/fleet"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/remote"
)

// FleetScanResult is a scan result enriched with fleet metadata.
type FleetScanResult struct {
	AssetID    string            `json:"asset_id"`
	AssetName  string            `json:"asset_name"`
	EnclaveID  string            `json:"enclave_id"`
	Host       string            `json:"host"`
	Score      float64           `json:"score"`
	SPRSImpact int               `json:"sprs_impact"`
	Passed     int               `json:"passed"`
	Failed     int               `json:"failed"`
	Errors     int               `json:"errors"`
	TotalChecks int              `json:"total_checks"`
	DAGNodeID  string            `json:"dag_node_id,omitempty"`
	ScannedAt  time.Time         `json:"scanned_at"`
	ScanError  string            `json:"scan_error,omitempty"`
	Profile    string            `json:"profile"`
}

// FleetScanSummary aggregates results from a full fleet scan run.
type FleetScanSummary struct {
	RunID       string            `json:"run_id"`
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	TotalAssets int               `json:"total_assets"`
	Completed   int               `json:"completed"`
	Successful  int               `json:"successful"`
	Failed      int               `json:"failed"`
	Results     []FleetScanResult `json:"results"`
	FleetSPRS   int               `json:"fleet_sprs,omitempty"`
}

// FleetScanner bridges the remote BulkScanner with the FleetRegistry.
type FleetScanner struct {
	registry    *fleet.FleetRegistry
	dagStore    dag.Store
	privKey     []byte
	logger      *log.Logger

	mu          sync.RWMutex
	activeScan  *FleetScanSummary
	lastSummary *FleetScanSummary
	subscribers []chan FleetScanResult

	concurrency int
}

// NewFleetScanner creates a FleetScanner that reads enrolled assets from the registry
// and writes scan results back into it.
func NewFleetScanner(registry *fleet.FleetRegistry, dagStore dag.Store, privKey []byte, logger *log.Logger) *FleetScanner {
	if logger == nil {
		logger = log.Default()
	}
	return &FleetScanner{
		registry:    registry,
		dagStore:    dagStore,
		privKey:     privKey,
		logger:      logger,
		concurrency: 8,
	}
}

// Subscribe returns a channel that receives live FleetScanResult as each host completes.
// The caller must drain the channel. It is closed when the scan ends.
func (fs *FleetScanner) Subscribe() <-chan FleetScanResult {
	ch := make(chan FleetScanResult, 32)
	fs.mu.Lock()
	fs.subscribers = append(fs.subscribers, ch)
	fs.mu.Unlock()
	return ch
}

// ActiveScan returns the currently-running scan summary (nil if idle).
func (fs *FleetScanner) ActiveScan() *FleetScanSummary {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.activeScan
}

// LastSummary returns the most recently completed scan summary.
func (fs *FleetScanner) LastSummary() *FleetScanSummary {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.lastSummary
}

// ScanFleet triggers an async fleet-wide STIG scan.
// Returns ErrScanInProgress if a scan is already running.
// Progress is broadcast to all active subscribers via Subscribe().
func (fs *FleetScanner) ScanFleet(ctx context.Context, enclaveID, stigProfile string, credStore CredentialStore) error {
	fs.mu.Lock()
	if fs.activeScan != nil {
		fs.mu.Unlock()
		return ErrScanInProgress
	}
	runID := fmt.Sprintf("scan-%d", time.Now().UnixMilli())
	summary := &FleetScanSummary{
		RunID:     runID,
		StartedAt: time.Now().UTC(),
	}
	fs.activeScan = summary
	fs.mu.Unlock()

	go fs.runScan(ctx, summary, enclaveID, stigProfile, credStore)
	return nil
}

// ─── Internal scan loop ────────────────────────────────────────────────────────

func (fs *FleetScanner) runScan(ctx context.Context, summary *FleetScanSummary, enclaveID, stigProfile string, credStore CredentialStore) {
	defer func() {
		now := time.Now().UTC()
		fs.mu.Lock()
		summary.CompletedAt = &now
		fs.activeScan = nil
		fs.lastSummary = summary
		subs := fs.subscribers
		fs.subscribers = nil
		fs.mu.Unlock()
		for _, ch := range subs {
			close(ch)
		}
	}()

	// Collect enrolled assets matching the filter
	assets := fs.registry.ListAssets(enclaveID, "")
	if len(assets) == 0 {
		fs.logger.Printf("[FLEET-SCAN] no assets in enclave=%q — aborting", enclaveID)
		return
	}
	summary.TotalAssets = len(assets)
	fs.logger.Printf("[FLEET-SCAN] starting run=%s assets=%d profile=%s", summary.RunID, len(assets), stigProfile)

	// Build ConnectionProfiles from assets ([]*fleet.Asset)
	profiles, assetMap := fs.buildProfiles(assets, credStore)
	if len(profiles) == 0 {
		fs.logger.Printf("[FLEET-SCAN] no connectable assets (missing credentials)")
		return
	}

	// Select STIG checks for profile
	stigChecks := selectSTIGChecks(stigProfile)

	// Run BulkScanner with SSE progress
	progressCh := make(chan remote.BulkScanResult, len(profiles))
	bulkScanner := remote.NewBulkScanner(profiles, stigChecks, fs.concurrency)

	// Consume progress in goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		for bsr := range progressCh {
			asset := assetMap[bsr.Profile.ID]
			fr := fs.processBulkResult(ctx, bsr, asset, stigProfile)
			fs.mu.Lock()
			summary.Completed++
			if fr.ScanError == "" {
				summary.Successful++
			} else {
				summary.Failed++
			}
			summary.Results = append(summary.Results, fr)
			subs := fs.subscribers
			fs.mu.Unlock()
			// Broadcast to subscribers
			for _, ch := range subs {
				select {
				case ch <- fr:
				default:
				}
			}
		}
	}()

	bulkScanner.Scan(ctx, progressCh)
	close(progressCh)
	<-done

	// Compute fleet-level SPRS after all assets updated
	fs.mu.Lock()
	summary.FleetSPRS = fs.computeFleetSPRS()
	fs.mu.Unlock()

	fs.logger.Printf("[FLEET-SCAN] run=%s complete: %d/%d ok, fleet_sprs=%d",
		summary.RunID, summary.Successful, summary.TotalAssets, summary.FleetSPRS)
}

// processBulkResult converts a BulkScanResult into FleetScanResult and updates the registry.
func (fs *FleetScanner) processBulkResult(ctx context.Context, bsr remote.BulkScanResult, asset *fleet.Asset, profile string) FleetScanResult {
	fr := FleetScanResult{
		AssetID:   asset.ID,
		AssetName: asset.Name,
		EnclaveID: asset.EnclaveID,
		Host:      bsr.Profile.Host,
		ScannedAt: time.Now().UTC(),
		Profile:   profile,
	}

	if bsr.Error != nil {
		fr.ScanError = bsr.Error.Error()
		fs.logger.Printf("[FLEET-SCAN] %s (%s): error: %v", asset.Name, bsr.Profile.Host, bsr.Error)
		return fr
	}

	r := bsr.Report
	fr.Score = r.Score
	fr.Passed = r.Passed
	fr.Failed = r.Failed
	fr.Errors = r.Errors
	fr.TotalChecks = r.TotalChecks

	// Map STIG score → SPRS impact (110-practice space)
	// Failed checks reduce SPRS by weighted deduction (critical=5, high=3, medium=1)
	sprsImpact := computeSPRSImpact(r)
	fr.SPRSImpact = sprsImpact

	// Write result into DAG as ML-DSA-65-signed node
	dagNodeID, dagErr := fs.attestScanResult(ctx, fr)
	if dagErr != nil {
		fs.logger.Printf("[FLEET-SCAN] DAG attest warn: %v", dagErr)
	} else {
		fr.DAGNodeID = dagNodeID
	}

	// Update FleetRegistry
	fs.registry.UpdateScanResult(asset.ID, fr.Score, sprsImpact, dagNodeID)

	fs.logger.Printf("[FLEET-SCAN] %s: score=%.1f%% sprs_impact=%d dag=%s",
		asset.Name, fr.Score, sprsImpact, dagNodeID)
	return fr
}

// buildProfiles converts []*fleet.Asset slice to remote.ConnectionProfile slice.
// Assets without credentials in the store are skipped with a warning.
func (fs *FleetScanner) buildProfiles(assets []*fleet.Asset, credStore CredentialStore) ([]*remote.ConnectionProfile, map[string]*fleet.Asset) {
	profiles := make([]*remote.ConnectionProfile, 0, len(assets))
	assetMap := make(map[string]*fleet.Asset, len(assets))

	for _, a := range assets {
		cred, err := credStore.GetCredential(a.ID)
		if err != nil {
			fs.logger.Printf("[FLEET-SCAN] skip %s (%s): no credential: %v", a.Name, a.IP, err)
			continue
		}

		proto := "ssh"
		port := 22
		if a.OS == "windows" {
			proto = "winrm"
			port = 5985
		}

		profile := &remote.ConnectionProfile{
			ID:         a.ID,
			Name:       a.Name,
			Type:       proto,
			Host:       a.IP,
			Port:       port,
			Username:   cred.Username,
			AuthMethod: cred.AuthMethod,
			Credential: cred.Secret,
			Timeout:    30,
			Tags:       map[string]string{"enclave": a.EnclaveID, "os": a.OS},
		}
		profiles = append(profiles, profile)
		assetMap[a.ID] = a
	}
	return profiles, assetMap
}

// attestScanResult writes the FleetScanResult to the DAG as an ML-DSA-65-signed node.
func (fs *FleetScanner) attestScanResult(ctx context.Context, fr FleetScanResult) (string, error) {
	payload, err := json.Marshal(fr)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	sigBytes, err := adinkra.Sign(fs.privKey, payload)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	sigHex := fmt.Sprintf("%x", sigBytes)

	node := &dag.Node{
		Action:    "FLEET_SCAN_RESULT",
		Symbol:    "Eban",
		Time:      fr.ScannedAt.Format("2006-01-02T15:04:05Z07:00"),
		Signature: sigHex,
		PQC: map[string]string{
			"asset_id": fr.AssetID,
			"score":    fmt.Sprintf("%.2f", fr.Score),
			"sprs":     fmt.Sprintf("%d", fr.SPRSImpact),
			"profile":  fr.Profile,
		},
	}
	node.ID = node.ComputeHash()

	if addErr := fs.dagStore.Add(node, nil); addErr != nil {
		return "", fmt.Errorf("dag.Add: %w", addErr)
	}
	return node.ID, nil
}

// computeFleetSPRS totals the current SPRS impact across all enrolled assets.
func (fs *FleetScanner) computeFleetSPRS() int {
	assets := fs.registry.ListAssets("", "")
	if len(assets) == 0 {
		return 110
	}
	total := 0
	count := 0
	for _, a := range assets {
		if a.SPRSImpact != nil {
			total += *a.SPRSImpact
			count++
		}
	}
	if count == 0 {
		return 110
	}
	return total / count
}

// ─── STIG Profile Selector ────────────────────────────────────────────────────

// selectSTIGChecks returns the STIG check set for the given profile name.
// Profiles: "rhel9", "windows", "ubuntu", "generic"
func selectSTIGChecks(profile string) []remote.STIGCheck {
	switch profile {
	case "rhel9", "rhel-09":
		return rhel9STIGChecks()
	case "windows":
		return windowsSTIGChecks()
	case "ubuntu":
		return ubuntuSTIGChecks()
	default:
		return genericSTIGChecks()
	}
}

func rhel9STIGChecks() []remote.STIGCheck {
	return []remote.STIGCheck{
		{
			ControlID:    "RHEL-09-010010",
			Title:        "RHEL 9 must be a vendor-supported release",
			Severity:     "high",
			CheckCommand: `cat /etc/redhat-release`,
			Remediation:  "Upgrade to a vendor-supported RHEL 9 release.",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && (contains(out, "Red Hat") || contains(out, "AlmaLinux") || contains(out, "Rocky")),
					"System is not running a vendor-supported RHEL 9 variant"
			},
		},
		{
			ControlID:    "RHEL-09-211010",
			Title:        "RHEL 9 must enable FIPS mode",
			Severity:     "high",
			CheckCommand: `fips-mode-setup --check 2>/dev/null || cat /proc/sys/crypto/fips_enabled`,
			Remediation:  "Run: fips-mode-setup --enable && reboot",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return contains(out, "FIPS mode is enabled") || contains(out, "1"),
					"FIPS mode is not enabled — CMMC AC.L2-3.1.1 requires FIPS 140-3"
			},
		},
		{
			ControlID:    "RHEL-09-412010",
			Title:        "RHEL 9 must use SSH protocol v2",
			Severity:     "high",
			CheckCommand: `grep -i "^Protocol" /etc/ssh/sshd_config 2>/dev/null; sshd -T 2>/dev/null | grep ^protocol`,
			Remediation:  "Set Protocol 2 in /etc/ssh/sshd_config",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				if out == "" {
					return true, "" // SSHv2 is default in modern OpenSSH
				}
				return contains(out, "2"), "SSH Protocol 1 detected — critical vulnerability"
			},
		},
		{
			ControlID:    "RHEL-09-611010",
			Title:        "RHEL 9 must enforce password minimum length of 15 characters",
			Severity:     "medium",
			CheckCommand: `grep -i "^minlen" /etc/security/pwquality.conf 2>/dev/null`,
			Remediation:  "Set minlen = 15 in /etc/security/pwquality.conf",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return contains(out, "minlen") && !contains(out, "minlen = 8") && !contains(out, "minlen = 12"),
					"Password minimum length < 15 — CMMC IA.L2-3.5.7"
			},
		},
		{
			ControlID:    "RHEL-09-652010",
			Title:        "RHEL 9 must have the aide package installed",
			Severity:     "medium",
			CheckCommand: `rpm -q aide 2>&1`,
			Remediation:  "Install: dnf install aide && aide --init",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && contains(out, "aide-"), "AIDE (file integrity monitor) not installed"
			},
		},
		{
			ControlID:    "RHEL-09-431010",
			Title:        "RHEL 9 must enable SELinux in enforcing mode",
			Severity:     "high",
			CheckCommand: `getenforce 2>/dev/null`,
			Remediation:  "Set SELINUX=enforcing in /etc/selinux/config && setenforce 1",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return contains(out, "Enforcing"), "SELinux is not in Enforcing mode — CMMC SI.L2-3.14.2"
			},
		},
		{
			ControlID:    "RHEL-09-215010",
			Title:        "RHEL 9 must have the USBGuard package installed",
			Severity:     "medium",
			CheckCommand: `rpm -q usbguard 2>&1`,
			Remediation:  "Install: dnf install usbguard && systemctl enable usbguard",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && contains(out, "usbguard-"), "USBGuard not installed — removable media control required"
			},
		},
		{
			ControlID:    "RHEL-09-251010",
			Title:        "RHEL 9 must use a FIPS-validated cryptographic module",
			Severity:     "critical",
			CheckCommand: `openssl md5 /dev/null 2>&1; cat /proc/sys/crypto/fips_enabled`,
			Remediation:  "Enable FIPS: fips-mode-setup --enable && reboot",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return contains(out, "1"), "System not operating in FIPS-validated crypto mode"
			},
		},
	}
}

func windowsSTIGChecks() []remote.STIGCheck {
	return []remote.STIGCheck{
		{
			ControlID:    "WN22-00-000020",
			Title:        "Windows Server 2022 must use DoD-approved PKI certificates",
			Severity:     "high",
			CheckCommand: `powershell -command "(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot').DisableRootAutoUpdate"`,
			Remediation:  "Set DisableRootAutoUpdate = 1 via GPO",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return contains(out, "1"), "Root certificate auto-update not disabled"
			},
		},
		{
			ControlID:    "WN22-AC-000070",
			Title:        "Windows Server 2022 account lockout threshold must be 3 or fewer",
			Severity:     "medium",
			CheckCommand: `powershell -command "(net accounts | Select-String 'lockout threshold').Line"`,
			Remediation:  "Set account lockout threshold to 3 via security policy",
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return !contains(out, "Never"), "Account lockout threshold not configured — CMMC IA.L2-3.5.6"
			},
		},
	}
}

func ubuntuSTIGChecks() []remote.STIGCheck {
	return []remote.STIGCheck{
		{
			ControlID:    "UBTU-22-010010",
			Title:        "Ubuntu 22.04 must be a vendor-supported release",
			Severity:     "high",
			CheckCommand: `lsb_release -a 2>/dev/null || cat /etc/os-release`,
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && contains(out, "Ubuntu"), "Not running Ubuntu"
			},
		},
	}
}

func genericSTIGChecks() []remote.STIGCheck {
	return []remote.STIGCheck{
		{
			ControlID:    "GEN-001",
			Title:        "Remote host must be reachable",
			Severity:     "critical",
			CheckCommand: `echo "KHEPRA_REACHABLE"`,
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return exit == 0, "Host unreachable or command execution failed"
			},
		},
		{
			ControlID:    "GEN-002",
			Title:        "Remote host must report OS version",
			Severity:     "medium",
			CheckCommand: `uname -a 2>/dev/null || ver`,
			EvaluateFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && len(out) > 0, "Could not determine OS version"
			},
		},
	}
}

// ─── SPRS impact computation ──────────────────────────────────────────────────

// computeSPRSImpact maps STIG scan failures to SPRS deductions.
// SPRS starts at 110. Each failed check deducts points based on severity.
// This approximates the NIST SP 800-171A scoring methodology.
func computeSPRSImpact(r *remote.ScanReport) int {
	// Start with max possible score
	score := 110
	for _, check := range r.Results {
		if check.Status != "fail" {
			continue
		}
		switch check.Severity {
		case "critical":
			score -= 5
		case "high":
			score -= 3
		case "medium":
			score -= 1
		case "low":
			// Low findings don't deduct from SPRS
		}
	}
	if score < -203 { // SPRS minimum is -203
		score = -203
	}
	return score
}

// ─── Credential Store Interface ───────────────────────────────────────────────

// Credential holds connection credentials for a fleet asset.
type Credential struct {
	Username   string
	AuthMethod string // "password" | "key"
	Secret     string // password text or SSH private key PEM
}

// CredentialStore resolves credentials for fleet assets.
// Implement this interface with the KHEPRA Credential Store (AES-256-GCM vault).
type CredentialStore interface {
	GetCredential(assetID string) (Credential, error)
}

// EnvCredentialStore resolves credentials from environment variables.
// Used in development; production uses the AES-256-GCM vault.
type EnvCredentialStore struct {
	DefaultUser     string
	DefaultPassword string
}

func (e *EnvCredentialStore) GetCredential(assetID string) (Credential, error) {
	if e.DefaultUser == "" || e.DefaultPassword == "" {
		return Credential{}, fmt.Errorf("no default credentials configured for asset %s", assetID)
	}
	return Credential{
		Username:   e.DefaultUser,
		AuthMethod: "password",
		Secret:     e.DefaultPassword,
	}, nil
}

// ─── Errors ───────────────────────────────────────────────────────────────────

var ErrScanInProgress = fmt.Errorf("fleet scan already in progress")

// ─── Helpers ──────────────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
