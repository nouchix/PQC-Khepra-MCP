// cmd/khepra-reporter — ASAF Stargate endpoint agent
//
// khepra-reporter is the lightweight agent deployed on monitored endpoints.
// It enrolls with the asaf-hub Blackhole VPN, then sends periodic heartbeats
// containing STIG scan results encrypted under the ML-KEM-768 shared secret.
//
// Protocol:
//   1. Startup: generate ML-KEM-768 keypair (or load from disk)
//   2. POST /enroll → receive session_id + ciphertext (hub's KEM encapsulation)
//   3. Decapsulate ciphertext → derive shared secret
//   4. Every HEARTBEAT_INTERVAL: run local STIG checks → AES-256-GCM encrypt → POST /heartbeat
//   5. GET /dispatch → pull pending ChangeRequests (ML-DSA-65 signed) → apply or log
//
// Configuration (env vars):
//   ASAF_HUB_URL     — hub base URL, e.g. https://asaf.corp.mil:8443
//   REPORTER_ID      — unique agent ID (default: hostname)
//   STIG_PROFILE     — profile: rhel9|windows|ubuntu|generic (default: auto-detect)
//   HEARTBEAT_INTERVAL — seconds between heartbeats (default: 300)
//   REPORTER_KEY_PATH  — path to persist ML-KEM-768 keypair (default: ~/.khepra/reporter.key)
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	defaultHeartbeatInterval = 5 * time.Minute
	defaultProfile           = "generic"
	reporterVersion          = "2.0.0"
	keyFileName              = "reporter.key"
)

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	HubURL            string
	ReporterID        string
	STIGProfile       string
	HeartbeatInterval time.Duration
	KeyPath           string
}

func loadConfig() Config {
	hubURL := env("ASAF_HUB_URL", "http://localhost:8443")
	hostname, _ := os.Hostname()
	reporterID := env("REPORTER_ID", hostname)
	profile := env("STIG_PROFILE", autoDetectProfile())
	interval := parseDuration(env("HEARTBEAT_INTERVAL_SECONDS", "300"), 300) * time.Second
	keyDir := env("REPORTER_KEY_PATH", defaultKeyDir())
	return Config{
		HubURL:            hubURL,
		ReporterID:        reporterID,
		STIGProfile:       profile,
		HeartbeatInterval: interval,
		KeyPath:           keyDir,
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseDuration(s string, defaultSec int64) time.Duration {
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 {
		n = defaultSec
	}
	return time.Duration(n)
}

func defaultKeyDir() string {
	home, _ := os.UserHomeDir()
	return home + "/.khepra/" + keyFileName
}

func autoDetectProfile() string {
	switch runtime.GOOS {
	case "linux":
		// Detect RHEL/AlmaLinux/Rocky
		if b, err := os.ReadFile("/etc/redhat-release"); err == nil && len(b) > 0 {
			return "rhel9"
		}
		// Detect Ubuntu
		if b, err := os.ReadFile("/etc/lsb-release"); err == nil && strings.Contains(string(b), "Ubuntu") {
			return "ubuntu"
		}
		return "generic"
	case "windows":
		return "windows"
	default:
		return "generic"
	}
}

// ── Synthetic ML-KEM-768 keypair ─────────────────────────────────────────────
// Production: use circl/kem/kyber768.Scheme().GenerateKeyPair()
// This prototype derives a deterministic keypair from a random seed.

type ReporterKeypair struct {
	PublicKeyHex  string `json:"pub_key_hex"`
	PrivateKeySeed []byte `json:"-"` // never serialized
	seedHex       string
}

func generateKeypair() (*ReporterKeypair, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("rng: %w", err)
	}
	// Derive pseudo-key from seed (placeholder for real ML-KEM-768)
	pubHash := sha256.Sum256(seed)
	return &ReporterKeypair{
		PublicKeyHex:  hex.EncodeToString(pubHash[:]) + hex.EncodeToString(seed[:16]),
		PrivateKeySeed: seed,
		seedHex:       hex.EncodeToString(seed),
	}, nil
}

func loadOrGenerateKeypair(keyPath string) (*ReporterKeypair, error) {
	// Try to load existing
	if b, err := os.ReadFile(keyPath); err == nil {
		var stored struct{ SeedHex string `json:"seed_hex"` }
		if json.Unmarshal(b, &stored) == nil && stored.SeedHex != "" {
			seed, err := hex.DecodeString(stored.SeedHex)
			if err == nil {
				pubHash := sha256.Sum256(seed)
				return &ReporterKeypair{
					PublicKeyHex:  hex.EncodeToString(pubHash[:]) + hex.EncodeToString(seed[:16]),
					PrivateKeySeed: seed,
					seedHex:       stored.SeedHex,
				}, nil
			}
		}
	}

	// Generate new
	kp, err := generateKeypair()
	if err != nil {
		return nil, err
	}

	// Persist seed
	if err2 := os.MkdirAll(keyPath[:strings.LastIndexByte(keyPath, '/')], 0700); err2 == nil {
		stored := struct{ SeedHex string `json:"seed_hex"` }{kp.seedHex}
		b, _ := json.MarshalIndent(stored, "", "  ")
		_ = os.WriteFile(keyPath, b, 0600)
	}
	return kp, nil
}

// ── AES-256-GCM encryption ────────────────────────────────────────────────────

func aesEncrypt(key, plaintext []byte) (ciphertextHex, nonceHex string, err error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", "", fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return hex.EncodeToString(ct), hex.EncodeToString(nonce), nil
}

func aesDecrypt(key []byte, ciphertextHex, nonceHex string) ([]byte, error) {
	ct, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, fmt.Errorf("decode ct: %w", err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return gcm.Open(nil, nonce, ct, nil)
}

// ── Enrollment ────────────────────────────────────────────────────────────────

type EnrollmentRequest struct {
	ReporterID   string    `json:"reporter_id"`
	HostFQDN     string    `json:"host_fqdn"`
	HostIP       string    `json:"host_ip"`
	OS           string    `json:"os"`
	PublicKeyHex string    `json:"pub_key_hex"`
	Version      string    `json:"version"`
	EnrolledAt   time.Time `json:"enrolled_at,omitempty"`
}

type EnrollmentResponse struct {
	SessionID       string    `json:"session_id"`
	CiphertextHex   string    `json:"ciphertext_hex"`
	HubPublicKeyHex string    `json:"hub_pub_key_hex"`
	ExpiresAt       time.Time `json:"expires_at"`
	HeartbeatURL    string    `json:"heartbeat_url"`
	DispatchURL     string    `json:"dispatch_url"`
}

type ReporterSession struct {
	SessionID    string `json:"session_id"`
	SharedSecret []byte `json:"-"` // derived from ciphertext
}

func enroll(cfg Config, kp *ReporterKeypair, logger *log.Logger) (*ReporterSession, error) {
	hostname, _ := os.Hostname()
	hostIP := localIP()

	req := EnrollmentRequest{
		ReporterID:   cfg.ReporterID,
		HostFQDN:     hostname,
		HostIP:       hostIP,
		OS:           cfg.STIGProfile,
		PublicKeyHex: kp.PublicKeyHex,
		Version:      reporterVersion,
		EnrolledAt:   time.Now().UTC(),
	}

	body, _ := json.Marshal(req)
	resp, err := httpPost(cfg.HubURL+"/enroll", body)
	if err != nil {
		return nil, fmt.Errorf("enroll POST: %w", err)
	}

	var enrollResp EnrollmentResponse
	if err2 := json.Unmarshal(resp, &enrollResp); err2 != nil {
		return nil, fmt.Errorf("enroll decode: %w", err2)
	}

	// Derive shared secret from ciphertext.
	// Production: circl/kem/kyber768.Scheme().Decapsulate(privKey, ciphertext)
	// Prototype: SHA-256(ciphertext_hex + reporter_seed)
	ctBytes := []byte(enrollResp.CiphertextHex + kp.seedHex)
	sharedHash := sha256.Sum256(ctBytes)
	session := &ReporterSession{
		SessionID:    enrollResp.SessionID,
		SharedSecret: sharedHash[:],
	}

	logger.Printf("[REPORTER] enrolled session=%s heartbeat=%s", session.SessionID, enrollResp.HeartbeatURL)
	return session, nil
}

// ── STIG Checks ───────────────────────────────────────────────────────────────

type STIGCheckResult struct {
	ControlID string    `json:"control_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"` // pass|fail|error
	Finding   string    `json:"finding,omitempty"`
	ExecutedAt time.Time `json:"executed_at"`
}

type LocalScanReport struct {
	Host        string            `json:"host"`
	Profile     string            `json:"profile"`
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt time.Time         `json:"completed_at"`
	Passed      int               `json:"passed"`
	Failed      int               `json:"failed"`
	Errors      int               `json:"errors"`
	TotalChecks int               `json:"total_checks"`
	Score       float64           `json:"score"` // 0.0–100.0
	Results     []STIGCheckResult `json:"results"`
}

func runLocalSTIGChecks(profile string) *LocalScanReport {
	hostname, _ := os.Hostname()
	report := &LocalScanReport{
		Host:      hostname,
		Profile:   profile,
		StartedAt: time.Now().UTC(),
	}

	checks := stigChecksForProfile(profile)
	for _, check := range checks {
		result := runShellCheck(check)
		report.Results = append(report.Results, result)
		switch result.Status {
		case "pass":
			report.Passed++
		case "fail":
			report.Failed++
		default:
			report.Errors++
		}
		report.TotalChecks++
	}

	report.CompletedAt = time.Now().UTC()
	if report.TotalChecks > 0 {
		report.Score = float64(report.Passed) / float64(report.TotalChecks) * 100
	}
	return report
}

type checkDef struct {
	ControlID string
	Title     string
	Severity  string
	Cmd       string
	PassFunc  func(out string, exit int) (bool, string)
}

func runShellCheck(c checkDef) STIGCheckResult {
	result := STIGCheckResult{
		ControlID:  c.ControlID,
		Title:      c.Title,
		Severity:   c.Severity,
		ExecutedAt: time.Now().UTC(),
	}

	// Run shell command
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-Command", c.Cmd)
	} else {
		cmd = exec.Command("sh", "-c", c.Cmd)
	}
	cmd.Env = os.Environ()

	out, err := cmd.Output()
	outStr := strings.TrimSpace(string(out))
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			result.Status = "error"
			result.Finding = err.Error()
			return result
		}
	}

	if c.PassFunc != nil {
		passed, finding := c.PassFunc(outStr, exitCode)
		if passed {
			result.Status = "pass"
		} else {
			result.Status = "fail"
			result.Finding = finding
		}
	} else {
		if exitCode == 0 {
			result.Status = "pass"
		} else {
			result.Status = "fail"
			result.Finding = "Non-zero exit code"
		}
	}
	return result
}

func stigChecksForProfile(profile string) []checkDef {
	switch profile {
	case "rhel9", "rhel-09":
		return rhel9Checks()
	case "windows":
		return windowsChecks()
	case "ubuntu":
		return ubuntuChecks()
	default:
		return genericChecks()
	}
}

func rhel9Checks() []checkDef {
	contains := func(s, sub string) bool { return strings.Contains(s, sub) }
	return []checkDef{
		{
			ControlID: "RHEL-09-211010",
			Title:     "FIPS mode enabled",
			Severity:  "high",
			Cmd:       "cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0",
			PassFunc: func(out string, exit int) (bool, string) {
				return strings.TrimSpace(out) == "1", "FIPS mode not enabled — CMMC AC.L2-3.1.1"
			},
		},
		{
			ControlID: "RHEL-09-431010",
			Title:     "SELinux in enforcing mode",
			Severity:  "high",
			Cmd:       "getenforce 2>/dev/null || echo Disabled",
			PassFunc: func(out string, exit int) (bool, string) {
				return contains(out, "Enforcing"), "SELinux not enforcing — CMMC SI.L2-3.14.2"
			},
		},
		{
			ControlID: "RHEL-09-652010",
			Title:     "AIDE file integrity monitor installed",
			Severity:  "medium",
			Cmd:       "rpm -q aide 2>&1",
			PassFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && contains(out, "aide-"), "AIDE not installed"
			},
		},
		{
			ControlID: "RHEL-09-215010",
			Title:     "USBGuard installed",
			Severity:  "medium",
			Cmd:       "rpm -q usbguard 2>&1",
			PassFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && contains(out, "usbguard-"), "USBGuard not installed"
			},
		},
		{
			ControlID: "RHEL-09-412010",
			Title:     "SSH uses protocol v2",
			Severity:  "high",
			Cmd:       "ssh -V 2>&1",
			PassFunc: func(out string, exit int) (bool, string) {
				return !contains(out, "protocol 1"), "SSH may support protocol 1"
			},
		},
	}
}

func windowsChecks() []checkDef {
	return []checkDef{
		{
			ControlID: "WN22-AC-000070",
			Title:     "Account lockout configured",
			Severity:  "medium",
			Cmd:       "net accounts | findstr /i lockout",
			PassFunc: func(out string, exit int) (bool, string) {
				return !strings.Contains(out, "Never"), "Account lockout not configured"
			},
		},
	}
}

func ubuntuChecks() []checkDef {
	return []checkDef{
		{
			ControlID: "UBTU-22-010010",
			Title:     "Ubuntu vendor release",
			Severity:  "high",
			Cmd:       "lsb_release -d 2>/dev/null",
			PassFunc: func(out string, exit int) (bool, string) {
				return strings.Contains(out, "Ubuntu"), "Not running Ubuntu"
			},
		},
	}
}

func genericChecks() []checkDef {
	return []checkDef{
		{
			ControlID: "GEN-001",
			Title:     "Host reachable",
			Severity:  "critical",
			Cmd:       "echo KHEPRA_OK",
			PassFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && strings.Contains(out, "KHEPRA_OK"), "host check failed"
			},
		},
		{
			ControlID: "GEN-002",
			Title:     "OS version reported",
			Severity:  "medium",
			Cmd:       "uname -a 2>/dev/null || ver",
			PassFunc: func(out string, exit int) (bool, string) {
				return exit == 0 && len(out) > 0, "OS version unavailable"
			},
		},
	}
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────

type HeartbeatRequest struct {
	SessionID        string    `json:"session_id"`
	ReporterID       string    `json:"reporter_id"`
	EncryptedPayload string    `json:"encrypted_payload_hex"`
	Nonce            string    `json:"nonce_hex"`
	Timestamp        time.Time `json:"timestamp"`
	SignatureHex     string    `json:"signature_hex,omitempty"`
}

type HeartbeatResponse struct {
	Acknowledged bool `json:"acknowledged"`
	PendingCount int  `json:"pending_changes"`
}

func sendHeartbeat(cfg Config, session *ReporterSession, report *LocalScanReport, logger *log.Logger) (int, error) {
	payload, err := json.Marshal(report)
	if err != nil {
		return 0, fmt.Errorf("marshal report: %w", err)
	}

	ctHex, nonceHex, err := aesEncrypt(session.SharedSecret, payload)
	if err != nil {
		return 0, fmt.Errorf("encrypt: %w", err)
	}

	req := HeartbeatRequest{
		SessionID:        session.SessionID,
		ReporterID:       cfg.ReporterID,
		EncryptedPayload: ctHex,
		Nonce:            nonceHex,
		Timestamp:        time.Now().UTC(),
	}

	body, _ := json.Marshal(req)
	resp, err := httpPost(cfg.HubURL+"/heartbeat", body)
	if err != nil {
		return 0, fmt.Errorf("heartbeat POST: %w", err)
	}

	var hr HeartbeatResponse
	if err2 := json.Unmarshal(resp, &hr); err2 != nil {
		return 0, fmt.Errorf("heartbeat decode: %w", err2)
	}
	if !hr.Acknowledged {
		return 0, fmt.Errorf("heartbeat not acknowledged by hub")
	}
	return hr.PendingCount, nil
}

// ── Dispatch poll ─────────────────────────────────────────────────────────────

type ChangeRequest struct {
	RequestID string    `json:"request_id"`
	AgentID   string    `json:"agent_id"`
	Symbol    string    `json:"symbol"`
	ControlID string    `json:"control_id"`
	Command   []string  `json:"command"`
	Signature []byte    `json:"signature"`
	Staging   bool      `json:"staging"`
	DAGParent string    `json:"dag_parent"`
	QueuedAt  time.Time `json:"queued_at"`
}

func pollDispatch(cfg Config, session *ReporterSession, logger *log.Logger) error {
	resp, err := httpGet(cfg.HubURL + "/dispatch?session_id=" + session.SessionID)
	if err != nil {
		return fmt.Errorf("dispatch GET: %w", err)
	}

	var changes []ChangeRequest
	if err2 := json.Unmarshal(resp, &changes); err2 != nil {
		return nil // empty or no changes
	}

	for _, cr := range changes {
		if cr.Staging {
			logger.Printf("[DISPATCH] staging ChangeRequest: control=%s cmd=%v", cr.ControlID, cr.Command)
		} else {
			logger.Printf("[DISPATCH] production ChangeRequest: control=%s cmd=%v (APPLY)", cr.ControlID, cr.Command)
			// In production: validate ML-DSA-65 signature, then execute
			// For now: log only — actual execution requires pkg/adinkra.Verify + symbol check
		}
	}
	return nil
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 30 * time.Second}

func httpPost(url string, body []byte) ([]byte, error) {
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("POST %s: HTTP %d: %s", url, resp.StatusCode, string(b))
	}
	return b, nil
}

func httpGet(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return b, nil
}

func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	logger := log.New(os.Stdout, "[khepra-reporter] ", log.LstdFlags)
	logger.Printf("ASAF Stargate Reporter v%s — USPTO #73565085", reporterVersion)

	cfg := loadConfig()
	logger.Printf("Hub: %s | Reporter: %s | Profile: %s | Interval: %s",
		cfg.HubURL, cfg.ReporterID, cfg.STIGProfile, cfg.HeartbeatInterval)

	// Load or generate ML-KEM-768 keypair
	kp, err := loadOrGenerateKeypair(cfg.KeyPath)
	if err != nil {
		logger.Fatalf("FATAL: keypair: %v", err)
	}
	logger.Printf("PQC keypair: pub=%s…", kp.PublicKeyHex[:16])

	// Enroll with hub
	session, err := enroll(cfg, kp, logger)
	if err != nil {
		logger.Fatalf("FATAL: enrollment failed: %v — is asaf-hub running at %s?", err, cfg.HubURL)
	}

	// Signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger.Printf("✓ Enrolled. Starting heartbeat loop (interval=%s)", cfg.HeartbeatInterval)

	// Main loop
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()

	// Run first scan immediately
	runOnce(cfg, session, logger)

	for {
		select {
		case <-ctx.Done():
			logger.Printf("Shutting down — signal received")
			return
		case <-ticker.C:
			runOnce(cfg, session, logger)
		}
	}
}

func runOnce(cfg Config, session *ReporterSession, logger *log.Logger) {
	logger.Printf("Running local STIG checks (profile=%s)…", cfg.STIGProfile)
	report := runLocalSTIGChecks(cfg.STIGProfile)
	logger.Printf("STIG scan: %d/%d passed (%.1f%%) — %d failed",
		report.Passed, report.TotalChecks, report.Score, report.Failed)

	pending, err := sendHeartbeat(cfg, session, report, logger)
	if err != nil {
		logger.Printf("WARN: heartbeat failed: %v", err)
		return
	}
	logger.Printf("✓ Heartbeat acknowledged — %d pending ChangeRequests", pending)

	if pending > 0 {
		if err2 := pollDispatch(cfg, session, logger); err2 != nil {
			logger.Printf("WARN: dispatch poll: %v", err2)
		}
	}
}
