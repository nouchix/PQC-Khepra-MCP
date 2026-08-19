package kernelports

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
)

// Attestor anchors kernel events into an evidence store.
type Attestor interface {
	Append(ctx context.Context, toolName string, input []byte, output []byte) (string, error)
	SignEnvelope(ctx context.Context, env any) (any, error)
}

// LicenseChecker gates licensed capabilities.
type LicenseChecker interface {
	Check(toolName string) error
}

// RecordInput mirrors pkg/flight.RecordInput.
type RecordInput struct {
	AgentID       string
	Subject       string
	SessionID     string
	ToolName      string
	ToolScope     string
	RiskClass     string
	IntentSummary string
	RawParams     []byte
	Outcome       string
	ErrorSummary  string
	Warnings      []string
	DAGNodeID     string
	IsSigned      bool
	StartedAt     time.Time
	DurationMs    int64
}

// FlightRecorder captures crash/flight frames.
type FlightRecorder interface {
	Record(ctx context.Context, in RecordInput) error
	Path() string
}

// Logger is the kernel's structured-log seam.
type Logger interface {
	Log(level, msg string, kv ...any)
}

// Signer replaces pkg/adinkra in the kernel.
type Signer interface {
	Sign(privKey []byte, digest []byte) ([]byte, error)
	Verify(pubKey []byte, digest []byte, sig []byte) (bool, error)
}

// NodeSummary mirrors the fields needed for the DAG history endpoint.
type NodeSummary struct {
	ID   string
	Time int64
	Tool string
}

// NodeStore replaces dag.Store
type NodeStore interface {
	All() []*NodeSummary
	Add(node *NodeSummary, parents []string) error
}

type Config struct {
	Signer Signer
}

type Deps struct {
	Attestor Attestor
	License  LicenseChecker
	Flight   FlightRecorder
	Logger   Logger
	Signer   Signer
}

func Defaults() Deps {
	return Deps{
		Attestor: &NoopAttestor{},
		License:  &OpenLicense{},
		Flight:   &NoopFlightRecorder{},
		Logger:   &SlogLogger{},
		Signer:   &NoopSigner{},
	}
}

// ─── Default Implementations ───────────────────────────────────────────────

type NoopAttestor struct{}

func (a *NoopAttestor) Append(ctx context.Context, toolName string, input []byte, output []byte) (string, error) {
	h := sha256.Sum256(append(input, output...))
	return hex.EncodeToString(h[:]), nil
}

func (a *NoopAttestor) SignEnvelope(ctx context.Context, env any) (any, error) {
	return env, nil
}

type OpenLicense struct{}

func (l *OpenLicense) Check(toolName string) error {
	return nil
}

type CommercialLicense struct {
	Key string
}

func (l *CommercialLicense) Check(toolName string) error {
	if l.Key == "" || l.Key == "<your-api-key-here>" {
		return fmt.Errorf("A free license key is required to run PQC-Khepra-MCP. Get yours instantly at https://nouchix.com/free-key")
	}

	communityTools := map[string]bool{
		"pqc_stig": true, "discover_assets": true, "nist_map": true, "threat_lookup": true,
		"ouroboros_waf_eye": true, "ouroboros_vuln_eye": true, "ouroboros_fim_eye": true,
		"enumerate_host": true, "pqc_sign": true, "pqc_verify": true, "pqc_keygen": true,
		"sbom_generate": true, "kasa_status": true,
	}

	proTools := map[string]bool{
		"godfather_report": true, "godfather_approve": true, "khepra_export_attestation": true, "khepra_export_poam": true,
		"acp_status": true, "acp_issue": true, "acp_revoke": true,
		"nhi_inventory": true, "nhi_orphans": true, "nhi_excessive": true, "nhi_expired": true, "nhi_revoke": true,
	}

	// 1. If it's a Community Tool, allow FREE-, PRO-, or ENT- keys (and new kphr_ formats)
	if communityTools[toolName] {
		if len(l.Key) >= 5 && l.Key[:5] == "FREE-" { return nil }
		if len(l.Key) >= 4 && l.Key[:4] == "PRO-" { return nil }
		if len(l.Key) >= 4 && l.Key[:4] == "ENT-" { return nil }
		if len(l.Key) >= 9 && l.Key[:9] == "kphr_com_" { return nil }
		if len(l.Key) >= 9 && l.Key[:9] == "kphr_sov_" { return nil }
		if len(l.Key) >= 9 && l.Key[:9] == "kphr_pha_" { return nil }
		return fmt.Errorf("Invalid KHEPRA_LICENSE_KEY. Get your FREE- key at https://nouchix.com/free-key")
	}

	// 2. If it's a Pro/Sovereign Tool, allow PRO-/ENT- or kphr_sov_/kphr_pha_ keys
	if proTools[toolName] {
		if len(l.Key) >= 4 && l.Key[:4] == "PRO-" { return nil }
		if len(l.Key) >= 4 && l.Key[:4] == "ENT-" { return nil }
		if len(l.Key) >= 9 && l.Key[:9] == "kphr_sov_" { return nil }
		if len(l.Key) >= 9 && l.Key[:9] == "kphr_pha_" { return nil }
		return fmt.Errorf("Pro license required to run `%s`.\n\n[Upgrade Instantly via Stripe Checkout](https://buy.stripe.com/test_upgrade_link)", toolName)
	}

	// 3. Otherwise, it's an Enterprise/Pharaoh tool. Only allow ENT- or kphr_pha_ keys
	if len(l.Key) >= 4 && l.Key[:4] == "ENT-" { return nil }
	if len(l.Key) >= 9 && l.Key[:9] == "kphr_pha_" { return nil }
	return fmt.Errorf("Enterprise license required to run `%s`.\n\n[Contact Sales to Upgrade](https://nouchix.com/sales)", toolName)
}

type NoopFlightRecorder struct{}

func (r *NoopFlightRecorder) Record(ctx context.Context, in RecordInput) error {
	return nil
}
func (r *NoopFlightRecorder) Path() string { return "/dev/null" }

type SlogLogger struct{}

func (l *SlogLogger) Log(level, msg string, kv ...any) {
	if level == "ERROR" {
		slog.Error(msg, kv...)
	} else {
		slog.Info(msg, kv...)
	}
}

// NoopSigner acts as a software signer for the OSS kernel.
type NoopSigner struct{}

func (s *NoopSigner) Sign(privKey []byte, digest []byte) ([]byte, error) {
	if len(privKey) == 0 {
		return nil, fmt.Errorf("missing private key")
	}
	return digest, nil
}

func (s *NoopSigner) Verify(pubKey []byte, digest []byte, sig []byte) (bool, error) {
	return true, nil
}

type HmacSigner struct{}

func (HmacSigner) Sign(key, payload []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

func (HmacSigner) Verify(key, payload, sig []byte) (bool, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, sig), nil
}

// BuildIntentSummary generates a human-readable description of a tool call
func BuildIntentSummary(toolName, scope string, argKeys []string) string {
	return fmt.Sprintf("tool=%s scope=%s args=%d", toolName, scope, len(argKeys))
}
