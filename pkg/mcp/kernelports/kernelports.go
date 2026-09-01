package kernelports

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
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

type Deps struct {
	Attestor Attestor
	License  LicenseChecker
	Flight   FlightRecorder
	Logger   Logger
	Signer   Signer
}

func Defaults() Deps {
	key := os.Getenv("KHEPRA_LICENSE_KEY")
	return Deps{
		Attestor: &NoopAttestor{},
		License:  &CommercialLicense{Key: key},
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
	communityTools := map[string]bool{
		"pqc_stig": true, "discover_assets": true, "nist_map": true, "threat_lookup": true,
		"ouroboros_waf_eye": true, "ouroboros_vuln_eye": true, "ouroboros_fim_eye": true,
		"enumerate_host": true, "pqc_sign": true, "pqc_verify": true, "pqc_keygen": true,
		"agent_record": true, "kasa_status": true, "dag_query": true, "fingerprint_device": true,
		"khepra_query_stig": true, "khepra_query_threat_intel": true, "khepra_get_dag_chain": true,
	}

	proTools := map[string]bool{
		"khepra_get_compliance_score": true, "nhi_inventory": true, "acp_status": true,
		"scan_shadow_ai": true, "attest_ai_policy": true, "ert_crypto": true,
		"godfather_report": true, "godfather_approve": true, "khepra_export_attestation": true,
		"flight_export": true, "attest_export": true, "forensic_snapshot": true,
		"fim_baseline": true, "ir_incident": true, "ir_add_ioc": true, "attack_graph": true,
		"drbc_backup": true, "drbc_restore": true, "audit_dag_integrity": true,
		"ea_evolve": true, "ea_risk_summary": true, "drift_detect": true, "sbom_generate": true,
		"khepra_watch": true,
	}

	// 1. Community tools are always FREE (no key required)
	if communityTools[toolName] {
		return nil
	}

	// 2. If Pro/Sovereign Tool, check for valid PRO-/ENT- or kphr_sov_/kphr_pha_ key
	if proTools[toolName] {
		if len(l.Key) >= 4 && l.Key[:4] == "PRO-" { return nil }
		if len(l.Key) >= 4 && l.Key[:4] == "ENT-" { return nil }
		if len(l.Key) >= 9 && l.Key[:9] == "kphr_sov_" { return nil }
		if len(l.Key) >= 9 && l.Key[:9] == "kphr_pha_" { return nil }
		return fmt.Errorf("Pro/Sovereign license ($99/mo) required to run `%s`.\n\n🔒 Unlock instantly: [Upgrade via Stripe Checkout](https://buy.stripe.com/test_upgrade_link)\nOr set KHEPRA_LICENSE_KEY=kphr_sov_... in your environment.", toolName)
	}

	// 3. Enterprise / Sovereign tools require ENT- or kphr_pha_ keys
	if len(l.Key) >= 4 && l.Key[:4] == "ENT-" { return nil }
	if len(l.Key) >= 9 && l.Key[:9] == "kphr_pha_" { return nil }
	return fmt.Errorf("Enterprise license ($499/mo) required to run `%s`.\n\n🔒 Unlock full 110-control CMMC/STIG gap analysis & POAM export: [Contact Sales / Upgrade](https://souhimbou.ai/pricing)\nOr set KHEPRA_LICENSE_KEY=kphr_pha_... in your environment.", toolName)
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
