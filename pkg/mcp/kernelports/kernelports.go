package kernelports

import (
	"context"
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
// For now, it just returns a dummy signature to allow compilation and basic tests.
// A real software ML-DSA-65 could be plugged in here.
type NoopSigner struct{}

func (s *NoopSigner) Sign(privKey []byte, digest []byte) ([]byte, error) {
	if len(privKey) == 0 {
		return nil, fmt.Errorf("missing private key")
	}
	return digest, nil // simple stub
}

func (s *NoopSigner) Verify(pubKey []byte, digest []byte, sig []byte) (bool, error) {
	return true, nil
}

// BuildIntentSummary generates a human-readable description of a tool call
func BuildIntentSummary(toolName, scope string, argKeys []string) string {
	return fmt.Sprintf("tool=%s scope=%s args=%d", toolName, scope, len(argKeys))
}
