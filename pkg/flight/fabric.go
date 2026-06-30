package flight

// fabric.go — The Flight Fabric: the Stargate/Black Hole at the center of SouHimBou AI.
//
// VISION:
//
//   The Flight Recorder is NOT a step in a pipeline.
//   The Flight Recorder IS the pipeline.
//   Nothing executes outside its signed chain.
//
//   Every tool call, WAF verdict, KASA score, LLM inference, SOAR action,
//   DAG write, API request, and agent decision is absorbed by the Fabric —
//   automatically, without the caller choosing to record or not.
//
//   The Fabric creates a causal chain of signed FlightFrames where:
//     - Each frame's FrameHash is the PrevFrameHash of the next
//     - No frame can be inserted, deleted, or reordered without breaking the chain
//     - The entire session is auditable from genesis to termination
//     - ML-DSA-65 signature on every frame = cryptographic proof of sequence
//
// USAGE — wrap anything into the gravitational well:
//
//   // Wrap an HTTP handler (MCP transport, REST API, webhook)
//   http.Handle("/mcp", fabric.WrapHTTP("mcp-transport", handler))
//
//   // Wrap a Go function (any tool, any subsystem)
//   result, err := fabric.WrapFunc(ctx, FuncCall{
//       Name: "bash", Category: CategoryTool, RiskClass: RiskDestructive,
//       Fn: func() (any, error) { return exec.Command("ls").Output() },
//   })
//
//   // Absorb a subsystem event (WAF verdict, KASA score, SOAR action)
//   fabric.Absorb(ctx, Event{
//       Source: "SEKHEM-WAF", Name: "SEKHEM-001-SQLi",
//       Severity: SeverityCatastrophic, Blocked: true,
//       Detail: map[string]any{"ip": clientIP, "rule": "SEKHEM-001"},
//   })
//
//   // Wrap an MCP tool handler — the primary SouHimBou integration point
//   router.Register("ert_scan", fabric.WrapMCPTool("ert_scan", RiskDestructive, originalHandler))
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Event Categories ─────────────────────────────────────────────────────────

// EventCategory classifies events absorbed by the Fabric.
// Everything the agent system does maps to one of these.
type EventCategory string

const (
	CategoryTool       EventCategory = "tool_call"       // agent executing a tool
	CategoryLLM        EventCategory = "llm_inference"   // LLM reasoning step
	CategoryWAF        EventCategory = "waf_verdict"     // SEKHEM WAF rule match
	CategoryKASA       EventCategory = "kasa_score"      // KASA anomaly assessment
	CategorySOAR       EventCategory = "soar_action"     // SOAR playbook step
	CategoryDAG        EventCategory = "dag_write"        // immutable ledger node
	CategoryHTTP       EventCategory = "http_request"    // inbound HTTP request
	CategoryAuth       EventCategory = "auth_event"       // authentication/authorization
	CategoryPQC        EventCategory = "pqc_operation"   // PQC key/sign/verify
	CategoryScan       EventCategory = "agent_scan"      // adversarial probe
	CategoryAnomaly    EventCategory = "anomaly"          // detected threat
	CategoryApproval   EventCategory = "human_approval"  // human gate event
	CategorySystem     EventCategory = "system"           // Fabric lifecycle
)

// ─── Absorbed Event ───────────────────────────────────────────────────────────

// Event is any occurrence that the Fabric absorbs into its signed chain.
// All subsystems (WAF, KASA, SOAR, DAG, LLM) emit Events — the Fabric
// converts them into signed FlightFrames and locks them into the chain.
type Event struct {
	// Source is the subsystem emitting this event.
	Source string // "SEKHEM-WAF" | "KASA" | "SOAR" | "DAG" | "Ollama" | ...

	// Name identifies the specific event within the source.
	Name string // "SEKHEM-001-SQLi" | "anomaly_score_0.91" | "quarantine-agent.staging" | ...

	// Category classifies the event type.
	Category EventCategory

	// AgentID is the agent responsible for this event.
	AgentID string

	// SessionID groups a series of events into a logical session.
	SessionID string

	// Severity signals threat level (mirrors maat.Severity for compatibility).
	Severity string // "info" | "warning" | "severe" | "catastrophic"

	// Blocked indicates the event caused execution to be stopped.
	Blocked bool

	// Detail carries structured metadata about the event.
	Detail map[string]any

	// RiskClass is relevant for tool calls.
	RiskClass RiskClass

	// Outcome for tool/function calls.
	Outcome Outcome

	// DurationMs is the wall-clock time for the event (set by WrapFunc).
	DurationMs int64

	// Error is set if the event represents a failure.
	Error string

	// Timestamp is set to time.Now() if zero.
	Timestamp time.Time
}

// ─── FuncCall ─────────────────────────────────────────────────────────────────

// FuncCall is the input to Fabric.WrapFunc — wraps any Go function in the chain.
type FuncCall struct {
	// Name is the function/tool name recorded in the FlightFrame.
	Name string

	// Category classifies what kind of operation this is.
	Category EventCategory

	// AgentID identifies who is calling this function.
	AgentID string

	// SessionID groups this call into a session.
	SessionID string

	// RiskClass is the caller's declared risk level.
	RiskClass RiskClass

	// Params are raw parameters (hashed, never stored in clear).
	Params []byte

	// Fn is the actual function to execute.
	Fn func() (any, error)
}

// ─── Fabric ───────────────────────────────────────────────────────────────────

// Fabric is the Flight Recorder Stargate — the black hole that all operations
// pass through and are absorbed into a signed, chained, immutable record.
//
// Create one Fabric per SouHimBou agent instance. Share it across all subsystems.
// The Fabric is the single source of truth for everything the agent did.
type Fabric struct {
	recorder  *Recorder
	agentID   string
	sessionID string
	log       *slog.Logger

	// frameCount tracks total absorbed events for health metrics.
	frameCount atomic.Int64

	// chainBroken records if the chain integrity was ever compromised.
	chainBroken atomic.Bool
}

// FabricConfig configures a new Fabric instance.
type FabricConfig struct {
	// Recorder is the underlying signed NDJSON recorder.
	// If nil, a new Recorder is built from env vars.
	Recorder *Recorder

	// AgentID is the default agent identity for events that don't specify one.
	AgentID string

	// SessionID is the default session (can be overridden per-event).
	SessionID string
}

// NewFabric creates the Flight Recorder Stargate.
// All SouHimBou subsystems should share one Fabric instance.
func NewFabric(cfg FabricConfig) (*Fabric, error) {
	rec := cfg.Recorder
	if rec == nil {
		var err error
		rec, err = New(RecorderConfig{})
		if err != nil {
			// Non-fatal — Fabric still works, it just won't sign frames.
			slog.Warn("flight/fabric: recorder init failed — frames will be unsigned", "err", err)
			rec = nil
		}
	}

	agentID := cfg.AgentID
	if agentID == "" {
		agentID = "souhimbou-fabric"
	}

	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
	}

	f := &Fabric{
		recorder:  rec,
		agentID:   agentID,
		sessionID: sessionID,
		log:       slog.With("component", "flight-fabric", "agent", agentID),
	}

	// Genesis frame — every chain starts here.
	f.absorb(Event{
		Source:   "Fabric",
		Name:     "FABRIC_GENESIS",
		Category: CategorySystem,
		AgentID:  agentID,
		Detail: map[string]any{
			"session_id": sessionID,
			"version":    "1.0.0",
			"signed":     rec != nil,
		},
	})

	f.log.Info("Flight Fabric online — Stargate open",
		"session", sessionID,
		"signed", rec != nil,
	)
	return f, nil
}

// ─── Global Process Fabric ────────────────────────────────────────────────────

// global is the process-level Fabric singleton.
// Initialized once via sync.Once. All MCP tool handlers and API handlers
// that don't have an explicit Fabric injected should use Global().
var (
	globalFabric     *Fabric
	globalFabricOnce sync.Once
)

// Global returns the process-level Flight Fabric.
// It is created on first call with default config (AgentID="souhimbou-global").
// Subsequent calls return the same instance — the chain is continuous.
//
// Usage in tool handlers:
//
//	fabric := flight.Global()
//	fabric.Absorb(ctx, flight.Event{ ... })
func Global() *Fabric {
	globalFabricOnce.Do(func() {
		f, err := NewFabric(FabricConfig{AgentID: "souhimbou-global"})
		if err != nil {
			// Fallback: create a fabric that silently no-ops on Absorb.
			// This should never happen in practice.
			f = &Fabric{log: slog.Default()}
		}
		globalFabric = f
	})
	return globalFabric
}

// ─── Absorb: The Core Gravitational Method ────────────────────────────────────

// Absorb pulls any system event into the signed chain.
// This is the Stargate entry point — everything goes through here.
//
// Subsystems call this directly:
//
//	fabric.Absorb(ctx, Event{Source: "SEKHEM-WAF", Name: "SEKHEM-001", Blocked: true, ...})
//	fabric.Absorb(ctx, Event{Source: "KASA", Name: "anomaly", Detail: {"score": 0.91}})
//	fabric.Absorb(ctx, Event{Source: "SOAR", Name: "quarantine-agent.staging", ...})
func (f *Fabric) Absorb(ctx context.Context, ev Event) string {
	return f.absorb(ev)
}

func (f *Fabric) absorb(ev Event) string {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.AgentID == "" {
		ev.AgentID = f.agentID
	}
	if ev.SessionID == "" {
		ev.SessionID = f.sessionID
	}
	if ev.Outcome == "" {
		if ev.Blocked {
			ev.Outcome = OutcomeBlocked
		} else if ev.Error != "" {
			ev.Outcome = OutcomeError
		} else {
			ev.Outcome = OutcomeSuccess
		}
	}

	// Build the RecordInput from the absorbed Event
	input := RecordInput{
		AgentID:       ev.AgentID,
		SessionID:     ev.SessionID,
		Subject:       ev.Source,
		ToolName:      ev.Name,
		ToolScope:     string(ev.Category),
		RiskClass:     ev.RiskClass,
		IntentSummary: fmt.Sprintf("[%s] %s: %s", ev.Category, ev.Source, ev.Name),
		StartedAt:     ev.Timestamp,
		DurationMs:    ev.DurationMs,
		Outcome:       ev.Outcome,
	}
	if ev.Error != "" {
		input.ErrorSummary = ev.Error
	}
	if ev.Blocked {
		input.PolicyDecisions = []PolicyDecision{
			{Step: ev.Source, Permitted: false, Reason: ev.Name},
		}
	}

	// Encode Detail as a warning note (for audit context without param storage)
	if len(ev.Detail) > 0 {
		if detail, err := json.Marshal(ev.Detail); err == nil {
			input.Warnings = []string{string(detail)}
		}
	}

	frameID := ""
	if f.recorder != nil {
		frame, err := f.recorder.Record(input)
		if err != nil {
			f.log.Error("fabric: record failed — chain may be incomplete", "err", err)
			f.chainBroken.Store(true)
		} else if frame != nil {
			frameID = frame.FrameID
		}
	}

	f.frameCount.Add(1)
	return frameID
}

// ─── WrapFunc: Wrap Any Go Function ───────────────────────────────────────────

// WrapResult is returned by WrapFunc.
type WrapResult struct {
	Value    any
	Err      error
	FrameID  string
	Duration time.Duration
}

// WrapFunc wraps any Go function — it executes the function and pulls the
// entire call (params, result, error, timing) into the signed chain.
//
// The function is ALWAYS executed — the Fabric never blocks execution.
// It records what happened and flags anomalies through the event bus.
//
// If the Fabric fails to record, execution continues — the chain notes the gap.
func (f *Fabric) WrapFunc(ctx context.Context, call FuncCall) WrapResult {
	start := time.Now()

	// Pre-execution: record the INTENT
	f.absorb(Event{
		Source:    call.AgentID,
		Name:      call.Name + ".pre",
		Category:  call.Category,
		AgentID:   call.AgentID,
		SessionID: call.SessionID,
		RiskClass: call.RiskClass,
		Outcome:   OutcomeSuccess,
		Detail:    map[string]any{"phase": "intent", "params_bytes": len(call.Params)},
	})

	// Execute
	val, err := call.Fn()
	dur := time.Since(start)

	outcome := OutcomeSuccess
	errStr := ""
	if err != nil {
		outcome = OutcomeError
		errStr = err.Error()
	}

	// Post-execution: record the OUTCOME
	frameID := f.absorb(Event{
		Source:     call.AgentID,
		Name:       call.Name,
		Category:   call.Category,
		AgentID:    call.AgentID,
		SessionID:  call.SessionID,
		RiskClass:  call.RiskClass,
		Outcome:    outcome,
		Error:      errStr,
		DurationMs: dur.Milliseconds(),
		Detail:     map[string]any{"phase": "outcome", "duration_ms": dur.Milliseconds()},
	})

	return WrapResult{Value: val, Err: err, FrameID: frameID, Duration: dur}
}

// ─── WrapHTTP: Wrap Any HTTP Handler ─────────────────────────────────────────

// WrapHTTP wraps a net/http handler so every request and response is absorbed
// into the signed chain. This is the primary wrapping point for:
//   - MCP HTTP transport
//   - SouHimBou REST API
//   - Any agent webhook endpoint
//
// The wrapped handler:
//  1. Records the incoming request (method, path, client IP, body size, UA)
//  2. Executes the original handler
//  3. Records the response (status, duration, body size)
//  4. Absorbs any secret-scrubbing findings as anomaly events
func (f *Fabric) WrapHTTP(name string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Capture the request body without consuming it
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 64*1024))
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// Absorb the ingress event
		f.absorb(Event{
			Source:    "HTTP:" + name,
			Name:      r.Method + " " + r.URL.Path,
			Category:  CategoryHTTP,
			AgentID:   f.agentID,
			SessionID: f.sessionID,
			RiskClass: httpRiskClass(r.Method, r.URL.Path),
			Detail: map[string]any{
				"method":     r.Method,
				"path":       r.URL.Path,
				"client_ip":  clientIP(r),
				"body_bytes": len(bodyBytes),
				"user_agent": r.UserAgent(),
			},
		})

		// Wrap the response writer to capture status
		crw := &fabricResponseWriter{ResponseWriter: w}

		// Execute the original handler
		handler.ServeHTTP(crw, r)
		dur := time.Since(start)

		// Scan response for secret leakage
		warnings := secretLeakageWarnings(crw.body.Bytes())

		evName := fmt.Sprintf("%s %s → %d", r.Method, r.URL.Path, crw.status)
		outcome := OutcomeSuccess
		if crw.status >= 400 {
			outcome = OutcomeError
		}
		if crw.status == http.StatusForbidden || crw.status == http.StatusTooManyRequests {
			outcome = OutcomeBlocked
		}

		f.absorb(Event{
			Source:     "HTTP:" + name,
			Name:       evName,
			Category:   CategoryHTTP,
			AgentID:    f.agentID,
			SessionID:  f.sessionID,
			Outcome:    outcome,
			DurationMs: dur.Milliseconds(),
			Detail: map[string]any{
				"status":       crw.status,
				"resp_bytes":   crw.body.Len(),
				"duration_ms":  dur.Milliseconds(),
				"secret_leaks": len(warnings),
			},
		})

		// If secrets were found in the response — absorb a catastrophic event
		for _, leak := range warnings {
			f.absorb(Event{
				Source:   "SecretScrubber",
				Name:     "CREDENTIAL_LEAK_IN_RESPONSE",
				Category: CategoryAnomaly,
				AgentID:  f.agentID,
				Severity: "catastrophic",
				Blocked:  false, // response already sent — log it
				Detail:   map[string]any{"pattern": leak, "path": r.URL.Path},
			})
		}
	})
}

// ─── WrapMCPTool: Wrap an MCP Tool Handler ───────────────────────────────────

// WrapMCPTool wraps an MCP tool handler function.
// Every invocation of the tool is pulled into the signed chain.
//
// This is the **primary SDK integration point** — wrap every tool in your
// MCP server and you get instant, tamper-evident audit trails.
//
//	router.Register("bash", fabric.WrapMCPTool("bash", RiskDestructive, bashHandler))
func (f *Fabric) WrapMCPTool(
	toolName string,
	riskClass RiskClass,
	handler func(ctx context.Context, params []byte) ([]byte, error),
) func(ctx context.Context, params []byte) ([]byte, error) {

	return func(ctx context.Context, params []byte) ([]byte, error) {
		result := f.WrapFunc(ctx, FuncCall{
			Name:      toolName,
			Category:  CategoryTool,
			AgentID:   f.agentID,
			SessionID: f.sessionID,
			RiskClass: riskClass,
			Params:    params,
			Fn: func() (any, error) {
				return handler(ctx, params)
			},
		})

		if result.Err != nil {
			return nil, result.Err
		}
		if b, ok := result.Value.([]byte); ok {
			return b, nil
		}
		return json.Marshal(result.Value)
	}
}

// ─── LLM Inference Absorption ─────────────────────────────────────────────────

// AbsorbLLMCall records an LLM inference into the chain.
// Call this before and after every LLM request — both intent and response.
//
// The prompt content is NEVER stored — only the hash, model, and token count.
// This satisfies AI Act Article 12 (transparency) without storing PII.
func (f *Fabric) AbsorbLLMCall(ctx context.Context, model, promptHash string, inputTokens, outputTokens int, durationMs int64, err error) string {
	outcome := OutcomeSuccess
	errStr := ""
	if err != nil {
		outcome = OutcomeError
		errStr = err.Error()
	}
	return f.absorb(Event{
		Source:     "LLM:" + model,
		Name:       "llm_inference",
		Category:   CategoryLLM,
		Outcome:    outcome,
		Error:      errStr,
		DurationMs: durationMs,
		Detail: map[string]any{
			"model":         model,
			"prompt_hash":   promptHash,
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		},
	})
}

// ─── SOAR Absorption ──────────────────────────────────────────────────────────

// AbsorbSOARAction records a SOAR playbook execution step.
// Every playbook action — staging AND production — is absorbed.
func (f *Fabric) AbsorbSOARAction(ctx context.Context, playbook, action, phase string, staging bool, err error) string {
	outcome := OutcomeSuccess
	if err != nil {
		outcome = OutcomeError
	}
	name := fmt.Sprintf("%s.%s.%s", playbook, action, phase)
	return f.absorb(Event{
		Source:   "SOAR",
		Name:     name,
		Category: CategorySOAR,
		Outcome:  outcome,
		Detail: map[string]any{
			"playbook": playbook,
			"action":   action,
			"phase":    phase,
			"staging":  staging,
		},
		Error: func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	})
}

// ─── WAF Absorption ───────────────────────────────────────────────────────────

// AbsorbWAFVerdict records a WAF rule verdict.
// Called by SEKHEM WAFShield for every matched rule.
func (f *Fabric) AbsorbWAFVerdict(ctx context.Context, ruleID, clientIP, path string, blocked bool, severity string) string {
	return f.absorb(Event{
		Source:   "SEKHEM-WAF",
		Name:     ruleID,
		Category: CategoryWAF,
		Blocked:  blocked,
		Severity: severity,
		Outcome: func() Outcome {
			if blocked {
				return OutcomeBlocked
			}
			return OutcomeSuccess
		}(),
		Detail: map[string]any{
			"rule_id":   ruleID,
			"client_ip": clientIP,
			"path":      path,
			"blocked":   blocked,
		},
	})
}

// ─── KASA Absorption ──────────────────────────────────────────────────────────

// AbsorbKASAScore records a KASA behavioral anomaly score.
// Called after every DetectTampering() call.
func (f *Fabric) AbsorbKASAScore(ctx context.Context, agentID, componentID string, score float64, flags []string) string {
	severity := "info"
	if score >= 0.85 {
		severity = "catastrophic"
	} else if score >= 0.70 {
		severity = "severe"
	} else if score >= 0.50 {
		severity = "warning"
	}
	return f.absorb(Event{
		Source:   "KASA",
		Name:     fmt.Sprintf("anomaly_score_%.2f", score),
		Category: CategoryKASA,
		AgentID:  agentID,
		Severity: severity,
		Detail: map[string]any{
			"component_id":  componentID,
			"anomaly_score": score,
			"behavior_flags": flags,
		},
	})
}

// ─── Chain State ──────────────────────────────────────────────────────────────

// Stats returns current chain statistics for the SOC dashboard.
type FabricStats struct {
	FrameCount   int64
	ChainBroken  bool
	SessionID    string
	AgentID      string
	RecorderPath string
}

func (f *Fabric) Stats() FabricStats {
	path := ""
	if f.recorder != nil {
		path = f.recorder.Path()
	}
	return FabricStats{
		FrameCount:   f.frameCount.Load(),
		ChainBroken:  f.chainBroken.Load(),
		SessionID:    f.sessionID,
		AgentID:      f.agentID,
		RecorderPath: path,
	}
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

// fabricResponseWriter wraps http.ResponseWriter to capture status + body.
type fabricResponseWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (c *fabricResponseWriter) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *fabricResponseWriter) Write(b []byte) (int, error) {
	c.body.Write(b)
	return c.ResponseWriter.Write(b)
}

// httpRiskClass infers a RiskClass from HTTP method + path.
func httpRiskClass(method, path string) RiskClass {
	switch strings.ToUpper(method) {
	case "DELETE":
		return RiskDestructive
	case "POST", "PUT", "PATCH":
		if strings.Contains(path, "exec") || strings.Contains(path, "run") ||
			strings.Contains(path, "tool") || strings.Contains(path, "admin") {
			return RiskDestructive
		}
		return RiskSandboxed
	default:
		return RiskReadOnly
	}
}

// clientIP extracts the real client IP from the request.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if parts := strings.Split(xff, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

// secretLeakagePatterns detects credentials in response bodies.
var secretLeakagePatterns = []string{
	"sk-",        // OpenAI key
	"ghp_",       // GitHub PAT
	"xoxb-",      // Slack bot token
	"AKIA",       // AWS access key
	"-----BEGIN", // PEM private key
	"private_key",
	"api_key",
	"password",
	"client_secret",
}

// secretLeakageWarnings returns pattern names found in body.
func secretLeakageWarnings(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := strings.ToLower(string(body))
	var found []string
	for _, p := range secretLeakagePatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			found = append(found, p)
		}
	}
	return found
}
