// Package souhimbou — wrapper.go
//
// The AI Agent Security Wrapper — re-implemented to delegate everything
// to the Flight Fabric (pkg/flight/fabric.go).
//
// The Fabric is the black hole. The Wrapper is how you point your agent at it.
//
// Usage (3-line SDK integration):
//
//	// 1. Create the Fabric — the Stargate everything flows through
//	fabric, _ := flight.NewFabric(flight.FabricConfig{AgentID: "my-agent"})
//
//	// 2. Build the SouHimBou Agent (with orchestrator, KASA, WAF, SOAR)
//	agent, _ := souhimbou.New(ctx, souhimbou.Config{...})
//
//	// 3. Wrap: now every tool call is absorbed by the security stack + Fabric
//	wrapper := souhimbou.Wrap(agent, fabric, souhimbou.WrapConfig{...})
//	router.Register("bash", wrapper.InterceptMCPTool("bash", flight.RiskDestructive, bashHandler))
//
// Security intercept chain (in order, all results absorbed by Fabric):
//
//	① SEKHEM WAFShield   — L7 rules (injection/XSS/rate/UA)
//	② KASA              — ML anomaly + behavioral analysis
//	③ PolymorphicEngine — PQC boundary sign (ML-DSA-65)
//	④ Fabric.Absorb()   — everything pulled into the signed chain
//	⑤ [EXECUTE]
//	⑥ SOAR (on anomaly) — staged playbook → human gate
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.
package souhimbou

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/maat"
)

// ─── Tool Call Interface ─────────────────────────────────────────────────────

// ToolCall represents a single agent tool invocation to be intercepted.
type ToolCall struct {
	AgentID   string            // Identity of the calling agent
	SessionID string            // Groups related calls into a session
	ToolName  string            // Tool being invoked (e.g. "bash", "stig_check")
	ToolScope string            // Blast radius classification ("read_only", "system", "network")
	Params    []byte            // Raw params (hashed, never stored)
	RiskClass flight.RiskClass  // Caller-declared risk; may be upgraded by KASA
	StartedAt time.Time         // Call initiation time (zero = time.Now())
	ClientIP  string            // For WAF rate-limiting and geo-velocity
	UserAgent string            // For WAF UA fingerprinting
}

// ToolResult is the outcome of a wrapped tool call.
type ToolResult struct {
	Permitted   bool   // Whether the call was allowed through
	BlockedBy   string // Which security layer blocked (empty if permitted)
	BlockReason string // Human-readable block reason
	FrameID     string // Flight Recorder frame ID for audit references
	DAGNodeID   string // Immutable DAG node ID
	AnomalyScore float64 // KASA anomaly score (0.0 = clean, 1.0 = critical)
	IncidentID  string // Set if a SOAR incident was opened
}

// ─── Wrap Config ──────────────────────────────────────────────────────────────

// WrapConfig configures the agent security wrapper.
type WrapConfig struct {
	AgentID             string // Default agent identity
	TierMinimum         string // "free" | "pro" | "enterprise"
	BlockOnKASACritical bool   // Block execution on KASA score >= threshold (recommended)
	BlockOnWAFHit       bool   // Block on any WAF rule match (recommended)
	PassthroughMode     bool   // Monitor-only: never block, just record
}

func (c *WrapConfig) defaults() {
	if c.AgentID == "" {
		c.AgentID = "unknown-agent"
	}
	if c.TierMinimum == "" {
		c.TierMinimum = "free"
	}
}

// ─── Agent Security Wrapper ───────────────────────────────────────────────────

// Wrapper intercepts every AI agent tool call and runs it through the
// full KHEPRA security stack, with everything absorbed by the Flight Fabric.
//
// Tier behavior:
//   - Free:       Fabric absorbs all events; PassthroughMode=true (no blocking)
//   - Pro:        BlockOnKASACritical + SOAR staging playbooks
//   - Enterprise: Full blocking + human approval gates + SOAR production
type Wrapper struct {
	cfg    WrapConfig
	agent  *Agent
	fabric *flight.Fabric
}

// Wrap creates a security wrapper around a SouHimBou Agent, using the given
// Fabric as the gravitational center of all security events.
func Wrap(a *Agent, fabric *flight.Fabric, cfg WrapConfig) *Wrapper {
	cfg.defaults()
	return &Wrapper{cfg: cfg, agent: a, fabric: fabric}
}

// Intercept runs a tool call through the full KHEPRA security stack.
// All security events (WAF, KASA, PQC, Flight, DAG) are absorbed by the Fabric.
// The caller must check result.Permitted before executing the actual tool.
func (w *Wrapper) Intercept(ctx context.Context, call ToolCall) (ToolResult, error) {
	if call.StartedAt.IsZero() {
		call.StartedAt = time.Now()
	}
	if call.AgentID == "" {
		call.AgentID = w.cfg.AgentID
	}

	result := ToolResult{Permitted: true}

	// ── ① SEKHEM WAFShield ────────────────────────────────────────────────────
	if blocked, reason, ruleID := w.runWAF(ctx, call); blocked {
		// Absorb the WAF verdict into the Fabric chain.
		// isfetReason enriches the audit record with the specific Maat violation type.
		isfetCtx := isfetReason(nil) // baseline: "WAF rule matched"
		w.fabric.AbsorbWAFVerdict(ctx, ruleID, call.ClientIP, "/mcp/tool/"+call.ToolName, true, "catastrophic")

		result.FrameID = w.fabric.Absorb(ctx, flight.Event{
			Source:    "SEKHEM-WAF",
			Name:      reason,
			Category:  flight.CategoryWAF,
			AgentID:   call.AgentID,
			SessionID: call.SessionID,
			Blocked:   true,
			Severity:  "catastrophic",
			RiskClass: call.RiskClass,
			Detail:    map[string]any{"tool": call.ToolName, "rule": ruleID, "isfet": isfetCtx},
		})

		w.agent.publish(AgentEvent{
			ID:       newEventID(),
			Timestamp: time.Now().UTC(),
			AgentID:  call.AgentID,
			Type:     EventAnomaly,
			Symbol:   SymbolEban,
			Severity: "critical",
			Summary:  fmt.Sprintf("WAF BLOCK: %s → %s (%s)", call.AgentID, call.ToolName, reason),
			Detail:   map[string]any{"waf_rule": ruleID, "tool": call.ToolName},
			Signed:   true,
		})

		if !w.cfg.PassthroughMode && w.cfg.BlockOnWAFHit {
			result.Permitted = false
			result.BlockedBy = "SEKHEM-WAFShield"
			result.BlockReason = reason
			return result, nil
		}
	}

	// ── ② KASA DetectTampering ────────────────────────────────────────────────
	anomalyScore, kasaFlags := w.runKASA(call)
	result.AnomalyScore = anomalyScore

	// Always absorb the KASA score — no matter what the result is
	w.fabric.AbsorbKASAScore(ctx, call.AgentID, call.ToolName, anomalyScore, kasaFlags)

	if anomalyScore >= ThreatThresholdCritical {
		// Open SOAR incident
		incident := Incident{
			ID:            newEventID(),
			AgentID:       call.AgentID,
			Score:         ThreatScore{AgentID: call.AgentID, AnomalyScore: anomalyScore, TopReason: kasaFlagsToReason(kasaFlags)},
			OpenedAt:      time.Now().UTC(),
			Status:        IncidentPending,
			Playbook:      "quarantine-agent",
			NeedsApproval: true,
		}
		w.agent.mu.Lock()
		w.agent.incidents = append(w.agent.incidents, incident)
		w.agent.mu.Unlock()
		result.IncidentID = incident.ID

		// Absorb the incident into Fabric
		w.fabric.Absorb(ctx, flight.Event{
			Source:   "KASA",
			Name:     fmt.Sprintf("CRITICAL_ANOMALY_%.2f", anomalyScore),
			Category: flight.CategoryAnomaly,
			AgentID:  call.AgentID,
			Severity: "catastrophic",
			Detail: map[string]any{
				"score":      anomalyScore,
				"flags":      kasaFlags,
				"incident":   incident.ID,
				"tool":       call.ToolName,
			},
		})

		// Absorb SOAR staging action
		go func() {
			err := w.agent.soar.Execute(ctx, incident.Playbook, true)
			w.fabric.AbsorbSOARAction(ctx, incident.Playbook, "execute", "staging", true, err)
		}()

		w.agent.publish(AgentEvent{
			ID:       newEventID(),
			Timestamp: time.Now().UTC(),
			AgentID:  call.AgentID,
			Type:     EventIncident,
			Symbol:   SymbolEban,
			Severity: "critical",
			Summary:  fmt.Sprintf("KASA CRITICAL (%.2f): %s → %s | Incident %s", anomalyScore, call.AgentID, call.ToolName, incident.ID),
			Detail:   map[string]any{"score": anomalyScore, "flags": kasaFlags, "incident": incident.ID},
			Signed:   true,
		})

		if !w.cfg.PassthroughMode && w.cfg.BlockOnKASACritical {
			result.Permitted = false
			result.BlockedBy = "KASA"
			result.BlockReason = fmt.Sprintf("anomaly score %.2f >= critical threshold", anomalyScore)
			return result, nil
		}
	} else if anomalyScore >= ThreatThresholdHigh {
		go func() {
			err := w.agent.soar.Execute(ctx, "rate-limit-agent", true)
			w.fabric.AbsorbSOARAction(ctx, "rate-limit-agent", "execute", "staging", true, err)
		}()
	}

	// ── ③ PolymorphicEngine PQC sign ─────────────────────────────────────────
	if w.agent.orch != nil && w.agent.orch.Poly != nil {
		payload, _ := json.Marshal(map[string]any{
			"agent": call.AgentID, "tool": call.ToolName,
			"ts": call.StartedAt.UnixNano(), "risk": call.RiskClass,
		})
		if _, err := w.agent.orch.WrapRequest(payload, call.AgentID); err != nil {
			w.agent.log.Warn("polymorphic wrap failed — proceeding unsigned", "err", err)
		}
		w.fabric.Absorb(ctx, flight.Event{
			Source:   "PolymorphicEngine",
			Name:     "PQC_BOUNDARY_SIGN",
			Category: flight.CategoryPQC,
			AgentID:  call.AgentID,
			Detail:   map[string]any{"tool": call.ToolName, "algo": "ML-DSA-65"},
		})
	}

	// ── ④ Fabric absorbs the permitted tool call ──────────────────────────────
	fid := w.fabric.Absorb(ctx, flight.Event{
		Source:    call.AgentID,
		Name:      call.ToolName,
		Category:  flight.CategoryTool,
		AgentID:   call.AgentID,
		SessionID: call.SessionID,
		RiskClass: call.RiskClass,
		Outcome:   flight.OutcomeSuccess,
		Detail: map[string]any{
			"tool":          call.ToolName,
			"scope":         call.ToolScope,
			"anomaly_score": anomalyScore,
			"permitted":     true,
		},
	})
	result.FrameID = fid

	// ── ⑤ DAG attestation ────────────────────────────────────────────────────
	if w.agent.orch != nil && w.agent.orch.DAG != nil {
		node := &dag.Node{
			Action: "AGENT_TOOL_CALL",
			Symbol: string(SymbolNkyinkyim),
			Time:   time.Now().Format(time.RFC3339),
			PQC: map[string]string{
				"agent":         call.AgentID,
				"tool":          call.ToolName,
				"frame_id":      fid,
				"anomaly_score": fmt.Sprintf("%.4f", anomalyScore),
			},
		}
		if err := w.agent.orch.DAG.Add(node, nil); err == nil {
			result.DAGNodeID = node.ID
		}
	}

	// ── ⑥ SSE event ──────────────────────────────────────────────────────────
	w.agent.publish(AgentEvent{
		ID:       newEventID(),
		Timestamp: time.Now().UTC(),
		AgentID:  call.AgentID,
		Type:     EventToolCall,
		Symbol:   SymbolNkyinkyim,
		Severity: riskToSeverity(call.RiskClass),
		Summary:  fmt.Sprintf("%s → %s [permitted, frame=%s]", call.AgentID, call.ToolName, fid),
		Detail: map[string]any{
			"tool": call.ToolName, "frame_id": fid,
			"anomaly_score": anomalyScore, "dag_node": result.DAGNodeID,
		},
		Signed: true,
	})

	return result, nil
}

// ─── WrapHTTP: Delegate to Fabric ─────────────────────────────────────────────

// WrapHTTP wraps an HTTP handler through the Fabric.
// The Fabric records every request and response in the signed chain.
func (w *Wrapper) WrapHTTP(name string, handler http.Handler) http.Handler {
	return w.fabric.WrapHTTP(name, handler)
}

// ─── InterceptMCPTool: Delegate to Fabric ─────────────────────────────────────

// InterceptMCPTool wraps an MCP tool handler through both the security stack
// and the Fabric. Everything is absorbed — intent, execution, outcome.
func (w *Wrapper) InterceptMCPTool(
	toolName string,
	riskClass flight.RiskClass,
	handler func(ctx context.Context, params []byte) ([]byte, error),
) func(ctx context.Context, params []byte) ([]byte, error) {

	// Wrap through the Fabric first (Stargate) — this records intent + outcome
	fabricWrapped := w.fabric.WrapMCPTool(toolName, riskClass, handler)

	// Then wrap through the security stack (WAF + KASA + SOAR)
	return func(ctx context.Context, params []byte) ([]byte, error) {
		// Security pre-check
		call := ToolCall{
			AgentID:   w.cfg.AgentID,
			ToolName:  toolName,
			ToolScope: toolName,
			RiskClass: riskClass,
			Params:    params,
			StartedAt: time.Now(),
		}
		result, err := w.Intercept(ctx, call)
		if err != nil {
			return nil, fmt.Errorf("souhimbou wrapper: %w", err)
		}
		if !result.Permitted {
			// Absorb the block into the Fabric
			w.fabric.Absorb(ctx, flight.Event{
				Source:   "Wrapper",
				Name:     "TOOL_BLOCKED_" + toolName,
				Category: flight.CategoryTool,
				AgentID:  w.cfg.AgentID,
				Blocked:  true,
				RiskClass: riskClass,
				Detail: map[string]any{
					"tool":         toolName,
					"blocked_by":   result.BlockedBy,
					"block_reason": result.BlockReason,
				},
			})
			return nil, fmt.Errorf("souhimbou: tool %q blocked by %s: %s",
				toolName, result.BlockedBy, result.BlockReason)
		}

		// Execute through Fabric (Stargate handles the actual recording)
		return fabricWrapped(ctx, params)
	}
}

// ─── WAF Integration ──────────────────────────────────────────────────────────

// runWAF synthesises a minimal HTTP request from the ToolCall and runs it
// through the SEKHEM WAFShield's rule chain.
// Returns (blocked, reason, ruleID).
func (w *Wrapper) runWAF(ctx context.Context, call ToolCall) (bool, string, string) {
	waf := w.agent.orch.WAFShield()
	if waf == nil {
		return false, "", ""
	}

	url := "/mcp/tool/" + sanitizePath(call.ToolName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		strings.NewReader(string(call.Params)))
	if err != nil {
		return false, "", ""
	}
	req.RemoteAddr = call.ClientIP
	if req.RemoteAddr == "" {
		req.RemoteAddr = "127.0.0.1:0"
	}
	if call.UserAgent != "" {
		req.Header.Set("User-Agent", call.UserAgent)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", "souhimbou.internal")
	req.ContentLength = int64(len(call.Params))

	// Run each WAF rule
	for _, rule := range waf.Rules() {
		if result := rule.Inspect(req); result != nil {
			reason := fmt.Sprintf("%s matched on tool=%s", result.RuleID, call.ToolName)
			return true, reason, result.RuleID
		}
	}
	return false, "", ""
}

// ─── KASA Integration ─────────────────────────────────────────────────────────

// runKASA runs ML-powered tamper + behavioral analysis on the tool call.
// Returns (anomalyScore, behaviorFlags).
func (w *Wrapper) runKASA(call ToolCall) (float64, []string) {
	if w.agent.orch == nil || w.agent.orch.KASACrypto == nil {
		return 0.0, nil
	}
	data := map[string]any{
		"agent":     call.AgentID,
		"tool":      call.ToolName,
		"scope":     call.ToolScope,
		"risk":      call.RiskClass,
		"params_sz": len(call.Params),
		"ts":        call.StartedAt.Unix(),
		"ip":        call.ClientIP,
	}
	_, report := w.agent.orch.KASACrypto.DetectTampering(data, call.AgentID)
	if report == nil {
		return 0.0, nil
	}
	return report.AnomalyScore, report.BehaviorFlags
}

// ─── Isfet / Maat helpers ─────────────────────────────────────────────────────

func isfetReason(isfet []maat.Isfet) string {
	if len(isfet) == 0 {
		return "WAF rule matched"
	}
	f := isfet[0]
	if len(f.Omens) > 0 {
		return fmt.Sprintf("%s: %s", f.Source, f.Omens[0].Name)
	}
	return string(f.Severity) + " threat detected"
}

func kasaFlagsToReason(flags []string) string {
	if len(flags) == 0 {
		return "KASA anomaly detected"
	}
	return "KASA: " + strings.Join(flags, ", ")
}

func sanitizePath(s string) string {
	return strings.NewReplacer(".", "_", "/", "_", "..", "").Replace(s)
}
