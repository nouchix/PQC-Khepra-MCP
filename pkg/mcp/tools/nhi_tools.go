package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/nhi"
)

// ─── NHI Governance Tool Suite ─────────────────────────────────────────────────
//
// These tools expose pkg/nhi.NHITracker capabilities as read-only governance
// tools plus a single destructive revoke endpoint, following least-privilege
// MCP guidance.

// NHIInventoryTool returns the full NHI credential inventory.
// Risk class: read_only
type NHIInventoryTool struct {
	tracker *nhi.NHITracker
}

func NewNHIInventoryTool(t *nhi.NHITracker) *NHIInventoryTool {
	return &NHIInventoryTool{tracker: t}
}

type NHIInventoryResponse struct {
	TotalRecords   int                  `json:"total_records"`
	Records        []NHIRecordSummary   `json:"records"`
	RiskBreakdown  map[string]int       `json:"risk_breakdown"`
	Timestamp      string               `json:"timestamp"`
}

type NHIRecordSummary struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Owner     string   `json:"owner"`
	Platform  string   `json:"platform"`
	Scopes    []string `json:"scopes"`
	RiskScore float64  `json:"risk_score"`
	Managed   bool     `json:"managed"`
	Expired   bool     `json:"expired"`
	DaysUntilExpiry int `json:"days_until_expiry"`
}

func (t *NHIInventoryTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if t.tracker == nil {
		return nil, nil, fmt.Errorf("nhi_inventory: tracker not initialized")
	}

	records, err := t.tracker.Inventory()
	if err != nil {
		return nil, nil, fmt.Errorf("nhi_inventory: %w", err)
	}
	summaries := make([]NHIRecordSummary, 0, len(records))
	riskBreakdown := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, r := range records {
		summary := NHIRecordSummary{
			ID:              r.ID,
			Type:            string(r.Type),
			Owner:           r.Owner,
			Platform:        r.Platform,
			Scopes:          r.Scopes,
			RiskScore:       r.RiskScore,
			Managed:         r.Managed,
			Expired:         r.IsExpired(),
			DaysUntilExpiry: r.DaysUntilExpiry(),
		}
		summaries = append(summaries, summary)

		switch {
		case r.RiskScore >= 0.9:
			riskBreakdown["critical"]++
		case r.RiskScore >= 0.7:
			riskBreakdown["high"]++
		case r.RiskScore >= 0.4:
			riskBreakdown["medium"]++
		default:
			riskBreakdown["low"]++
		}
	}

	return &NHIInventoryResponse{
		TotalRecords:  len(summaries),
		Records:       summaries,
		RiskBreakdown: riskBreakdown,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
	}, nil, nil
}

// ─── NHI Orphan Detection (Read-Only) ──────────────────────────────────────────

// NHIOrphansTool detects credentials with no active owner.
type NHIOrphansTool struct {
	tracker *nhi.NHITracker
}

func NewNHIOrphansTool(t *nhi.NHITracker) *NHIOrphansTool {
	return &NHIOrphansTool{tracker: t}
}

func (t *NHIOrphansTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if t.tracker == nil {
		return nil, nil, fmt.Errorf("nhi_orphans: tracker not initialized")
	}

	orphans := t.tracker.IdentifyOrphans()
	summaries := make([]NHIRecordSummary, 0, len(orphans))
	for _, r := range orphans {
		summaries = append(summaries, NHIRecordSummary{
			ID:              r.ID,
			Type:            string(r.Type),
			Owner:           r.Owner,
			Platform:        r.Platform,
			Scopes:          r.Scopes,
			RiskScore:       r.RiskScore,
			Managed:         r.Managed,
			Expired:         r.IsExpired(),
			DaysUntilExpiry: r.DaysUntilExpiry(),
		})
	}

	var warnings []string
	if len(orphans) > 0 {
		warnings = append(warnings, fmt.Sprintf("%d orphaned NHI credentials detected — review and revoke", len(orphans)))
	}

	return map[string]any{
		"orphan_count": len(orphans),
		"orphans":      summaries,
		"timestamp":    time.Now().UTC().Format(time.RFC3339Nano),
	}, warnings, nil
}

// ─── NHI Excessive Privilege Detection (Read-Only) ─────────────────────────────

// NHIExcessiveTool detects credentials with overly broad permissions.
type NHIExcessiveTool struct {
	tracker *nhi.NHITracker
}

func NewNHIExcessiveTool(t *nhi.NHITracker) *NHIExcessiveTool {
	return &NHIExcessiveTool{tracker: t}
}

func (t *NHIExcessiveTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if t.tracker == nil {
		return nil, nil, fmt.Errorf("nhi_excessive: tracker not initialized")
	}

	maxScopes := 5 // default threshold
	if ms, ok := call.Args["max_scopes"].(float64); ok && ms > 0 {
		maxScopes = int(ms)
	}
	riskThreshold := 0.5 // default risk threshold
	if rt, ok := call.Args["risk_threshold"].(float64); ok && rt > 0 {
		riskThreshold = rt
	}

	excessive := t.tracker.IdentifyExcessive(maxScopes, riskThreshold)
	summaries := make([]NHIRecordSummary, 0, len(excessive))
	for _, r := range excessive {
		summaries = append(summaries, NHIRecordSummary{
			ID:              r.ID,
			Type:            string(r.Type),
			Owner:           r.Owner,
			Platform:        r.Platform,
			Scopes:          r.Scopes,
			RiskScore:       r.RiskScore,
			Managed:         r.Managed,
			Expired:         r.IsExpired(),
			DaysUntilExpiry: r.DaysUntilExpiry(),
		})
	}

	return map[string]any{
		"excessive_count": len(excessive),
		"max_scope_threshold": maxScopes,
		"excessive":       summaries,
		"timestamp":       time.Now().UTC().Format(time.RFC3339Nano),
	}, nil, nil
}

// ─── NHI Expired Credential Detection (Read-Only) ─────────────────────────────

// NHIExpiredTool detects credentials past their expiration date.
type NHIExpiredTool struct {
	tracker *nhi.NHITracker
}

func NewNHIExpiredTool(t *nhi.NHITracker) *NHIExpiredTool {
	return &NHIExpiredTool{tracker: t}
}

func (t *NHIExpiredTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if t.tracker == nil {
		return nil, nil, fmt.Errorf("nhi_expired: tracker not initialized")
	}

	expired := t.tracker.IdentifyExpired()
	summaries := make([]NHIRecordSummary, 0, len(expired))
	for _, r := range expired {
		summaries = append(summaries, NHIRecordSummary{
			ID:              r.ID,
			Type:            string(r.Type),
			Owner:           r.Owner,
			Platform:        r.Platform,
			Scopes:          r.Scopes,
			RiskScore:       r.RiskScore,
			Managed:         r.Managed,
			Expired:         true,
			DaysUntilExpiry: r.DaysUntilExpiry(),
		})
	}

	var warnings []string
	if len(expired) > 0 {
		warnings = append(warnings, fmt.Sprintf("%d expired NHI credentials found — revoke immediately", len(expired)))
	}

	return map[string]any{
		"expired_count": len(expired),
		"expired":       summaries,
		"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
	}, warnings, nil
}

// ─── NHI Revoke (Destructive) ──────────────────────────────────────────────────

// NHIRevokeTool revokes a non-human identity credential.
// Risk class: destructive (requires ConfirmationGate approval).
type NHIRevokeTool struct {
	tracker *nhi.NHITracker
}

func NewNHIRevokeTool(t *nhi.NHITracker) *NHIRevokeTool {
	return &NHIRevokeTool{tracker: t}
}

func (t *NHIRevokeTool) Handle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if t.tracker == nil {
		return nil, nil, fmt.Errorf("nhi_revoke: tracker not initialized")
	}

	nhiID, _ := call.Args["nhi_id"].(string)
	if nhiID == "" {
		return nil, nil, fmt.Errorf("nhi_revoke: nhi_id is required")
	}

	if err := t.tracker.RevokeNHI(nhiID); err != nil {
		return nil, nil, fmt.Errorf("nhi_revoke: %w", err)
	}

	return map[string]any{
		"status":     "revoked",
		"nhi_id":     nhiID,
		"revoked_at": time.Now().UTC().Format(time.RFC3339),
	}, nil, nil
}
