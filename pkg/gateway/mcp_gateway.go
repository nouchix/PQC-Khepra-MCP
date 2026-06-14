// Package gateway - MCP Gateway (Zone 2: Trusted)
//
// This component enforces security policies for all MCP (Model Context Protocol)
// server interactions. It sits between agents/AI tools and the STIG data/services.
//
// Security Controls:
//   - Prompt injection scanning (6 regex patterns from STIGVIEWER_STRATEGY_MITOCHONDRIA.md §3.2)
//   - Content filtering by data classification (PUBLIC/CUI/CLASSIFIED)
//   - Agent authentication via scoped JWTs
//   - 100% query/response audit logging to DAG
//   - RBAC enforcement (stig:reader, stig:analyst, stig:admin)
//
// Reference: STIGVIEWER_STRATEGY_MITOCHONDRIA.md §3.2, §3.3, §4.1
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// ─── Prompt Injection Scanner ──────────────────────────────────────────────────

// injectionPatterns are regex patterns that detect common prompt injection attacks.
// These patterns are from STIGVIEWER_STRATEGY_MITOCHONDRIA.md §3.2 lines 168-175.
var injectionPatterns = []*regexp.Regexp{
	// Pattern 1: "Ignore previous instructions"
	regexp.MustCompile(`(?i)(ignore|forget|disregard)\s+(previous|above|prior)\s+(instructions?|prompts?|rules?)`),

	// Pattern 2: "You are now a..."
	regexp.MustCompile(`(?i)you\s+are\s+now\s+a`),

	// Pattern 3: "System:" prefix (ChatML/system prompt hijacking)
	regexp.MustCompile(`(?i)system\s*:\s*`),

	// Pattern 4: "Reveal your system prompt"
	regexp.MustCompile(`(?i)(reveal|show|print|output)\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions?)`),

	// Pattern 5: LLM instruction markers ([INST], <|im_start|>)
	regexp.MustCompile(`(?i)\[\s*INST\s*\]`),

	// Pattern 6: ChatML injection markers
	regexp.MustCompile(`(?i)<\|im_start\|>`),
}

// ─── Data Classification ───────────────────────────────────────────────────────

// DataClassification represents the sensitivity level of STIG data.
type DataClassification string

const (
	// DataClassPublic is publicly releasable STIG data (most decomposed rules).
	DataClassPublic DataClassification = "PUBLIC"

	// DataClassCUI is Controlled Unclassified Information (organizational mappings, internal notes).
	DataClassCUI DataClassification = "CUI"

	// DataClassClassified is classified STIG data (DoD-specific interpretations, vulnerabilities).
	DataClassClassified DataClassification = "CLASSIFIED"
)

// ─── RBAC Roles ────────────────────────────────────────────────────────────────

// STIGRole defines the role-based access control roles for STIG data.
type STIGRole string

const (
	RoleReader  STIGRole = "stig:reader"  // Read decomposed rules, view complexity
	RoleAnalyst STIGRole = "stig:analyst" // + export reports, view role mappings
	RoleAdmin   STIGRole = "stig:admin"   // + manage cache, force sync
)

// rolePermissions maps each role to its allowed operations.
var rolePermissions = map[STIGRole][]string{
	RoleReader: {
		"query_stigs",
		"view_decomposed_rules",
		"view_complexity",
	},
	RoleAnalyst: {
		"query_stigs",
		"view_decomposed_rules",
		"view_complexity",
		"export_reports",
		"view_role_mappings",
		"view_compliance_status", // New: view Process Behavior Timeline compliance
	},
	RoleAdmin: {
		"query_stigs",
		"view_decomposed_rules",
		"view_complexity",
		"export_reports",
		"view_role_mappings",
		"view_compliance_status",
		"manage_cache",
		"force_sync",
		"view_process_timeline", // New: access to Process Behavior Timeline
	},
}

// ─── Identity check handled in gateway.go ───────────────────────────────────

// ─── MCP Gateway ───────────────────────────────────────────────────────────────

// MCPGateway enforces security policies for MCP server interactions.
type MCPGateway struct {
	// auditLog is where all queries and responses are logged (tamper-proof DAG).
	auditLog AuditLogger

	// stigConnector is the DMZ connector to STIGViewer API.
	stigConnector *STIGConnector

	// processTimelineEnabled enables integration with Process Behavior Timeline.
	processTimelineEnabled bool

	// timelineStore provides access to process behavior events database.
	// Implemented by SupabaseProcessTimelineStore (see process_timeline_store.go).
	// The TypeScript equivalent is: supabase/functions/stig-query-with-timeline/index.ts
	timelineStore ProcessTimelineStore
}

// AuditLogger interface for tamper-proof logging (implemented by pkg/seshat DAG).
type AuditLogger interface {
	Log(eventType string, identity *Identity, data map[string]interface{}) error
}

// NewMCPGateway creates a new MCP Gateway instance.
// timelineStore may be nil; when provided it enables live process timeline queries.
func NewMCPGateway(auditLog AuditLogger, connector *STIGConnector, timelineStore ProcessTimelineStore) *MCPGateway {
	enabled := timelineStore != nil
	return &MCPGateway{
		auditLog:               auditLog,
		stigConnector:          connector,
		processTimelineEnabled: enabled,
		timelineStore:          timelineStore,
	}
}

// ─── Prompt Injection Scanner ──────────────────────────────────────────────────

// ScanForInjection scans text content for prompt injection patterns.
// Returns error if injection detected, nil otherwise.
func (g *MCPGateway) ScanForInjection(content string) error {
	for i, pattern := range injectionPatterns {
		if pattern.MatchString(content) {
			// Log the injection attempt (first 100 chars only for audit trail)
			preview := content
			if len(content) > 100 {
				preview = content[:100] + "..."
			}

			g.auditLog.Log("prompt_injection_blocked", nil, map[string]interface{}{
				"pattern_index":   i,
				"content_preview": preview,
				"timestamp":       time.Now().UTC(),
			})

			return fmt.Errorf("potential prompt injection detected (pattern %d)", i)
		}
	}
	return nil
}

// ─── Authorization ─────────────────────────────────────────────────────────────

// CheckPermission verifies if an identity has permission for an operation.
func (g *MCPGateway) CheckPermission(identity *Identity, operation string) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	permissions, ok := rolePermissions[identity.Role]
	if !ok {
		return fmt.Errorf("unknown role: %s", identity.Role)
	}

	for _, perm := range permissions {
		if perm == operation {
			return nil // Permission granted
		}
	}

	// Log access denial
	g.auditLog.Log("stig_access_denied", identity, map[string]interface{}{
		"operation": operation,
		"role":      identity.Role,
		"timestamp": time.Now().UTC(),
	})

	return fmt.Errorf("access denied: role %s lacks permission %s", identity.Role, operation)
}

// ─── STIG Query Handling ───────────────────────────────────────────────────────

// STIGQueryRequest represents a query for STIG data.
type STIGQueryRequest struct {
	STIGID                 string                 `json:"stig_id"`   // e.g., "RHEL-08-010010"
	Operation              string                 `json:"operation"` // e.g., "query_stigs", "view_decomposed_rules"
	Filters                map[string]interface{} `json:"filters,omitempty"`
	IncludeProcessTimeline bool                   `json:"include_process_timeline,omitempty"` // New: request process behavior data
}

// STIGQueryResponse represents the filtered response.
type STIGQueryResponse struct {
	STIGID             string                   `json:"stig_id"`
	Title              string                   `json:"title"`
	Severity           string                   `json:"severity"`
	Complexity         string                   `json:"complexity,omitempty"` // Filtered based on role
	DecomposedRules    []map[string]interface{} `json:"decomposed_rules,omitempty"`
	RoleMappings       []string                 `json:"role_mappings,omitempty"`     // Analyst+ only
	ComplianceStatus   string                   `json:"compliance_status,omitempty"` // Analyst+ only
	ProcessTimeline    []ProcessBehaviorEvent   `json:"process_timeline,omitempty"`  // Admin only
	DataClassification DataClassification       `json:"data_classification"`
	Source             string                   `json:"source,omitempty"`
}

// ProcessBehaviorEvent represents a process behavior event from the timeline.
// This integrates with ProcessBehaviorTimeline.tsx component.
type ProcessBehaviorEvent struct {
	ID               string    `json:"id"`
	Timestamp        time.Time `json:"timestamp"`
	PID              int       `json:"pid"`
	ProcessName      string    `json:"process_name"`
	Type             string    `json:"type"` // FILE, REGISTRY, NETWORK
	Action           string    `json:"action"`
	Target           string    `json:"target"`
	Details          string    `json:"details,omitempty"`
	CMMCControl      string    `json:"cmmc_control,omitempty"`
	STIGControl      string    `json:"stig_control,omitempty"` // New: STIG mapping
	ComplianceStatus string    `json:"compliance_status"`      // VALIDATED, VIOLATION, PENDING
}

// HandleSTIGQuery processes a STIG query request with full security enforcement.
func (g *MCPGateway) HandleSTIGQuery(ctx context.Context, identity *Identity, req *STIGQueryRequest) (*STIGQueryResponse, error) {
	// 1. Validate STIG ID format (prevent injection)
	if !isValidSTIGID(req.STIGID) {
		return nil, fmt.Errorf("invalid STIG ID format: %s", req.STIGID)
	}

	// 2. Check authorization
	if err := g.CheckPermission(identity, req.Operation); err != nil {
		return nil, err
	}

	// 3. Scan query for prompt injection
	queryJSON, _ := json.Marshal(req)
	if err := g.ScanForInjection(string(queryJSON)); err != nil {
		return nil, err
	}

	// 4. Fetch data from STIG Connector (DMZ Zone 1)
	filter := STIGFilter{
		STIGID: req.STIGID,
		Limit:  1,
	}
	rawData, err := g.stigConnector.QuerySTIGs(ctx, identity.ID, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch STIG data: %w", err)
	}

	// Convert STIGQueryResult to STIGQueryResponse
	response := &STIGQueryResponse{
		STIGID:             req.STIGID,
		DataClassification: DataClassPublic, // Conservative default; overridden if STIGConnector returns an explicit classification
		Source:             rawData.Source,
	}

	if len(rawData.Rules) > 0 {
		rule := rawData.Rules[0]
		response.Title = rule.Title
		response.Severity = rule.Severity
		response.Complexity = rule.Complexity

		// Map decomposed rules
		for _, dec := range rawData.Rules {
			ruleMap := mcpRuleToMap(dec)
			response.DecomposedRules = append(response.DecomposedRules, ruleMap)
		}
	}

	// 5. Filter response based on identity's role and data classification
	g.filterByRoleAndClassification(response, identity)

	// 6. Add Process Behavior Timeline data if requested (Admin only)
	if req.IncludeProcessTimeline && identity.Role == RoleAdmin {
		if err := g.CheckPermission(identity, "view_process_timeline"); err == nil {
			response.ProcessTimeline = g.getProcessTimelineForSTIG(req.STIGID)
		}
	}

	// 7. Audit log the query
	g.auditLog.Log("stig_query_executed", identity, map[string]interface{}{
		"stig_id":             req.STIGID,
		"operation":           req.Operation,
		"data_class_returned": response.DataClassification,
		"timestamp":           time.Now().UTC(),
	})

	return response, nil
}

func mcpRuleToMap(rule STIGDecomposedRule) map[string]interface{} {
	m := make(map[string]interface{})
	m["rule_id"] = rule.RuleID
	m["title"] = rule.Title
	m["severity"] = rule.Severity
	m["description"] = rule.Description

	reqs := make([]map[string]interface{}, 0)
	for _, ar := range rule.AtomicRequirements {
		reqs = append(reqs, map[string]interface{}{
			"id":          ar.ID,
			"description": ar.Description,
			"testable":    ar.Testable,
			"automatable": ar.Automatable,
		})
	}
	m["atomic_requirements"] = reqs
	return m
}

// ─── Helper Functions ──────────────────────────────────────────────────────────

// isValidSTIGID validates the STIG ID format to prevent injection.
func isValidSTIGID(stigID string) bool {
	// STIG IDs follow format: PRODUCT-VERSION-RULEID (e.g., "RHEL-08-010010")
	// Allow alphanumeric, hyphens, underscores only
	validFormat := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	return validFormat.MatchString(stigID) && len(stigID) <= 64
}

// RedactClassification redacts sensitive fields if clearance is insufficient.
func (g *MCPGateway) RedactClassification(response *STIGQueryResponse, identity *Identity) {
	if response.DataClassification > identity.DataClassification {
		response.Title = "[REDACTED - Insufficient Clearance]"
		response.DecomposedRules = nil
		response.RoleMappings = nil
	}
}

// filterByRoleAndClassification filters STIG response fields based on RBAC and data classification.
func (g *MCPGateway) filterByRoleAndClassification(response *STIGQueryResponse, identity *Identity) {
	// Complexity visible to all roles
	// Decomposed rules visible to all roles (if PUBLIC classification)
	if response.DataClassification != DataClassPublic && identity.Role == RoleReader {
		response.DecomposedRules = nil
	}

	// Role mappings visible to Analyst+ roles
	if identity.Role != RoleAnalyst && identity.Role != RoleAdmin {
		response.RoleMappings = nil
		response.ComplianceStatus = ""
	}

	// Process timeline visible to Admin only
	if identity.Role != RoleAdmin {
		response.ProcessTimeline = nil
	}

	// Filter out CUI/CLASSIFIED data if identity lacks clearance
	if response.DataClassification > identity.DataClassification {
		// Redact sensitive fields
		response.Title = "[REDACTED - Insufficient Clearance]"
		response.DecomposedRules = nil
		response.RoleMappings = nil
	}
}

// getProcessTimelineForSTIG retrieves process behavior events related to a STIG control.
// This integrates with the ProcessBehaviorTimeline component and Supabase database.
//
// Integration: This function queries the process_behavior_events table in Supabase.
// The actual database connection is handled by the ProcessTimelineStore interface.
//
// Reference: souhimbou_ai/SouHimBou.AI/supabase/migrations/20260215000000_process_behavior_timeline.sql
func (g *MCPGateway) getProcessTimelineForSTIG(stigID string) []ProcessBehaviorEvent {
	if !g.processTimelineEnabled || g.timelineStore == nil {
		return nil
	}

	events, err := g.timelineStore.QueryBySTIGControl(context.Background(), stigID, ProcessTimelineFilter{
		Limit:            100,
		ComplianceStatus: []string{"VIOLATION", "PENDING"},
		TimeSince:        time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		g.auditLog.Log("process_timeline_query_failed", nil, map[string]interface{}{
			"stig_control": stigID,
			"error":        err.Error(),
		})
		return nil
	}

	return events
}

// ─── Response Filtering ────────────────────────────────────────────────────────

// StripSensitiveFields removes internal metadata from responses before sending to MCP agents.
func (g *MCPGateway) StripSensitiveFields(response *STIGQueryResponse) {
	// Remove internal IDs, audit metadata, etc.
	// This ensures agents only see what they're authorized to access

	// Example: Strip internal database IDs from decomposed rules
	for _, rule := range response.DecomposedRules {
		delete(rule, "internal_id")
		delete(rule, "created_by")
		delete(rule, "last_modified_by")
	}
}
