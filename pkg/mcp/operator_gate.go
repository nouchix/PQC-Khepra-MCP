// Package mcp — operator_gate.go
//
// OperatorPolicyGate is the ConfirmationGate for transports that have no
// channel to ask a human (stdio, the hub's MCP endpoint). It replaces the
// former auto-approve gates: a destructive tool runs only when the operator
// has named it in KHEPRA_APPROVED_DESTRUCTIVE_TOOLS. There is no wildcard and
// no approve-all setting, and every decision is logged.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
package mcp

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

// ApprovedDestructiveToolsEnv lists, comma-separated, the destructive tools
// the operator has pre-approved for this process.
const ApprovedDestructiveToolsEnv = "KHEPRA_APPROVED_DESTRUCTIVE_TOOLS"

// OperatorPolicyGate approves only destructive tools the operator listed.
type OperatorPolicyGate struct {
	logger  *log.Logger
	allowed map[string]bool
}

// NewOperatorPolicyGate builds a gate from an explicit list of tool names.
// Entries "*" and "all" are ignored: approval must name each tool.
func NewOperatorPolicyGate(logger *log.Logger, tools []string) *OperatorPolicyGate {
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	allowed := make(map[string]bool)
	for _, t := range tools {
		t = strings.TrimSpace(t)
		if t == "" || t == "*" || strings.EqualFold(t, "all") {
			continue
		}
		allowed[t] = true
	}
	return &OperatorPolicyGate{logger: logger, allowed: allowed}
}

// NewOperatorPolicyGateFromEnv reads ApprovedDestructiveToolsEnv.
func NewOperatorPolicyGateFromEnv(logger *log.Logger) *OperatorPolicyGate {
	g := NewOperatorPolicyGate(logger, strings.Split(os.Getenv(ApprovedDestructiveToolsEnv), ","))
	names := make([]string, 0, len(g.allowed))
	for n := range g.allowed {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		g.logger.Printf("[CONFIRM] no destructive tools approved (%s unset); destructive calls will be refused", ApprovedDestructiveToolsEnv)
	} else {
		g.logger.Printf("[CONFIRM] operator-approved destructive tools: %s", strings.Join(names, ", "))
	}
	return g
}

// Confirm implements ConfirmationGate.
func (g *OperatorPolicyGate) Confirm(_ context.Context, spec ToolSpec, _ MCPToolCall) error {
	if g.allowed[spec.Name] {
		g.logger.Printf("[CONFIRM] approved by operator policy: %s (risk_class=%s)", spec.Name, spec.RiskClass)
		return nil
	}
	g.logger.Printf("[CONFIRM] refused: %s (risk_class=%s) — not in %s", spec.Name, spec.RiskClass, ApprovedDestructiveToolsEnv)
	return fmt.Errorf("%s is a destructive tool and the operator has not approved it (set %s)", spec.Name, ApprovedDestructiveToolsEnv)
}
