// Package mcp — domain-specific scope parameter allow-list (injection resistance).
//
// NSA "MCP Security Design Considerations" flags tool parameter injection as an
// active threat vector — a compromised upstream agent can craft malicious target,
// scope, or profile parameters that traverse paths or override compliance profiles.
//
// This file embeds the canonical taxonomy of permitted values for domain-specific
// parameters. ValidateScopedToolArgs() enforces allow-list membership before any
// scan-related tool reaches the Go engine. No shell interpolation of user-supplied
// strings occurs because parameters never reach a shell — but allow-listing prevents
// a rogue agent from feeding a scan profile it invented to override compliance scope.

package mcp

import "fmt"

// ─── Scope Taxonomy Allow-Lists ─────────────────────────────────────────────
//
// These maps encode the canonical set of permitted values for domain-specific
// MCP tool parameters. Any value not in the map is rejected before dispatch.
// Add new entries here when DISA releases new STIG baselines or NIST updates.

// knownOSTargets is the allow-list for "target" parameters on ert_scan, stig_check.
// Values match DISA STIG product identifiers and common OS family strings.
var knownOSTargets = map[string]bool{
	// RHEL family
	"RHEL-9": true, "RHEL-9-V1R3": true, "RHEL-9-V1R2": true,
	"RHEL-8": true, "RHEL-8-V1R14": true, "RHEL-8-V1R13": true,
	"RHEL-7": true, "RHEL-7-V3R15": true,
	// Ubuntu
	"Ubuntu-22.04": true, "Ubuntu-22.04-LTS": true,
	"Ubuntu-20.04": true, "Ubuntu-20.04-LTS": true,
	"Ubuntu-18.04": true,
	// Windows Server
	"Windows-Server-2022": true, "Windows-Server-2022-V1R4": true,
	"Windows-Server-2019": true, "Windows-Server-2019-V2R9": true,
	"Windows-Server-2016": true,
	// Kubernetes / Container
	"Kubernetes-STIG": true, "Kubernetes-V1R12": true,
	"Docker-CE-STIG": true,
	// Network/Infrastructure
	"Cisco-IOS-XE": true, "Cisco-NX-OS": true,
	"Palo-Alto-PAN-OS": true,
	// Generic OS families (for non-STIG scans)
	"linux": true, "windows": true, "macos": true, "container": true,
	// Special: local scan (no specific target OS)
	"local": true, ".": true,
}

// knownFrameworks is the allow-list for "scope", "framework", "profile" parameters.
var knownFrameworks = map[string]bool{
	// NIST
	"NIST-800-53": true, "NIST-800-53-Rev5": true, "NIST-800-53-Rev4": true,
	"NIST-800-171": true, "NIST-800-171-Rev2": true, "NIST-800-171-Rev3": true,
	"NIST-800-172": true,
	// CMMC — canonical forms
	"CMMC-L1": true, "CMMC-L2": true, "CMMC-L3": true,
	"CMMC-2.0-L1": true, "CMMC-2.0-L2": true, "CMMC-2.0-L3": true,
	"CMMC-3.0-L3": true,
	// CMMC — short-form aliases (used by agents and tool callers)
	"CMMC": true, "CMMC_L1": true, "CMMC_L2": true, "CMMC_L3": true,
	"cmmc": true, "cmmc-l1": true, "cmmc-l2": true, "cmmc-l3": true,
	// STIG baselines
	"STIG-RHEL-9": true, "STIG-RHEL-8": true, "STIG-RHEL-7": true,
	"STIG-Ubuntu-22": true, "STIG-Ubuntu-20": true,
	"STIG-Windows-Server-2022": true, "STIG-Windows-Server-2019": true,
	"STIG-Kubernetes": true, "STIG-Docker": true,
	// STIG — short-form aliases
	"STIG": true, "stig": true,
	"RHEL-09-STIG-V1R3": true, "RHEL-09-STIG": true,
	"RHEL-08-STIG-V1R14": true, "RHEL-08-STIG": true,
	// CIS Benchmarks
	"CIS-RHEL-9-L1": true, "CIS-RHEL-9-L2": true,
	"CIS-Ubuntu-22-L1": true, "CIS-Ubuntu-22-L2": true,
	"CIS-Kubernetes-L1": true, "CIS-Kubernetes-L2": true,
	// FedRAMP
	"FedRAMP-HIGH": true, "FedRAMP-MODERATE": true, "FedRAMP-LOW": true,
	"FedRAMP": true, "fedramp": true,
	// DoD/IC
	"DoD-IL2": true, "DoD-IL4": true, "DoD-IL5": true, "DoD-IL6": true,
	// PQC — canonical
	"NIST-PQC-FIPS203": true, "NIST-PQC-FIPS204": true, "NIST-PQC-FIPS205": true,
	"NSM-10": true, "CISA-PQC": true,
	// PQC — short-form aliases
	"PQC-Readiness": true, "PQC": true, "pqc": true, "pqc-readiness": true,
	// NIST — short-form aliases
	"NIST": true, "nist": true,
	"NIST_800_53": true, "NIST_800_171": true,
	// Generic / wildcard (for summary/discovery tools)
	"all": true, "auto": true,
	// Assessment depth profiles (used by owasp_agent_assess, cmmc_assess, ert_readiness, etc.)
	// These are not compliance frameworks — they're operational assessment modes.
	"full": true, "quick": true, "executive": true,
	"standard": true, "deep": true, "summary": true, "detailed": true,
	"fast": true, "lite": true,
}

// knownScanLanes is the allow-list for "lanes" array elements in ert_scan.
var knownScanLanes = map[string]bool{
	"sast": true, "dast": true, "sca": true, "secrets": true,
	"container": true, "iac": true, "sbom": true, "pqc": true,
	"stig": true, "network": true, "compliance": true,
	"vuln": true, "forensics": true,
}

// ─── Scoped Validator ───────────────────────────────────────────────────────

// scopedFields maps field names to their allow-list. Case-insensitive field names.
type scopedField struct {
	allowList map[string]bool
	paramName string // human-readable name for error messages
}

var scopedFieldMap = map[string]scopedField{
	"target":    {allowList: knownOSTargets, paramName: "target OS/profile"},
	"scope":     {allowList: knownFrameworks, paramName: "compliance framework scope"},
	"framework": {allowList: knownFrameworks, paramName: "compliance framework"},
	"profile":   {allowList: knownFrameworks, paramName: "scan profile"},
	"baseline":  {allowList: knownFrameworks, paramName: "STIG baseline"},
}

// ValidateScopedToolArgs enforces domain-specific allow-list validation on
// tool parameters before they reach the Go engine.
//
// This is a defense-in-depth layer on top of ValidateToolArgs — it fires before
// the generic injection/traversal checks in Step 1.6 of the router chain.
//
// toolName is used for context in error messages only; validation is currently
// uniform across all tools. Tool-specific overrides can be added to an extended
// version of scopedFieldMap keyed by toolName.
func ValidateScopedToolArgs(args map[string]any, toolName string) *ValidationError {
	for fieldKey, fieldMeta := range scopedFieldMap {
		val, ok := args[fieldKey]
		if !ok {
			continue // field not present — not required by this validator
		}

		// Validate string values
		strVal, ok := val.(string)
		if !ok {
			continue // non-string — let schema validation handle type errors
		}
		if strVal == "" {
			continue // empty string — optional field, skip
		}

		if !fieldMeta.allowList[strVal] {
			return &ValidationError{
				Code:    ErrCodeInvalidArg,
				Field:   fieldKey,
				Message: fmt.Sprintf("tool %q: %s value %q is not in the permitted taxonomy (see docs/scope_taxonomy.md)", toolName, fieldMeta.paramName, strVal),
			}
		}
	}

	// Validate "lanes" array elements (ert_scan-specific)
	if lanesVal, ok := args["lanes"]; ok {
		if lanes, ok := lanesVal.([]any); ok {
			for i, l := range lanes {
				if s, ok := l.(string); ok && s != "" {
					if !knownScanLanes[s] {
						return &ValidationError{
							Code:    ErrCodeInvalidArg,
							Field:   fmt.Sprintf("lanes[%d]", i),
							Message: fmt.Sprintf("tool %q: scan lane %q is not in the permitted taxonomy", toolName, s),
						}
					}
				}
			}
		}
	}

	return nil
}

// IsPermittedTarget returns true if target is in the OS target allow-list.
// Exported for use in tool-level pre-validation.
func IsPermittedTarget(target string) bool {
	return knownOSTargets[target]
}

// IsPermittedFramework returns true if framework is in the framework allow-list.
func IsPermittedFramework(framework string) bool {
	return knownFrameworks[framework]
}

// RegisterCustomTarget adds a target to the runtime allow-list.
// For enterprise deployments with custom STIG baselines not in the default taxonomy.
// Thread-unsafe: call during server initialization only.
func RegisterCustomTarget(target string) {
	knownOSTargets[target] = true
}

// RegisterCustomFramework adds a framework to the runtime allow-list.
// Thread-unsafe: call during server initialization only.
func RegisterCustomFramework(framework string) {
	knownFrameworks[framework] = true
}
