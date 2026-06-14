package ert

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/scanners"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/types"
)

// ──────────────────────────────────────────────────────────────────────────────
// Horus Lanes — zero-dependency built-in scanners from pkg/scanners
//
// Each Horus capability gets its own LaneRunner for OWASP-aligned isolation:
//   - HorusVulnLane:       Manifest vulnerability pattern matching
//   - HorusSecretLane:     Entropy-based secret detection
//   - HorusComplianceLane: CIS/STIG/NIST compliance checks
//   - HorusContainerLane:  Dockerfile misconfiguration scanning
// ──────────────────────────────────────────────────────────────────────────────

// ── Horus Vulnerability Lane ─────────────────────────────────────────────────

// HorusVulnLane scans for known vulnerable packages in manifests.
type HorusVulnLane struct{}

// NewHorusVulnLane creates a new Horus vulnerability lane.
func NewHorusVulnLane() *HorusVulnLane {
	return &HorusVulnLane{}
}

// Name returns the lane identifier.
func (l *HorusVulnLane) Name() ScanLane {
	return LaneHorusVuln
}

// Run executes the Horus vulnerability scan against the target path.
func (l *HorusVulnLane) Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error) {
	target := req.TargetPath
	if target == "" {
		return nil, fmt.Errorf("horus_vuln: target_path required")
	}

	log.Printf("[HORUS-VULN] Scanning: %s", target)

	vulns, err := scanners.RunBuiltInVulnerabilityScan(target)
	if err != nil {
		return nil, fmt.Errorf("horus vulnerability scan failed: %w", err)
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	findings := make([]UnifiedFinding, 0, len(vulns))
	for _, v := range vulns {
		findings = append(findings, horusVulnToUnified(v))
	}

	log.Printf("[HORUS-VULN] Complete: %d vulnerabilities found", len(findings))
	return findings, nil
}

func horusVulnToUnified(v types.Vulnerability) UnifiedFinding {
	return UnifiedFinding{
		ID:       fmt.Sprintf("horus_vuln:%s:%s", v.Package, v.ID),
		Source:   "horus",
		Category: CategoryVulnerability,

		Severity:    v.Severity,
		Title:       fmt.Sprintf("%s in %s@%s", v.ID, v.Package, v.Version),
		Description: v.Description,

		Asset:    v.Package,
		Location: v.Artifact,

		CVEID:  v.ID,
		CVSSv3: v.CVSS,

		Evidence: map[string]interface{}{
			"version":    v.Version,
			"fixed_in":   v.FixedIn,
			"references": v.References,
		},

		Timestamp: time.Now().UTC(),
		Raw:       v,
	}
}

// ── Horus Secret Lane ────────────────────────────────────────────────────────

// HorusSecretLane scans for hardcoded secrets using entropy analysis
// and pattern matching.
type HorusSecretLane struct{}

// NewHorusSecretLane creates a new Horus secret detection lane.
func NewHorusSecretLane() *HorusSecretLane {
	return &HorusSecretLane{}
}

// Name returns the lane identifier.
func (l *HorusSecretLane) Name() ScanLane {
	return LaneHorusSecret
}

// Run executes the Horus secret scan against the target path.
func (l *HorusSecretLane) Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error) {
	target := req.TargetPath
	if target == "" {
		return nil, fmt.Errorf("horus_secret: target_path required")
	}

	log.Printf("[HORUS-SECRET] Scanning: %s", target)

	secrets, err := scanners.RunBuiltInSecretScan(target)
	if err != nil {
		return nil, fmt.Errorf("horus secret scan failed: %w", err)
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	findings := make([]UnifiedFinding, 0, len(secrets))
	for _, s := range secrets {
		findings = append(findings, horusSecretToUnified(s))
	}

	log.Printf("[HORUS-SECRET] Complete: %d secrets found", len(findings))
	return findings, nil
}

func horusSecretToUnified(s types.SecretFinding) UnifiedFinding {
	// Secrets are always at least HIGH severity
	severity := "HIGH"
	if s.Type == "Private Key" || s.Type == "AWS Key" {
		severity = "CRITICAL"
	}

	return UnifiedFinding{
		ID:       fmt.Sprintf("horus_secret:%s:%s:%d", s.Type, s.File, s.Line),
		Source:   "horus",
		Category: CategorySecret,

		Severity:    severity,
		Title:       fmt.Sprintf("%s detected in %s", s.Type, s.File),
		Description: s.Description,

		Asset:    s.File,
		Location: fmt.Sprintf("line:%d", s.Line),

		SecretType: s.Type,
		Entropy:    s.Entropy,
		Redacted:   s.Redacted,

		Remediation: "Rotate secret IMMEDIATELY. Remove from source control. Use a secrets manager (Vault, AWS Secrets Manager).",

		Evidence: map[string]interface{}{
			"file":     s.File,
			"line":     s.Line,
			"type":     s.Type,
			"entropy":  s.Entropy,
			"redacted": s.Redacted,
		},

		Timestamp: time.Now().UTC(),
		Raw:       s,
	}
}

// ── Horus Compliance Lane ────────────────────────────────────────────────────

// HorusComplianceLane runs CIS/STIG/NIST compliance checks.
type HorusComplianceLane struct{}

// NewHorusComplianceLane creates a new Horus compliance lane.
func NewHorusComplianceLane() *HorusComplianceLane {
	return &HorusComplianceLane{}
}

// Name returns the lane identifier.
func (l *HorusComplianceLane) Name() ScanLane {
	return LaneHorusCompliance
}

// Run executes the Horus compliance scan.
func (l *HorusComplianceLane) Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error) {
	framework := req.ComplianceFramework
	if framework == "" {
		framework = "cis"
	}

	log.Printf("[HORUS-COMPLIANCE] Running %s compliance checks", framework)

	report, err := scanners.RunBuiltInComplianceScan(framework)
	if err != nil {
		return nil, fmt.Errorf("horus compliance scan failed: %w", err)
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Convert each FAILED check to a UnifiedFinding
	findings := make([]UnifiedFinding, 0)
	for _, cf := range report.Findings {
		if cf.Status == "FAIL" {
			findings = append(findings, horusComplianceToUnified(cf, framework))
		}
	}

	log.Printf("[HORUS-COMPLIANCE] Complete: %d/%d checks passed (%.1f%%), %d findings",
		report.PassedChecks, report.TotalChecks, report.ComplianceRate, len(findings))

	return findings, nil
}

func horusComplianceToUnified(cf types.ComplianceFinding, framework string) UnifiedFinding {
	return UnifiedFinding{
		ID:       fmt.Sprintf("horus_compliance:%s:%s", framework, cf.ID),
		Source:   "horus",
		Category: CategoryCompliance,

		Severity:    cf.Severity,
		Title:       fmt.Sprintf("[%s] %s", cf.ID, cf.Title),
		Description: cf.Description,

		Asset:    framework,
		Location: cf.ID,

		Framework:   framework,
		ControlID:   cf.ID,
		Remediation: cf.Remediation,

		Evidence: map[string]interface{}{
			"framework": framework,
			"check_id":  cf.ID,
			"status":    cf.Status,
			"evidence":  cf.Evidence,
		},

		Timestamp: time.Now().UTC(),
		Raw:       cf,
	}
}

// ── Horus Container Lane ─────────────────────────────────────────────────────

// HorusContainerLane scans Dockerfiles for misconfigurations.
type HorusContainerLane struct{}

// NewHorusContainerLane creates a new Horus container scanning lane.
func NewHorusContainerLane() *HorusContainerLane {
	return &HorusContainerLane{}
}

// Name returns the lane identifier.
func (l *HorusContainerLane) Name() ScanLane {
	return LaneHorusContainer
}

// Run executes the Horus container scan.
func (l *HorusContainerLane) Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error) {
	target := req.TargetPath
	if target == "" {
		target = req.ImageRef
	}
	if target == "" {
		return nil, fmt.Errorf("horus_container: target_path or image_ref required")
	}

	log.Printf("[HORUS-CONTAINER] Scanning: %s", target)

	containerFindings, err := scanners.RunBuiltInContainerScan(target)
	if err != nil {
		return nil, fmt.Errorf("horus container scan failed: %w", err)
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	findings := make([]UnifiedFinding, 0)

	// Convert misconfigurations
	if containerFindings != nil {
		for i, misconfig := range containerFindings.Misconfigurations {
			findings = append(findings, UnifiedFinding{
				ID:       fmt.Sprintf("horus_container:misconfig:%s:%d", target, i),
				Source:   "horus",
				Category: CategoryMisconfigure,

				Severity:    "MEDIUM",
				Title:       fmt.Sprintf("Container Misconfiguration: %s", misconfig),
				Description: misconfig,

				Asset:    containerFindings.ImageName,
				Location: "Dockerfile",

				Remediation: "Review Dockerfile best practices. See CIS Docker Benchmark.",

				Evidence: map[string]interface{}{
					"image_name":        containerFindings.ImageName,
					"misconfiguration":  misconfig,
				},

				Timestamp: time.Now().UTC(),
				Raw:       containerFindings,
			})
		}

		// Convert any secrets found in container context
		for _, s := range containerFindings.Secrets {
			findings = append(findings, horusSecretToUnified(s))
		}
	}

	log.Printf("[HORUS-CONTAINER] Complete: %d findings", len(findings))
	return findings, nil
}
