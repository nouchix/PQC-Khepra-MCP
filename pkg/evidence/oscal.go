package evidence

// oscal.go — NIST OSCAL 1.1.2 emitters for the KHEPRA evidence package.
//
// This is the machine-readable bridge between KHEPRA's technical evidence and
// the canonical formats a 3PAO / agency / eMASS pipeline consumes. It produces
// two OSCAL models:
//
//   - assessment-results   : every KHEPRA Finding rendered as an OSCAL
//                            observation + finding, mapped to its control.
//                            This is the artifact `compliance-trestle` / trestlebot
//                            in the audit enclave assembles into the SAR.
//   - component-definition : the KHEPRA Tool -> Evidence mapping
//                            (COMPLIANCE_AUDIT_ROADMAP.md Section 4) rendered as
//                            OSCAL components, so each tool is a documented,
//                            control-satisfying component in the SSP.
//
// Design choices:
//   - Deterministic UUIDs (RFC 4122 v5, SHA-1 over a fixed KHEPRA namespace).
//     The same package state yields byte-identical OSCAL, so the audit enclave
//     can diff two runs and the DAG/ML-DSA-65 attestation stays stable.
//   - Standard library only. No new module dependencies.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
// Patent: USPTO #73565085 (KHEPRA Protocol)

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	oscalVersion = "1.1.2"

	// Source profiles the OSCAL documents import. These are relative hrefs the
	// audit enclave resolves against its trestle-managed catalog/profile store.
	srcNIST80053 = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
	srcNIST800171 = "trestle://profiles/nist-800-171-rev2/profile.json"
)

// ─── OSCAL common structs ─────────────────────────────────────────────────────

type oscalProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Ns    string `json:"ns,omitempty"`
	Class string `json:"class,omitempty"`
}

type oscalMetadata struct {
	Title        string      `json:"title"`
	Published    time.Time   `json:"published"`
	LastModified time.Time   `json:"last-modified"`
	Version      string      `json:"version"`
	OscalVersion string      `json:"oscal-version"`
	Props        []oscalProp `json:"props,omitempty"`
}

// ─── assessment-results ───────────────────────────────────────────────────────

type oscalAssessmentResults struct {
	AssessmentResults struct {
		UUID     string         `json:"uuid"`
		Metadata oscalMetadata  `json:"metadata"`
		ImportAP oscalHref      `json:"import-ap"`
		Results  []oscalARResult `json:"results"`
	} `json:"assessment-results"`
}

type oscalHref struct {
	Href string `json:"href"`
}

type oscalARResult struct {
	UUID             string                 `json:"uuid"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Start            time.Time              `json:"start"`
	ReviewedControls oscalReviewedControls  `json:"reviewed-controls"`
	Observations     []oscalObservation     `json:"observations,omitempty"`
	Findings         []oscalARFinding       `json:"findings,omitempty"`
}

type oscalReviewedControls struct {
	ControlSelections []oscalControlSelection `json:"control-selections"`
}

type oscalControlSelection struct {
	Description     string                `json:"description,omitempty"`
	IncludeControls []oscalIncludeControl `json:"include-controls,omitempty"`
}

type oscalIncludeControl struct {
	ControlID string `json:"control-id"`
}

type oscalObservation struct {
	UUID             string                  `json:"uuid"`
	Title            string                  `json:"title,omitempty"`
	Description      string                  `json:"description"`
	Methods          []string                `json:"methods"`
	Types            []string                `json:"types,omitempty"`
	Collected        time.Time               `json:"collected"`
	RelevantEvidence []oscalRelevantEvidence `json:"relevant-evidence,omitempty"`
}

type oscalRelevantEvidence struct {
	Href        string `json:"href,omitempty"`
	Description string `json:"description"`
}

type oscalARFinding struct {
	UUID                string             `json:"uuid"`
	Title               string             `json:"title"`
	Description         string             `json:"description"`
	Props               []oscalProp        `json:"props,omitempty"`
	Target              oscalFindingTarget `json:"target"`
	RelatedObservations []oscalRelatedObs  `json:"related-observations,omitempty"`
}

type oscalFindingTarget struct {
	Type     string            `json:"type"`
	TargetID string            `json:"target-id"`
	Status   oscalTargetStatus `json:"status"`
}

type oscalTargetStatus struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type oscalRelatedObs struct {
	ObservationUUID string `json:"observation-uuid"`
}

// ─── component-definition ─────────────────────────────────────────────────────

type oscalComponentDefinition struct {
	ComponentDefinition struct {
		UUID       string           `json:"uuid"`
		Metadata   oscalMetadata    `json:"metadata"`
		Components []oscalComponent `json:"components"`
	} `json:"component-definition"`
}

type oscalComponent struct {
	UUID                   string                  `json:"uuid"`
	Type                   string                  `json:"type"`
	Title                  string                  `json:"title"`
	Description            string                  `json:"description"`
	Props                  []oscalProp             `json:"props,omitempty"`
	ControlImplementations []oscalControlImpl      `json:"control-implementations,omitempty"`
}

type oscalControlImpl struct {
	UUID                    string                    `json:"uuid"`
	Source                  string                    `json:"source"`
	Description             string                    `json:"description"`
	ImplementedRequirements []oscalImplementedReq     `json:"implemented-requirements"`
}

type oscalImplementedReq struct {
	UUID        string      `json:"uuid"`
	ControlID   string      `json:"control-id"`
	Description string      `json:"description"`
	Props       []oscalProp `json:"props,omitempty"`
}

// ─── KHEPRA Tool -> Control mapping (roadmap Section 4) ────────────────────────

// khepraTool is one row of the COMPLIANCE_AUDIT_ROADMAP.md Section 4 table,
// promoted to an OSCAL component with control-satisfaction claims.
type khepraTool struct {
	Name     string   // MCP/CLI tool name
	Produces string   // what the tool emits
	Controls []string // NIST 800-53 rev5 control-ids (lowercase, OSCAL form)
	CMMC     []string // CMMC L2 practice ids (for props)
	Artifact string   // date-stamped evidence artifact path pattern
}

// khepraToolCatalog mirrors the roadmap Section 4 table verbatim. It is the
// single source of truth for the generated component-definition.
var khepraToolCatalog = []khepraTool{
	{"pqc_stig", "PQC-01-STIG-V1R1 compliance report", []string{"sc-13", "sc-8"}, []string{"SC.L2-3.13.8"}, "evidence/pqc_stig_YYYYMMDD.json"},
	{"ert_crypto", "Weak crypto inventory + PQC migration plan", []string{"sc-12"}, []string{"SC.L2-3.13.8"}, "evidence/crypto_inventory_YYYYMMDD.json"},
	{"ert_scan", "SBOM + CVE scan + remediation roadmap", []string{"sa-12", "sr-3"}, []string{"SR.L2-3.14"}, "evidence/sbom_YYYYMMDD.json"},
	{"ert_readiness", "NIST 800-171 gap analysis", []string{"ca-2", "ca-5"}, []string{"CA.L2-3.12.1"}, "evidence/nist171_gaps_YYYYMMDD.json"},
	{"stig_check", "CAT I/II/III findings", []string{"cm-6"}, []string{"CM.L2-3.4.1"}, "evidence/stig_findings_YYYYMMDD.json"},
	{"vuln_scan", "Dependency CVE report", []string{"ra-5", "si-2"}, []string{"RA.L2-3.11.2"}, "evidence/vuln_scan_YYYYMMDD.json"},
	{"container_scan", "Dockerfile misconfig + base image vulns", []string{"cm-7", "sa-12"}, []string{"CM.L2-3.4.6"}, "evidence/container_scan_YYYYMMDD.json"},
	{"secret_scan", "Hardcoded credential detection", []string{"ia-5"}, []string{"IA.L2-3.5.7"}, "evidence/secret_scan_YYYYMMDD.json"},
	{"audit_collect", "Process list + system state snapshot", []string{"au-12"}, []string{"AU.L2-3.3.1"}, "evidence/audit_collect_YYYYMMDD.json"},
	{"threat_model", "STRIDE analysis + MITRE ATT&CK mapping", []string{"ra-3"}, []string{"RA.L2-3.11.1"}, "evidence/threat_model_YYYYMMDD.json"},
	{"owasp_agent_assess", "Agentic AI Top 10 + MCP-specific risks", []string{"si-7"}, []string{"SI.L2-3.14.7"}, "evidence/agent_assess_YYYYMMDD.json"},
	{"dag_write", "Tamper-evident attestation chain", []string{"au-9", "au-12"}, []string{"AU.L2-3.3.1"}, "evidence/dag_attestation_YYYYMMDD.json"},
	{"drift_detect", "Configuration drift vs baseline", []string{"cm-6", "cm-8"}, []string{"CM.L2-3.4.1"}, "evidence/drift_YYYYMMDD.json"},
	{"kasa_start", "Continuous threat hunting / daily pentest", []string{"ca-8"}, []string{"CA.L2-3.12.1"}, "evidence/kasa_YYYYMMDD.json"},
}

// ─── Public API ───────────────────────────────────────────────────────────────

// OSCALAssessmentResults renders the package findings as an OSCAL 1.1.2
// assessment-results document (indented JSON). This is the artifact the audit
// enclave's trestle pipeline assembles into a Security Assessment Report.
func OSCALAssessmentResults(pkg *C3PAOPackage) ([]byte, error) {
	return json.MarshalIndent(buildAssessmentResults(pkg), "", "  ")
}

// OSCALComponentDefinition renders the KHEPRA Tool -> Control mapping as an
// OSCAL 1.1.2 component-definition (indented JSON). It is package-independent;
// `generated` stamps metadata timestamps.
func OSCALComponentDefinition(generated time.Time) ([]byte, error) {
	return json.MarshalIndent(buildComponentDefinition(generated), "", "  ")
}

// ─── Builders ─────────────────────────────────────────────────────────────────

func buildAssessmentResults(pkg *C3PAOPackage) oscalAssessmentResults {
	var doc oscalAssessmentResults
	ar := &doc.AssessmentResults
	ar.UUID = uuidV5("assessment-results:" + pkg.PackageID)
	ar.Metadata = oscalMetadata{
		Title:        "KHEPRA ERT Assessment Results — " + pkg.Target,
		Published:    pkg.Generated,
		LastModified: pkg.Generated,
		Version:      pkg.PackageID,
		OscalVersion: oscalVersion,
		Props: []oscalProp{
			{Name: "tool", Value: "KHEPRA ERT v2.0"},
			{Name: "patent", Value: "USPTO #73565085"},
			{Name: "algorithm", Value: "ML-DSA-65 / FIPS 204"},
			{Name: "framework", Value: pkg.Framework},
			{Name: "sprs-score", Value: fmt.Sprintf("%d", pkg.SPRS.Score)},
			{Name: "manifest-signature", Value: pkg.ManifestSignature},
		},
	}
	ar.ImportAP = oscalHref{Href: "./khepra-assessment-plan.json"}

	result := oscalARResult{
		UUID:        uuidV5("result:" + pkg.PackageID),
		Title:       "KHEPRA Automated Assessment",
		Description: "Automated Examine+Test assessment produced by KHEPRA ERT and sealed to the immutable KHEPRA DAG via ML-DSA-65 (FIPS 204).",
		Start:       pkg.Generated,
	}

	// Deduplicate reviewed controls.
	seen := map[string]bool{}
	for _, f := range pkg.Findings {
		cid := controlID(f)
		if cid == "" || seen[cid] {
			continue
		}
		seen[cid] = true
		result.ReviewedControls.ControlSelections = append(
			result.ReviewedControls.ControlSelections,
			oscalControlSelection{IncludeControls: []oscalIncludeControl{{ControlID: cid}}},
		)
	}
	if len(result.ReviewedControls.ControlSelections) == 0 {
		result.ReviewedControls.ControlSelections = []oscalControlSelection{
			{Description: "No control-mapped findings in this assessment."},
		}
	}

	for _, f := range pkg.Findings {
		obsUUID := uuidV5("observation:" + pkg.PackageID + ":" + f.ID)
		findUUID := uuidV5("finding:" + pkg.PackageID + ":" + f.ID)
		cid := controlID(f)

		result.Observations = append(result.Observations, oscalObservation{
			UUID:        obsUUID,
			Title:       f.Title,
			Description: firstNonEmpty(f.Detail, f.Title),
			Methods:     []string{"TEST"},
			Types:       []string{"finding"},
			Collected:   collectedAt(f, pkg.Generated),
			RelevantEvidence: []oscalRelevantEvidence{
				{Href: "./04-findings.json", Description: "KHEPRA finding record (ML-DSA-65 signed)"},
				{Description: "attest-hash: " + f.AttestHash},
			},
		})

		result.Findings = append(result.Findings, oscalARFinding{
			UUID:        findUUID,
			Title:       fmt.Sprintf("%s — %s", f.ID, f.Title),
			Description: firstNonEmpty(f.Remediation, "See related observation for technical detail and remediation."),
			Props:       findingProps(f),
			Target: oscalFindingTarget{
				Type:     "objective-id",
				TargetID: cid,
				Status:   oscalTargetStatus{State: "not-satisfied", Reason: f.RejectPattern},
			},
			RelatedObservations: []oscalRelatedObs{{ObservationUUID: obsUUID}},
		})
	}

	ar.Results = []oscalARResult{result}
	return doc
}

func buildComponentDefinition(generated time.Time) oscalComponentDefinition {
	var doc oscalComponentDefinition
	cd := &doc.ComponentDefinition
	cd.UUID = uuidV5("component-definition:khepra-ert")
	cd.Metadata = oscalMetadata{
		Title:        "KHEPRA ERT Tool → Control Component Definition",
		Published:    generated,
		LastModified: generated,
		Version:      "2.0",
		OscalVersion: oscalVersion,
		Props: []oscalProp{
			{Name: "tool", Value: "KHEPRA ERT v2.0"},
			{Name: "patent", Value: "USPTO #73565085"},
			{Name: "source", Value: "COMPLIANCE_AUDIT_ROADMAP.md Section 4"},
		},
	}

	for _, t := range khepraToolCatalog {
		reqs := make([]oscalImplementedReq, 0, len(t.Controls))
		for _, c := range t.Controls {
			reqs = append(reqs, oscalImplementedReq{
				UUID:        uuidV5("implreq:" + t.Name + ":" + c),
				ControlID:   c,
				Description: fmt.Sprintf("KHEPRA `%s` produces %s, providing continuous technical evidence for %s.", t.Name, t.Produces, strings.ToUpper(c)),
				Props: []oscalProp{
					{Name: "evidence-artifact", Value: t.Artifact},
					{Name: "cmmc-practice", Value: strings.Join(t.CMMC, ", ")},
				},
			})
		}
		cd.Components = append(cd.Components, oscalComponent{
			UUID:        uuidV5("component:" + t.Name),
			Type:        "software",
			Title:       "KHEPRA " + t.Name,
			Description: t.Produces,
			Props: []oscalProp{
				{Name: "tool-name", Value: t.Name},
				{Name: "provider", Value: "NouchiX / SecRed Knowledge Inc."},
			},
			ControlImplementations: []oscalControlImpl{{
				UUID:                    uuidV5("controlimpl:" + t.Name),
				Source:                  srcNIST80053,
				Description:             fmt.Sprintf("Control satisfaction claims for the %s tool.", t.Name),
				ImplementedRequirements: reqs,
			}},
		})
	}
	return doc
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// controlID picks the OSCAL control-id for a finding: prefer the NIST 800-171
// reference, else a lowercased finding ID (which is typically an 800-53 id).
func controlID(f Finding) string {
	if strings.TrimSpace(f.NIST) != "" {
		return strings.TrimSpace(f.NIST)
	}
	return strings.ToLower(strings.TrimSpace(f.ID))
}

func findingProps(f Finding) []oscalProp {
	props := []oscalProp{
		{Name: "severity", Value: f.Severity},
		{Name: "sprs-points", Value: fmt.Sprintf("%d", f.SPRSPoints)},
		{Name: "poam-eligible", Value: fmt.Sprintf("%t", f.POAMEligible)},
	}
	if f.CMMCPractice != "" {
		props = append(props, oscalProp{Name: "cmmc-practice", Value: f.CMMCPractice})
	}
	if f.CCI != "" {
		props = append(props, oscalProp{Name: "cci", Value: f.CCI})
	}
	if f.MITRETechnique != "" {
		props = append(props, oscalProp{Name: "mitre-technique", Value: f.MITRETechnique})
	}
	if f.RejectPattern != "" {
		props = append(props, oscalProp{Name: "c3pao-reject-pattern", Value: f.RejectPattern})
	}
	if f.AttestHash != "" {
		props = append(props, oscalProp{Name: "attest-hash", Value: f.AttestHash, Class: "ml-dsa-65"})
	}
	return props
}

func collectedAt(f Finding, fallback time.Time) time.Time {
	if !f.SignedAt.IsZero() {
		return f.SignedAt
	}
	return fallback
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// uuidV5 returns a deterministic RFC 4122 v5 UUID (SHA-1) over a fixed KHEPRA
// namespace and the given name, so identical package state yields identical
// OSCAL for clean audit-enclave diffs.
func uuidV5(name string) string {
	// Fixed KHEPRA evidence namespace (ASCII "khepra-evidence!").
	ns := []byte{0x6b, 0x68, 0x65, 0x70, 0x72, 0x61, 0x2d, 0x65, 0x76, 0x69, 0x64, 0x65, 0x6e, 0x63, 0x65, 0x21}
	h := sha1.New()
	h.Write(ns)
	h.Write([]byte(name))
	s := h.Sum(nil)
	var u [16]byte
	copy(u[:], s[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
