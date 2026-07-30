// Package evidence implements the KHEPRA C3PAO Evidence Package generator.
//
// It produces a forensic-grade, 13-artifact ZIP that satisfies the CMMC
// Assessment Process (CAP) v2.0 Examine+Interview+Test evidence standard.
// Every artifact is ML-DSA-65 signed and linked to the immutable KHEPRA DAG.
//
// The package is a shared dependency across all three NouchiX product surfaces:
//   - AdinKhepra ASAF (CLI: ert full --evidence-zip)
//   - PQC-Khepra-MCP (MCP tool: attest_export)
//   - SouHimBou AI   (Flight recorder: recorder.ExportEvidencePackage)
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
// Patent: USPTO #73565085 (KHEPRA Protocol)
package evidence

import "time"

// ─── Rejection pattern constants (per CUOPS intel 2026-07-07) ─────────────────

const (
	RejectPaperTiger   = "PAPER_TIGER"    // Policy exists, no technical proof
	RejectScopeGap     = "SCOPE_GAP"      // Asset inventory doesn't match live env
	RejectHygiene      = "HYGIENE"        // Undated, unmapped, or stale artifacts
	RejectHistoryGap   = "HISTORY_GAP"    // Insufficient log retention / review records
	RejectPOAMIneligible = "POAM_INELIGIBLE" // Non-POA&M control partially implemented
)

// ─── Core types ───────────────────────────────────────────────────────────────

// Finding is a single CMMC/STIG violation mapped to its full C3PAO context.
// This is the canonical finding type for all evidence exports.
type Finding struct {
	// Identity
	ID    string `json:"id"`    // e.g. "SC-13", "SI-10"
	Title string `json:"title"` // Human-readable title

	// Severity & POA&M eligibility (per NIST SP 800-171 DoD Assessment)
	Severity     string `json:"severity"`      // "CAT I" | "CAT II" | "CAT III"
	POAMEligible bool   `json:"poam_eligible"` // false = NON-POA&M (immediate failure)
	SPRSPoints   int    `json:"sprs_points"`   // 1 | 3 | 5 (DoD Assessment weight)

	// C3PAO rejection pattern this finding addresses
	RejectPattern string `json:"reject_pattern"` // PAPER_TIGER | SCOPE_GAP | HYGIENE | ...

	// Financial impact
	ExposureUSD    float64 `json:"exposure_usd"`
	RemediationUSD float64 `json:"remediation_usd,omitempty"`

	// Framework mapping (Examine evidence layer)
	CMMCPractice   string `json:"cmmc_practice"`    // e.g. "CMMC.SC.L2-3.13.10"
	NIST           string `json:"nist_800_171"`     // e.g. "3.13.10"
	CCI            string `json:"cci"`              // e.g. "CCI-002450"
	MITRETechnique string `json:"mitre_technique"`  // e.g. "T1110"

	// Technical detail (Test evidence layer)
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`

	// Attestation (every finding is ML-DSA-65 signed)
	AttestHash string    `json:"attest_hash"` // SHA3-256 over finding content
	SignedAt   time.Time `json:"signed_at"`
	SignedBy   string    `json:"signed_by"` // "ML-DSA-65 / FIPS 204"
}

// DAGNode is a single node in the KHEPRA immutable DAG, serialized for evidence.
type DAGNode struct {
	Index      int       `json:"index"`
	Label      string    `json:"label"`
	Type       string    `json:"type"`        // "genesis" | "flight" | "finding" | "cert"
	Hash       string    `json:"hash"`        // SHA-256 content-addressed
	ParentHash string    `json:"parent_hash"` // "GENESIS" for first node
	Timestamp  time.Time `json:"timestamp"`
	SignedBy   string    `json:"signed_by"`
}

// FlightFrame is one entry from the SouHimBou AI Flight Recorder.
type FlightFrame struct {
	Index       int       `json:"frame_index"`
	Tool        string    `json:"tool"`
	Type        string    `json:"type"`
	Outcome     string    `json:"outcome"` // "OutcomeSuccess" | "OutcomeError"
	DAGNodeID   string    `json:"dag_node_id"`
	FrameHash   string    `json:"frame_hash"`
	Signature   string    `json:"signature"`
	Timestamp   time.Time `json:"timestamp"`
}

// AssetRecord is one discovered asset from Package C (Sonar).
type AssetRecord struct {
	AssetID         string `json:"asset_id"`
	Hostname        string `json:"hostname"`
	IPAddress       string `json:"ip_address"`
	OS              string `json:"os"`
	Role            string `json:"role"`
	CUIHandler      bool   `json:"cui_handler"`
	InScope         bool   `json:"in_scope"`
	DiscoveryMethod string `json:"discovery_method"`
}

// ESP is an External Service Provider identified by Sonar.
type ESP struct {
	Name             string   `json:"name"`
	Service          string   `json:"service"`
	CUIExposure      bool     `json:"cui_exposure"`
	ResponsibilityOwner string `json:"responsibility_owner"` // "ESP" | "Organization"
	InheritedControls []string `json:"inherited_controls"`
}

// Personnel is a person to be interviewed during the C3PAO assessment.
type Personnel struct {
	Name              string   `json:"name"`
	Title             string   `json:"title"`
	ControlsResponsible []string `json:"controls_responsible"`
}

// TrainingRecord is an AT control evidence entry.
type TrainingRecord struct {
	Role              string    `json:"role"`
	TrainingCompleted string    `json:"training_completed"`
	CompletedAt       time.Time `json:"completed_at"`
	AttestHash        string    `json:"attest_hash"`
}

// SPRSResult is the calculated SPRS score for DoD portal submission.
type SPRSResult struct {
	Score         int            `json:"score"`          // -203 to 110
	MaxScore      int            `json:"max_score"`      // 110
	Deduction     int            `json:"deduction"`      // points subtracted
	UniqueNIST    int            `json:"unique_nist_practices_failed"`
	Threshold     int            `json:"threshold"`      // 110 for CMMC L2
	PassFail      string         `json:"pass_fail"`      // "PASS" | "FAIL"
	Breakdown     []SPRSLine     `json:"breakdown"`      // per unique practice
}

// SPRSLine is one row in the SPRS score breakdown table.
type SPRSLine struct {
	NISTRef   string `json:"nist_800_171"`
	Control   string `json:"cmmc_practice"`
	Severity  string `json:"severity"`
	Points    int    `json:"points_deducted"`
	FindingID string `json:"finding_id"`
	Title     string `json:"title"`
}

// C3PAOPackage is the complete evidence package metadata.
// The actual artifacts are written to disk by Builder.
type C3PAOPackage struct {
	PackageID string    `json:"package_id"`
	Generated time.Time `json:"generated_at"`

	// Target
	Target    string `json:"target"`
	Framework string `json:"framework"` // "CMMC Level 2 / NIST SP 800-171 Rev2"

	// Findings
	Findings []Finding `json:"findings"`

	// DAG + flight
	DAGNodes     []DAGNode     `json:"dag_nodes"`
	FlightFrames []FlightFrame `json:"flight_frames,omitempty"`

	// Assets + ESPs (from Sonar)
	Assets []AssetRecord `json:"assets,omitempty"`
	ESPs   []ESP         `json:"esps,omitempty"`

	// Personnel (Interview layer)
	Personnel       []Personnel      `json:"personnel,omitempty"`
	TrainingRecords []TrainingRecord `json:"training_records,omitempty"`

	// Computed scores
	SPRS           SPRSResult `json:"sprs"`
	TotalExposure  float64    `json:"total_exposure_usd"`
	RemediationCost float64   `json:"remediation_cost_usd"`
	ROI            int        `json:"roi_multiple"`

	// Output
	ZipPath          string `json:"zip_path"`
	ArtifactCount    int    `json:"artifact_count"`
	ManifestSignature string `json:"manifest_signature"`
}

// BuildConfig controls what the Builder generates.
type BuildConfig struct {
	// Required
	Findings []Finding
	DAGNodes []DAGNode
	Target   string

	// Optional — enriches the package
	FlightFrames    []FlightFrame
	Assets          []AssetRecord
	ESPs            []ESP
	Personnel       []Personnel
	TrainingRecords []TrainingRecord

	// Output
	OutputDir  string // where to write the ZIP (default: ".")
	Framework  string // default: "CMMC Level 2 / NIST SP 800-171 Rev2"

	// Signing
	PrivKey []byte // ML-DSA-65 private key for manifest signature
	PubKey  []byte // ML-DSA-65 public key (hex-encoded in manifest)
}
