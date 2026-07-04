// Package fleet implements the ASAF Fleet Manager — the sovereign asset registry
// and CUI boundary declaration engine for CMMC Phase 1 (SCOPE).
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package fleet

import (
	"time"
)

// ── Asset ─────────────────────────────────────────────────────────────────────

// Protocol specifies the management protocol for an asset.
type Protocol string

const (
	ProtocolSSH   Protocol = "ssh"
	ProtocolWinRM Protocol = "winrm"
	ProtocolAPI   Protocol = "api"
	ProtocolSNMP  Protocol = "snmp"
)

// DeviceType classifies the physical/virtual nature of an asset.
type DeviceType string

const (
	DeviceServer      DeviceType = "server"
	DeviceWorkstation DeviceType = "workstation"
	DeviceNetwork     DeviceType = "network"   // firewall, switch, router
	DeviceCloud       DeviceType = "cloud"     // EC2, RDS, Lambda, etc.
	DeviceOT          DeviceType = "ot"        // OT/SCADA/ICS/IoT
	DeviceContainer   DeviceType = "container" // Docker/k8s workload
)

// CMMCCategory defines an asset's CMMC scoping classification
// per the CMMC Level 2 Scoping Guide (DoD Instruction 8582.01).
type CMMCCategory string

const (
	// CUIAsset — directly processes, transmits, or stores CUI.
	// MUST achieve CMMC Level 2 compliance.
	CUIAsset CMMCCategory = "cui"

	// SecurityProtectionAsset — protects CUI assets (IAM, firewalls, SIEM).
	// MUST achieve CMMC Level 2 compliance.
	SecurityProtectionAsset CMMCCategory = "security"

	// ContractorRiskManaged — shares network with CUI systems but doesn't
	// directly handle CUI. Must achieve at minimum CMMC Level 1.
	ContractorRiskManaged CMMCCategory = "crm"

	// OutOfScope — fully isolated from CUI (air-gapped VLAN, no CUI contact).
	// Excluded from CMMC scope.
	OutOfScope CMMCCategory = "out_of_scope"

	// Specialized — OT/SCADA/IoT in-scope if CUI-adjacent.
	Specialized CMMCCategory = "specialized"

	// Unclassified — newly enrolled, awaiting classification by operator.
	Unclassified CMMCCategory = "unclassified"
)

// AuthMethod defines the credential type used to authenticate to an asset.
type AuthMethod string

const (
	AuthPassword AuthMethod = "password"
	AuthSSHKey   AuthMethod = "key"
	AuthKerberos AuthMethod = "kerberos"
	AuthCert     AuthMethod = "cert"
	AuthAPIKey   AuthMethod = "api_key"
	AuthIAMRole  AuthMethod = "iam_role"
)

// ConnectionProfile captures the parameters needed to establish a management
// session to an asset. Credentials are stored by reference (cred_ref) into
// the KHEPRA Credential Store — never in cleartext here.
type ConnectionProfile struct {
	Protocol   Protocol   `json:"protocol"`
	Port       int        `json:"port"`
	Username   string     `json:"username,omitempty"`
	AuthMethod AuthMethod `json:"auth_method"`
	CredRef    string     `json:"cred_ref,omitempty"` // key into credential vault — never plaintext
	HostKeyFP  string     `json:"host_key_fp,omitempty"` // TOFU fingerprint (SSH)
	Timeout    int        `json:"timeout_s,omitempty"`   // connection timeout in seconds
}

// Asset represents a single managed endpoint in the ASAF fleet.
// ID is SHA-256(hostname+ip+port) for content-addressability.
type Asset struct {
	ID           string          `json:"id"`
	EnclaveID    string          `json:"enclave_id"`
	Name         string          `json:"name"`
	Hostname     string          `json:"hostname,omitempty"`
	IP           string          `json:"ip"`
	OS           string          `json:"os,omitempty"`          // "rhel9", "win2022", "ubuntu22"
	DeviceType   DeviceType      `json:"device_type,omitempty"`
	CMMCCategory CMMCCategory    `json:"cmmc_category"`
	STIGProfile  string          `json:"stig_profile,omitempty"` // auto-matched from OS
	ConnProfile  ConnectionProfile `json:"conn_profile"`
	Tags         []string        `json:"tags,omitempty"`
	Notes        string          `json:"notes,omitempty"`

	// Scan state
	LastScan    *time.Time `json:"last_scan,omitempty"`
	LastScore   *float64   `json:"last_score,omitempty"`   // 0.0–1.0 normalized
	SPRSImpact  *int       `json:"sprs_impact,omitempty"` // how many SPRS points this asset costs

	// DAG attestation
	DAGNodeID  string     `json:"dag_node_id,omitempty"`
	AttestedAt *time.Time `json:"attested_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`

	// Connectivity test result (not persisted — populated at runtime)
	ConnStatus string `json:"conn_status,omitempty"` // "ok", "auth_failed", "unreachable", "untested"
}

// ── Enclave ────────────────────────────────────────────────────────────────────

// Enclave is a named network segment within the customer's CUI boundary.
// Analogous to SecureCRT's session folder — groups assets for bulk operations.
type Enclave struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`         // "CUI Production Network"
	CIDRs       []string   `json:"cidrs"`        // ["10.0.1.0/24"]
	Environment string     `json:"environment"`  // "production", "staging", "dev"
	Description string     `json:"description,omitempty"`
	AssetIDs    []string   `json:"asset_ids"`
	SPRS        int        `json:"sprs"`         // aggregate SPRS for this enclave
	CreatedAt   time.Time  `json:"created_at"`
	AttestedAt  *time.Time `json:"attested_at,omitempty"`
	DAGNodeID   string     `json:"dag_node_id,omitempty"`
}

// ── PracticeStatus ─────────────────────────────────────────────────────────────

// PracticeStatus tracks the fleet-level status of a single CMMC practice.
// A practice is NOT MET if ANY in-scope CUI asset fails it.
type PracticeStatus struct {
	CMMCPractice string  `json:"cmmc_practice"` // "AC.L2-3.1.1"
	NISTControl  string  `json:"nist_control"`  // "AC-2"
	SPRSWeight   int     `json:"sprs_weight"`   // deduction from NIST SP 800-171A
	PassingCount int     `json:"passing_count"`
	FailingCount int     `json:"failing_count"`
	TotalCount   int     `json:"total_count"`
	Status       string  `json:"status"` // "met", "not_met", "partial", "unknown"
	BlastRadius  float64 `json:"blast_radius"` // failing_count/total_count — 0.0–1.0
}

// ── BoundaryDeclaration ────────────────────────────────────────────────────────

// BoundaryDeclaration is the ML-DSA-65 signed Phase 1 SCOPE output.
// This is the first node in the CMMC compliance DAG chain.
// The C3PAO assessor reviews this at the start of every assessment.
type BoundaryDeclaration struct {
	ID               string     `json:"id"`
	OrganizationName string     `json:"org_name"`
	CAGECode         string     `json:"cage_code,omitempty"`
	CMMCLevel        int        `json:"cmmc_level"` // 1, 2, or 3
	CUISPRS          int        `json:"cui_sprs"`   // aggregate SPRS across all CUI assets
	TotalAssets      int        `json:"total_assets"`
	InScopeAssets    int        `json:"in_scope_assets"`
	Enclaves         []Enclave  `json:"enclaves"`
	Practices        []PracticeStatus `json:"practices,omitempty"`
	AssetRosterHash  string     `json:"asset_roster_hash"` // SHA-256 of sorted asset list
	DeclaredBy       string     `json:"declared_by"`       // operator identity
	DeclaredAt       time.Time  `json:"declared_at"`
	Signature        []byte     `json:"signature"` // ML-DSA-65 over canonical JSON
	PublicKeyHex     string     `json:"pub_key_hex,omitempty"`
	DAGNodeID        string     `json:"dag_node_id"`
}

// ── Simulation ────────────────────────────────────────────────────────────────

// BoundaryCostSimulation models the SPRS impact of a proposed boundary change.
// "ASAF shows you what your boundary costs you in SPRS points before you lock it in."
type BoundaryCostSimulation struct {
	// Current state
	CurrentSPRS       int `json:"current_sprs"`
	CurrentAssetCount int `json:"current_asset_count"`

	// Proposed change
	AddAssetIDs    []string `json:"add_asset_ids,omitempty"`
	RemoveAssetIDs []string `json:"remove_asset_ids,omitempty"`

	// Computed impact
	ProjectedSPRS          int              `json:"projected_sprs"`
	SPRSDelta              int              `json:"sprs_delta"` // negative = points lost
	NewFailingPractices    []PracticeStatus `json:"new_failing_practices,omitempty"`
	RemovedFailures        []PracticeStatus `json:"removed_failures,omitempty"`
	EstimatedRemediationCost int64          `json:"estimated_remediation_cost_usd,omitempty"`
	Recommendation         string           `json:"recommendation,omitempty"`
}

// ── Import ────────────────────────────────────────────────────────────────────

// ImportResult is returned by the SecureCRT-style import wizard.
type ImportResult struct {
	Imported int           `json:"imported"`
	Skipped  int           `json:"skipped"`
	Errors   []ImportError `json:"errors,omitempty"`
	Assets   []*Asset      `json:"assets"`
}

// ImportError describes a row that failed to import.
type ImportError struct {
	Row     int    `json:"row"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// ── STIG Profile Auto-Matching ────────────────────────────────────────────────

// OSToSTIGProfile maps detected OS strings to their canonical STIG profile.
// Used for auto-suggestion during fleet enrollment.
var OSToSTIGProfile = map[string]string{
	"rhel9":    "RHEL-09-STIG",
	"rhel8":    "RHEL-08-STIG",
	"ubuntu22": "Ubuntu-22-STIG",
	"ubuntu20": "Ubuntu-20-STIG",
	"win2022":  "Windows-2022-STIG",
	"win2019":  "Windows-2019-STIG",
	"win11":    "Windows-11-STIG",
	"win10":    "Windows-10-STIG",
	"centos7":  "CentOS-7-STIG",
	"debian11": "Debian-11-STIG",
}

// PortToCMMCCategory suggests a CMMC category based on observable open ports.
// Used for AI-assisted asset classification during auto-discovery.
var PortToCMMCCategory = map[int]struct {
	Category   CMMCCategory
	Reason     string
}{
	22:   {SecurityProtectionAsset, "SSH management — likely security protection"},
	389:  {SecurityProtectionAsset, "LDAP — directory services (Security Protection Asset)"},
	636:  {SecurityProtectionAsset, "LDAPS — directory services"},
	443:  {CUIAsset, "HTTPS — likely handles CUI traffic"},
	3389: {CUIAsset, "RDP — Windows workstation/server, review for CUI"},
	5985: {SecurityProtectionAsset, "WinRM — management endpoint"},
	8443: {CUIAsset, "HTTPS alt — review for CUI handling"},
}
