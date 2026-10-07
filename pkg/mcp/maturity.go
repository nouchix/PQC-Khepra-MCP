// Package mcp — maturity.go
//
// Every public tool carries an implementation status and a Technology
// Readiness Level (TRL), published in tools/list under
// _meta["com.nouchix/maturity"]. Status values:
//
//	real         does the work its description states, on real inputs
//	partial      real code path with narrow coverage, a missing data source,
//	             or behaviour that depends on configuration
//	in_progress  no implementation in this build; calls return an error
//
// TRL follows the DoD TRA scale read for software: 2 = concept only,
// 3 = engine-backed proof of concept, 4 = unit-validated with an oracle.
// A tool's TRL may only rise with oracle-backed tests at that level.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
package mcp

import "fmt"

// ToolMaturity is a tool's implementation status and TRL.
type ToolMaturity struct {
	Status string `json:"status"`
	TRL    int    `json:"trl"`
	Note   string `json:"note,omitempty"`
}

const (
	MaturityReal       = "real"
	MaturityPartial    = "partial"
	MaturityInProgress = "in_progress"

	// MaturityMetaKey is the tools/list _meta key carrying ToolMaturity.
	MaturityMetaKey = "com.nouchix/maturity"

	// InProgressPrefix starts the description of every in_progress tool.
	InProgressPrefix = "[Implementation in progress — returns an error in this build] "
)

func mReal(note string) ToolMaturity { return ToolMaturity{Status: MaturityReal, TRL: 3, Note: note} }
func mPartial(note string) ToolMaturity {
	return ToolMaturity{Status: MaturityPartial, TRL: 3, Note: note}
}
func mInProgress(note string) ToolMaturity {
	return ToolMaturity{Status: MaturityInProgress, TRL: 2, Note: note}
}

const auditPending = "engine-backed; per-tool audit and oracle validation pending"

// toolMaturity covers every tool in the public manifest. Tools absent from
// this table (for example, ones registered by private builds) are neither
// listed with maturity nor blocked by it.
var toolMaturity = map[string]ToolMaturity{
	// Write gate and non-human identity
	"acp_status": mReal(""), "acp_issue": mReal(""), "acp_revoke": mReal(""),
	"nhi_inventory": mPartial("lists only identities registered with the tracker"),
	"nhi_orphans":   mPartial("lists only identities registered with the tracker"),
	"nhi_excessive": mPartial("lists only identities registered with the tracker"),
	"nhi_expired":   mPartial("lists only identities registered with the tracker"),
	"nhi_revoke":    mPartial("revokes only identities registered with the tracker"),

	// ERT
	"ert_scan": mPartial(auditPending), "ert_readiness": mPartial(auditPending),
	"ert_architect": mPartial(auditPending), "ert_crypto": mReal("source and SBOM crypto inventory"),
	"ert_godfather": mPartial(auditPending),

	// Compliance
	"stig_check":                  mPartial("executable checks cover a small subset of RHEL 9 rules"),
	"pqc_stig":                    mPartial("PQC-01-STIG is a NouchiX control set, not a DISA STIG"),
	"cmmc_assess":                 mPartial("practices without evidence are Not Assessed; rule coverage is narrow"),
	"nist_map":                    mPartial("built-in control data; crosswalk validation pending"),
	"khepra_query_stig":           mReal("embedded STIG/CCI/NIST crosswalk"),
	"khepra_get_compliance_score": mPartial("limited by STIG rule coverage"),
	"khepra_export_attestation":   mPartial("limited by STIG rule coverage"),
	"khepra_export_poam":          mPartial("limited by STIG rule coverage"),
	"asaf_lint":                   mInProgress("no handler in this build"),
	"compliance_model_check":      mInProgress("no handler in this build"),

	// Evidence, DAG, flight recorder
	"dag_attestation":      mPartial(auditPending),
	"khepra_get_dag_chain": mReal(""),
	"dag_write":            mPartial(auditPending),
	"dag_query":            mReal(""),
	"dag_audit":            mPartial("checks required fields only; hashes, parent links and signatures are not verified"),
	"audit_dag_integrity":  mPartial("deprecated alias of dag_audit; checks required fields only"),
	"agent_record":         mPartial("local capture depends on the configured attestor; remote forwarding is optional"),
	"flight_record":        mPartial(auditPending),
	"flight_export":        mPartial("packages only findings derived from recorded frames"),
	"attest_export":        mPartial("packages only findings from a real scan"),

	// Threat intelligence and analysis
	"khepra_query_threat_intel": mPartial("requires the offline CVE database (data/cve-database)"),
	"threat_lookup":             mPartial("searches the built-in knowledge base only"),
	"threat_model":              mPartial("STRIDE catalogue derived from the project profile"),
	"godfather_report":          mInProgress("report generation needs a connected DAG and real findings"),
	"godfather_approve":         mPartial("approves staged reports; report generation is in progress"),
	"attack_graph":              mReal(""),

	// KASA, EA, quantum
	"kasa_start": mPartial(auditPending), "kasa_status": mPartial(auditPending),
	"kasa_task": mPartial(auditPending), "kasa_scan": mPartial(auditPending),
	"kasa_forensics": mPartial(auditPending), "kasa_crypto_agent": mPartial(auditPending),
	"ea_evolve": mReal(""), "ea_threat_score": mReal(""), "ea_risk_summary": mReal(""),
	"quantum_optimize": mPartial("classical simulated annealing; no tests yet"),

	// Monitoring
	"khepra_watch":       mPartial(auditPending),
	"drift_detect":       mInProgress("compared two empty snapshots; real baseline comparison pending"),
	"fim_baseline":       mPartial(auditPending),
	"ouroboros_waf_eye":  mPartial("lists recorded DAG events; not a live monitor"),
	"ouroboros_stig_eye": mPartial("lists recorded DAG events; not a live monitor"),
	"ouroboros_vuln_eye": mPartial("lists recorded DAG events; not a live monitor"),
	"ouroboros_fim_eye":  mPartial("lists recorded DAG events; not a live monitor"),

	// IR
	"ir_incident": mReal(""),
	"ir_add_ioc":  mPartial("IOC entries are signed with an ephemeral key"),

	// Host, scanning, forensics
	"discover_assets": mReal(""), "enumerate_host": mReal(""), "fingerprint_device": mReal(""),
	"port_scan":              mReal(""),
	"forensic_snapshot":      mPartial(auditPending),
	"vuln_scan":              mPartial("matches manifests against a small built-in CVE table"),
	"secret_scan":            mPartial("five regex rules"),
	"container_scan":         mPartial("Dockerfile lint only; image layers are not inspected"),
	"compliance_scan":        mPartial("four built-in checks"),
	"packet_analyze":         mPartial(auditPending),
	"sbom_generate":          mReal("uses syft when installed, otherwise a filesystem walk; the mode is reported"),
	"owasp_agent_assess":     mPartial(auditPending),
	"agent_scan":             mPartial(auditPending),
	"dark_crypto_contribute": mPartial(auditPending),

	// PQC primitives
	"pqc_sign": mReal(""), "pqc_verify": mReal(""), "pqc_keygen": mReal(""),

	// Backup and orchestration
	"drbc_backup": mReal("KHQ3 envelope"), "drbc_restore": mReal("KHQ3 envelope"),
	"khepra_edge_exec": mInProgress("no handler in this build"),
	"playbook_execute": mInProgress("no handler in this build"),

	// Upstream proxies
	"stripe_call": mReal("proxies the Stripe MCP server"),
	"mcp_gateway": mReal("proxies a configured upstream MCP server"),
}

// MaturityOf returns the maturity of a public tool and whether it is listed.
func MaturityOf(name string) (ToolMaturity, bool) {
	if m, ok := toolMaturity[name]; ok {
		return m, true
	}
	return providedMaturityOf(name)
}

// ErrInProgress is returned for a tool with no implementation in this build.
func ErrInProgress(name string) error {
	return fmt.Errorf("%s: implementation in progress — this build does not produce results for this tool", name)
}

// inProgress reports whether name is listed as in_progress.
func inProgress(name string) bool {
	m, ok := MaturityOf(name)
	return ok && m.Status == MaturityInProgress
}
