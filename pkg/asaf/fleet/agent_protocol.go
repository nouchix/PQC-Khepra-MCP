// Package fleet implements the sovereign ASAF Fleet Manager and protocol.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package fleet

import "time"

// AgentRegistrationRequest represents the payload sent by an endpoint agent to register with the Hub.
type AgentRegistrationRequest struct {
	Action        string `json:"action"` // "enroll"
	Token         string `json:"token"`
	Hostname      string `json:"hostname"`
	IP            string `json:"ip"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	KernelVersion string `json:"kernel_version"`
	Enclave       string `json:"enclave"`
	PublicKeyHex  string `json:"public_key_hex,omitempty"`
}

// AgentRegistrationResponse is returned by the Hub after validating enrollment and minting a DAG node.
type AgentRegistrationResponse struct {
	OK           bool      `json:"ok"`
	AgentID      string    `json:"agent_id"`
	SessionToken string    `json:"session_token"`
	DAGNodeID    string    `json:"dag_node_id"`
	Signature    string    `json:"signature"`
	Status       string    `json:"status"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	Message      string    `json:"message"`
}

// AgentHeartbeat represents the periodic status and telemetry beacon sent by the agent.
type AgentHeartbeat struct {
	Action                string    `json:"action"` // "heartbeat"
	AgentID               string    `json:"agent_id"`
	Timestamp             time.Time `json:"timestamp"`
	ListeningPorts        []int     `json:"listening_ports"`
	FIPSEnabled           bool      `json:"fips_enabled"`
	PAMFaillockConfigured bool      `json:"pam_faillock_configured"`
	BitLockerActive       bool      `json:"bitlocker_active"`
	STIGScore             int       `json:"stig_score"` // 0-100
	Signature             string    `json:"signature"`  // ML-DSA-65 over posture digest
}

// FleetTask represents an ad-hoc or scheduled query sent to the agent (FleetDM/osquery style).
type FleetTask struct {
	TaskID    string `json:"task_id"`
	QueryType string `json:"query_type"` // "stig_check", "listening_ports", "user_audit"
	Command   string `json:"command,omitempty"`
	TimeoutS  int    `json:"timeout_s"`
}

// ComplianceCheckResult represents the structured findings returned by an agent after running a check.
type ComplianceCheckResult struct {
	AgentID     string    `json:"agent_id"`
	TaskID      string    `json:"task_id"`
	RuleID      string    `json:"rule_id"` // e.g. "RHEL-09-010010" or "CMMC-AC.L2-3.1.1"
	Status      string    `json:"status"`  // "PASS", "FAIL", "NOT_APPLICABLE"
	Evidence    string    `json:"evidence"`
	SPRSWeight  int       `json:"sprs_weight"`
	ExecutedAt  time.Time `json:"executed_at"`
	Attestation string    `json:"attestation"`
}

// ── Fleet-DM / Osquery Remote Fleet Integration Models ───────────────────────

// OsqueryEnrollRequest is the payload sent by standard osquery agents enrolling via TLS.
type OsqueryEnrollRequest struct {
	EnrollSecret   string `json:"enroll_secret"`
	HostIdentifier string `json:"host_identifier"`
	PlatformType   string `json:"platform_type,omitempty"`
	Platform       string `json:"platform,omitempty"`
	OsqueryVersion string `json:"osquery_version,omitempty"`
	HardwareUUID   string `json:"hardware_uuid,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	IP             string `json:"ip,omitempty"`
	EnclaveID      string `json:"enclave_id,omitempty"`
}

// OsqueryEnrollResponse is returned to osquery endpoints upon successful enrollment.
type OsqueryEnrollResponse struct {
	NodeKey     string `json:"node_key"`
	NodeInvalid bool   `json:"node_invalid"`
}

// OsqueryConfigRequest represents an osquery configuration pull.
type OsqueryConfigRequest struct {
	NodeKey string `json:"node_key"`
}

// OsqueryConfigResponse delivers sovereign query packs and schedule configs to osquery.
type OsqueryConfigResponse struct {
	Packs       map[string]OsqueryPack `json:"packs"`
	NodeInvalid bool                   `json:"node_invalid,omitempty"`
}

// OsqueryPack defines a collection of periodic queries.
type OsqueryPack struct {
	Queries map[string]OsqueryPackQuery `json:"queries"`
}

// OsqueryPackQuery is an individual SQL query within an osquery pack.
type OsqueryPackQuery struct {
	Query       string `json:"query"`
	Interval    int    `json:"interval"`
	Description string `json:"description,omitempty"`
}

// OsqueryDistributedReadRequest requests live queries to execute.
type OsqueryDistributedReadRequest struct {
	NodeKey string `json:"node_key"`
}

// OsqueryDistributedReadResponse delivers pending live queries to an osquery host.
type OsqueryDistributedReadResponse struct {
	Queries     map[string]string `json:"queries"`
	NodeInvalid bool              `json:"node_invalid,omitempty"`
}

// OsqueryDistributedWriteRequest receives live query execution results from osquery.
type OsqueryDistributedWriteRequest struct {
	NodeKey  string                         `json:"node_key"`
	Queries  map[string][]map[string]string `json:"queries"`
	Statuses map[string]int                 `json:"statuses"`
}

// OsqueryDistributedWriteResponse acknowledges distributed query results.
type OsqueryDistributedWriteResponse struct {
	NodeInvalid bool `json:"node_invalid,omitempty"`
}

// FleetHost is the unified sovereign Fleet-DM host representation.
type FleetHost struct {
	ID             string    `json:"id"`
	HostIdentifier string    `json:"host_identifier"`
	NodeKey        string    `json:"node_key"`
	Hostname       string    `json:"hostname"`
	IP             string    `json:"ip"`
	OS             string    `json:"os"`
	Platform       string    `json:"platform"`
	Arch           string    `json:"arch"`
	HardwareUUID   string    `json:"hardware_uuid"`
	HardwareModel  string    `json:"hardware_model"`
	EnclaveID      string    `json:"enclave_id"`
	Status         string    `json:"status"` // "online", "offline", "enrolled"
	STIGScore      int       `json:"stig_score"`
	SPRSScore      int       `json:"sprs_score"`
	FIPSEnabled    bool      `json:"fips_enabled"`
	ListeningPorts []int     `json:"listening_ports,omitempty"`
	LastSeen       time.Time `json:"last_seen"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	DAGNodeID      string    `json:"dag_node_id,omitempty"`
}
