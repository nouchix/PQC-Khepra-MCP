package connectors

import (
	"time"
)

// =============================================================================
// AI AGENT ENVIRONMENT CONNECTOR INTERFACE
// Extends the existing connectors package with AI agent discovery capabilities.
// All connectors default to read-only. Write operations (credential revocation)
// require Autonomous=true + Khepra ASAF attestation.
// Supports: AWS, GCP, Azure, GitHub, Slack, Salesforce, Okta, Snowflake,
//           OpenAI, Kubernetes, Windows and any future platform.
// =============================================================================

// AgentSummary is a lightweight agent record returned by DiscoverAgents.
type AgentSummary struct {
	ID           string   // Platform-scoped agent identifier
	Name         string   // Human-readable name
	AgentType    string   // "openai-assistant", "claude", "langchain", "mcp-server", "shadow", etc.
	Environment  string   // Platform name (matches connector Platform())
	RiskScore    float64  // 0.0 (low) → 1.0 (critical)
	Permissions  []string // Known permission scopes
	LastSeen     time.Time
	Managed      bool // true = Khepra-provisioned, false = discovered externally
	PQCProtected bool // true = has valid Adinkhepra PQC attestation
}

// NHISummary is a lightweight NHI record for connector-level discovery.
type NHISummary struct {
	ID        string     // Credential identifier
	Type      string     // "api-key", "oauth-token", "service-account", "pat"
	Owner     string     // Agent/user that holds this credential
	Platform  string     // Issuing platform
	Scopes    []string   // Granted permission scopes
	ExpiresAt *time.Time // nil = never expires
	RiskScore float64
}

// AgentEnvironmentConnector is the interface every platform connector must implement.
// Implementations MUST be thread-safe and default to read-only operations.
type AgentEnvironmentConnector interface {
	// Name returns a human-readable connector name (e.g. "Kubernetes Connector").
	Name() string

	// Platform returns the platform identifier (e.g. "k8s", "aws", "github").
	Platform() string

	// DiscoverAgents scans the environment for AI agent processes / resources.
	DiscoverAgents() ([]AgentSummary, error)

	// DiscoverNHIs scans for machine credentials (API keys, tokens, service accounts).
	DiscoverNHIs() ([]NHISummary, error)

	// RevokeCredential revokes a credential by ID.
	// Returns ErrReadOnly if IsReadOnly() is true and Autonomous mode is not set.
	RevokeCredential(id string) error

	// IsReadOnly returns true if the connector operates in read-only/discovery mode.
	IsReadOnly() bool
}

// ErrReadOnly is returned when a write operation is attempted on a read-only connector.
const ErrReadOnly = connectorError("connector is in read-only mode; set Autonomous=true to enable write operations")

type connectorError string

func (e connectorError) Error() string { return string(e) }

// ConnectorRegistry holds all registered environment connectors.
type ConnectorRegistry struct {
	connectors []AgentEnvironmentConnector
}

// NewConnectorRegistry creates an empty registry.
func NewConnectorRegistry() *ConnectorRegistry {
	return &ConnectorRegistry{}
}

// Register adds a connector to the registry.
func (r *ConnectorRegistry) Register(c AgentEnvironmentConnector) {
	r.connectors = append(r.connectors, c)
}

// DiscoverAll runs DiscoverAgents on all registered connectors and merges results.
func (r *ConnectorRegistry) DiscoverAll() ([]AgentSummary, error) {
	var all []AgentSummary
	for _, c := range r.connectors {
		agents, err := c.DiscoverAgents()
		if err != nil {
			continue // log and continue — partial results are better than none
		}
		all = append(all, agents...)
	}
	return all, nil
}

// DiscoverAllNHIs runs DiscoverNHIs on all registered connectors.
func (r *ConnectorRegistry) DiscoverAllNHIs() ([]NHISummary, error) {
	var all []NHISummary
	for _, c := range r.connectors {
		nhis, err := c.DiscoverNHIs()
		if err != nil {
			continue
		}
		all = append(all, nhis...)
	}
	return all, nil
}
