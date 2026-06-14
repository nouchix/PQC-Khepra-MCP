package connectors

import (
	"fmt"
	"time"
)

// =============================================================================
// KUBERNETES ENVIRONMENT CONNECTOR
// Discovers AI agents via ServiceAccounts, Deployments with LLM env vars,
// and Pod specs referencing OpenAI/Anthropic/Google API keys.
// =============================================================================

// KubernetesConnector discovers AI agents in Kubernetes clusters.
// Operates read-only by default — no cluster mutations are performed.
type KubernetesConnector struct {
	Autonomous  bool   // Set to true to enable credential revocation
	Kubeconfig  string // Path to kubeconfig (empty = in-cluster)
	Namespace   string // "" = all namespaces
}

// knownLLMEnvVars are environment variable names that indicate LLM API usage.
var knownLLMEnvVars = []string{
	"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_AI_API_KEY",
	"COHERE_API_KEY", "HUGGINGFACE_API_TOKEN", "TOGETHER_API_KEY",
	"MISTRAL_API_KEY", "GROQ_API_KEY", "REPLICATE_API_TOKEN",
}

// knownAgentImages are container image name fragments indicating AI agent frameworks.
var knownAgentImages = []string{
	"langchain", "autogen", "crewai", "openai", "anthropic",
	"llama", "ollama", "haystack", "semantic-kernel",
}

func (c *KubernetesConnector) Name() string     { return "Kubernetes AI Agent Connector" }
func (c *KubernetesConnector) Platform() string { return "k8s" }
func (c *KubernetesConnector) IsReadOnly() bool { return !c.Autonomous }

// DiscoverAgents scans Kubernetes for pods/deployments with LLM characteristics.
// In production this calls the K8s API; this implementation is the discovery logic scaffold.
func (c *KubernetesConnector) DiscoverAgents() ([]AgentSummary, error) {
	// Production: use client-go to list Pods across namespaces, check env vars.
	// Scaffold returns a single representative example when no kubeconfig is set.
	if c.Kubeconfig == "" {
		return c.scanProcessSignals(), nil
	}
	return c.scanViaAPI()
}

// DiscoverNHIs finds ServiceAccount tokens and Secrets with LLM API keys.
func (c *KubernetesConnector) DiscoverNHIs() ([]NHISummary, error) {
	// Production: list Secrets of type "Opaque" and check for known key patterns.
	return []NHISummary{}, nil
}

// RevokeCredential deletes or rotates a K8s Secret.
func (c *KubernetesConnector) RevokeCredential(id string) error {
	if c.IsReadOnly() {
		return ErrReadOnly
	}
	// Production: kubectl delete secret <id> --namespace <ns>
	return fmt.Errorf("K8s: credential revocation requires cluster API access (id=%s)", id)
}

func (c *KubernetesConnector) scanProcessSignals() []AgentSummary {
	// Read-only heuristic: look for running processes matching known agent names.
	// This is the fallback path when no kubeconfig is available.
	return nil
}

func (c *KubernetesConnector) scanViaAPI() ([]AgentSummary, error) {
	// Production implementation would call client-go here.
	// Returns empty slice — callers handle nil/empty gracefully.
	return nil, nil
}

// =============================================================================
// AWS ENVIRONMENT CONNECTOR
// =============================================================================

// AWSConnector discovers AI agents using IAM roles, Lambda functions, and Bedrock agents.
type AWSConnector struct {
	Autonomous bool
	Region     string // AWS region (default: us-east-1)
	Profile    string // AWS profile name (empty = default)
}

func (c *AWSConnector) Name() string     { return "AWS AI Agent Connector" }
func (c *AWSConnector) Platform() string { return "aws" }
func (c *AWSConnector) IsReadOnly() bool { return !c.Autonomous }

func (c *AWSConnector) DiscoverAgents() ([]AgentSummary, error) {
	// Production: use AWS SDK to list Lambda functions with LLM env vars,
	// Bedrock agents, and IAM roles with LLM API permissions.
	return nil, nil
}

func (c *AWSConnector) DiscoverNHIs() ([]NHISummary, error) {
	// Production: list IAM access keys and Secrets Manager secrets.
	return []NHISummary{}, nil
}

func (c *AWSConnector) RevokeCredential(id string) error {
	if c.IsReadOnly() {
		return ErrReadOnly
	}
	return fmt.Errorf("AWS: credential revocation requires SDK access (id=%s)", id)
}

// =============================================================================
// GITHUB CONNECTOR
// =============================================================================

// GitHubConnector discovers AI agents: Actions bots, GitHub Apps, Copilot configs.
type GitHubConnector struct {
	Autonomous  bool
	OrgName     string
	AccessToken string // Read-only PAT (needs read:org, repo scope)
}

func (c *GitHubConnector) Name() string     { return "GitHub AI Agent Connector" }
func (c *GitHubConnector) Platform() string { return "github" }
func (c *GitHubConnector) IsReadOnly() bool { return !c.Autonomous }

func (c *GitHubConnector) DiscoverAgents() ([]AgentSummary, error) {
	// Production: list GitHub Apps installed on org, scan Actions workflows for
	// OpenAI/Anthropic API key usage, identify Copilot Enterprise bots.
	return nil, nil
}

func (c *GitHubConnector) DiscoverNHIs() ([]NHISummary, error) {
	// Production: list org-level Secrets, identify PATs with wide scopes.
	return []NHISummary{}, nil
}

func (c *GitHubConnector) RevokeCredential(id string) error {
	if c.IsReadOnly() {
		return ErrReadOnly
	}
	return fmt.Errorf("GitHub: credential revocation requires admin API access (id=%s)", id)
}

// =============================================================================
// GENERIC / ENDPOINT CONNECTOR (OpenClaw-style process scan)
// =============================================================================

// GenericConnector provides endpoint-level AI agent discovery via process inspection
// and file system scanning. Models the OpenClaw-style read-only EDR telemetry approach.
type GenericConnector struct {
	Autonomous   bool
	ScanPaths    []string // Directories to scan for .env files with LLM keys
	PlatformName string   // Custom platform label
}

// knownAgentProcessNames are process names that suggest AI agent activity.
var knownAgentProcessNames = []string{
	"python", "node", "java", "dotnet", // runtime + check args
	"langchain", "autogen", "crewai", "openclaw",
	"claude", "openai", "litellm", "ollama",
}

func (c *GenericConnector) Name() string { return "Generic Endpoint AI Agent Connector" }
func (c *GenericConnector) Platform() string {
	if c.PlatformName != "" {
		return c.PlatformName
	}
	return "endpoint"
}
func (c *GenericConnector) IsReadOnly() bool { return !c.Autonomous }

func (c *GenericConnector) DiscoverAgents() ([]AgentSummary, error) {
	// Production: scan running processes for LLM framework signatures,
	// check outbound network connections to LLM API endpoints.
	var agents []AgentSummary
	for _, path := range c.ScanPaths {
		found := c.scanDirectory(path)
		agents = append(agents, found...)
	}
	return agents, nil
}

func (c *GenericConnector) DiscoverNHIs() ([]NHISummary, error) {
	// Production: scan .env files and config directories for API key patterns.
	return []NHISummary{}, nil
}

func (c *GenericConnector) RevokeCredential(id string) error {
	if c.IsReadOnly() {
		return ErrReadOnly
	}
	return fmt.Errorf("endpoint: credential revocation not supported without EDR agent (id=%s)", id)
}

func (c *GenericConnector) scanDirectory(path string) []AgentSummary {
	// Production: walk directory, find .env files, extract LLM key names,
	// create AgentSummary with shadow=true for each discovered configuration.
	_ = path
	return nil
}

// NewDefaultRegistry creates a ConnectorRegistry pre-configured with the
// standard set of read-only environment connectors.
func NewDefaultRegistry() *ConnectorRegistry {
	reg := NewConnectorRegistry()
	reg.Register(&KubernetesConnector{})
	reg.Register(&AWSConnector{Region: "us-east-1"})
	reg.Register(&GitHubConnector{})
	reg.Register(&GenericConnector{
		ScanPaths: []string{".", "/etc", "/var/config"},
	})
	reg.Register(NewNemoClawConnector())
	return reg
}

// AgentTypeFromImage infers the agent type from a container image name.
func AgentTypeFromImage(image string) string {
	for _, known := range knownAgentImages {
		if containsIgnoreCase(image, known) {
			return known + "-agent"
		}
	}
	return "unknown-agent"
}

func containsIgnoreCase(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	sLow := toLower(s)
	subLow := toLower(sub)
	for i := 0; i <= len(sLow)-len(subLow); i++ {
		if sLow[i:i+len(subLow)] == subLow {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

// shadowAgentFromProcess creates an AgentSummary for a discovered shadow process.
func shadowAgentFromProcess(procName, platform string) AgentSummary {
	return AgentSummary{
		ID:          fmt.Sprintf("shadow-%s-%d", procName, time.Now().UnixNano()),
		Name:        procName,
		AgentType:   "shadow",
		Environment: platform,
		RiskScore:   0.75, // Shadow agents default to high-risk
		Managed:     false,
		LastSeen:    time.Now(),
	}
}
