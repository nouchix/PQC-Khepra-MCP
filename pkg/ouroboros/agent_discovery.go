package ouroboros

import (
	"fmt"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/connectors"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/nhi"
)

// =============================================================================
// AGENT DISCOVERY EYE — ASAF PLATFORM PILLAR 1: DISCOVER
// Implements the WedjatEye interface to detect shadow and managed AI agents
// across all registered environment connectors.
// Shadow agents (unmanaged, unknown) surface as maat.Isfet findings.
// =============================================================================

// AgentInventoryItem is the rich, Khepra-augmented agent record.
type AgentInventoryItem struct {
	ID             string
	Name           string
	AgentType      string // "openai-assistant","mcp-server","langchain","shadow",etc.
	Environment    string // Platform name
	NHIs           []nhi.NHIRecord
	RiskScore      float64
	Permissions    []string
	LastSeen       time.Time
	Managed        bool   // true = ACP-provisioned
	PQCProtected   bool   // true = valid Adinkhepra attestation
	Symbol         string // Adinkra symbol assigned by ACP
	SpectralFP     string // Khepra-hash of spectral fingerprint
	STIGCATLevel   string // "CAT1"/"CAT2"/"CAT3" — STIG risk category
	CMMCDomain     string // CMMC domain (AC, CM, IA, IR, SI...)
	DAGVertexID    string // Latest DAG vertex for this agent
}

// AgentDiscoveryEye implements WedjatEye for AI agent discovery.
type AgentDiscoveryEye struct {
	registry *connectors.ConnectorRegistry
}

// NewAgentDiscoveryEye creates a discovery eye backed by the given connector registry.
func NewAgentDiscoveryEye(registry *connectors.ConnectorRegistry) *AgentDiscoveryEye {
	if registry == nil {
		registry = connectors.NewDefaultRegistry()
	}
	return &AgentDiscoveryEye{registry: registry}
}

// Name satisfies the WedjatEye interface.
func (ae *AgentDiscoveryEye) Name() string {
	return "AgentDiscoveryEye (ASAF)"
}

// Gaze satisfies the WedjatEye interface — discovers shadow agents and maps them to Isfet.
func (ae *AgentDiscoveryEye) Gaze() []maat.Isfet {
	agents, err := ae.registry.DiscoverAll()
	if err != nil {
		return nil
	}

	var findings []maat.Isfet
	for _, agent := range agents {
		if agent.Managed {
			continue // Managed agents are not shadow threats
		}

		severity := shadowAgentSeverity(agent.RiskScore)
		findings = append(findings, maat.Isfet{
			ID:       fmt.Sprintf("ASAF-SHADOW-%s", agent.ID),
			Severity: severity,
			Source:   "AgentDiscoveryEye",
			Omens: []maat.Omen{
				{Name: "agent_type", Value: agent.AgentType, Malevolence: agent.RiskScore},
				{Name: "platform", Value: agent.Environment, Malevolence: 0.0},
				{Name: "unmanaged", Value: "true", Malevolence: 0.5},
			},
			Certainty: riskToCertainty(agent.RiskScore),
		})
	}
	return findings
}

// Inventory returns the full, enriched agent inventory.
func (ae *AgentDiscoveryEye) Inventory() ([]AgentInventoryItem, error) {
	rawAgents, err := ae.registry.DiscoverAll()
	if err != nil {
		return nil, fmt.Errorf("AgentDiscoveryEye: discovery failed: %w", err)
	}

	var items []AgentInventoryItem
	for _, agent := range rawAgents {
		symbol := symbolForAgent(agent)
		fp := adinkra.GetSpectralFingerprint(symbol)
		item := AgentInventoryItem{
			ID:          agent.ID,
			Name:        agent.Name,
			AgentType:   agent.AgentType,
			Environment: agent.Environment,
			RiskScore:   agent.RiskScore,
			Permissions: agent.Permissions,
			LastSeen:    agent.LastSeen,
			Managed:     agent.Managed,
			PQCProtected: agent.PQCProtected,
			Symbol:      symbol,
			SpectralFP:  adinkra.Hash(fp),
			STIGCATLevel: riskToSTIGCAT(agent.RiskScore),
			CMMCDomain:  symbolToCMMCDomain(symbol),
		}
		items = append(items, item)
	}
	return items, nil
}

// =============================================================================
// HELPERS
// =============================================================================

func shadowAgentSeverity(riskScore float64) maat.Severity {
	switch {
	case riskScore >= 0.8:
		return maat.SeverityCatastrophic
	case riskScore >= 0.6:
		return maat.SeveritySevere
	case riskScore >= 0.4:
		return maat.SeverityModerate
	default:
		return maat.SeverityMinor
	}
}

func riskToCertainty(risk float64) float64 {
	if risk < 0 {
		return 0
	}
	if risk > 1 {
		return 1
	}
	return risk
}

func symbolForAgent(agent connectors.AgentSummary) string {
	if agent.PQCProtected {
		return "Eban" // Protected → Fortress
	}
	if !agent.Managed {
		return "Fawohodie" // Unmanaged → Emancipation/revocation
	}
	if agent.RiskScore > 0.5 {
		return "Nkyinkyim" // High-risk managed → adaptive journey
	}
	return "Dwennimmen" // Low-risk managed → distributed trust
}

func riskToSTIGCAT(risk float64) string {
	switch {
	case risk >= 0.7:
		return "CAT1"
	case risk >= 0.4:
		return "CAT2"
	default:
		return "CAT3"
	}
}

func symbolToCMMCDomain(symbol string) string {
	mapping := adinkra.MapSymbolToCompliance(symbol)
	for _, m := range mapping {
		switch m {
		case "CMMC":
			return "AC" // Access Control (default for CMMC-mapped symbols)
		case "DoD RMF", "STIG":
			return "IA" // Identification and Authentication
		case "FedRAMP":
			return "CM" // Configuration Management
		case "PCI DSS", "HIPAA":
			return "SI" // System and Information Integrity
		}
	}
	return "AC" // default
}
