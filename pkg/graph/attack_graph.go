// Package graph provides the attack path visualization data model for the
// Khepra Protocol ASAF platform. It builds a node/edge graph from agent inventory
// and NHI records, then identifies exploitable paths for the frontend visualization.
package graph

import (
	"encoding/json"
	"fmt"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/connectors"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/nhi"
)

// NodeType classifies a graph node.
type NodeType string

const (
	NodeTypeAgent    NodeType = "agent"
	NodeTypeNHI      NodeType = "nhi"
	NodeTypeResource NodeType = "resource"
	NodeTypeUser     NodeType = "user"
)

// Node is a vertex in the attack graph.
type Node struct {
	ID           string   `json:"id"`
	Type         NodeType `json:"type"`
	Label        string   `json:"label"`
	Platform     string   `json:"platform"`
	Risk         float64  `json:"risk"`
	Symbol       string   `json:"symbol,omitempty"`   // Adinkra symbol (agents only)
	PQCProtected bool     `json:"pqc_protected"`
	Managed      bool     `json:"managed"`
}

// EdgeRelation classifies the relationship between nodes.
type EdgeRelation string

const (
	EdgeRelationUses       EdgeRelation = "uses"       // agent → NHI
	EdgeRelationAccesses   EdgeRelation = "accesses"   // NHI → resource
	EdgeRelationProvisions EdgeRelation = "provisions" // ACP → agent
	EdgeRelationControls   EdgeRelation = "controls"   // agent → resource directly
)

// Edge is a directed connection between two nodes.
type Edge struct {
	From         string       `json:"from"`
	To           string       `json:"to"`
	Relation     EdgeRelation `json:"relation"`
	Exploitable  bool         `json:"exploitable"`   // true = could be used in an attack path
	PQCProtected bool         `json:"pqc_protected"` // true = protected by ML-DSA/Kyber
}

// AttackGraph is the complete graph representation used by the frontend.
type AttackGraph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []*Edge          `json:"edges"`
}

// BuildAttackGraph constructs an attack graph from agent inventory and NHI records.
func BuildAttackGraph(inventory []connectors.AgentSummary, nhis []*nhi.NHIRecord) *AttackGraph {
	g := &AttackGraph{
		Nodes: make(map[string]*Node),
		Edges: make([]*Edge, 0),
	}

	// Add agent nodes.
	for _, agent := range inventory {
		nodeID := "agent-" + agent.ID
		symbol := ""
		if agent.PQCProtected {
			symbol = "Eban"
		}
		g.Nodes[nodeID] = &Node{
			ID:           nodeID,
			Type:         NodeTypeAgent,
			Label:        agent.Name,
			Platform:     agent.Environment,
			Risk:         agent.RiskScore,
			Symbol:       symbol,
			PQCProtected: agent.PQCProtected,
			Managed:      agent.Managed,
		}

		// Add resource nodes for each environment the agent accesses.
		resNodeID := "resource-" + agent.Environment
		if _, exists := g.Nodes[resNodeID]; !exists {
			g.Nodes[resNodeID] = &Node{
				ID:       resNodeID,
				Type:     NodeTypeResource,
				Label:    agent.Environment,
				Platform: agent.Environment,
				Risk:     0.0,
			}
		}

		// Agent → resource edge.
		g.Edges = append(g.Edges, &Edge{
			From:         nodeID,
			To:           resNodeID,
			Relation:     EdgeRelationControls,
			Exploitable:  !agent.PQCProtected || agent.RiskScore > 0.5,
			PQCProtected: agent.PQCProtected,
		})
	}

	// Add NHI nodes and link them to agents.
	for _, record := range nhis {
		nhiNodeID := "nhi-" + record.ID
		g.Nodes[nhiNodeID] = &Node{
			ID:       nhiNodeID,
			Type:     NodeTypeNHI,
			Label:    fmt.Sprintf("%s (%s)", record.ID, record.Type),
			Platform: record.Platform,
			Risk:     record.RiskScore,
			Managed:  record.Managed,
		}

		// Owner agent → NHI edge.
		ownerNodeID := "agent-" + record.Owner
		if _, exists := g.Nodes[ownerNodeID]; exists {
			g.Edges = append(g.Edges, &Edge{
				From:         ownerNodeID,
				To:           nhiNodeID,
				Relation:     EdgeRelationUses,
				Exploitable:  record.IsExpired() || record.RiskScore > 0.6,
				PQCProtected: len(record.PQCAttestation) > 0,
			})
		}

		// NHI → platform resource edge.
		resNodeID := "resource-" + record.Platform
		if _, exists := g.Nodes[resNodeID]; !exists {
			g.Nodes[resNodeID] = &Node{
				ID:       resNodeID,
				Type:     NodeTypeResource,
				Label:    record.Platform,
				Platform: record.Platform,
				Risk:     0.0,
			}
		}
		g.Edges = append(g.Edges, &Edge{
			From:         nhiNodeID,
			To:           resNodeID,
			Relation:     EdgeRelationAccesses,
			Exploitable:  record.RiskScore > 0.5,
			PQCProtected: false,
		})
	}

	return g
}

// FindAttackPaths returns all exploitable edge sequences from a source node to a target.
// Uses depth-first search with a maximum depth of 6 hops to prevent unbounded traversal.
func (ag *AttackGraph) FindAttackPaths(fromNodeID, toNodeID string) [][]*Edge {
	if _, ok := ag.Nodes[fromNodeID]; !ok {
		return nil
	}
	if _, ok := ag.Nodes[toNodeID]; !ok {
		return nil
	}

	var results [][]*Edge
	visited := make(map[string]bool)
	var dfs func(current string, path []*Edge, depth int)

	dfs = func(current string, path []*Edge, depth int) {
		if depth > 6 {
			return
		}
		if current == toNodeID && len(path) > 0 {
			// Found a path — copy and record it.
			p := make([]*Edge, len(path))
			copy(p, path)
			results = append(results, p)
			return
		}
		visited[current] = true
		for _, e := range ag.Edges {
			if e.From == current && !visited[e.To] && e.Exploitable {
				dfs(e.To, append(path, e), depth+1)
			}
		}
		delete(visited, current)
	}

	dfs(fromNodeID, nil, 0)
	return results
}

// HighRiskPaths returns all exploitable edge chains where every node has risk ≥ 0.5.
func (ag *AttackGraph) HighRiskPaths() [][]*Edge {
	var highRisk [][]*Edge
	for fromID := range ag.Nodes {
		for toID := range ag.Nodes {
			if fromID == toID {
				continue
			}
			paths := ag.FindAttackPaths(fromID, toID)
			for _, path := range paths {
				allHigh := true
				for _, e := range path {
					from := ag.Nodes[e.From]
					to := ag.Nodes[e.To]
					if from == nil || to == nil || (from.Risk < 0.5 && to.Risk < 0.5) {
						allHigh = false
						break
					}
				}
				if allHigh {
					highRisk = append(highRisk, path)
				}
			}
		}
	}
	return highRisk
}

// ToJSON serialises the graph to JSON for frontend consumption.
func (ag *AttackGraph) ToJSON() ([]byte, error) {
	return json.Marshal(ag)
}

// NodeList returns nodes as a slice (useful for API responses).
func (ag *AttackGraph) NodeList() []*Node {
	out := make([]*Node, 0, len(ag.Nodes))
	for _, n := range ag.Nodes {
		out = append(out, n)
	}
	return out
}
