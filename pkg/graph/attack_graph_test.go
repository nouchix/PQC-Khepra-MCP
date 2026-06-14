// Integration tests for the attack path graph.
// Tests validate graph construction from real inventory data and DFS path-finding.
package graph

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/connectors"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/nhi"
)

func makeAgent(id, name, env string, risk float64, pqc, managed bool) connectors.AgentSummary {
	return connectors.AgentSummary{
		ID:           id,
		Name:         name,
		AgentType:    "openai-assistant",
		Environment:  env,
		RiskScore:    risk,
		PQCProtected: pqc,
		Managed:      managed,
		LastSeen:     time.Now(),
	}
}

func makeNHI(id, owner, platform string, risk float64, expired bool) *nhi.NHIRecord {
	rec := &nhi.NHIRecord{
		ID:        id,
		Type:      nhi.NHITypeAPIKey,
		Owner:     owner,
		Platform:  platform,
		RiskScore: risk,
		Managed:   true,
	}
	if expired {
		past := time.Now().Add(-24 * time.Hour)
		rec.ExpiresAt = &past
	}
	return rec
}

// TestBuildAttackGraphNodes verifies that BuildAttackGraph correctly creates
// agent and resource nodes from the inventory.
func TestBuildAttackGraphNodes(t *testing.T) {
	inventory := []connectors.AgentSummary{
		makeAgent("agt-1", "ScanBot", "aws", 0.3, true, true),
		makeAgent("agt-2", "SlackBot", "slack", 0.7, false, false),
	}
	nhis := []*nhi.NHIRecord{
		makeNHI("nhi-s3-key", "agt-1", "aws", 0.2, false),
	}

	g := BuildAttackGraph(inventory, nhis)

	if _, ok := g.Nodes["agent-agt-1"]; !ok {
		t.Error("agent-agt-1 node missing")
	}
	if _, ok := g.Nodes["agent-agt-2"]; !ok {
		t.Error("agent-agt-2 node missing")
	}
	if _, ok := g.Nodes["resource-aws"]; !ok {
		t.Error("resource-aws node missing")
	}
	if _, ok := g.Nodes["nhi-nhi-s3-key"]; !ok {
		t.Error("nhi-nhi-s3-key node missing")
	}
}

// TestBuildAttackGraphPQCEdges verifies that PQC-protected agents get
// non-exploitable edges (when risk is also low).
func TestBuildAttackGraphPQCEdges(t *testing.T) {
	inventory := []connectors.AgentSummary{
		makeAgent("agt-pqc", "SecureBot", "k8s", 0.1, true, true),
		makeAgent("agt-legacy", "LegacyBot", "k8s", 0.8, false, false),
	}
	g := BuildAttackGraph(inventory, nil)

	// Find edge from pqc agent to resource
	var pqcEdge, legacyEdge *Edge
	for _, e := range g.Edges {
		if e.From == "agent-agt-pqc" {
			pqcEdge = e
		}
		if e.From == "agent-agt-legacy" {
			legacyEdge = e
		}
	}

	if pqcEdge == nil {
		t.Fatal("no edge from pqc agent")
	}
	if pqcEdge.Exploitable {
		t.Error("PQC-protected low-risk agent should have non-exploitable edge")
	}
	if legacyEdge == nil {
		t.Fatal("no edge from legacy agent")
	}
	if !legacyEdge.Exploitable {
		t.Error("legacy high-risk agent should have exploitable edge")
	}
}

// TestFindAttackPathsSimpleChain verifies that FindAttackPaths discovers
// a known two-hop path from agent → NHI → resource.
func TestFindAttackPathsSimpleChain(t *testing.T) {
	inventory := []connectors.AgentSummary{
		makeAgent("agt-pivot", "PivotBot", "github", 0.8, false, false),
	}
	nhis := []*nhi.NHIRecord{
		makeNHI("nhi-github-pat", "agt-pivot", "github", 0.85, false),
	}

	g := BuildAttackGraph(inventory, nhis)

	paths := g.FindAttackPaths("agent-agt-pivot", "resource-github")
	if len(paths) == 0 {
		t.Error("expected at least one attack path from agent-agt-pivot to resource-github")
	}
}

// TestFindAttackPathsNoPathForPQC verifies that a PQC-protected low-risk agent
// has no exploitable path to a resource.
func TestFindAttackPathsNoPathForPQC(t *testing.T) {
	inventory := []connectors.AgentSummary{
		makeAgent("agt-safe", "SafeBot", "aws", 0.1, true, true),
	}
	g := BuildAttackGraph(inventory, nil)

	paths := g.FindAttackPaths("agent-agt-safe", "resource-aws")
	// PQC-protected + risk < 0.5 → edge.Exploitable=false → no path
	if len(paths) != 0 {
		t.Errorf("expected no attack paths for PQC-protected agent, got %d", len(paths))
	}
}

// TestFindAttackPathsNonExistentNodes verifies nil/empty return for unknown nodes.
func TestFindAttackPathsNonExistentNodes(t *testing.T) {
	g := &AttackGraph{Nodes: map[string]*Node{}, Edges: nil}
	paths := g.FindAttackPaths("agent-missing", "resource-missing")
	if paths != nil {
		t.Errorf("expected nil for missing nodes, got %v", paths)
	}
}

// TestHighRiskPaths verifies that HighRiskPaths only returns paths where
// every node has risk ≥ 0.5.
func TestHighRiskPaths(t *testing.T) {
	inventory := []connectors.AgentSummary{
		makeAgent("agt-hi-risk", "DangerBot", "aws", 0.9, false, false),
		makeAgent("agt-lo-risk", "SafeBot", "aws", 0.1, true, true),
	}
	nhis := []*nhi.NHIRecord{
		makeNHI("nhi-dangerous", "agt-hi-risk", "aws", 0.95, false),
	}

	g := BuildAttackGraph(inventory, nhis)
	highRisk := g.HighRiskPaths()

	// Every edge in every high-risk path must connect nodes with risk ≥ 0.5
	for _, path := range highRisk {
		for _, e := range path {
			from := g.Nodes[e.From]
			to := g.Nodes[e.To]
			if from != nil && to != nil {
				if from.Risk < 0.5 && to.Risk < 0.5 {
					t.Errorf("high-risk path includes low-risk edge: %s(%.2f) → %s(%.2f)",
						e.From, from.Risk, e.To, to.Risk)
				}
			}
		}
	}
}

// TestToJSON verifies that the attack graph serializes to valid JSON.
func TestToJSON(t *testing.T) {
	inventory := []connectors.AgentSummary{
		makeAgent("agt-1", "Bot1", "aws", 0.5, true, true),
	}
	g := BuildAttackGraph(inventory, nil)

	data, err := g.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("ToJSON produced invalid JSON: %v", err)
	}
	if _, ok := parsed["nodes"]; !ok {
		t.Error("JSON missing 'nodes' field")
	}
	if _, ok := parsed["edges"]; !ok {
		t.Error("JSON missing 'edges' field")
	}
}

// TestNodeList verifies that NodeList returns all nodes in the graph.
func TestNodeList(t *testing.T) {
	inventory := []connectors.AgentSummary{
		makeAgent("agt-1", "Bot1", "aws", 0.5, true, true),
		makeAgent("agt-2", "Bot2", "github", 0.3, false, false),
	}
	g := BuildAttackGraph(inventory, nil)
	nodes := g.NodeList()

	// Should have 2 agent nodes + 2 resource nodes (aws, github)
	if len(nodes) < 4 {
		t.Errorf("expected at least 4 nodes, got %d", len(nodes))
	}
}

// TestDepthLimitPreventsInfiniteTraversal verifies that FindAttackPaths
// does not infinite-loop on cycles and respects the 6-hop depth limit.
func TestDepthLimitPreventsInfiniteTraversal(t *testing.T) {
	// Build a linear chain of 10 agents pointing to each other
	g := &AttackGraph{
		Nodes: make(map[string]*Node),
		Edges: make([]*Edge, 0),
	}
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("n%d", i)
		g.Nodes[id] = &Node{ID: id, Risk: 0.9}
		if i > 0 {
			prev := fmt.Sprintf("n%d", i-1)
			g.Edges = append(g.Edges, &Edge{
				From: prev, To: id,
				Exploitable: true,
			})
		}
	}

	// Path from n0 to n9 is 9 hops — exceeds the 6-hop limit
	paths := g.FindAttackPaths("n0", "n9")
	if len(paths) != 0 {
		t.Errorf("expected 0 paths exceeding 6-hop limit, got %d", len(paths))
	}

	// Path from n0 to n6 is exactly 6 hops — should be found
	paths6 := g.FindAttackPaths("n0", "n6")
	if len(paths6) == 0 {
		t.Error("expected path of 6 hops to be discovered")
	}
}
