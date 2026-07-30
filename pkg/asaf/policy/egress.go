package policy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/agi"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ir"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/maat"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/seshat"
)

// EgressBoundaryGuard enforces Phase-1 CIDR confinement and DAG attestation on all outbound dials.
type EgressBoundaryGuard struct {
	EnclaveCIDRs []string
	DAGStore     dag.Store
	IRManager    *ir.Manager
	Guardian     *maat.Guardian
	AgentID      string
	SignKey      []byte
}

// NewEgressBoundaryGuard creates a new EgressBoundaryGuard.
func NewEgressBoundaryGuard(cidrs []string, store dag.Store, irm *ir.Manager, kasa *agi.Engine, chronicle *seshat.Chronicle, agentID string, signKey []byte) *EgressBoundaryGuard {
	var g *maat.Guardian
	if kasa != nil {
		g = maat.NewGuardian("ASAF_EGRESS", kasa, chronicle)
	}
	return &EgressBoundaryGuard{
		EnclaveCIDRs: cidrs,
		DAGStore:     store,
		IRManager:    irm,
		Guardian:     g,
		AgentID:      agentID,
		SignKey:      signKey,
	}
}

// CheckTarget verifies if the target IP is within the declared enclaves, logs to DAG, triggers IR if not, and consults KASA.
func (ebg *EgressBoundaryGuard) CheckTarget(ctx context.Context, targetIP string) error {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return fmt.Errorf("invalid target IP: %s", targetIP)
	}

	inEnclave := false
	for _, cidr := range ebg.EnclaveCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			inEnclave = true
			break
		}
	}

	// DAG Attestation of attempt
	if ebg.DAGStore != nil {
		node := &dag.Node{
			Action: "EGRESS_DIAL_ATTEMPT",
			Symbol: "Nkyinkyim",
			Time:   time.Now().UTC().Format(time.RFC3339),
			PQC: map[string]string{
				"target":        targetIP,
				"enclave_match": fmt.Sprintf("%t", inEnclave),
				"agent":         ebg.AgentID,
			},
		}
		node.Hash = node.ComputeHash()
		node.ID = node.Hash

		if len(ebg.SignKey) > 0 {
			if sigBytes, err := adinkra.Sign(ebg.SignKey, []byte(node.Hash)); err == nil {
				node.Signature = base64.StdEncoding.EncodeToString(sigBytes)
			}
		}

		// Pass nil for parents for now, DAGStore handles linking
		ebg.DAGStore.Add(node, nil)
	}

	if !inEnclave {
		if ebg.IRManager != nil {
			ebg.IRManager.CreateIncident(
				"Out-of-Boundary Egress Attempt",
				fmt.Sprintf("Connector or Blackhole VPN attempted to dial %s which is outside declared enclaves.", targetIP),
				ir.SevHigh,
				"UNAUTHORIZED_EGRESS",
				ebg.SignKey,
			)
		}
		return fmt.Errorf("target %s is outside declared CMMC Phase-1 enclaves", targetIP)
	}

	// Guardian Pre-Check
	if ebg.Guardian != nil {
		isfet := []maat.Isfet{
			{
				ID:        "egress-check-" + targetIP,
				Severity:  maat.SeverityMinor,
				Source:    "EgressBoundaryGuard",
				Omens:     []maat.Omen{{Name: "DialTarget", Value: targetIP}},
				Certainty: 1.0,
			},
		}
		hekas := ebg.Guardian.WeighAndDecide(isfet)
		// If Guardian produces a blocking Heka action (e.g. Block), fail
		for _, h := range hekas {
			if h.Action == "Block" || h.Action == "Quarantine" {
				return fmt.Errorf("maat.Guardian blocked dial to %s: %s", targetIP, h.Action)
			}
		}
	}

	return nil
}
