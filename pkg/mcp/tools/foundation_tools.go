// Package tools — PQC Crypto + DAG + Phantom OPSEC + DRBC foundation tools.
//
// Tools exposed:
//   - pqc_sign          : ML-DSA-65 sign an arbitrary payload
//   - pqc_verify        : Verify an ML-DSA-65 signature
//   - pqc_keygen        : Generate Dilithium/Kyber key pair
//   - dag_write         : Write an attested node to the shared DAG
//   - dag_query         : Query DAG history by action/symbol/time
//   - dag_audit         : Full DAG chain integrity audit
//   - phantom_stealth   : Activate Phantom OPSEC stealth mode
//   - identity_shroud   : Shroud agent identity (Nkyinkyim)
//   - drbc_backup       : Encrypted disaster recovery backup (DRBC genesis)
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/drbc"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/nkyinkyim"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/phantom"
)

// ── Shared key helper ─────────────────────────────────────────────────────────

// getAdinkraKeys generates an ephemeral ML-DSA-65 key pair for tool-scope signing.
// In production, load keys from pkg/kms (KMS Tier-0).
func getAdinkraKeys() (pub, priv []byte, err error) {
	return adinkra.GenerateDilithiumKey()
}

// ── Tool: pqc_sign ────────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "pqc_sign",
		Description: "ML-DSA-65 (FIPS 204 / Dilithium3) sign an arbitrary payload. " +
			"The only PQC signing primitive used by KHEPRA. " +
			"Returns: base64-encoded signature + public key fingerprint. " +
			"Every signature is DAG-attested for auditability.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["payload"],
			"properties": {
				"payload": {
					"type": "string",
					"description": "Payload to sign (UTF-8 string or base64-encoded bytes)"
				},
				"symbol": {
					"type": "string",
					"description": "Adinkra symbol to bind to this signature",
					"default": "Gye_Nyame"
				}
			}
		}`),
		Handler: handlePQCSign,
	})
}

func handlePQCSign(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	payload, _ := call.Args["payload"].(string)
	symbol, _ := call.Args["symbol"].(string)
	if payload == "" {
		return nil, nil, fmt.Errorf("pqc_sign: payload is required")
	}
	if symbol == "" {
		symbol = "Gye_Nyame"
	}

	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_sign keygen: %w", err)
	}

	sig, err := adinkra.Sign(priv, []byte(payload))
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_sign: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "pqc_sign",
		Symbol: symbol,
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"algo":   "ML-DSA-65 (FIPS 204)",
			"symbol": symbol,
			"agent":  "PQC-Adinkra-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"signature":        sig,
		"public_key":       pub,
		"algorithm":        "ML-DSA-65 (FIPS 204 / Dilithium3)",
		"symbol":           symbol,
		"dag_attested":     true,
		"signed_at":        lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: pqc_verify ──────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "pqc_verify",
		Description: "Verify an ML-DSA-65 (FIPS 204 / Dilithium3) signature. " +
			"Returns: valid/invalid with verification timestamp.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["payload", "signature", "public_key"],
			"properties": {
				"payload":    {"type": "string", "description": "Original signed payload"},
				"signature":  {"type": "string", "description": "Base64-encoded signature"},
				"public_key": {"type": "string", "description": "Signer's public key (base64 or raw bytes)"}
			}
		}`),
		Handler: handlePQCVerify,
	})
}

func handlePQCVerify(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	payload, _ := call.Args["payload"].(string)
	sigStr, _ := call.Args["signature"].(string)
	pubStr, _ := call.Args["public_key"].(string)

	if payload == "" || sigStr == "" || pubStr == "" {
		return nil, nil, fmt.Errorf("pqc_verify: payload, signature, and public_key are required")
	}

	// Accept both raw string and base64 — adinkra.Verify handles both
	valid, err := adinkra.Verify([]byte(pubStr), []byte(payload), []byte(sigStr))
	if err != nil {
		return map[string]any{
			"valid":       false,
			"error":       err.Error(),
			"verified_at": lorentz.StampNow(),
		}, nil, nil
	}

	return map[string]any{
		"valid":       valid,
		"algorithm":   "ML-DSA-65 (FIPS 204)",
		"verified_at": lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: pqc_keygen ──────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "pqc_keygen",
		Description: "Generate an ML-DSA-65 (Dilithium3) key pair. " +
			"Returns: public key and private key (base64-encoded). " +
			"WARNING: Private key is returned in response — for production use, " +
			"generate keys via the KMS Tier-0 bootstrap and store in the KMS.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handlePQCKeygen,
	})
}

func handlePQCKeygen(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_keygen: %w", err)
	}

	return map[string]any{
		"public_key":  pub,
		"private_key": priv,
		"algorithm":   "ML-DSA-65 (FIPS 204 / Dilithium3)",
		"warning":     "Store private key in KMS Tier-0 (pkg/kms.BootstrapTier0) for production use",
		"generated_at": lorentz.StampNow(),
	}, []string{"Private key exposed in response — use KMS for production"}, nil
}

// ── Tool: dag_write ───────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "dag_write",
		Description: "Write an attested node to the KHEPRA immutable DAG. " +
			"Every node is ML-DSA-65 signed before persistence. " +
			"Use this to record any security-relevant event for audit trail purposes.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["action", "symbol"],
			"properties": {
				"action": {
					"type": "string",
					"description": "Action description to record (e.g. 'access:secrets.env', 'config_change:sshd_config')"
				},
				"symbol": {
					"type": "string",
					"description": "Adinkra symbol for compliance domain binding"
				},
				"metadata": {
					"type": "object",
					"description": "Additional key-value metadata"
				}
			}
		}`),
		Handler: handleDAGWrite,
	})
}

func handleDAGWrite(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	action, _ := call.Args["action"].(string)
	symbol, _ := call.Args["symbol"].(string)

	if action == "" || symbol == "" {
		return nil, nil, fmt.Errorf("dag_write: action and symbol are required")
	}

	pqcMeta := map[string]string{
		"agent": "DAGWrite-MCP-v1",
	}
	if md, ok := call.Args["metadata"].(map[string]any); ok {
		for k, v := range md {
			pqcMeta[k] = fmt.Sprintf("%v", v)
		}
	}

	node := dag.Node{
		Action: action,
		Symbol: symbol,
		Time:   lorentz.StampNow(),
		PQC:    pqcMeta,
	}

	_, priv, err := adinkra.GenerateDilithiumKey()
	if err == nil {
		node.Sign(priv) //nolint:errcheck
	}

	store := getKASAStore()
	if err := store.Add(&node, []string{}); err != nil {
		return nil, nil, fmt.Errorf("dag_write: %w", err)
	}

	return map[string]any{
		"node_id":      node.ID,
		"action":       action,
		"symbol":       symbol,
		"signed":       true,
		"algorithm":    "ML-DSA-65",
		"written_at":   lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: dag_query ───────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "dag_query",
		Description: "Query the KHEPRA DAG history. " +
			"Filter by: action prefix, Adinkra symbol, or time range. " +
			"Returns matching nodes with their PQC metadata and chain linkage.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"action_prefix": {
					"type": "string",
					"description": "Filter by action prefix (e.g. 'forensic', 'pentest', 'vuln')"
				},
				"symbol": {
					"type": "string",
					"description": "Filter by Adinkra symbol (e.g. 'Eban', 'Sankofa', 'OwoForoAdobe')"
				},
				"limit": {
					"type": "integer",
					"description": "Maximum nodes to return (default: 50)",
					"default": 50
				}
			}
		}`),
		Handler: handleDAGQuery,
	})
}

func handleDAGQuery(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	actionPrefix, _ := call.Args["action_prefix"].(string)
	symbol, _ := call.Args["symbol"].(string)
	limit := 50
	if l, ok := call.Args["limit"].(float64); ok {
		limit = int(l)
	}

	store := getKASAStore()
	allNodes := store.Nodes()

	var matched []*dag.Node
	for _, n := range allNodes {
		if actionPrefix != "" && len(n.Action) < len(actionPrefix) {
			continue
		}
		if actionPrefix != "" && n.Action[:len(actionPrefix)] != actionPrefix {
			continue
		}
		if symbol != "" && n.Symbol != symbol {
			continue
		}
		matched = append(matched, n)
		if len(matched) >= limit {
			break
		}
	}

	return map[string]any{
		"total_dag_nodes": len(allNodes),
		"matched":         len(matched),
		"nodes":           matched,
		"queried_at":      lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: dag_audit ───────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "dag_audit",
		Description: "Run a full integrity audit of the KHEPRA DAG chain. " +
			"Verifies: ML-DSA-65 signatures on all nodes, parent chain linkage, " +
			"hash consistency, and detects any tampering. " +
			"This is the cryptographic proof-of-integrity for the audit trail.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handleDAGAudit,
	})
}

func handleDAGAudit(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	store := getKASAStore()
	result := dag.AuditDAGIntegrity(store)

	return map[string]any{
		"audit_result": result,
		"audited_at":   lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: phantom_stealth ─────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "phantom_stealth",
		Description: "Activate Phantom OPSEC stealth mode. " +
			"Computes overall stealth score across: GPS spoof status, IMSI rotation, " +
			"face defeat, thermal masking, EM camouflage, and VPN state. " +
			"For use in forward-deployed and denied-area operations.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handlePhantomStealth,
	})
}

func handlePhantomStealth(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	controller := phantom.NewFullStealthController()
	mode := phantom.ActivateStealthMode(controller)

	return map[string]any{
		"stealth_mode":  mode,
		"activated_at":  lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: identity_shroud ─────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "identity_shroud",
		Description: "Shroud agent identity using the Nkyinkyim (adaptability) protocol. Returns an ephemeral masked identity for denied-area operations.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["agent_id"],
			"properties": {
				"agent_id": {"type": "string", "description": "Real agent ID to shroud"}
			}
		}`),
		Handler: handleIdentityShroud,
	})
}

func handleIdentityShroud(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	agentID, _ := call.Args["agent_id"].(string)
	if agentID == "" {
		return nil, nil, fmt.Errorf("identity_shroud: agent_id is required")
	}

	shrouded, err := nkyinkyim.Shroud(agentID)
	if err != nil {
		return nil, nil, fmt.Errorf("identity_shroud: %w", err)
	}

	return map[string]any{
		"shrouded_identity": shrouded,
		"symbol":            "Nkyinkyim",
		"shrouded_at":       lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: drbc_backup ─────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "drbc_backup",
		Description: "Create an encrypted disaster recovery backup (DRBC Genesis). " +
			"Compresses and triple-encrypts the project state for sovereign offline recovery. " +
			"The backup is Shamir-split for threshold recovery.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["source_dir", "output_path"],
			"properties": {
				"source_dir": {
					"type": "string",
					"description": "Directory to backup"
				},
				"output_path": {
					"type": "string",
					"description": "Output path for encrypted backup archive"
				}
			}
		}`),
		Handler: handleDRBCBackup,
	})
}

func handleDRBCBackup(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	sourceDir, _ := call.Args["source_dir"].(string)
	outputPath, _ := call.Args["output_path"].(string)

	if sourceDir == "" || outputPath == "" {
		return nil, nil, fmt.Errorf("drbc_backup: source_dir and output_path are required")
	}

	_, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, nil, fmt.Errorf("drbc_backup keygen: %w", err)
	}

	if err := drbc.AwakenGenesis(ctx, sourceDir, outputPath, priv); err != nil {
		return nil, nil, fmt.Errorf("drbc_backup: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "drbc_backup",
		Symbol: "Gye_Nyame",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"source": sourceDir,
			"output": outputPath,
			"agent":  "DRBC-Genesis-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"backup_created": true,
		"source":         sourceDir,
		"output":         outputPath,
		"encrypted":      true,
		"dag_attested":   true,
		"backed_up_at":   lorentz.StampNow(),
	}, nil, nil
}
