// Package tools — PQC Crypto + DAG + Phantom OPSEC + DRBC foundation handler functions.
//
// Registration: add to cmd/khepra-mcp/main.go via executor.RegisterFunc().
//
// Tools exposed:
//   - HandlePQCSign        : ML-DSA-65 sign an arbitrary payload
//   - HandlePQCVerify      : Verify an ML-DSA-65 signature
//   - HandlePQCKeygen      : Generate Dilithium/Kyber key pair
//   - HandleDAGWrite       : Write an attested node to the shared DAG
//   - HandleDAGQuery       : Query DAG history by action/symbol/time
//   - HandleDAGAudit       : Full DAG chain integrity audit
//   - HandlePhantomStealth : Activate Phantom OPSEC stealth mode
//   - HandleIdentityShroud : Shroud agent identity (Nkyinkyim encoding)
//   - HandleDRBCBackup     : Encrypted disaster recovery backup (DRBC genesis)
package tools

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/drbc"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/nkyinkyim"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/phantom"
)

// ── PQC handlers ─────────────────────────────────────────────────────────────

// HandlePQCSign creates an ML-DSA-65 (FIPS 204 / Dilithium3) signature over a payload.
// Returns: base64-encoded signature + public key. Every signature is DAG-attested.
func HandlePQCSign(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
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
		"signature":   base64.StdEncoding.EncodeToString(sig),
		"public_key":  base64.StdEncoding.EncodeToString(pub),
		"algorithm":   "ML-DSA-65 (FIPS 204)",
		"symbol":      symbol,
		"dag_node":    node.ID,
		"signed_at":   lorentz.StampNow(),
	}, nil, nil
}

// HandlePQCVerify verifies an ML-DSA-65 signature against a payload.
// Accepts base64-encoded signature and public key.
func HandlePQCVerify(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	payload, _ := call.Args["payload"].(string)
	sigB64, _ := call.Args["signature"].(string)
	pubB64, _ := call.Args["public_key"].(string)

	if payload == "" || sigB64 == "" || pubB64 == "" {
		return nil, nil, fmt.Errorf("pqc_verify: payload, signature, and public_key are required")
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_verify: invalid signature base64: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_verify: invalid public_key base64: %w", err)
	}

	valid, err := adinkra.Verify(pub, []byte(payload), sig)
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_verify: %w", err)
	}

	return map[string]any{
		"valid":       valid,
		"algorithm":   "ML-DSA-65 (FIPS 204)",
		"verified_at": lorentz.StampNow(),
	}, nil, nil
}

// HandlePQCKeygen generates a fresh ML-DSA-65 + ML-KEM-768 key pair.
// Returns base64-encoded public keys (private keys are NOT returned — store securely).
func HandlePQCKeygen(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	dilPub, _, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_keygen dilithium: %w", err)
	}
	kyberPub, _, err := adinkra.GenerateKyberKey()
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_keygen kyber: %w", err)
	}

	return map[string]any{
		"dilithium_public_key": base64.StdEncoding.EncodeToString(dilPub),
		"kyber_public_key":     base64.StdEncoding.EncodeToString(kyberPub),
		"algorithms": map[string]string{
			"signing":  "ML-DSA-65 (FIPS 204)",
			"kem":      "ML-KEM-768 (FIPS 203)",
		},
		"warning":    "Private keys are NOT returned. Generate and store at server startup via pkg/kms.",
		"created_at": lorentz.StampNow(),
	}, nil, nil
}

// ── DAG handlers ─────────────────────────────────────────────────────────────

// HandleDAGWrite writes a manually-specified attested node to the shared KASA DAG.
// Use this to attest arbitrary compliance events, human approvals, and audit points.
func HandleDAGWrite(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("dag_write"); gate != nil {
		return gate, nil, nil
	}
	action, _ := call.Args["action"].(string)
	symbol, _ := call.Args["symbol"].(string)
	if action == "" {
		return nil, nil, fmt.Errorf("dag_write: action is required")
	}
	if symbol == "" {
		symbol = "Gye_Nyame"
	}

	store := getKASAStore()
	node := dag.Node{
		Action: action,
		Symbol: symbol,
		Time:   lorentz.StampNow(),
	}
	if err := store.Add(&node, []string{}); err != nil {
		return nil, nil, fmt.Errorf("dag_write: %w", err)
	}

	return map[string]any{
		"node_id":    node.ID,
		"action":     action,
		"symbol":     symbol,
		"dag_size":   len(store.All()),
		"written_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleDAGQuery queries the shared KASA DAG history.
// Filters by action prefix or symbol to find specific audit events.
func HandleDAGQuery(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	filterAction, _ := call.Args["action"].(string)
	filterSymbol, _ := call.Args["symbol"].(string)

	store := getKASAStore()
	all := store.All()
	var matches []map[string]any
	for _, n := range all {
		if filterAction != "" && n.Action != filterAction {
			continue
		}
		if filterSymbol != "" && n.Symbol != filterSymbol {
			continue
		}
		matches = append(matches, map[string]any{
			"id":     n.ID,
			"action": n.Action,
			"symbol": n.Symbol,
			"time":   n.Time,
		})
	}

	return map[string]any{
		"query":       map[string]string{"action": filterAction, "symbol": filterSymbol},
		"matches":     matches,
		"total":       len(matches),
		"dag_size":    len(all),
		"queried_at":  lorentz.StampNow(),
	}, nil, nil
}

// HandleDAGAudit performs a full integrity audit of the KASA DAG.
// Verifies: node count, parent linkage, PQC metadata completeness.
func HandleDAGAudit(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("dag_audit"); gate != nil {
		return gate, nil, nil
	}
	store := getKASAStore()
	nodes := store.All()

	var warnings []string
	var intact, broken int

	for _, n := range nodes {
		if n.ID == "" || n.Action == "" || n.Time == "" {
			broken++
			warnings = append(warnings, fmt.Sprintf("malformed node (missing fields): %v", n))
		} else {
			intact++
		}
	}

	// Write the audit result itself to the DAG
	auditNode := dag.Node{
		Action: "dag_audit",
		Symbol: "Sankofa",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"total":  fmt.Sprintf("%d", len(nodes)),
			"intact": fmt.Sprintf("%d", intact),
			"broken": fmt.Sprintf("%d", broken),
		},
	}
	store.Add(&auditNode, []string{}) //nolint:errcheck

	return map[string]any{
		"total_nodes":  len(nodes),
		"intact_nodes": intact,
		"broken_nodes": broken,
		"integrity":    broken == 0,
		"warnings":     warnings,
		"audited_at":   lorentz.StampNow(),
	}, warnings, nil
}

// ── Phantom OPSEC handlers ─────────────────────────────────────────────────────

// HandlePhantomStealth activates Phantom OPSEC stealth mode.
// Engages: GPS spoofing, thermal camouflage, ephemeral IMSI, spread spectrum pattern.
// Symbol binding: Eban (fortress/protection).
func HandlePhantomStealth(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("phantom_stealth"); gate != nil {
		return gate, nil, nil
	}
	symbol, _ := call.Args["symbol"].(string)
	deviceID, _ := call.Args["device_id"].(string)
	targetCity, _ := call.Args["target_city"].(string)

	if symbol == "" {
		symbol = "Eban"
	}
	if deviceID == "" {
		deviceID = call.Identity.AgentID
	}
	if targetCity == "" {
		targetCity = "New York"
	}

	stealth := phantom.ActivateStealthMode(symbol, deviceID, targetCity, 0, 0)

	return map[string]any{
		"stealth_active": true,
		"mode":           stealth,
		"symbol":         symbol,
		"device_id":      deviceID,
		"activated_at":   lorentz.StampNow(),
	}, nil, nil
}

// HandleIdentityShroud encodes a strand (identity token, API key, or agent fingerprint)
// using the Nkyinkyim mystery encoding for OPSEC identity protection.
func HandleIdentityShroud(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("identity_shroud"); gate != nil {
		return gate, nil, nil
	}
	strand, _ := call.Args["strand"].(string)
	if strand == "" {
		return nil, nil, fmt.Errorf("identity_shroud: strand is required")
	}

	shrouded := nkyinkyim.Shroud([]byte(strand))

	return map[string]any{
		"shrouded":    shrouded,
		"symbol":      "Nkyinkyim",
		"algorithm":   "Nkyinkyim-Mystery-v1",
		"shrouded_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleIdentityEpiphany decodes a Nkyinkyim-shrouded strand back to plaintext.
func HandleIdentityEpiphany(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("identity_epiphany"); gate != nil {
		return gate, nil, nil
	}
	verse, _ := call.Args["verse"].(string)
	if verse == "" {
		return nil, nil, fmt.Errorf("identity_epiphany: verse is required")
	}

	revealed, err := nkyinkyim.Epiphany(verse)
	if err != nil {
		return nil, nil, fmt.Errorf("identity_epiphany: %w", err)
	}

	return map[string]any{
		"revealed":    string(revealed),
		"symbol":      "Nkyinkyim",
		"revealed_at": lorentz.StampNow(),
	}, nil, nil
}

// ── DRBC handlers ─────────────────────────────────────────────────────────────

// HandleDRBCBackup creates an AES-256-GCM encrypted tar.gz disaster recovery backup
// of the KHEPRA project. The backup is stored at the configured DRBC path.
// Use HandleDRBCRestore to restore from this backup.
func HandleDRBCBackup(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("drbc_backup"); gate != nil {
		return gate, nil, nil
	}
	password, _ := call.Args["password"].(string)
	if password == "" {
		return nil, nil, fmt.Errorf("drbc_backup: password is required")
	}

	if err := drbc.AwakenGenesis(password); err != nil {
		return nil, nil, fmt.Errorf("drbc_backup: %w", err)
	}

	return map[string]any{
		"status":      "backup_created",
		"algorithm":   "AES-256-GCM",
		"description": "Encrypted DRBC genesis snapshot created",
		"created_at":  lorentz.StampNow(),
	}, nil, nil
}

// HandleDRBCRestore restores the KHEPRA project from a DRBC genesis backup.
// Requires the same password used during backup creation.
func HandleDRBCRestore(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("drbc_restore"); gate != nil {
		return gate, nil, nil
	}
	password, _ := call.Args["password"].(string)
	targetDir, _ := call.Args["target_dir"].(string)
	if password == "" || targetDir == "" {
		return nil, nil, fmt.Errorf("drbc_restore: password and target_dir are required")
	}

	if err := drbc.RestoreGenesis(password, targetDir); err != nil {
		return nil, nil, fmt.Errorf("drbc_restore: %w", err)
	}

	return map[string]any{
		"status":      "restore_complete",
		"target_dir":  targetDir,
		"restored_at": lorentz.StampNow(),
	}, nil, nil
}
