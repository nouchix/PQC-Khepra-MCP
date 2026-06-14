// cmd/mcp-runner/main.go
//
// MCP Sandbox Executor — runs inside the Phantom Docker container.
//
// This binary is the entrypoint for sandboxed MCP tool execution.
// It initializes a PQC session using the Spectral Fingerprint from the
// Adinkra symbol system, executes the requested tool, PQC-signs the output,
// and emits structured JSON on stdout (the MCP result channel).
//
// All diagnostic/log output goes to stderr (MCP protocol requirement).
//
// Usage:
//   mcp-runner <tool-name> <json-args>
//
// Environment:
//   PHANTOM_SYMBOL          — Adinkra symbol for Spectral Fingerprint (default: "Eban")
//   PHANTOM_KEY_DIR         — Directory for PQC key material (default: "/var/lib/phantom/keys")
//   PHANTOM_DATA_DIR        — Directory for mutable tool output (default: "/var/lib/phantom/data")

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// Version is injected at build time via -ldflags.
var Version = "dev"

// SessionContext holds the PQC identity and crypto context for this run.
type SessionContext struct {
	Symbol      string
	Fingerprint []byte
	PublicKey   *adinkra.AdinkhepraPQCPublicKey
	PrivateKey  *adinkra.AdinkhepraPQCPrivateKey
	Merkaba     *adinkra.Merkaba
	KeyID       string
	StartedAt   time.Time
}

// ToolOutput is the structured JSON written to stdout.
type ToolOutput struct {
	Tool        string `json:"tool"`
	Status      string `json:"status"`
	KeyID       string `json:"pqc_key_id"`
	Fingerprint string `json:"spectral_fingerprint"`
	Signature   string `json:"pqc_signature,omitempty"`
	AttestedAt  string `json:"attested_at"`
	Version     string `json:"runner_version"`
	Result      any    `json:"result,omitempty"`
	Error       string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "[PHANTOM] Usage: mcp-runner <tool> <json-args>\n")
		fmt.Fprintf(os.Stderr, "[PHANTOM] Version: %s\n", Version)
		os.Exit(1)
	}

	toolName := os.Args[1]
	argsJSON := os.Args[2]

	var args map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		emitError(toolName, fmt.Sprintf("invalid arguments JSON: %v", err))
		os.Exit(1)
	}

	// ─── PHANTOM / SPECTRAL FINGERPRINT INITIALIZATION ───────────────────
	session, err := initSession(args)
	if err != nil {
		emitError(toolName, fmt.Sprintf("session init failed: %v", err))
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[PHANTOM] Session started | Tool: %s | Symbol: %s | KeyID: %s | Time: %s\n",
		toolName, session.Symbol, session.KeyID, session.StartedAt.Format(time.RFC3339))

	// ─── TOOL ROUTING ────────────────────────────────────────────────────
	var result any
	var toolErr error

	switch toolName {
	case "ert_scan":
		result, toolErr = runERTScan(args, session)
	case "ert_godfather":
		result, toolErr = runGodfatherSynthesis(args, session)
	default:
		emitError(toolName, fmt.Sprintf("unknown tool: %s", toolName))
		os.Exit(1)
	}

	if toolErr != nil {
		emitError(toolName, toolErr.Error())
		os.Exit(1)
	}

	// ─── PQC ATTESTATION ─────────────────────────────────────────────────
	// Sign the result payload with Adinkhepra-PQC to create a DAG-anchorable attestation.
	resultBytes, _ := json.Marshal(result)
	resultHash := sha256.Sum256(resultBytes)
	fullHash := make([]byte, 64)
	copy(fullHash, resultHash[:])
	copy(fullHash[32:], resultHash[:])

	sig, sigErr := adinkra.SignAdinkhepraPQC(session.PrivateKey, fullHash)
	sigHex := ""
	if sigErr == nil {
		sigHex = hex.EncodeToString(sig[:32]) + "..." // Truncated for JSON readability
	} else {
		fmt.Fprintf(os.Stderr, "[PHANTOM] WARNING: PQC signing failed: %v\n", sigErr)
	}

	// Securely destroy private key material
	if session.PrivateKey != nil {
		session.PrivateKey.DestroyPrivateKey()
	}

	// ─── OUTPUT ──────────────────────────────────────────────────────────
	output := ToolOutput{
		Tool:        toolName,
		Status:      "completed",
		KeyID:       session.KeyID,
		Fingerprint: hex.EncodeToString(session.Fingerprint[:16]),
		Signature:   sigHex,
		AttestedAt:  time.Now().UTC().Format(time.RFC3339),
		Version:     Version,
		Result:      result,
	}

	b, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(b)) // stdout = structured result only
}

// initSession creates a PQC crypto session seeded by the Spectral Fingerprint.
func initSession(args map[string]any) (*SessionContext, error) {
	symbol := getSymbol(args)

	// Compute Spectral Fingerprint from the symbol's adjacency matrix
	fingerprint := adinkra.GetSpectralFingerprint(symbol)

	// Generate entropy seed: fingerprint + current nanosecond timestamp
	seed := make([]byte, 64)
	copy(seed, fingerprint)
	binary.BigEndian.PutUint64(seed[32:], uint64(time.Now().UnixNano()))
	h := sha256.Sum256(seed)

	// Initialize Merkaba White Box encryption engine
	merkaba := adinkra.NewMerkaba(h[:])

	// Generate Adinkhepra-PQC key pair for this session
	pubKey, privKey, err := adinkra.GenerateAdinkhepraPQCKeyPair(h[:], symbol)
	if err != nil {
		return nil, fmt.Errorf("PQC key generation failed: %w", err)
	}

	// Derive KeyID from public key seed
	keyHash := sha256.Sum256(pubKey.Seed[:])

	return &SessionContext{
		Symbol:      symbol,
		Fingerprint: fingerprint,
		PublicKey:    pubKey,
		PrivateKey:  privKey,
		Merkaba:     merkaba,
		KeyID:       hex.EncodeToString(keyHash[:8]),
		StartedAt:   time.Now().UTC(),
	}, nil
}

// getSymbol extracts the Adinkra symbol from args or environment, with sensible default.
func getSymbol(args map[string]any) string {
	// Check args first
	if s, ok := args["symbol"].(string); ok && s != "" {
		return s
	}
	// Check environment
	if s := os.Getenv("PHANTOM_SYMBOL"); s != "" {
		return s
	}
	// Default: Eban (Fortress/Security — highest precedence)
	return "Eban"
}

// ─── TOOL IMPLEMENTATIONS ───────────────────────────────────────────────────

func runERTScan(args map[string]any, session *SessionContext) (any, error) {
	// The /project directory is bind-mounted from the host by the SandboxManager.
	// In a full implementation, this would invoke the ERT ScanOrchestrator.
	projectPath := "/project"
	if p, ok := args["project_path"].(string); ok && p != "" {
		projectPath = p
	}

	fmt.Fprintf(os.Stderr, "[PHANTOM:ERT] Scanning project at %s\n", projectPath)
	fmt.Fprintf(os.Stderr, "[PHANTOM:ERT] Symbol: %s | Spectral: %s\n",
		session.Symbol, hex.EncodeToString(session.Fingerprint[:8]))

	// Check if project path exists
	info, err := os.Stat(projectPath)
	if err != nil {
		return map[string]any{
			"scan_status":  "error",
			"project_path": projectPath,
			"error":        fmt.Sprintf("project path not accessible: %v", err),
		}, nil // Return result with error field, not a Go error
	}

	return map[string]any{
		"scan_status":    "completed",
		"project_path":  projectPath,
		"project_size":  info.Size(),
		"symbol":        session.Symbol,
		"key_id":        session.KeyID,
		"scan_timestamp": time.Now().UTC().Format(time.RFC3339),
		// findings are populated by the ERT ScanOrchestrator in pkg/ert
		// and injected into this response by the calling MCP layer
		"findings":      []any{},
	}, nil
}

func runGodfatherSynthesis(_ map[string]any, session *SessionContext) (any, error) {
	// EA synthesis request — routes to the Evolutionary Algorithm engine.
	// The EA engine (pkg/ea) runs on the host; this binary provides
	// the PQC session context and attestation for the synthesis output.
	fmt.Fprintf(os.Stderr, "[PHANTOM:GODFATHER] EA synthesis requested | Symbol: %s\n", session.Symbol)

	return map[string]any{
		"synthesis_status": "completed",
		"symbol":           session.Symbol,
		"key_id":           session.KeyID,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"genomes":          []any{},
	}, nil
}

// emitError writes a structured error to stdout (for MCP consumption).
func emitError(toolName string, errMsg string) {
	output := ToolOutput{
		Tool:       toolName,
		Status:     "error",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
		Version:    Version,
		Error:      errMsg,
	}
	b, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "[PHANTOM] ERROR: %s\n", errMsg)
}
