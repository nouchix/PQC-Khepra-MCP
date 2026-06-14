package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

// ComplianceAttestRecord is the JSONL entry written to dag-chain.jsonl.
// It embeds dag.Node fields directly so any verifier can reconstruct and
// verify the signature without needing the full adinkhepra binary.
type ComplianceAttestRecord struct {
	// DAG identity
	ID      string   `json:"id"`
	Parents []string `json:"parents"` // hash of previous record in chain

	// Attestation body
	Action    string `json:"action"` // e.g. "cmmc_control_updated"
	Symbol    string `json:"symbol"` // Adinkra symbol (Sankofa = "learn from past")
	ActorID   string `json:"actor_id"`
	OrgID     string `json:"org_id"`
	Timestamp string `json:"timestamp"` // ISO8601

	// Compliance-specific payload
	ControlID        string `json:"control_id"`         // e.g. "03.03.08"
	StatusTransition string `json:"status_transition"`  // e.g. "planned→partial"
	DocumentPath     string `json:"document_path"`      // relative path to narrative file
	DocumentHash     string `json:"document_hash"`      // sha256 of document at time of attest
	Note             string `json:"note,omitempty"`

	// PQC proof
	PQCMetadata struct {
		Algorithm string `json:"algorithm"` // "Dilithium3"
		PublicKey string `json:"public_key,omitempty"`
	} `json:"pqc_metadata"`

	Hash      string `json:"hash"`      // content hash of this record
	Signature string `json:"signature"` // hex Dilithium3 signature over Hash
}

const (
	// Adinkra symbol for compliance attestation:
	// Sankofa — "Go back and fetch it" — learning from the past to secure the future.
	// The perfect symbol for an audit chain.
	complianceAttestSymbol = "Sankofa"

	complianceAttestAction = "cmmc_compliance_attest"
)

func complianceAttestCmd(args []string) {
	fs := flag.NewFlagSet("compliance-attest", flag.ExitOnError)
	document   := fs.String("document", "", "Path to the SSP narrative or CMMC_TRACKER.md file being attested (required)")
	controlID  := fs.String("control", "", "NIST 800-171 control ID being updated, e.g. 03.03.08 (required)")
	symbol     := fs.String("symbol", "", "Status transition, e.g. 'planned→partial' (required)")
	note       := fs.String("note", "", "Free-text note for the audit record")
	keyPath    := fs.String("key", "", "Path to Dilithium3 private key (default: adinkhepra_master_dilithium)")
	chainFile  := fs.String("chain", "", "Path to dag-chain.jsonl (default: ../asaf-compliance/attestations/dag-chain.jsonl)")
	actor      := fs.String("actor", "souhimbou@nouchix.com", "Actor ID (signer identity)")
	org        := fs.String("org", "secred-knowledge-inc", "Organization ID")
	fs.Parse(args)

	// ── Validate required flags ──────────────────────────────────────────────
	if *document == "" || *controlID == "" || *symbol == "" {
		fmt.Fprintln(os.Stderr, "Error: --document, --control, and --symbol are required")
		printComplianceAttestUsage()
		os.Exit(1)
	}

	// ── Resolve defaults ─────────────────────────────────────────────────────
	if *keyPath == "" {
		// Look for master Dilithium key in standard locations
		candidates := []string{
			"adinkhepra_master_dilithium",
			filepath.Join(getExeDir(), "adinkhepra_master_dilithium"),
			resolvePath("keys/adinkhepra_master_dilithium"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				*keyPath = c
				break
			}
		}
		if *keyPath == "" {
			fmt.Fprintln(os.Stderr, "Error: Dilithium3 private key not found. Use --key to specify path.")
			fmt.Fprintln(os.Stderr, "  Checked: adinkhepra_master_dilithium, keys/adinkhepra_master_dilithium")
			os.Exit(1)
		}
	}

	if *chainFile == "" {
		// Default: sibling asaf-compliance repo
		*chainFile = filepath.Join("..", "asaf-compliance", "attestations", "dag-chain.jsonl")
	}

	// ── Read document and compute SHA-256 hash ───────────────────────────────
	docData, err := os.ReadFile(*document)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading document: %v\n", err)
		os.Exit(1)
	}
	docHash := sha256.Sum256(docData)
	docHashHex := hex.EncodeToString(docHash[:])

	// ── Read private key ─────────────────────────────────────────────────────
	privKeyData, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading private key: %v\n", err)
		os.Exit(1)
	}
	privKey, err := hex.DecodeString(strings.TrimSpace(string(privKeyData)))
	if err != nil {
		// Not hex — use raw bytes (PEM or binary key)
		privKey = privKeyData
	}

	// ── Find parent hash (tail of chain) ─────────────────────────────────────
	parentHash := ""
	if chainData, err := os.ReadFile(*chainFile); err == nil {
		lines := strings.Split(strings.TrimSpace(string(chainData)), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			var prev ComplianceAttestRecord
			if json.Unmarshal([]byte(line), &prev) == nil && prev.Hash != "" {
				parentHash = prev.Hash
				break
			}
		}
	}

	// ── Build the attestation record ─────────────────────────────────────────
	now := time.Now().UTC()
	rec := ComplianceAttestRecord{
		Action:           complianceAttestAction,
		Symbol:           complianceAttestSymbol,
		ActorID:          *actor,
		OrgID:            *org,
		Timestamp:        now.Format(time.RFC3339),
		ControlID:        *controlID,
		StatusTransition: *symbol,
		DocumentPath:     *document,
		DocumentHash:     "sha256:" + docHashHex,
		Note:             *note,
	}
	rec.PQCMetadata.Algorithm = "Dilithium3"

	if parentHash != "" {
		rec.Parents = []string{parentHash}
	}

	// ── Compute content hash (same canonical approach as pkg/dag Node) ───────
	// We hash: action|symbol|timestamp|controlID|statusTransition|docHash|parent
	canonParts := []string{
		rec.Action,
		rec.Symbol,
		rec.Timestamp,
		rec.ControlID,
		rec.StatusTransition,
		rec.DocumentHash,
		parentHash,
	}
	canonRaw := strings.Join(canonParts, "|")
	contentHash := dag.HashBytes([]byte(canonRaw))
	rec.Hash = contentHash
	rec.ID = contentHash

	// ── Sign with Dilithium3 ─────────────────────────────────────────────────
	sigBytes, err := adinkra.Sign(privKey, []byte(rec.Hash))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Signing error: %v\n", err)
		os.Exit(1)
	}
	rec.Signature = hex.EncodeToString(sigBytes)

	// ── Ensure attestations directory exists ─────────────────────────────────
	if err := os.MkdirAll(filepath.Dir(*chainFile), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create attestations dir: %v\n", err)
		os.Exit(1)
	}

	// ── Append to dag-chain.jsonl ─────────────────────────────────────────────
	line, err := json.Marshal(rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Serialization error: %v\n", err)
		os.Exit(1)
	}

	f, err := os.OpenFile(*chainFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open chain file: %v\n", err)
		os.Exit(1)
	}
	w := bufio.NewWriter(f)
	w.Write(line)
	w.WriteString("\n")
	w.Flush()
	f.Close()

	// ── Print receipt ─────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║        ADINKHEPRA // COMPLIANCE ATTESTATION SEALED          ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Symbol     : %s (Sankofa — go back and fetch it)\n", complianceAttestSymbol)
	fmt.Printf("  Control    : %s\n", rec.ControlID)
	fmt.Printf("  Transition : %s\n", rec.StatusTransition)
	fmt.Printf("  Document   : %s\n", rec.DocumentPath)
	fmt.Printf("  Doc SHA256 : %s\n", rec.DocumentHash)
	fmt.Printf("  Node Hash  : %s\n", rec.Hash)
	fmt.Printf("  Parent     : %s\n", parentHash)
	fmt.Printf("  Algorithm  : Dilithium3 (NIST FIPS 204 / ML-DSA)\n")
	fmt.Printf("  Sig (first 32 chars): %s...\n", rec.Signature[:32])
	fmt.Printf("  Chain file : %s\n", *chainFile)
	fmt.Printf("  Timestamp  : %s\n", rec.Timestamp)
	fmt.Println()
	fmt.Printf("✓ Attestation appended to DAG chain. Hash chain depth: %s\n",
		countChainDepth(*chainFile))
	fmt.Println()
	fmt.Println("  Verify with:")
	fmt.Printf("    python asaf-compliance/attestations/verify.py \\\n")
	fmt.Printf("      %s \\\n", *chainFile)
	fmt.Printf("      adinkhepra_master_dilithium.pub\n")
	fmt.Println()
}

// countChainDepth returns human-readable chain depth string
func countChainDepth(chainFile string) string {
	data, err := os.ReadFile(chainFile)
	if err != nil {
		return "1"
	}
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return fmt.Sprintf("%d nodes", count)
}

func printComplianceAttestUsage() {
	fmt.Println(`adinkhepra compliance-attest — PQC-signed DAG attestation for CMMC compliance changes

Usage:
  adinkhepra compliance-attest \
    --document <path/to/narrative.md> \
    --control  <03.xx.xx> \
    --symbol   "<planned→partial>" \
    [--note    "<free text>"] \
    [--key     <dilithium3_privkey>] \
    [--chain   <path/to/dag-chain.jsonl>] \
    [--actor   <email>] \
    [--org     <org-id>]

Examples:
  # Mark a control narrative as partial (from planned)
  adinkhepra compliance-attest \
    --document ../asaf-compliance/ASAF-GovCloud-SSP/SP_800_171_03.03/SP_800_171_03.03.08.md \
    --control  03.03.08 \
    --symbol   "planned→partial" \
    --note     "S3 Object Lock evidence exported, narrative written"

  # Close a POAM item
  adinkhepra compliance-attest \
    --document ../asaf-compliance/CMMC_TRACKER.md \
    --control  POAM-001 \
    --symbol   "open→closed" \
    --note     "pkg/supabase build tags added, verified in sovereign build"

The attestation node is:
  - Hashed  : SHA-256 of canonical fields (action|symbol|timestamp|controlID|transition|docHash|parent)
  - Signed  : Dilithium3 (NIST FIPS 204 / ML-DSA) using adinkhepra_master_dilithium
  - Chained : Each node references the hash of the previous node (tamper-evident)
  - Stored  : Appended to dag-chain.jsonl (one JSON object per line)
  - Verified: python asaf-compliance/attestations/verify.py <chain> <pubkey>`)
}
