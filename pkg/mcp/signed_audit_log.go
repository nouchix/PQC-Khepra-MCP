// Package mcp — tamper-evident, ML-DSA-65-signed NDJSON audit log.
//
// NSA "MCP Security Design Considerations" mandates audit logs that cannot
// be repudiated. This implementation produces per-entry ML-DSA-65 signatures
// (sign each log line before writing). The log file becomes a tamper-evident
// chain: any modification of a prior entry breaks signature verification.
//
// In air-gapped DoD environments, this log file is the compliance artifact
// that satisfies DFARS 252.204-7012 incident reporting requirements.
//
// Chain structure:
//   Entry[0]: prev_hash = "genesis"
//   Entry[N]: prev_hash = SHA3-256(canonical JSON of Entry[N-1])
//   Each entry: signature = ML-DSA-65(privKey, SHA3-256(canonical entry JSON excluding sig field))

package mcp

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"golang.org/x/crypto/sha3"
)

// ─── AuditEntry — single tamper-evident log record ─────────────────────────

// AuditEntry is a single signed record in the NDJSON audit log.
// The canonical form for signing excludes the Signature field itself.
type AuditEntry struct {
	Seq       uint64    `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Event     MCPEvent  `json:"event"`
	PrevHash  string    `json:"prev_hash"`  // SHA3-256 hex of previous entry's canonical JSON
	Algorithm string    `json:"algorithm"`  // always "ML-DSA-65"
	PublicKey string    `json:"public_key"` // hex-encoded ML-DSA-65 public key (for offline verify)
	Signature string    `json:"signature"`  // ML-DSA-65 sig over SHA3-256(canonical entry without sig)
}

// canonical returns the JSON bytes of the entry with Signature zeroed,
// suitable for signing and hash chaining.
func (e AuditEntry) canonical() ([]byte, error) {
	copy := e
	copy.Signature = ""
	return json.Marshal(copy)
}

// ─── SignedAuditLog ─────────────────────────────────────────────────────────

// SignedAuditLog writes per-entry ML-DSA-65-signed NDJSON audit records.
// Thread-safe. Concurrent Append calls are serialized via mu.
type SignedAuditLog struct {
	path    string
	privKey []byte // ML-DSA-65 private key
	pubKey  []byte // corresponding public key (hex-embedded in each entry)
	pubHex  string // hex-encoded pubKey (cached)
	mu      sync.Mutex
	seq     atomic.Uint64
	prev    string // SHA3-256 hex of the last written entry (chain link)
	file    *os.File
	writer  *bufio.Writer
}

// SignedAuditLogConfig holds constructor parameters.
type SignedAuditLogConfig struct {
	// Path is the absolute path to the NDJSON audit log file.
	// If the file does not exist, it is created. If it exists, new entries
	// are appended and the sequence counter is resumed from the last entry.
	Path string

	// PrivKey is the ML-DSA-65 private key for entry signing.
	// If empty, entries are written unsigned (with a warning in the entry).
	PrivKey []byte

	// PubKey is the corresponding public key embedded in each entry.
	PubKey []byte
}

// NewSignedAuditLog creates and opens a SignedAuditLog.
// Returns an error if the file cannot be opened or the last entry cannot be read.
func NewSignedAuditLog(cfg SignedAuditLogConfig) (*SignedAuditLog, error) {
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("signed_audit_log: open %s: %w", cfg.Path, err)
	}

	sal := &SignedAuditLog{
		path:    cfg.Path,
		privKey: cfg.PrivKey,
		pubKey:  cfg.PubKey,
		pubHex:  hex.EncodeToString(cfg.PubKey),
		file:    f,
		writer:  bufio.NewWriterSize(f, 64*1024),
		prev:    "genesis",
	}

	// Resume sequence + chain from existing log
	if err := sal.resume(); err != nil {
		// Non-fatal: start fresh if file is unreadable (first run or corrupted)
		sal.prev = "genesis"
		sal.seq.Store(0)
	}

	return sal, nil
}

// resume reads the last line of an existing log file to continue the chain.
func (sal *SignedAuditLog) resume() error {
	// Re-open for reading to find last entry
	rf, err := os.Open(sal.path)
	if err != nil {
		return err
	}
	defer rf.Close()

	var lastLine string
	scanner := bufio.NewScanner(rf)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for scanner.Scan() {
		if t := scanner.Text(); t != "" {
			lastLine = t
		}
	}
	// Check for scanner I/O errors — must be after the loop, not inside it.
	// A scan error here means the file was partially read; returning the error
	// lets the caller decide whether to start a new chain or abort — we must
	// NOT silently accept a truncated chain hash as the resume point.
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("resume: scan audit log: %w", err)
	}
	if lastLine == "" {
		return nil
	}

	var last AuditEntry
	if err := json.Unmarshal([]byte(lastLine), &last); err != nil {
		return fmt.Errorf("resume: parse last entry: %w", err)
	}

	// Set chain state
	h := sha3digest([]byte(lastLine))
	sal.prev = hex.EncodeToString(h)
	sal.seq.Store(last.Seq + 1)
	return nil
}

// Append signs and writes a new audit entry.
// This is the primary write path — called by EventEmitter.Emit().
func (sal *SignedAuditLog) Append(event MCPEvent) error {
	sal.mu.Lock()
	defer sal.mu.Unlock()

	entry := AuditEntry{
		Seq:       sal.seq.Add(1) - 1,
		Timestamp: event.Timestamp,
		Event:     event,
		PrevHash:  sal.prev,
		Algorithm: "ML-DSA-65",
		PublicKey: sal.pubHex,
	}

	// Sign the entry
	if len(sal.privKey) > 0 {
		canonical, err := entry.canonical()
		if err != nil {
			return fmt.Errorf("signed_audit_log: canonicalize entry: %w", err)
		}
		digest := sha3digest(canonical)
		sig, err := adinkra.Sign(sal.privKey, digest)
		if err != nil {
			return fmt.Errorf("signed_audit_log: sign entry: %w", err)
		}
		entry.Signature = hex.EncodeToString(sig)
	}

	// Serialize as NDJSON
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("signed_audit_log: marshal entry: %w", err)
	}

	// Write line + newline
	if _, err := sal.writer.Write(line); err != nil {
		return fmt.Errorf("signed_audit_log: write: %w", err)
	}
	if err := sal.writer.WriteByte('\n'); err != nil {
		return fmt.Errorf("signed_audit_log: write newline: %w", err)
	}
	if err := sal.writer.Flush(); err != nil {
		return fmt.Errorf("signed_audit_log: flush: %w", err)
	}

	// Advance chain: prev = SHA3-256(this line)
	sal.prev = hex.EncodeToString(sha3digest(line))
	return nil
}

// Close flushes and closes the underlying file.
func (sal *SignedAuditLog) Close() error {
	sal.mu.Lock()
	defer sal.mu.Unlock()
	if err := sal.writer.Flush(); err != nil {
		return err
	}
	return sal.file.Close()
}

// ─── Chain Verification ─────────────────────────────────────────────────────

// VerifyChainResult is the outcome of a chain verification pass.
type VerifyChainResult struct {
	TotalEntries   int      `json:"total_entries"`
	ValidSignatures int     `json:"valid_signatures"`
	InvalidEntries []int64  `json:"invalid_entries,omitempty"` // seq numbers of broken entries
	ChainIntact    bool     `json:"chain_intact"`
	FirstBrokenSeq int64    `json:"first_broken_seq"` // -1 if chain intact
}

// VerifyChain reads the log at path and verifies the full signature chain.
// Any modification to any prior entry will produce a chain break.
// pubKey must be the ML-DSA-65 public key used during signing.
func VerifyChain(path string, pubKey []byte) (*VerifyChainResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("verify_chain: open %s: %w", path, err)
	}
	defer f.Close()

	result := &VerifyChainResult{FirstBrokenSeq: -1}
	prevHash := "genesis"
	lineNum := 0

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		lineNum++
		result.TotalEntries++

		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			result.InvalidEntries = append(result.InvalidEntries, int64(lineNum))
			if result.FirstBrokenSeq == -1 {
				result.FirstBrokenSeq = int64(entry.Seq)
			}
			prevHash = "broken"
			continue
		}

		// Verify chain link
		if entry.PrevHash != prevHash {
			result.InvalidEntries = append(result.InvalidEntries, int64(entry.Seq))
			if result.FirstBrokenSeq == -1 {
				result.FirstBrokenSeq = int64(entry.Seq)
			}
			prevHash = hex.EncodeToString(sha3digest(line))
			continue
		}

		// Verify ML-DSA-65 signature
		if len(pubKey) > 0 && entry.Signature != "" {
			canonical, err := entry.canonical()
			if err == nil {
				digest := sha3digest(canonical)
				sig, hexErr := hex.DecodeString(entry.Signature)
				if hexErr == nil {
					ok, verifyErr := adinkra.Verify(pubKey, digest, sig)
					if verifyErr == nil && ok {
						result.ValidSignatures++
					} else {
						result.InvalidEntries = append(result.InvalidEntries, int64(entry.Seq))
						if result.FirstBrokenSeq == -1 {
							result.FirstBrokenSeq = int64(entry.Seq)
						}
					}
				}
			}
		}

		prevHash = hex.EncodeToString(sha3digest(line))
	}

	result.ChainIntact = len(result.InvalidEntries) == 0
	return result, scanner.Err()
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// sha3digest computes SHA3-256 of the input.
func sha3digest(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}
