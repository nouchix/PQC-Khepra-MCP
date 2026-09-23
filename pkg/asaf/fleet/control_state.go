// pkg/asaf/fleet/control_state.go
// Incremental scanning state store — per-asset, per-control state hashing.
//
// This is the continuous monitoring proof for C3PAO evidence.
// Every scan computes a lightweight "state probe" command and hashes its output.
// If the hash matches the stored value → control is "unchanged" (reuse DAG ref).
// If the hash differs → full check runs → new DAG node created.
//
// This eliminates the "PAPER_TIGER" C3PAO rejection pattern:
//   "Logs only for the audit week" → DAG shows state for every scan since enrollment.
//
// Storage: JSON file at <dagPath>/fleet/control_states.json
// Concurrency: RWMutex — safe for parallel fleet scan workers.
//
// IP: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// USPTO #73565085 (KHEPRA Protocol)

package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ControlState records the last known state of a STIG control on an asset.
type ControlState struct {
	AssetID     string    `json:"asset_id"`
	ControlID   string    `json:"control_id"`   // e.g. "RHEL-10-211010"
	StateHash   string    `json:"state_hash"`   // sha256(probe output)
	Status      string    `json:"status"`       // "pass" | "fail" | "unknown" | "not_implemented"
	Severity    string    `json:"severity"`     // "critical" | "high" | "medium" | "low"
	ProbeOutput string    `json:"probe_output"` // truncated (first 512 bytes)
	DAGNodeID   string    `json:"dag_node_id"`  // attestation reference for this state
	ScannedAt   time.Time `json:"scanned_at"`
	ChangedAt   time.Time `json:"changed_at"`   // last time StateHash changed
	ScanCount   int       `json:"scan_count"`   // total times this control was checked
	STIGVersion string    `json:"stig_version"` // e.g. "RHEL-10-STIG-V1R2"
}

// StateKey is the map key: assetID + ":" + controlID
type StateKey = string

// ControlStateStore manages per-control scan state for the entire fleet.
type ControlStateStore struct {
	mu       sync.RWMutex
	states   map[StateKey]*ControlState
	dataPath string // directory where control_states.json is written
	dirty    bool   // true when in-memory state differs from disk
}

// NewControlStateStore loads (or creates) the state store from dataPath.
func NewControlStateStore(dataPath string) (*ControlStateStore, error) {
	if err := os.MkdirAll(dataPath, 0700); err != nil {
		return nil, fmt.Errorf("control state store: mkdir %s: %w", dataPath, err)
	}

	s := &ControlStateStore{
		states:   make(map[StateKey]*ControlState),
		dataPath: dataPath,
	}

	stateFile := filepath.Join(dataPath, "control_states.json")
	data, err := os.ReadFile(stateFile)
	if os.IsNotExist(err) {
		return s, nil // fresh start
	}
	if err != nil {
		return nil, fmt.Errorf("control state store: read: %w", err)
	}

	var states []*ControlState
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, fmt.Errorf("control state store: parse: %w", err)
	}
	for _, st := range states {
		s.states[stateKey(st.AssetID, st.ControlID)] = st
	}
	return s, nil
}

// IsUnchanged returns true if the given probe output matches the stored state hash.
// When true, the caller can skip the full check and reuse the existing DAGNodeID.
func (s *ControlStateStore) IsUnchanged(assetID, controlID, probeOutput string) (bool, *ControlState) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := stateKey(assetID, controlID)
	stored, ok := s.states[key]
	if !ok {
		return false, nil // never scanned — run full check
	}
	return hashOutput(probeOutput) == stored.StateHash, stored
}

// Record stores or updates the control state after a full scan check.
// If the hash changed, ChangedAt is updated. DAGNodeID should be the
// newly created DAG attestation node for this result.
func (s *ControlStateStore) Record(st *ControlState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := stateKey(st.AssetID, st.ControlID)
	existing, ok := s.states[key]

	st.ScanCount = 1
	if ok {
		st.ScanCount = existing.ScanCount + 1
		// Only update ChangedAt if the hash actually changed
		if st.StateHash == existing.StateHash {
			st.ChangedAt = existing.ChangedAt
		} else {
			st.ChangedAt = st.ScannedAt
		}
	} else {
		st.ChangedAt = st.ScannedAt
	}

	// Truncate probe output for storage (save space, avoid sensitive data)
	if len(st.ProbeOutput) > 512 {
		st.ProbeOutput = st.ProbeOutput[:512] + "…"
	}

	s.states[key] = st
	s.dirty = true
}

// GetAssetStates returns all known control states for an asset.
// Used by the compliance graph to render current posture without re-scanning.
func (s *ControlStateStore) GetAssetStates(assetID string) []*ControlState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*ControlState
	for key, st := range s.states {
		if len(key) > len(assetID) && key[:len(assetID)] == assetID {
			result = append(result, st)
		}
	}
	return result
}

// FleetSummary returns aggregate pass/fail counts across the entire fleet.
func (s *ControlStateStore) FleetSummary() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := map[string]int{
		"pass":            0,
		"fail":            0,
		"unknown":         0,
		"not_implemented": 0,
	}
	for _, st := range s.states {
		counts[st.Status]++
	}
	return counts
}

// Flush writes the in-memory state to disk.
// Called after each scan run (or periodically by a background goroutine).
func (s *ControlStateStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.dirty {
		return nil
	}

	states := make([]*ControlState, 0, len(s.states))
	for _, st := range s.states {
		states = append(states, st)
	}

	data, err := json.MarshalIndent(states, "", "  ")
	if err != nil {
		return fmt.Errorf("control state flush: marshal: %w", err)
	}

	stateFile := filepath.Join(s.dataPath, "control_states.json")
	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("control state flush: write: %w", err)
	}
	if err := os.Rename(tmpFile, stateFile); err != nil {
		return fmt.Errorf("control state flush: rename: %w", err)
	}

	s.dirty = false
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func stateKey(assetID, controlID string) StateKey {
	return assetID + ":" + controlID
}

func hashOutput(output string) string {
	h := sha256.Sum256([]byte(output))
	return hex.EncodeToString(h[:])
}

// HashProbeOutput is exported for use by the fleet scanner when computing state hashes.
func HashProbeOutput(output string) string {
	return hashOutput(output)
}
