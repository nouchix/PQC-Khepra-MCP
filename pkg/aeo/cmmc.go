package aeo

import (
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/forensics"
)

// PracticeEvidence links one AEO to one CMMC practice it substantiates.
type PracticeEvidence struct {
	CMMCPractice string `json:"cmmc_practice"` // e.g. "CMMC.AU.L2-3.3.1"
	NIST         string `json:"nist_800_171"`  // e.g. "3.3.1"
	Rationale    string `json:"rationale"`
	AEOHash      string `json:"aeo_hash"`
}

// CMMCEvidence maps a verified AEO onto the CMMC 2.0 practices it proves.
// This is what turns the agent's forensic self-documentation into assessor
// deliverables: the same signed object that proves WHAT the agent did also
// satisfies the audit-and-accountability evidence standard for it.
func CMMCEvidence(obj *EvidenceObject) []PracticeEvidence {
	base := []PracticeEvidence{
		{
			CMMCPractice: "CMMC.AU.L2-3.3.1",
			NIST:         "3.3.1",
			Rationale:    "AEO is a system audit record: agent identity, task, tools, observations, and timestamp are captured for every action.",
			AEOHash:      obj.Hash,
		},
		{
			CMMCPractice: "CMMC.AU.L2-3.3.2",
			NIST:         "3.3.2",
			Rationale:    "Actions are traceable to a unique agent (did:khepra DID bound to an ML-DSA-65 key), supporting individual accountability.",
			AEOHash:      obj.Hash,
		},
		{
			CMMCPractice: "CMMC.AU.L2-3.3.8",
			NIST:         "3.3.8",
			Rationale:    "Audit information is protected from unauthorized modification: content-addressed, ML-DSA-65 signed, and DAG-anchored.",
			AEOHash:      obj.Hash,
		},
	}

	// Forensic host snapshots additionally substantiate SI and IR practices.
	for _, t := range obj.ToolsUsed {
		if t == ForensicSnapshotTool {
			base = append(base,
				PracticeEvidence{
					CMMCPractice: "CMMC.SI.L2-3.14.6",
					NIST:         "3.14.6",
					Rationale:    "Snapshot monitors the system (processes, connections, ports, sessions) to detect attacks and indicators of potential attacks.",
					AEOHash:      obj.Hash,
				},
				PracticeEvidence{
					CMMCPractice: "CMMC.SI.L2-3.14.7",
					NIST:         "3.14.7",
					Rationale:    "Snapshot comparison identifies unauthorized use: new processes, new connections, and modified critical files are surfaced as observations.",
					AEOHash:      obj.Hash,
				},
				PracticeEvidence{
					CMMCPractice: "CMMC.IR.L2-3.6.1",
					NIST:         "3.6.1",
					Rationale:    "Signed point-in-time forensic snapshots provide the detection and analysis capability of an operational incident-handling capability.",
					AEOHash:      obj.Hash,
				},
			)
			break
		}
	}
	return base
}

// ForensicSnapshotTool is the tool label used when an AEO wraps an
// Imhotep's Eye host snapshot.
const ForensicSnapshotTool = "imhotep-forensic-snapshot"

// RecordForensicSnapshot bridges the host layer into the agent layer: it
// wraps a pkg/forensics snapshot as a signed AEO. The snapshot's own hash is
// carried as observation evidence, so host state and agent action are sealed
// together — the endpoint's condition and the entity that observed it become
// one verifiable record.
func (r *Recorder) RecordForensicSnapshot(snapshot *forensics.ForensicSnapshot, collectionTime time.Duration) (*EvidenceObject, error) {
	rec := r.StartTask(
		"forensic snapshot "+snapshot.SnapshotID,
		fmt.Sprintf("collect point-in-time forensic state of host %s for CMMC AU/SI/IR evidence", snapshot.Hostname),
	)
	rec.RecordToolCall(ForensicSnapshotTool, snapshot.Hostname, collectionTime, "ok")

	rec.RecordObservation(snapshot.Hostname,
		fmt.Sprintf("system state captured: %d processes, %d network connections, %d listening ports, %d monitored files",
			len(snapshot.Processes), len(snapshot.NetworkConns), len(snapshot.OpenPorts), len(snapshot.FileHashes)),
		1.0, snapshot.Hash)

	for path, hash := range snapshot.FileHashes {
		rec.RecordObservation(path, "critical file integrity hash recorded", 1.0, hash)
	}

	return rec.Seal()
}

// RecordSnapshotDelta records the differences between two snapshots as an
// AEO — the evidence trail for "what changed on this host, and who saw it".
func (r *Recorder) RecordSnapshotDelta(old, new *forensics.ForensicSnapshot, changes []string) (*EvidenceObject, error) {
	rec := r.StartTask(
		"forensic delta "+old.SnapshotID+" -> "+new.SnapshotID,
		"compare consecutive forensic snapshots to detect unauthorized change on host "+new.Hostname,
	)
	rec.RecordToolCall(ForensicSnapshotTool, new.Hostname, 0, "ok")

	if len(changes) == 0 {
		rec.RecordObservation(new.Hostname, "no changes detected between snapshots", 1.0, new.Hash)
	}
	for _, change := range changes {
		rec.RecordObservation(new.Hostname, change, 1.0, new.Hash)
	}

	return rec.Seal()
}
