package aeo

import (
	"strings"
	"testing"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/forensics"
)

func testKeys(t *testing.T) (priv, pub []byte) {
	t.Helper()
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return priv, pub
}

func sealTask(t *testing.T, r *Recorder, task string) *EvidenceObject {
	t.Helper()
	rec := r.StartTask(task, "intent: "+task)
	rec.RecordToolCall("filesystem", "/etc/passwd", 12*time.Millisecond, "ok")
	rec.RecordToolCall("static-analysis", "pkg/auth", 40*time.Millisecond, "ok")
	rec.RecordObservation("pkg/auth/pqc_auth.go", "missing signature validation", 0.97, "")
	obj, err := rec.Seal()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return obj
}

func TestSealAndVerify(t *testing.T) {
	priv, pub := testKeys(t)
	r := NewRecorder(priv, pub)

	obj := sealTask(t, r, "security audit PQC-Khepra-MCP")

	if !strings.HasPrefix(obj.AgentID, DIDMethod) {
		t.Fatalf("bad agent DID: %s", obj.AgentID)
	}
	if obj.CryptographicAttestation.Algorithm != AttestAlgorithm {
		t.Fatalf("expected %s, got %s", AttestAlgorithm, obj.CryptographicAttestation.Algorithm)
	}
	if err := obj.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	priv, pub := testKeys(t)
	r := NewRecorder(priv, pub)
	obj := sealTask(t, r, "audit")

	obj.Observations[0].Finding = "everything is fine, nothing to see"
	if err := obj.Verify(); err == nil {
		t.Fatal("tampered AEO passed verification")
	}
}

func TestIdentityBinding(t *testing.T) {
	priv, pub := testKeys(t)
	r := NewRecorder(priv, pub)
	obj := sealTask(t, r, "audit")

	// Re-seal the same content with a different key: content hash still
	// matches, signature is valid, but the DID no longer binds.
	priv2, pub2 := testKeys(t)
	if err := obj.Seal(priv2, pub2); err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	if err := obj.Verify(); err == nil {
		t.Fatal("AEO signed by a foreign key passed identity verification")
	}
}

func TestChainAndReplay(t *testing.T) {
	priv, pub := testKeys(t)
	r := NewRecorder(priv, pub)

	ledgerPriv, _ := testKeys(t)
	ledger := NewLedger(dag.NewMemory(), ledgerPriv)

	var objs []*EvidenceObject
	for i := 0; i < 3; i++ {
		obj := sealTask(t, r, "audit round")
		if err := ledger.Append(obj); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		objs = append(objs, obj)
	}

	// Chain links: each parent is the previous hash, genesis is empty.
	if objs[0].ParentEvent != "" {
		t.Fatal("genesis parent not empty")
	}
	for i := 1; i < 3; i++ {
		if objs[i].ParentEvent != objs[i-1].Hash {
			t.Fatalf("chain link broken at %d", i)
		}
	}

	history, err := ledger.Replay(r.AgentID())
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("expected 3 events, got %d", len(history))
	}

	// Duplicate and out-of-chain appends must be rejected.
	if err := ledger.Append(objs[2]); err == nil {
		t.Fatal("duplicate append accepted")
	}

	// A second recorder with the same key would fork the chain; the ledger
	// must reject an event whose parent is not the current tip.
	fork := NewRecorder(priv, pub) // lastHash is "", so next event claims genesis
	forkObj := sealTask(t, fork, "forked history")
	if err := ledger.Append(forkObj); err == nil {
		t.Fatal("forked genesis accepted for an agent with existing history")
	}
}

func TestDAGAnchoring(t *testing.T) {
	priv, pub := testKeys(t)
	r := NewRecorder(priv, pub)
	ledgerPriv, _ := testKeys(t)
	store := dag.NewMemory()
	ledger := NewLedger(store, ledgerPriv)

	obj := sealTask(t, r, "anchored audit")
	if err := ledger.Append(obj); err != nil {
		t.Fatalf("append: %v", err)
	}

	nodes := store.All()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 anchor node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Action != DAGAction || n.PQC["aeo_hash"] != obj.Hash || n.PQC["agent_id"] != r.AgentID() {
		t.Fatalf("anchor node malformed: %+v", n)
	}
	if n.Signature == "" {
		t.Fatal("anchor node not signed")
	}
}

func TestBehaviorFingerprintDeterminism(t *testing.T) {
	calls := []ToolCall{
		{Tool: "github", LatencyMS: 5},
		{Tool: "filesystem", LatencyMS: 7},
		{Tool: "github", LatencyMS: 3},
	}
	a := fingerprint(calls)
	b := fingerprint(calls)
	if a.ExecutionPattern != b.ExecutionPattern || a.ToolGraph != b.ToolGraph {
		t.Fatal("fingerprint not deterministic")
	}

	reordered := []ToolCall{calls[1], calls[0], calls[2]}
	c := fingerprint(reordered)
	if a.ExecutionPattern == c.ExecutionPattern {
		t.Fatal("different execution order produced identical execution pattern")
	}
}

func TestTrustScoring(t *testing.T) {
	priv, pub := testKeys(t)
	r := NewRecorder(priv, pub)
	ledger := NewLedger(dag.NewMemory(), nil)

	for i := 0; i < 4; i++ {
		obj := sealTask(t, r, "consistent audit")
		if err := ledger.Append(obj); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	report := ledger.Trust(r.AgentID())
	if report.IntegrityScore != 100 {
		t.Fatalf("integrity: expected 100, got %d (%v)", report.IntegrityScore, report.Anomalies)
	}
	if report.ConsistencyScore != 100 {
		t.Fatalf("consistency: expected 100 for identical behavior, got %d", report.ConsistencyScore)
	}
	if report.Score < 95 {
		t.Fatalf("overall: expected >=95, got %d", report.Score)
	}

	unknown := ledger.Trust("did:khepra:nobody")
	if unknown.Score != 0 || unknown.Events != 0 {
		t.Fatalf("unknown agent should score 0, got %d", unknown.Score)
	}
}

func TestForensicSnapshotBridge(t *testing.T) {
	priv, pub := testKeys(t)
	r := NewRecorder(priv, pub)

	snapshot := &forensics.ForensicSnapshot{
		SnapshotID: "forensic-test-1",
		Timestamp:  time.Now().UTC(),
		Hostname:   "cui-host-01",
		Processes:  []forensics.ProcessInfo{{PID: 1, Name: "init"}},
		FileHashes: map[string]string{"/etc/ssh/sshd_config": "IMHOTEPHASH"},
		Hash:       "SNAPHASH",
	}

	obj, err := r.RecordForensicSnapshot(snapshot, 250*time.Millisecond)
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if err := obj.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if obj.Observations[0].Evidence != "SNAPHASH" {
		t.Fatal("snapshot hash not carried as observation evidence")
	}

	practices := CMMCEvidence(obj)
	want := map[string]bool{
		"CMMC.AU.L2-3.3.1": false, "CMMC.AU.L2-3.3.2": false, "CMMC.AU.L2-3.3.8": false,
		"CMMC.SI.L2-3.14.6": false, "CMMC.SI.L2-3.14.7": false, "CMMC.IR.L2-3.6.1": false,
	}
	for _, p := range practices {
		if _, ok := want[p.CMMCPractice]; ok {
			want[p.CMMCPractice] = true
		}
		if p.AEOHash != obj.Hash {
			t.Fatalf("practice %s not linked to AEO hash", p.CMMCPractice)
		}
	}
	for practice, seen := range want {
		if !seen {
			t.Fatalf("missing practice mapping: %s", practice)
		}
	}

	// Delta recording chains onto the same agent history.
	delta, err := r.RecordSnapshotDelta(snapshot, snapshot, []string{"NEW PROCESS: PID=666 Name=cryptominer"})
	if err != nil {
		t.Fatalf("delta: %v", err)
	}
	if delta.ParentEvent != obj.Hash {
		t.Fatal("delta AEO not chained to snapshot AEO")
	}
}
