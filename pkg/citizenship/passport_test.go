package citizenship

import (
	"testing"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/aeo"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
)

func keys(t *testing.T) (priv, pub []byte) {
	t.Helper()
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return priv, pub
}

// buildHistory seals n chained AEOs for one agent into a fresh ledger.
func buildHistory(t *testing.T, n int) (*aeo.Ledger, *aeo.Recorder) {
	t.Helper()
	agentPriv, agentPub := keys(t)
	rec := aeo.NewRecorder(agentPriv, agentPub)
	ledger := aeo.NewLedger(dag.NewMemory(), nil)

	for i := 0; i < n; i++ {
		task := rec.StartTask("compliance audit", "verify CMMC AU controls")
		task.RecordToolCall("filesystem", "/etc", 10*time.Millisecond, "ok")
		task.RecordToolCall("static-analysis", "pkg/", 20*time.Millisecond, "ok")
		task.RecordObservation("pkg/auth", "control satisfied", 0.99, "")
		obj, err := task.Seal()
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		if err := ledger.Append(obj); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return ledger, rec
}

func TestIssueAndVerify(t *testing.T) {
	ledger, rec := buildHistory(t, 3)
	regPriv, regPub := keys(t)
	registrar := NewRegistrar("KHEPRA Test Registrar", regPriv, regPub)

	passport, err := registrar.Issue(ledger, rec.AgentID())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if passport.Events != 3 || passport.AgentID != rec.AgentID() {
		t.Fatalf("passport claims wrong: %+v", passport)
	}
	if passport.TrustScore < 95 {
		t.Fatalf("expected high trust for clean history, got %d", passport.TrustScore)
	}
	if passport.RegistrarID != registrar.ID() {
		t.Fatal("registrar DID mismatch")
	}
	if err := passport.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := passport.VerifyAgainstLedger(ledger); err != nil {
		t.Fatalf("verify against ledger: %v", err)
	}
}

func TestRefusesAgentWithoutHistory(t *testing.T) {
	ledger, _ := buildHistory(t, 1)
	regPriv, regPub := keys(t)
	registrar := NewRegistrar("KHEPRA Test Registrar", regPriv, regPub)

	if _, err := registrar.Issue(ledger, "did:khepra:nobody"); err == nil {
		t.Fatal("passport issued for agent with no history")
	}
}

func TestTamperedPassportRejected(t *testing.T) {
	ledger, rec := buildHistory(t, 2)
	regPriv, regPub := keys(t)
	registrar := NewRegistrar("KHEPRA Test Registrar", regPriv, regPub)

	passport, err := registrar.Issue(ledger, rec.AgentID())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// A clean history already scores 100 — tamper DOWNWARD so the canonical
	// content is guaranteed to change.
	passport.TrustScore = 7
	passport.Events = 9000
	if err := passport.Verify(); err == nil {
		t.Fatal("tampered passport passed verification")
	}
}

func TestStalePassportStillVerifiesAgainstAdvancedLedger(t *testing.T) {
	ledger, rec := buildHistory(t, 2)
	regPriv, regPub := keys(t)
	registrar := NewRegistrar("KHEPRA Test Registrar", regPriv, regPub)

	passport, err := registrar.Issue(ledger, rec.AgentID())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Ledger advances after issue: passport is stale but honest.
	task := rec.StartTask("later audit", "another round")
	task.RecordToolCall("filesystem", "/etc", time.Millisecond, "ok")
	obj, err := task.Seal()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := ledger.Append(obj); err != nil {
		t.Fatalf("append: %v", err)
	}

	if err := passport.VerifyAgainstLedger(ledger); err != nil {
		t.Fatalf("stale-but-honest passport rejected: %v", err)
	}
}

func TestRevocation(t *testing.T) {
	ledger, rec := buildHistory(t, 2)
	regPriv, regPub := keys(t)
	registrar := NewRegistrar("KHEPRA Test Registrar", regPriv, regPub)

	passport, err := registrar.Issue(ledger, rec.AgentID())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	revoked, err := registrar.Revoke(passport)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !revoked.Revoked {
		t.Fatal("revoked flag not set")
	}
	if err := revoked.Verify(); err != nil {
		t.Fatalf("revoked passport must still verify as a document: %v", err)
	}

	// A foreign registrar cannot revoke.
	otherPriv, otherPub := keys(t)
	other := NewRegistrar("Impostor", otherPriv, otherPub)
	if _, err := other.Revoke(passport); err == nil {
		t.Fatal("foreign registrar revoked a passport it did not issue")
	}
}
