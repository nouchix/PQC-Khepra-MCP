package sekhem

import (
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
)

// ─── WAFMetrics ──────────────────────────────────────────────────────────────

func TestWAFMetrics_InitialState(t *testing.T) {
	m := newWAFMetrics()
	if m == nil {
		t.Fatal("newWAFMetrics returned nil")
	}
	snap := m.Snapshot()
	if snap.TotalChecked != 0 {
		t.Errorf("expected TotalChecked=0, got %d", snap.TotalChecked)
	}
	if snap.Blocked != 0 || snap.Challenged != 0 || snap.Bypassed != 0 {
		t.Error("expected all counters zero on init")
	}
}

func TestWAFMetrics_Record_Block(t *testing.T) {
	m := newWAFMetrics()
	m.record("SEKHEM-001", WAFActionBlock)
	m.record("SEKHEM-001", WAFActionBlock)

	snap := m.Snapshot()
	if snap.TotalChecked != 2 {
		t.Errorf("expected TotalChecked=2, got %d", snap.TotalChecked)
	}
	if snap.Blocked != 2 {
		t.Errorf("expected Blocked=2, got %d", snap.Blocked)
	}
	if snap.RuleHits["SEKHEM-001"] != 2 {
		t.Errorf("expected SEKHEM-001 hits=2, got %d", snap.RuleHits["SEKHEM-001"])
	}
}

func TestWAFMetrics_Record_Challenge(t *testing.T) {
	m := newWAFMetrics()
	m.record("SEKHEM-RATE", WAFActionChallenge)

	snap := m.Snapshot()
	if snap.Challenged != 1 {
		t.Errorf("expected Challenged=1, got %d", snap.Challenged)
	}
	if snap.Blocked != 0 {
		t.Errorf("expected Blocked=0, got %d", snap.Blocked)
	}
}

func TestWAFMetrics_Record_Bypass(t *testing.T) {
	m := newWAFMetrics()
	m.record("SEKHEM-BYPASS", WAFActionBypass)

	snap := m.Snapshot()
	if snap.Bypassed != 1 {
		t.Errorf("expected Bypassed=1, got %d", snap.Bypassed)
	}
}

func TestWAFMetrics_Snapshot_IsCopy(t *testing.T) {
	m := newWAFMetrics()
	m.record("SEKHEM-001", WAFActionBlock)

	snap1 := m.Snapshot()
	m.record("SEKHEM-001", WAFActionBlock) // second record
	snap2 := m.Snapshot()

	// snap1 should not be affected by the second record
	if snap1.TotalChecked != 1 {
		t.Errorf("snapshot should be immutable: expected 1, got %d", snap1.TotalChecked)
	}
	if snap2.TotalChecked != 2 {
		t.Errorf("expected snap2 TotalChecked=2, got %d", snap2.TotalChecked)
	}
}

// ─── severityToMalevolence ───────────────────────────────────────────────────

func TestSeverityToMalevolence_Range(t *testing.T) {
	tests := []struct {
		sev      maat.Severity
		minScore float64
		maxScore float64
	}{
		{maat.SeverityMinor, 0.0, 0.5},
		{maat.SeverityModerate, 0.5, 0.7},
		{maat.SeveritySevere, 0.7, 0.9},
		{maat.SeverityCatastrophic, 0.9, 1.0},
	}
	for _, tc := range tests {
		score := severityToMalevolence(tc.sev)
		if score < tc.minScore || score > tc.maxScore {
			t.Errorf("severity=%s malevolence=%f out of expected [%f,%f]",
				tc.sev, score, tc.minScore, tc.maxScore)
		}
	}
}

func TestSeverityToMalevolence_Unknown(t *testing.T) {
	score := severityToMalevolence("UNKNOWN")
	if score <= 0 || score > 1 {
		t.Errorf("unknown severity should still return a valid [0,1] score, got %f", score)
	}
}

// ─── newCorrelationID ────────────────────────────────────────────────────────

func TestNewCorrelationID_NonEmpty(t *testing.T) {
	id := newCorrelationID()
	if id == "" {
		t.Error("expected non-empty correlation ID")
	}
}

func TestNewCorrelationID_Unique(t *testing.T) {
	id1 := newCorrelationID()
	id2 := newCorrelationID()
	if id1 == id2 {
		t.Error("correlation IDs should be unique")
	}
}

// ─── NewWAFShield ────────────────────────────────────────────────────────────

func TestNewWAFShield_NotNil(t *testing.T) {
	shield, err := NewWAFShield(WAFShieldConfig{})
	if err != nil {
		t.Fatalf("NewWAFShield failed: %v", err)
	}
	defer shield.Close()
	if shield == nil {
		t.Fatal("NewWAFShield returned nil")
	}
}

func TestNewWAFShield_HasKyberKey(t *testing.T) {
	shield, err := NewWAFShield(WAFShieldConfig{})
	if err != nil {
		t.Fatalf("NewWAFShield failed: %v", err)
	}
	defer shield.Close()

	pub := shield.CurrentKyberPublicKey()
	if len(pub) == 0 {
		t.Error("expected non-empty Kyber public key after construction")
	}
}

func TestNewWAFShield_Metrics_InitiallyZero(t *testing.T) {
	shield, err := NewWAFShield(WAFShieldConfig{})
	if err != nil {
		t.Fatalf("NewWAFShield failed: %v", err)
	}
	defer shield.Close()

	snap := shield.Metrics()
	if snap.TotalChecked != 0 {
		t.Errorf("expected TotalChecked=0 on fresh WAFShield, got %d", snap.TotalChecked)
	}
}

func TestNewWAFShield_ThreatChan_Readable(t *testing.T) {
	shield, err := NewWAFShield(WAFShieldConfig{})
	if err != nil {
		t.Fatalf("NewWAFShield failed: %v", err)
	}
	defer shield.Close()

	ch := shield.ThreatChan()
	if ch == nil {
		t.Error("ThreatChan() should return a non-nil channel")
	}
}
