package ouroboros

import (
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
)

// ─── Test doubles ────────────────────────────────────────────────────────────

type stubEye struct {
	name   string
	isfets []maat.Isfet
}

func (e *stubEye) Name() string        { return e.name }
func (e *stubEye) Gaze() []maat.Isfet { return e.isfets }

type stubBlade struct {
	name      string
	action    string
	strikeErr error
	struck    []maat.Heka
}

func (b *stubBlade) Name() string              { return b.name }
func (b *stubBlade) CanStrike(h maat.Heka) bool { return h.Action == b.action }
func (b *stubBlade) Strike(h maat.Heka) error {
	b.struck = append(b.struck, h)
	return b.strikeErr
}

// ─── Blade constructors ──────────────────────────────────────────────────────

func TestNewRemediationBlade(t *testing.T) {
	b := NewRemediationBlade()
	if b == nil {
		t.Fatal("NewRemediationBlade returned nil")
	}
	if b.Name() == "" {
		t.Error("blade name should not be empty")
	}
}

func TestRemediationBlade_CanStrike_OnlyPurify(t *testing.T) {
	b := NewRemediationBlade()

	purify := maat.Heka{Action: maat.ActionPurify}
	if !b.CanStrike(purify) {
		t.Error("RemediationBlade should CanStrike ActionPurify")
	}

	banish := maat.Heka{Action: maat.ActionBanish}
	if b.CanStrike(banish) {
		t.Error("RemediationBlade should NOT CanStrike ActionBanish")
	}
}

func TestFirewallBlade_CanStrike_OnlyBanish(t *testing.T) {
	b := NewFirewallBlade()
	if b == nil {
		t.Fatal("NewFirewallBlade returned nil")
	}

	banish := maat.Heka{Action: maat.ActionBanish}
	if !b.CanStrike(banish) {
		t.Error("FirewallBlade should CanStrike ActionBanish")
	}

	purify := maat.Heka{Action: maat.ActionPurify}
	if b.CanStrike(purify) {
		t.Error("FirewallBlade should NOT CanStrike ActionPurify")
	}
}

func TestIsolationBlade_CanStrike_SealOrIsolate(t *testing.T) {
	b := NewIsolationBlade()

	if !b.CanStrike(maat.Heka{Action: maat.ActionSeal}) {
		t.Error("IsolationBlade should CanStrike ActionSeal")
	}
	if !b.CanStrike(maat.Heka{Action: maat.ActionIsolate}) {
		t.Error("IsolationBlade should CanStrike ActionIsolate")
	}
	if b.CanStrike(maat.Heka{Action: maat.ActionObserve}) {
		t.Error("IsolationBlade should NOT CanStrike ActionObserve")
	}
}

func TestMonitorBlade_CanStrike_OnlyObserve(t *testing.T) {
	b := NewMonitorBlade()

	if !b.CanStrike(maat.Heka{Action: maat.ActionObserve}) {
		t.Error("MonitorBlade should CanStrike ActionObserve")
	}
	if b.CanStrike(maat.Heka{Action: maat.ActionBanish}) {
		t.Error("MonitorBlade should NOT CanStrike ActionBanish")
	}
}

func TestMonitorBlade_Strike_DoesNotError(t *testing.T) {
	b := NewMonitorBlade()
	h := maat.Heka{
		Action:    maat.ActionObserve,
		Autonomous: true,
		Isfet: maat.Isfet{ID: "obs-1", Severity: maat.SeverityMinor},
	}
	if err := b.Strike(h); err != nil {
		t.Errorf("MonitorBlade.Strike should not error, got: %v", err)
	}
}

// ─── perceive (via Cycle) ────────────────────────────────────────────────────

func TestCyclePercieve_NoEyes(t *testing.T) {
	cycle := &Cycle{Eyes: []WedjatEye{}, stopChan: make(chan bool)}
	detected := cycle.perceive()
	if len(detected) != 0 {
		t.Errorf("expected 0 isfets with no eyes, got %d", len(detected))
	}
}

func TestCyclePercieve_SingleEyeWithIsfets(t *testing.T) {
	eye := &stubEye{
		name: "test-eye",
		isfets: []maat.Isfet{
			{ID: "a", Severity: maat.SeverityMinor},
			{ID: "b", Severity: maat.SeveritySevere},
		},
	}
	cycle := &Cycle{Eyes: []WedjatEye{eye}, stopChan: make(chan bool)}
	detected := cycle.perceive()
	if len(detected) != 2 {
		t.Errorf("expected 2 isfets, got %d", len(detected))
	}
}

func TestCyclePercieve_MultipleEyes_Combined(t *testing.T) {
	e1 := &stubEye{name: "e1", isfets: []maat.Isfet{{ID: "1"}}}
	e2 := &stubEye{name: "e2", isfets: []maat.Isfet{{ID: "2"}, {ID: "3"}}}
	e3 := &stubEye{name: "e3", isfets: []maat.Isfet{}} // silent eye

	cycle := &Cycle{Eyes: []WedjatEye{e1, e2, e3}, stopChan: make(chan bool)}
	detected := cycle.perceive()
	if len(detected) != 3 {
		t.Errorf("expected 3 isfets from 3 eyes, got %d", len(detected))
	}
}

// ─── Blade interface compliance ──────────────────────────────────────────────

func TestStubBlade_CanStrike(t *testing.T) {
	b := &stubBlade{name: "test", action: maat.ActionBanish}
	if !b.CanStrike(maat.Heka{Action: maat.ActionBanish}) {
		t.Error("stub should CanStrike its target action")
	}
	if b.CanStrike(maat.Heka{Action: maat.ActionObserve}) {
		t.Error("stub should NOT CanStrike other actions")
	}
}
