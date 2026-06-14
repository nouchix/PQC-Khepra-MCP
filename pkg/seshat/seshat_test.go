package seshat

import (
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

// ─── NewChronicle ───────────────────────────────────────────────────────────

func TestNewChronicle(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)
	if c == nil {
		t.Fatal("NewChronicle returned nil")
	}
	if c.DAGStore == nil {
		t.Error("DAGStore is nil")
	}
	if len(c.Papyrus) != 0 {
		t.Errorf("expected empty Papyrus, got %d entries", len(c.Papyrus))
	}
}

// ─── Inscribe ───────────────────────────────────────────────────────────────

func TestInscribe_WritesToPapyrus(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)

	err := c.Inscribe("Eban", map[string]any{"event": "test"})
	if err != nil {
		t.Fatalf("Inscribe returned error: %v", err)
	}
	if len(c.Papyrus) != 1 {
		t.Fatalf("expected 1 inscription, got %d", len(c.Papyrus))
	}
	ins := c.Papyrus[0]
	if ins.Symbol != "Eban" {
		t.Errorf("expected symbol Eban, got %s", ins.Symbol)
	}
	if ins.NodeID == "" {
		t.Error("expected non-empty NodeID")
	}
}

func TestInscribe_MultipleEntries(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)

	symbols := []string{"Eban", "Sankofa", "Dwennimmen", "Nkyinkyim"}
	for _, sym := range symbols {
		if err := c.Inscribe(sym, map[string]any{"sym": sym}); err != nil {
			t.Fatalf("Inscribe(%s) error: %v", sym, err)
		}
	}
	if len(c.Papyrus) != len(symbols) {
		t.Errorf("expected %d inscriptions, got %d", len(symbols), len(c.Papyrus))
	}
}

func TestInscribe_EmptyData(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)

	// Empty data map should still succeed
	err := c.Inscribe("Fawohodie", map[string]any{})
	if err != nil {
		t.Fatalf("Inscribe with empty data should succeed, got: %v", err)
	}
	if len(c.Papyrus) != 1 {
		t.Errorf("expected 1 inscription, got %d", len(c.Papyrus))
	}
}

// ─── ReadPapyrus ────────────────────────────────────────────────────────────

func TestReadPapyrus_LimitRespected(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)

	for i := 0; i < 5; i++ {
		c.Inscribe("Eban", map[string]any{"i": i}) //nolint:errcheck
	}

	recent := c.ReadPapyrus(3)
	if len(recent) != 3 {
		t.Errorf("expected 3 entries with limit=3, got %d", len(recent))
	}
}

func TestReadPapyrus_LimitLargerThanPapyrus(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)

	c.Inscribe("Sankofa", map[string]any{}) //nolint:errcheck
	c.Inscribe("Eban", map[string]any{})    //nolint:errcheck

	all := c.ReadPapyrus(100)
	if len(all) != 2 {
		t.Errorf("expected 2 entries (all), got %d", len(all))
	}
}

func TestReadPapyrus_ZeroLimit(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)

	c.Inscribe("Eban", map[string]any{}) //nolint:errcheck
	result := c.ReadPapyrus(0)
	if len(result) != 0 {
		t.Errorf("expected 0 entries with limit=0, got %d", len(result))
	}
}

// ─── ReadAll ────────────────────────────────────────────────────────────────

func TestReadAll_EmptyPapyrus(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)
	all := c.ReadAll()
	if len(all) != 0 {
		t.Errorf("expected empty Papyrus, got %d entries", len(all))
	}
}

func TestReadAll_AfterInscriptions(t *testing.T) {
	store := dag.NewMemory()
	c := NewChronicle(store, nil)

	for i := 0; i < 3; i++ {
		c.Inscribe("Eban", map[string]any{"n": i}) //nolint:errcheck
	}
	all := c.ReadAll()
	if len(all) != 3 {
		t.Errorf("expected 3 inscriptions, got %d", len(all))
	}
}
