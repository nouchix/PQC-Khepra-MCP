package intelligence

import (
	"strings"
	"testing"
)

// ─── OfflineProvider ─────────────────────────────────────────────────────────

func TestOfflineProvider_Name(t *testing.T) {
	p := &OfflineProvider{}
	if p.Name() == "" {
		t.Error("OfflineProvider.Name should not be empty")
	}
}

func TestOfflineProvider_Chat_EmptyMessages(t *testing.T) {
	p := &OfflineProvider{}
	resp, err := p.Chat([]Message{}, false)
	if err != nil {
		t.Fatalf("OfflineProvider.Chat should not error, got: %v", err)
	}
	if resp == "" {
		t.Error("expected non-empty response")
	}
}

func TestOfflineProvider_Chat_STIGQuery(t *testing.T) {
	p := &OfflineProvider{}
	resp, err := p.Chat([]Message{{Role: "user", Content: "How do I run a stig scan?"}}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(strings.ToLower(resp), "scan") {
		t.Errorf("expected scan-related guidance, got: %s", resp)
	}
}

func TestOfflineProvider_Chat_PQCQuery(t *testing.T) {
	p := &OfflineProvider{}
	resp, err := p.Chat([]Message{{Role: "user", Content: "Tell me about PQC migration"}}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == "" {
		t.Error("expected PQC response")
	}
}

func TestOfflineProvider_Chat_HelpQuery(t *testing.T) {
	p := &OfflineProvider{}
	resp, err := p.Chat([]Message{{Role: "user", Content: "help"}}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Help response should list commands
	if !strings.Contains(strings.ToLower(resp), "scan") {
		t.Errorf("help response should include scan command, got: %s", resp)
	}
}

func TestOfflineProvider_Chat_DAGQuery(t *testing.T) {
	p := &OfflineProvider{}
	resp, err := p.Chat([]Message{{Role: "user", Content: "What is the DAG?"}}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == "" {
		t.Error("expected non-empty DAG response")
	}
}

func TestOfflineProvider_Chat_DefaultFallback(t *testing.T) {
	p := &OfflineProvider{}
	resp, err := p.Chat([]Message{{Role: "user", Content: "random unrecognized query xyz123"}}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return a useful message about offline mode
	if !strings.Contains(strings.ToLower(resp), "offline") {
		t.Errorf("expected offline mode message for unrecognized query, got: %s", resp)
	}
}

// ─── NewBestAvailableProvider ────────────────────────────────────────────────

func TestNewBestAvailableProvider_NeverNil(t *testing.T) {
	// Without any API keys set, should return OfflineProvider
	p := NewBestAvailableProvider()
	if p == nil {
		t.Fatal("NewBestAvailableProvider should never return nil")
	}
	if p.Name() == "" {
		t.Error("provider name should not be empty")
	}
}

// ─── NewServer ───────────────────────────────────────────────────────────────

func TestNewServer_NotNil(t *testing.T) {
	s := NewServer(nil) // nil DAG — offline mode
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.Provider == nil {
		t.Error("Server provider should not be nil")
	}
}

func TestNewServer_EmptyHistory(t *testing.T) {
	s := NewServer(nil)
	if len(s.History) != 0 {
		t.Errorf("expected empty history, got %d messages", len(s.History))
	}
}

// ─── Message ─────────────────────────────────────────────────────────────────

func TestMessage_ZeroValue(t *testing.T) {
	var m Message
	if m.Role != "" || m.Content != "" {
		t.Error("zero-value Message should have empty fields")
	}
}
