package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestTokenDemarcGateway(t *testing.T) {
	good := strings.Repeat("a", 40)
	if _, err := NewTokenDemarcGateway(nil, nil); err == nil {
		t.Fatal("expected an error with no tokens")
	}
	if _, err := NewTokenDemarcGateway([]string{"short"}, nil); err == nil {
		t.Fatal("expected an error for a short token")
	}
	g, err := NewTokenDemarcGateway([]string{good}, []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if id, err := g.Authenticate(ctx, good); err != nil || id.AgentID == "" {
		t.Fatalf("configured token rejected: %v", err)
	}
	for _, cred := range []any{nil, "", "stdio", strings.Repeat("b", 40), Identity{AgentID: "x"}} {
		if _, err := g.Authenticate(ctx, cred); err == nil {
			t.Fatalf("credential %#v accepted", cred)
		}
	}
}
