package mcp

import "testing"

// allowAllLicense lets every tool through tier filtering so the test isolates
// the classified-tool filter.
type allowAllLicense struct{}

func (allowAllLicense) Check(string) error { return nil }

func TestListTools_HidesToolsMarkedClassified(t *testing.T) {
	const private = "private_build_tool"
	reg := &ManifestRegistry{byName: map[string]ToolSpec{
		"visible_tool": {Name: "visible_tool"},
		private:        {Name: private},
	}}
	r := &Router{registry: reg, license: allowAllLicense{}}

	listed := func() map[string]bool {
		out := map[string]bool{}
		for _, tool := range r.ListTools() {
			out[tool["name"].(string)] = true
		}
		return out
	}

	if !listed()[private] {
		t.Fatalf("precondition: %s should be listed before it is marked classified", private)
	}

	MarkClassified(private)
	t.Cleanup(func() {
		classifiedMu.Lock()
		delete(classifiedTools, private)
		classifiedMu.Unlock()
	})

	got := listed()
	if got[private] {
		t.Errorf("%s is still listed after MarkClassified", private)
	}
	if !got["visible_tool"] {
		t.Error("visible_tool disappeared; MarkClassified must hide only the named tools")
	}
}

func TestListTools_HidesBuiltinClassifiedTools(t *testing.T) {
	reg := &ManifestRegistry{byName: map[string]ToolSpec{
		"identity_shroud":   {Name: "identity_shroud"},
		"identity_epiphany": {Name: "identity_epiphany"},
	}}
	r := &Router{registry: reg, license: allowAllLicense{}}
	if n := len(r.ListTools()); n != 0 {
		t.Fatalf("expected classified tools to be hidden, got %d listed", n)
	}
}
