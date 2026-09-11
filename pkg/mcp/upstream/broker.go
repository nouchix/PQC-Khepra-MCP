package upstream

// broker.go: turns an upstream MCP server into KHEPRA-native ToolSpecs +
// handlers so its tools run through the Router's admission chain.
//
// Trust model for brokered tools — different from native tools, stated
// plainly:
//   - Native tools are pinned by the ML-DSA-65-signed manifest.
//   - Brokered tools are pinned trust-on-first-use: the first tools/list we
//     see is hashed per tool and sealed on disk (store.go). Every later
//     connect re-hashes and refuses any tool whose advertised schema or
//     description changed. That is the tool-rug / description-poisoning
//     defense; it is not a signature from the upstream, because upstreams
//     don't sign their manifests.
//   - Risk class is derived from the tool name and the upstream's
//     annotations, with an unknown-verb default of Destructive. A brokered
//     write therefore needs `_confirm: true` exactly like nhi_revoke does.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	khepramcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// Config describes one upstream to broker.
type Config struct {
	// URL is the upstream MCP endpoint (Streamable HTTP).
	URL string
	// Alias namespaces the tools: <alias>__<tool>. Lowercase [a-z0-9_].
	Alias string
	// Store holds sealed tokens + pins. Required.
	Store *Store
	// OAuth tunes the consent flow.
	OAuth OAuthConfig
	// Interactive permits launching the consent flow from Connect. When
	// false and no valid token exists, Connect fails with an actionable
	// error instead of blocking a stdio server on a browser.
	Interactive bool
	// TimeoutMs is the per-call budget written into each ToolSpec.
	TimeoutMs int
	Logger    *log.Logger
}

// Broker is one connected upstream.
type Broker struct {
	cfg    Config
	state  *ServerState
	client *Client
	mu     sync.Mutex // guards state.Tokens during refresh
	specs  []khepramcp.ToolSpec
	// Refused lists tools dropped because their pinned schema changed.
	Refused []string
	// NewlyPinned lists tools pinned for the first time on this connect.
	NewlyPinned []string
}

var aliasRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// New validates config and prepares (but does not connect) a broker.
func New(cfg Config) (*Broker, error) {
	if cfg.URL == "" {
		return nil, errors.New("upstream/broker: URL required")
	}
	if !strings.HasPrefix(cfg.URL, "https://") && !strings.HasPrefix(cfg.URL, "http://127.0.0.1") && !strings.HasPrefix(cfg.URL, "http://localhost") {
		return nil, fmt.Errorf("upstream/broker: %s — only https (or loopback http) upstreams are brokered; a bearer token over plain http is a credential leak", cfg.URL)
	}
	if !aliasRe.MatchString(cfg.Alias) {
		return nil, fmt.Errorf("upstream/broker: alias %q must match %s", cfg.Alias, aliasRe)
	}
	if cfg.Store == nil {
		return nil, errors.New("upstream/broker: Store required")
	}
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 30000
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	cfg.OAuth.Logger = cfg.Logger
	return &Broker{cfg: cfg}, nil
}

// Alias returns the tool namespace.
func (b *Broker) Alias() string { return b.cfg.Alias }

// Specs returns the ToolSpecs produced by Connect.
func (b *Broker) Specs() []khepramcp.ToolSpec { return b.specs }

// ─── Credential lifecycle ─────────────────────────────────────────────────────

func (b *Broker) currentToken() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == nil || b.state.Tokens == nil {
		return ""
	}
	return b.state.Tokens.AccessToken
}

// ensureToken guarantees a usable access token, refreshing or (if allowed)
// re-authorizing. Persists on any change.
func (b *Broker) ensureToken(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state.Tokens != nil && !b.state.Tokens.Expired() {
		return nil
	}
	if b.state.Tokens != nil && b.state.Tokens.RefreshToken != "" {
		ts, err := Refresh(ctx, b.cfg.OAuth, b.cfg.URL, b.state.Registration, b.state.Tokens)
		if err == nil {
			b.state.Tokens = ts
			b.cfg.Logger.Printf("[UPSTREAM:%s] token refreshed, expires %s", b.cfg.Alias, ts.ExpiresAt.Format(time.RFC3339))
			return b.cfg.Store.Save(b.state)
		}
		b.cfg.Logger.Printf("[UPSTREAM:%s] refresh failed: %v", b.cfg.Alias, err)
	}
	if !b.cfg.Interactive {
		return fmt.Errorf("upstream/broker: %s has no valid credential — run `khepra-mcp -login %s` to authorize", b.cfg.Alias, b.cfg.URL)
	}
	ts, reg, err := Authorize(ctx, b.cfg.OAuth, b.cfg.URL, b.state.Registration)
	if err != nil {
		return err
	}
	b.state.Tokens, b.state.Registration = ts, reg
	return b.cfg.Store.Save(b.state)
}

// withAuthRetry runs fn; on ErrUnauthorized it invalidates the cached token,
// obtains a fresh one (refresh → interactive consent if permitted), resets
// the MCP session, and retries exactly once. Methods can't be generic, hence
// the free function.
func withAuthRetry[T any](b *Broker, ctx context.Context, fn func() (T, error)) (T, error) {
	out, err := fn()
	if !errors.Is(err, ErrUnauthorized) {
		return out, err
	}
	b.mu.Lock()
	if b.state.Tokens != nil {
		b.state.Tokens.ExpiresAt = time.Now().Add(-time.Minute)
	}
	b.mu.Unlock()
	if err := b.ensureToken(ctx); err != nil {
		var zero T
		return zero, err
	}
	b.client.Reset()
	return fn()
}

// Login forces the interactive consent flow regardless of stored state.
func (b *Broker) Login(ctx context.Context) error {
	st, err := b.cfg.Store.Load(b.cfg.URL)
	if err != nil {
		return err
	}
	b.state = st
	cfg := b.cfg.OAuth
	cfg.OpenBrowser = true
	ts, reg, err := Authorize(ctx, cfg, b.cfg.URL, st.Registration)
	if err != nil {
		return err
	}
	st.Tokens, st.Registration = ts, reg
	return b.cfg.Store.Save(st)
}

// Logout discards sealed credentials and pins for this upstream.
func (b *Broker) Logout() error { return b.cfg.Store.Forget(b.cfg.URL) }

// ─── Connect + pin ────────────────────────────────────────────────────────────

// Connect loads sealed state, obtains a token, discovers tools, enforces
// pins, and builds ToolSpecs. Idempotent.
func (b *Broker) Connect(ctx context.Context) error {
	st, err := b.cfg.Store.Load(b.cfg.URL)
	if err != nil {
		return err
	}
	b.state = st
	b.client = NewClient(b.cfg.URL, b.currentToken, b.cfg.OAuth.withDefaults().HTTPClient)

	// Proactively refresh a token we already know is stale; otherwise let the
	// upstream tell us. Public MCP servers without auth must work too.
	if st.Tokens != nil && st.Tokens.Expired() && st.Tokens.RefreshToken != "" {
		if err := b.ensureToken(ctx); err != nil {
			b.cfg.Logger.Printf("[UPSTREAM:%s] pre-flight refresh: %v (will retry on 401)", b.cfg.Alias, err)
		}
	}
	defs, err := withAuthRetry(b, ctx, func() ([]ToolDef, error) { return b.client.ListTools(ctx) })
	if err != nil {
		return err
	}
	if len(defs) == 0 {
		return fmt.Errorf("upstream/broker: %s advertised zero tools", b.cfg.Alias)
	}

	repin := os.Getenv("KHEPRA_UPSTREAM_REPIN") == "1"
	firstPin := len(st.Pins) == 0
	seen := map[string]bool{}
	b.specs = b.specs[:0]
	b.Refused, b.NewlyPinned = nil, nil

	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	for _, d := range defs {
		seen[d.Name] = true
		hash := schemaHash(d)
		risk := classify(d)

		if pin, ok := st.Pins[d.Name]; ok {
			if pin.SchemaHash != hash {
				if repin {
					b.cfg.Logger.Printf("[UPSTREAM:%s] REPIN %s (operator override) old=%s new=%s", b.cfg.Alias, d.Name, pin.SchemaHash[:12], hash[:12])
				} else {
					b.cfg.Logger.Printf("[UPSTREAM:%s] REFUSED %s — advertised schema/description changed since pin (%s → %s). Tool-rug defense. Set KHEPRA_UPSTREAM_REPIN=1 after reviewing to accept.",
						b.cfg.Alias, d.Name, pin.SchemaHash[:12], hash[:12])
					b.Refused = append(b.Refused, d.Name)
					continue
				}
			}
			// A tool may not quietly *lower* its risk class between connects.
			if rank(risk) < rank(khepramcp.ToolRiskClass(pin.RiskClass)) && !repin {
				risk = khepramcp.ToolRiskClass(pin.RiskClass)
			}
		} else if !firstPin {
			b.NewlyPinned = append(b.NewlyPinned, d.Name)
			b.cfg.Logger.Printf("[UPSTREAM:%s] new tool %s appeared since first pin — pinning as %s", b.cfg.Alias, d.Name, risk)
		}
		st.Pins[d.Name] = PinnedTool{Name: d.Name, SchemaHash: hash, PinnedAt: time.Now(), RiskClass: string(risk), Description: d.Description}
		b.specs = append(b.specs, b.spec(d, hash, risk))
	}
	for name := range st.Pins {
		if !seen[name] {
			b.cfg.Logger.Printf("[UPSTREAM:%s] pinned tool %s no longer advertised (pin retained)", b.cfg.Alias, name)
		}
	}
	if firstPin {
		st.PinnedAt = time.Now()
		b.cfg.Logger.Printf("[UPSTREAM:%s] first connect — pinned %d tools (TOFU). Sealed at %s", b.cfg.Alias, len(b.specs), b.cfg.Store.Dir())
	}
	if err := b.cfg.Store.Save(st); err != nil {
		return err
	}
	b.cfg.Logger.Printf("[UPSTREAM:%s] %d tools brokered (%d refused, %d newly pinned) from %v",
		b.cfg.Alias, len(b.specs), len(b.Refused), len(b.NewlyPinned), b.client.ServerInfo())
	return nil
}

// schemaHash is SHA-256 over canonical JSON of what the LLM will see.
// inputSchema is re-marshalled through a map so key order can't perturb it.
func schemaHash(d ToolDef) string {
	var schema any
	if len(d.InputSchema) > 0 {
		_ = json.Unmarshal(d.InputSchema, &schema)
	}
	canon, _ := json.Marshal(map[string]any{"name": d.Name, "description": d.Description, "inputSchema": schema})
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// ─── Risk classification ──────────────────────────────────────────────────────

var (
	readVerbs  = regexp.MustCompile(`(?i)^(get|list|read|fetch|search|find|query|describe|show|check|view|lookup|stat|status|count|export|download)[_\-]?`)
	writeVerbs = regexp.MustCompile(`(?i)(^|[_\-])(create|add|update|edit|set|put|patch|delete|remove|destroy|drop|pause|resume|start|stop|reset|restart|enable|disable|toggle|send|post|write|upload|import|revoke|rotate|purge|clear|kill|deploy|rollback|assign|unassign|invite|approve|reject|cancel|archive)([_\-]|$)`)
)

// classify maps an upstream tool to a KHEPRA risk class.
//
//	explicit write verb            → Destructive (needs _confirm)
//	read verb, no write verb       → ReadOnly
//	readOnlyHint=true, no write    → ReadOnly
//	destructiveHint=true           → Destructive
//	anything else                  → Destructive (unknown = fail closed)
func classify(d ToolDef) khepramcp.ToolRiskClass {
	name := d.Name
	if writeVerbs.MatchString(name) {
		return khepramcp.RiskDestructive
	}
	if d.Annotations != nil && d.Annotations.DestructiveHint != nil && *d.Annotations.DestructiveHint {
		return khepramcp.RiskDestructive
	}
	if readVerbs.MatchString(name) {
		return khepramcp.RiskReadOnly
	}
	if d.Annotations != nil && d.Annotations.ReadOnlyHint != nil && *d.Annotations.ReadOnlyHint {
		return khepramcp.RiskReadOnly
	}
	return khepramcp.RiskDestructive
}

func rank(r khepramcp.ToolRiskClass) int {
	switch r {
	case khepramcp.RiskReadOnly:
		return 0
	case khepramcp.RiskSandboxed:
		return 1
	default:
		return 2
	}
}

// ─── ToolSpec synthesis ───────────────────────────────────────────────────────

func (b *Broker) namespaced(tool string) string { return b.cfg.Alias + "__" + tool }

func (b *Broker) spec(d ToolDef, hash string, risk khepramcp.ToolRiskClass) khepramcp.ToolSpec {
	var schema map[string]any
	if len(d.InputSchema) > 0 {
		_ = json.Unmarshal(d.InputSchema, &schema)
	}
	if schema == nil {
		schema = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	if risk == khepramcp.RiskDestructive {
		// Surface the confirmation gate in the schema so the LLM client sees
		// it rather than discovering it from an error.
		props, _ := schema["properties"].(map[string]any)
		if props == nil {
			props = map[string]any{}
		}
		props["_confirm"] = map[string]any{
			"type":        "boolean",
			"description": "KHEPRA human-in-the-loop gate: this tool mutates state on " + b.cfg.Alias + ". Set true only after the operator has reviewed the action.",
		}
		schema["properties"] = props
	}
	scope := "upstream:" + b.cfg.Alias + ":read"
	if risk != khepramcp.RiskReadOnly {
		scope = "upstream:" + b.cfg.Alias + ":write"
	}
	desc := d.Description
	if desc == "" {
		desc = "(upstream provided no description)"
	}
	return khepramcp.ToolSpec{
		Name:           b.namespaced(d.Name),
		Description:    fmt.Sprintf("[%s] %s", b.cfg.Alias, desc),
		RiskClass:      risk,
		Scope:          scope,
		SchemaVersion:  "upstream-tofu",
		SchemaHash:     hash,
		AllowedBackend: "in-process",
		TimeoutMs:      b.cfg.TimeoutMs,
		NetworkAllowed: true,
		Destructive:    risk == khepramcp.RiskDestructive,
		ArgsSchema:     schema,
		MaxPrivilege:   "network-read",
		Meta: map[string]any{
			"brokered":      true,
			"upstream":      b.cfg.URL,
			"upstream_tool": d.Name,
			"pin":           "tofu",
		},
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// RegisterHandlers wires one executor handler per brokered tool.
func (b *Broker) RegisterHandlers(ex *khepramcp.Executor) {
	for _, s := range b.specs {
		upstreamName, _ := s.Meta["upstream_tool"].(string)
		ex.RegisterFunc(s.Name, b.handler(upstreamName))
	}
}

func (b *Broker) handler(upstreamName string) func(context.Context, khepramcp.MCPToolCall) (any, []string, error) {
	return func(ctx context.Context, call khepramcp.MCPToolCall) (any, []string, error) {
		args := make(map[string]any, len(call.Args))
		for k, v := range call.Args {
			if k == "_confirm" { // KHEPRA-local; never forwarded
				continue
			}
			args[k] = v
		}
		res, err := withAuthRetry(b, ctx, func() (*CallResult, error) { return b.client.CallTool(ctx, upstreamName, args) })
		if err != nil {
			return nil, nil, fmt.Errorf("upstream %s/%s: %w", b.cfg.Alias, upstreamName, err)
		}
		var warnings []string
		if res.IsError {
			warnings = append(warnings, "upstream reported isError=true")
		}
		return flatten(res), warnings, nil
	}
}

// flatten turns the MCP content array into a result the Router can seal.
// structuredContent wins when present; otherwise text parts are joined and
// non-text parts are passed through raw.
func flatten(res *CallResult) any {
	if len(res.StructuredContent) > 0 {
		var v any
		if json.Unmarshal(res.StructuredContent, &v) == nil {
			return map[string]any{"structured": v, "is_error": res.IsError}
		}
	}
	var texts []string
	var other []json.RawMessage
	for _, c := range res.Content {
		var part struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(c, &part) == nil && part.Type == "text" {
			texts = append(texts, part.Text)
			continue
		}
		other = append(other, c)
	}
	out := map[string]any{"is_error": res.IsError}
	if len(texts) > 0 {
		joined := strings.Join(texts, "\n")
		// Upstreams often return JSON-as-text; surface it structured when so.
		var v any
		if json.Unmarshal([]byte(joined), &v) == nil {
			out["data"] = v
		} else {
			out["text"] = joined
		}
	}
	if len(other) > 0 {
		out["content"] = other
	}
	return out
}
