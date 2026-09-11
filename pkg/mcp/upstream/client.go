package upstream

// client.go: a minimal MCP client over Streamable HTTP (spec 2025-03-26+).
// Handles the parts a broker needs and nothing else: initialize, tools/list
// (paginated), tools/call, session id propagation, and both response
// encodings the transport allows (a JSON body, or an SSE stream carrying
// the JSON-RPC response as an event).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const protocolVersion = "2025-06-18"

// ErrUnauthorized is returned when the upstream answers 401/403 — the caller
// should refresh or re-authorize and retry.
var ErrUnauthorized = errors.New("upstream/client: unauthorized")

// ToolDef is one entry from upstream tools/list, kept verbatim so the
// schema hash pins exactly what the server advertised.
type ToolDef struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	InputSchema json.RawMessage  `json:"inputSchema,omitempty"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

// ToolAnnotations are the MCP spec's behavioral hints. They are *hints*
// from an untrusted server: we use readOnlyHint to relax, never to bypass
// — a tool that claims read-only but has a mutating verb in its name is
// still classified by the verb.
type ToolAnnotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool `json:"openWorldHint,omitempty"`
}

// CallResult mirrors the tools/call result shape.
type CallResult struct {
	Content []json.RawMessage `json:"content"`
	IsError bool              `json:"isError,omitempty"`
	// StructuredContent is the 2025-06-18 typed result, when present.
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
}

// Client talks to one upstream MCP server.
type Client struct {
	url       string
	http      *http.Client
	tokenFn   func() string // returns current bearer token, "" for none
	sessionID atomic.Value  // string
	nextID    atomic.Int64
	initOnce  sync.Mutex
	initDone  bool
	serverInf map[string]any
}

// NewClient constructs a client. tokenFn is consulted on every request so
// refreshed tokens take effect without rebuilding the client.
func NewClient(url string, tokenFn func() string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	c := &Client{url: url, http: hc, tokenFn: tokenFn}
	c.sessionID.Store("")
	return c
}

// URL returns the upstream endpoint.
func (c *Client) URL() string { return c.url }

// ServerInfo returns the upstream's advertised serverInfo after Initialize.
func (c *Client) ServerInfo() map[string]any { return c.serverInf }

// ─── JSON-RPC plumbing ────────────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("upstream rpc error %d: %s", e.Code, e.Message) }

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// post sends one JSON-RPC message. If id is nil it is a notification and
// the body is not parsed.
func (c *Client) post(ctx context.Context, method string, params any, wantID *int64) (*rpcResponse, *http.Response, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: wantID, Method: method, Params: params})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", protocolVersion)
	if sid, _ := c.sessionID.Load().(string); sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if tok := c.tokenFn(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream/client: %s: %w", method, err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, resp, ErrUnauthorized
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID.Store(sid)
	}
	if wantID == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return nil, resp, fmt.Errorf("upstream/client: %s: %s", method, resp.Status)
		}
		return nil, resp, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, resp, fmt.Errorf("upstream/client: %s: %s: %s", method, resp.Status, truncate(raw, 200))
	}

	ct := resp.Header.Get("Content-Type")
	var rr *rpcResponse
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		rr, err = readSSEResponse(resp.Body, *wantID)
	default:
		rr = &rpcResponse{}
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(rr)
	}
	if err != nil {
		return nil, resp, fmt.Errorf("upstream/client: %s: decode: %w", method, err)
	}
	if rr.Error != nil {
		return rr, resp, rr.Error
	}
	return rr, resp, nil
}

// readSSEResponse scans an event stream for the JSON-RPC response whose id
// matches. Servers may interleave notifications; those are skipped.
func readSSEResponse(r io.Reader, wantID int64) (*rpcResponse, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	var data strings.Builder
	flush := func() (*rpcResponse, bool) {
		if data.Len() == 0 {
			return nil, false
		}
		payload := data.String()
		data.Reset()
		var rr rpcResponse
		if json.Unmarshal([]byte(payload), &rr) != nil {
			return nil, false
		}
		var id int64
		if len(rr.ID) == 0 || json.Unmarshal(rr.ID, &id) != nil || id != wantID {
			return nil, false
		}
		return &rr, true
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if rr, ok := flush(); ok {
				return rr, nil
			}
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			// "event:", "id:", ":" comments — ignored
		}
	}
	if rr, ok := flush(); ok {
		return rr, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("stream ended without response id=%d", wantID)
}

func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	id := c.nextID.Add(1)
	rr, _, err := c.post(ctx, method, params, &id)
	if err != nil {
		return err
	}
	if out != nil && len(rr.Result) > 0 {
		return json.Unmarshal(rr.Result, out)
	}
	return nil
}

// ─── MCP methods ──────────────────────────────────────────────────────────────

// Initialize performs the handshake once. Safe to call repeatedly.
func (c *Client) Initialize(ctx context.Context) error {
	c.initOnce.Lock()
	defer c.initOnce.Unlock()
	if c.initDone {
		return nil
	}
	var res struct {
		ProtocolVersion string         `json:"protocolVersion"`
		ServerInfo      map[string]any `json:"serverInfo"`
	}
	err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "khepra-mcp-broker", "version": "1.0.0"},
	}, &res)
	if err != nil {
		return err
	}
	c.serverInf = res.ServerInfo
	if _, _, err := c.post(ctx, "notifications/initialized", map[string]any{}, nil); err != nil {
		return err
	}
	c.initDone = true
	return nil
}

// Reset drops session state so the next call re-initializes (after re-auth).
func (c *Client) Reset() {
	c.initOnce.Lock()
	c.initDone = false
	c.sessionID.Store("")
	c.initOnce.Unlock()
}

// ListTools walks tools/list pagination to completion.
func (c *Client) ListTools(ctx context.Context) ([]ToolDef, error) {
	if err := c.Initialize(ctx); err != nil {
		return nil, err
	}
	var all []ToolDef
	cursor := ""
	for i := 0; i < 64; i++ { // pagination sanity bound
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var page struct {
			Tools      []ToolDef `json:"tools"`
			NextCursor string    `json:"nextCursor"`
		}
		if err := c.call(ctx, "tools/list", params, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Tools...)
		if page.NextCursor == "" {
			return all, nil
		}
		cursor = page.NextCursor
	}
	return all, errors.New("upstream/client: tools/list pagination did not terminate")
}

// CallTool invokes an upstream tool.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (*CallResult, error) {
	if err := c.Initialize(ctx); err != nil {
		return nil, err
	}
	if args == nil {
		args = map[string]any{}
	}
	var res CallResult
	if err := c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
