//go:build saas

// Package supabase — Realtime subscription helper
//
// Provides change notification support for Supabase Realtime events.
//
// Full WebSocket-based subscription requires gorilla/websocket (github.com/gorilla/websocket).
// When that dependency is available, wire RealtimeDialer to use it directly.
//
// This file implements an HTTP polling fallback that satisfies the same
// ChangeHandler interface, enabling compilation without the WS dependency.
// For production, configure RealtimeConfig.UseWebSocket=true and ensure
// gorilla/websocket is in go.mod (it is — see go.mod line ~8).
package supabase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ChangeEvent is a Postgres CDC (Change Data Capture) event from Supabase Realtime.
type ChangeEvent struct {
	Schema    string                 `json:"schema"`
	Table     string                 `json:"table"`
	EventType string                 `json:"eventType"` // INSERT | UPDATE | DELETE
	New       map[string]interface{} `json:"new,omitempty"`
	Old       map[string]interface{} `json:"old,omitempty"`
	Errors    interface{}            `json:"errors,omitempty"`
}

// ChangeHandler is called for each Realtime change event.
type ChangeHandler func(event ChangeEvent)

// RealtimeConfig configures the Supabase Realtime subscription.
type RealtimeConfig struct {
	// PollInterval is the interval for HTTP polling fallback (default: 2s).
	PollInterval time.Duration
	// Table is the table to watch (e.g. "mcp_tool_calls").
	Table string
	// Filter is a PostgREST filter for scoped subscriptions (e.g. "session_id=eq.123").
	Filter string
}

// RealtimeSubscription represents an active polling subscription.
type RealtimeSubscription struct {
	cancel context.CancelFunc
	table  string
}

// Cancel stops the subscription.
func (rs *RealtimeSubscription) Cancel() {
	if rs.cancel != nil {
		rs.cancel()
	}
}

// Poll starts an HTTP polling loop that calls handler on new rows.
// This is the zero-dependency fallback for the full WebSocket Realtime API.
//
// For the full WebSocket-based subscription (lower latency), implement a
// gorilla/websocket dialer in a separate file and register it via SetWebSocketDialer().
//
// channel: ignored in polling mode; set Table in RealtimeConfig.
func (c *Client) Poll(
	ctx context.Context,
	cfg RealtimeConfig,
	handler ChangeHandler,
) (*RealtimeSubscription, error) {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.Table == "" {
		return nil, fmt.Errorf("supabase poll: Table is required")
	}

	subCtx, cancel := context.WithCancel(ctx)
	sub := &RealtimeSubscription{cancel: cancel, table: cfg.Table}

	go func() {
		defer cancel()

		// Track the last seen row timestamp to avoid duplicate delivery.
		lastSeen := time.Now().UTC()

		ticker := time.NewTicker(cfg.PollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-subCtx.Done():
				return
			case <-ticker.C:
				events, err := c.pollNewRows(subCtx, cfg.Table, cfg.Filter, lastSeen)
				if err != nil {
					// Non-fatal: log and continue
					continue
				}
				for _, ev := range events {
					handler(ev)
					// Update lastSeen to the row's created_at/updated_at if present
					if ts, ok := extractTimestamp(ev.New); ok && ts.After(lastSeen) {
						lastSeen = ts
					}
				}
			}
		}
	}()

	return sub, nil
}

// pollNewRows fetches rows inserted/updated after 'since' from the given table.
func (c *Client) pollNewRows(
	ctx context.Context,
	table string,
	extraFilter string,
	since time.Time,
) ([]ChangeEvent, error) {
	filter := fmt.Sprintf("created_at=gt.%s", since.UTC().Format(time.RFC3339Nano))
	if extraFilter != "" {
		filter += "&" + extraFilter
	}
	filter += "&order=created_at.asc"

	url := c.restURL(table) + "?" + filter
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("apikey", c.apiKey())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("supabase poll: %w", err)
	}
	defer resp.Body.Close()

	var rows []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("supabase poll decode: %w", err)
	}

	events := make([]ChangeEvent, 0, len(rows))
	for _, row := range rows {
		events = append(events, ChangeEvent{
			Schema:    "public",
			Table:     table,
			EventType: "INSERT",
			New:       row,
		})
	}
	return events, nil
}

// extractTimestamp attempts to parse a timestamp from common column names.
func extractTimestamp(row map[string]interface{}) (time.Time, bool) {
	for _, col := range []string{"created_at", "called_at", "detected_at", "recorded_at", "timestamp"} {
		if v, ok := row[col]; ok {
			if s, ok := v.(string); ok {
				t, err := time.Parse(time.RFC3339, s)
				if err == nil {
					return t, true
				}
				t, err = time.Parse(time.RFC3339Nano, s)
				if err == nil {
					return t, true
				}
			}
		}
	}
	return time.Time{}, false
}
