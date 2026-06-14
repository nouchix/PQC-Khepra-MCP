package gateway

import (
	"context"
	"time"
)

// ProcessTimelineFilter specifies query filters for process behavior events.
// This type is available in ALL deployment modes (sovereign + SaaS).
type ProcessTimelineFilter struct {
	// Limit caps the number of events returned (default: 100).
	Limit int
	// ComplianceStatus filters by status values, e.g. ["VIOLATION", "PENDING"].
	ComplianceStatus []string
	// TimeSince restricts results to events after this time (zero = no lower bound).
	TimeSince time.Time
}

// ProcessTimelineStore is the interface for querying the process_behavior_events table.
//
// Sovereign (air-gap) mode: use a NoopProcessTimelineStore (no network calls).
// SaaS mode: use SupabaseProcessTimelineStore (defined in process_timeline_store.go,
// compiled only with the `saas` build tag).
type ProcessTimelineStore interface {
	// QueryBySTIGControl returns process events mapped to the given STIG control ID.
	QueryBySTIGControl(ctx context.Context, stigControl string, filter ProcessTimelineFilter) ([]ProcessBehaviorEvent, error)
}

// NoopProcessTimelineStore is the sovereign-mode stub.
// It satisfies the ProcessTimelineStore interface but makes no network calls.
// Wire this in sovereign/ironbank deployments where Supabase is not available.
type NoopProcessTimelineStore struct{}

func (n *NoopProcessTimelineStore) QueryBySTIGControl(_ context.Context, _ string, _ ProcessTimelineFilter) ([]ProcessBehaviorEvent, error) {
	return nil, nil // no data in air-gap mode — caller must handle nil gracefully
}
