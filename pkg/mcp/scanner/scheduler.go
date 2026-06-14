package scanner

// scheduler.go — Continuous scan orchestration with event-driven + polling fallback.
//
// Wires the Scanner into an event loop:
//   - Starts with CaptureBaseline()
//   - Re-scans on inbound ScanEvent OR when ticker fires
//   - Non-blocking result delivery (drops findings if consumer is slow)

import (
	"context"
	"log"
	"time"
)

// ScanEvent triggers an unscheduled scan run.
type ScanEvent struct {
	Reason string    // Human-readable trigger (e.g. "tool_registered", "manifest_reload")
	At     time.Time // When the trigger occurred
}

// Scheduler wraps Scanner in a continuous scanning loop.
type Scheduler struct {
	scanner  *Scanner
	interval time.Duration
	events   <-chan ScanEvent
	results  chan<- []MCPFinding
	logger   *log.Logger
}

// NewScheduler creates a Scheduler.
//
//   - interval: polling cadence (e.g. 5*time.Minute)
//   - events: optional inbound channel for on-demand scan triggers (nil = polling only)
//   - results: outbound channel receiving scan findings (nil = findings discarded)
func NewScheduler(
	router RouterInspector,
	acpPlane ACPInspector,
	interval time.Duration,
	events <-chan ScanEvent,
	results chan<- []MCPFinding,
	logger *log.Logger,
) *Scheduler {
	if logger == nil {
		logger = log.Default()
	}
	return &Scheduler{
		scanner:  New(router, acpPlane),
		interval: interval,
		events:   events,
		results:  results,
		logger:   logger,
	}
}

// Run starts the continuous scanning loop. Blocks until ctx is cancelled.
// Call in a goroutine: go scheduler.Run(ctx)
func (s *Scheduler) Run(ctx context.Context) {
	s.scanner.CaptureBaseline()
	s.logger.Printf("[scanner] baseline captured — continuous monitoring active (interval=%s)", s.interval)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Printf("[scanner] context cancelled — stopping")
			return

		case ev, ok := <-s.events:
			if !ok {
				s.logger.Printf("[scanner] event channel closed — stopping")
				return
			}
			s.logger.Printf("[scanner] event-triggered scan: reason=%q", ev.Reason)
			s.runScan(ctx)

		case <-ticker.C:
			s.runScan(ctx)
		}
	}
}

// runScan executes a scan and non-blockingly delivers findings.
func (s *Scheduler) runScan(ctx context.Context) {
	findings, err := s.scanner.Scan(ctx)
	if err != nil {
		s.logger.Printf("[scanner] scan error: %v", err)
	}

	if len(findings) > 0 {
		s.logger.Printf("[scanner] %d finding(s) detected", len(findings))
		for _, f := range findings {
			if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
				s.logger.Printf("[scanner] %s %s: %s", f.Severity, f.ThreatClass, f.Title)
			}
		}
	}

	if s.results == nil {
		return
	}
	// Non-blocking send — drop if consumer is slow (back-pressure safe)
	select {
	case s.results <- findings:
	default:
		s.logger.Printf("[scanner] results channel full — dropping %d findings (consumer is slow)", len(findings))
	}
}

// Scanner returns the underlying Scanner for direct Scan() calls.
func (s *Scheduler) Scanner() *Scanner { return s.scanner }
