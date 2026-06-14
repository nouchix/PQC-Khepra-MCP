package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// STIGScanner performs remote STIG compliance scanning
type STIGScanner struct {
	executor Executor
	profile  *ConnectionProfile
}

// STIGCheckResult holds the result of a single STIG check
type STIGCheckResult struct {
	ControlID   string    `json:"control_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"` // pass, fail, not_applicable, error
	Finding     string    `json:"finding,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Command     string    `json:"command,omitempty"`
	RawOutput   string    `json:"raw_output,omitempty"`
	ExecutedAt  time.Time `json:"executed_at"`
	Duration    string    `json:"duration"`
}

// ScanReport holds the complete scan results for a host
type ScanReport struct {
	Host        string            `json:"host"`
	Profile     string            `json:"profile"`
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt time.Time         `json:"completed_at"`
	TotalChecks int               `json:"total_checks"`
	Passed      int               `json:"passed"`
	Failed      int               `json:"failed"`
	Errors      int               `json:"errors"`
	Score       float64           `json:"score"`
	Results     []STIGCheckResult `json:"results"`
}

// NewSTIGScanner creates a new remote STIG scanner
func NewSTIGScanner(profile *ConnectionProfile) (*STIGScanner, error) {
	exec, err := NewExecutor(profile)
	if err != nil {
		return nil, err
	}
	return &STIGScanner{
		executor: exec,
		profile:  profile,
	}, nil
}

// ScanHost performs a STIG scan on a single host
func (s *STIGScanner) ScanHost(ctx context.Context, stigChecks []STIGCheck) (*ScanReport, error) {
	report := &ScanReport{
		Host:      s.profile.Host,
		Profile:   s.profile.TacticalNet,
		StartedAt: time.Now(),
		Results:   make([]STIGCheckResult, 0, len(stigChecks)),
	}

	// Connect to remote host
	if err := s.executor.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer s.executor.Close()

	// Execute each STIG check
	for _, check := range stigChecks {
		result := s.executeCheck(ctx, check)
		report.Results = append(report.Results, result)

		switch result.Status {
		case "pass":
			report.Passed++
		case "fail":
			report.Failed++
		default:
			report.Errors++
		}
		report.TotalChecks++
	}

	report.CompletedAt = time.Now()
	if report.TotalChecks > 0 {
		report.Score = float64(report.Passed) / float64(report.TotalChecks) * 100
	}

	return report, nil
}

// executeCheck runs a single STIG check
func (s *STIGScanner) executeCheck(ctx context.Context, check STIGCheck) STIGCheckResult {
	result := STIGCheckResult{
		ControlID:  check.ControlID,
		Title:      check.Title,
		Severity:   check.Severity,
		Command:    check.CheckCommand,
		ExecutedAt: time.Now(),
	}

	// Execute the check command
	cmdResult, err := s.executor.Execute(ctx, check.CheckCommand)
	if err != nil {
		result.Status = "error"
		result.Finding = err.Error()
		return result
	}

	result.RawOutput = cmdResult.Stdout
	result.Duration = cmdResult.Duration.String()

	// Evaluate the result against expected pattern
	if check.EvaluateFunc != nil {
		passed, finding := check.EvaluateFunc(cmdResult.Stdout, cmdResult.ExitCode)
		if passed {
			result.Status = "pass"
		} else {
			result.Status = "fail"
			result.Finding = finding
			result.Remediation = check.Remediation
		}
	} else {
		// Default: exit code 0 = pass
		if cmdResult.ExitCode == 0 {
			result.Status = "pass"
		} else {
			result.Status = "fail"
			result.Finding = "Non-zero exit code"
		}
	}

	return result
}

// STIGCheck defines a single compliance check
type STIGCheck struct {
	ControlID    string
	Title        string
	Severity     string // critical, high, medium, low
	CheckCommand string
	Remediation  string
	EvaluateFunc func(output string, exitCode int) (passed bool, finding string)
}

// BulkScanner scans multiple hosts in parallel
type BulkScanner struct {
	profiles    []*ConnectionProfile
	stigChecks  []STIGCheck
	concurrency int
}

// NewBulkScanner creates a bulk scanner
func NewBulkScanner(profiles []*ConnectionProfile, stigChecks []STIGCheck, concurrency int) *BulkScanner {
	if concurrency <= 0 {
		concurrency = 10
	}
	return &BulkScanner{
		profiles:    profiles,
		stigChecks:  stigChecks,
		concurrency: concurrency,
	}
}

// ScanResult combines host info with scan report
type BulkScanResult struct {
	Profile *ConnectionProfile
	Report  *ScanReport
	Error   error
}

// Scan executes STIG checks across all hosts
func (b *BulkScanner) Scan(ctx context.Context, progress chan<- BulkScanResult) []BulkScanResult {
	results := make([]BulkScanResult, len(b.profiles))
	sem := make(chan struct{}, b.concurrency)
	var wg sync.WaitGroup

	for i, profile := range b.profiles {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, prof *ConnectionProfile) {
			defer wg.Done()
			defer func() { <-sem }()

			scanner, err := NewSTIGScanner(prof)
			if err != nil {
				results[idx] = BulkScanResult{Profile: prof, Error: err}
				if progress != nil {
					progress <- results[idx]
				}
				return
			}

			report, err := scanner.ScanHost(ctx, b.stigChecks)
			results[idx] = BulkScanResult{
				Profile: prof,
				Report:  report,
				Error:   err,
			}

			if progress != nil {
				progress <- results[idx]
			}

			log.Printf("[SCAN] %s: Score=%.1f%% (%d/%d passed)",
				prof.Host, report.Score, report.Passed, report.TotalChecks)
		}(i, profile)
	}

	wg.Wait()
	return results
}

// ToJSON serializes scan results to JSON
func (r *ScanReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
