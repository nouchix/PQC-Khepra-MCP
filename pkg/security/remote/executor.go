package remote

import (
	"context"
	"fmt"
	"time"
)

// Executor is the interface for remote command execution
type Executor interface {
	// Connect establishes a connection to the remote host
	Connect(ctx context.Context) error
	// Execute runs a command on the remote host
	Execute(ctx context.Context, command string) (*CommandResult, error)
	// Close terminates the connection
	Close() error
	// Type returns the executor type (ssh, winrm)
	Type() string
}

// CommandResult holds the output of a remote command
type CommandResult struct {
	ExitCode   int
	Stdout     string
	Stderr     string
	Duration   time.Duration
	ExecutedAt time.Time
}

// ConnectionProfile defines how to connect to a remote host
type ConnectionProfile struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Type        string            `json:"type"` // "ssh", "winrm"
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Username    string            `json:"username"`
	AuthMethod  string            `json:"auth_method"` // "password", "key", "kerberos"
	Credential  string            `json:"credential"`  // password or path to key file
	Timeout     int               `json:"timeout_seconds"`
	Tags        map[string]string `json:"tags,omitempty"`
	TacticalNet string            `json:"tactical_net,omitempty"` // JDN, JNN, WIN-T, SATCOM
}

// NewExecutor creates an executor based on connection profile type
func NewExecutor(profile *ConnectionProfile) (Executor, error) {
	switch profile.Type {
	case "ssh":
		return NewSSHExecutor(profile)
	case "winrm":
		return NewWinRMExecutor(profile)
	default:
		return nil, fmt.Errorf("unsupported executor type: %s", profile.Type)
	}
}

// BatchExecutor runs commands across multiple hosts in parallel
type BatchExecutor struct {
	profiles    []*ConnectionProfile
	concurrency int
}

// NewBatchExecutor creates a batch executor
func NewBatchExecutor(profiles []*ConnectionProfile, concurrency int) *BatchExecutor {
	if concurrency <= 0 {
		concurrency = 10 // Default parallelism
	}
	return &BatchExecutor{
		profiles:    profiles,
		concurrency: concurrency,
	}
}

// BatchResult holds results from multiple hosts
type BatchResult struct {
	Host    string
	Profile *ConnectionProfile
	Result  *CommandResult
	Error   error
}

// Execute runs a command across all hosts in parallel
func (b *BatchExecutor) Execute(ctx context.Context, command string) []BatchResult {
	results := make([]BatchResult, len(b.profiles))
	sem := make(chan struct{}, b.concurrency)

	for i, profile := range b.profiles {
		sem <- struct{}{} // Acquire semaphore

		go func(idx int, prof *ConnectionProfile) {
			defer func() { <-sem }() // Release semaphore

			exec, err := NewExecutor(prof)
			if err != nil {
				results[idx] = BatchResult{
					Host:    prof.Host,
					Profile: prof,
					Error:   err,
				}
				return
			}
			defer exec.Close()

			if err := exec.Connect(ctx); err != nil {
				results[idx] = BatchResult{
					Host:    prof.Host,
					Profile: prof,
					Error:   err,
				}
				return
			}

			result, err := exec.Execute(ctx, command)
			results[idx] = BatchResult{
				Host:    prof.Host,
				Profile: prof,
				Result:  result,
				Error:   err,
			}
		}(i, profile)
	}

	// Wait for all goroutines
	for i := 0; i < b.concurrency; i++ {
		sem <- struct{}{}
	}

	return results
}
