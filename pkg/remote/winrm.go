package remote

import (
	"context"
	"fmt"
	"time"

	"github.com/masterzen/winrm"
)

// WinRMExecutor implements remote execution over WinRM
type WinRMExecutor struct {
	profile *ConnectionProfile
	client  *winrm.Client
}

// NewWinRMExecutor creates a new WinRM executor
func NewWinRMExecutor(profile *ConnectionProfile) (*WinRMExecutor, error) {
	if profile.Port == 0 {
		profile.Port = 5985 // HTTP WinRM
	}
	return &WinRMExecutor{profile: profile}, nil
}

// Connect establishes a WinRM connection
func (e *WinRMExecutor) Connect(ctx context.Context) error {
	endpoint := winrm.NewEndpoint(
		e.profile.Host,
		e.profile.Port,
		false, // HTTPS
		false, // Insecure
		nil,   // CA Cert
		nil,   // Client Cert
		nil,   // Client Key
		time.Duration(e.profile.Timeout)*time.Second,
	)

	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientNTLM{}
	}

	client, err := winrm.NewClientWithParameters(
		endpoint,
		e.profile.Username,
		e.profile.Credential,
		params,
	)
	if err != nil {
		return fmt.Errorf("winrm client creation failed: %w", err)
	}

	e.client = client
	return nil
}

// Execute runs a PowerShell command over WinRM
func (e *WinRMExecutor) Execute(ctx context.Context, command string) (*CommandResult, error) {
	if e.client == nil {
		return nil, fmt.Errorf("not connected")
	}

	start := time.Now()

	// Use RunPSWithContext which wraps command in PowerShell
	stdout, stderr, exitCode, err := e.client.RunPSWithContext(ctx, command)
	duration := time.Since(start)

	result := &CommandResult{
		ExitCode:   exitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		Duration:   duration,
		ExecutedAt: start,
	}

	return result, err
}

// Close terminates the WinRM connection
func (e *WinRMExecutor) Close() error {
	// WinRM is stateless, no persistent connection to close
	return nil
}

// Type returns the executor type
func (e *WinRMExecutor) Type() string {
	return "winrm"
}
