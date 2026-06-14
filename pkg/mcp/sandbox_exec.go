package mcp

import (
	"context"
	"os/exec"
)

// defaultExecCommandContext wraps exec.CommandContext for production use.
// This indirection exists so tests can inject a mock without touching the Docker daemon.
func defaultExecCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}
