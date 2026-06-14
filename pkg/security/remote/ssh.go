package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// knownHostsMu protects concurrent access to the known_hosts file
var knownHostsMu sync.Mutex

// SSHExecutor implements remote execution over SSH
type SSHExecutor struct {
	profile *ConnectionProfile
	client  *ssh.Client
}

// NewSSHExecutor creates a new SSH executor
func NewSSHExecutor(profile *ConnectionProfile) (*SSHExecutor, error) {
	if profile.Port == 0 {
		profile.Port = 22
	}
	return &SSHExecutor{profile: profile}, nil
}

// getKnownHostsPath returns the path to the known_hosts file
func getKnownHostsPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	return filepath.Join(homeDir, ".khepra", "known_hosts")
}

// hostKeyFingerprint computes a SHA-256 fingerprint of an SSH public key
func hostKeyFingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return hex.EncodeToString(hash[:])
}

// verifyHostKey implements TOFU (Trust On First Use) host key verification.
// On first connection, it stores the host key fingerprint.
// On subsequent connections, it rejects if the key has changed (potential MITM).
func verifyHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()

	hostsPath := getKnownHostsPath()
	fingerprint := hostKeyFingerprint(key)
	hostID := fmt.Sprintf("%s:%s", hostname, key.Type())

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(hostsPath), 0700); err != nil {
		return fmt.Errorf("failed to create known_hosts directory: %w", err)
	}

	// Read existing known_hosts
	data, err := os.ReadFile(hostsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read known_hosts: %w", err)
	}

	// Search for existing entry
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) == 2 && parts[0] == hostID {
			if parts[1] == fingerprint {
				// Known host, key matches — connection is safe
				log.Printf("[SSH] Host key verified for %s (fingerprint: %s...)", hostname, fingerprint[:16])
				return nil
			}
			// KEY CHANGED — potential MITM attack
			return fmt.Errorf(
				"[SECURITY] SSH HOST KEY CHANGED for %s! "+
					"Expected fingerprint: %s, got: %s. "+
					"This may indicate a man-in-the-middle attack. "+
					"If this is expected, remove the entry from %s",
				hostname, parts[1][:16]+"...", fingerprint[:16]+"...", hostsPath)
		}
	}

	// First connection — Trust On First Use: store the fingerprint
	log.Printf("[SSH] TOFU: First connection to %s — storing host key fingerprint: %s...", hostname, fingerprint[:16])

	f, err := os.OpenFile(hostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to write known_hosts: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "%s %s\n", hostID, fingerprint); err != nil {
		return fmt.Errorf("failed to write host key entry: %w", err)
	}

	return nil
}

// Connect establishes an SSH connection
func (e *SSHExecutor) Connect(ctx context.Context) error {
	var authMethods []ssh.AuthMethod

	switch e.profile.AuthMethod {
	case "password":
		authMethods = append(authMethods, ssh.Password(e.profile.Credential))
	case "key":
		// Read private key from file
		keyData, err := os.ReadFile(e.profile.Credential)
		if err != nil {
			return fmt.Errorf("failed to read SSH private key from %s: %w", e.profile.Credential, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("failed to parse SSH private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	default:
		return fmt.Errorf("unsupported auth method: %s", e.profile.AuthMethod)
	}

	config := &ssh.ClientConfig{
		User:            e.profile.Username,
		Auth:            authMethods,
		HostKeyCallback: verifyHostKey,
		Timeout:         time.Duration(e.profile.Timeout) * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", e.profile.Host, e.profile.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("ssh dial failed: %w", err)
	}

	e.client = client
	return nil
}

// Execute runs a command over SSH
func (e *SSHExecutor) Execute(ctx context.Context, command string) (*CommandResult, error) {
	if e.client == nil {
		return nil, fmt.Errorf("not connected")
	}

	session, err := e.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	start := time.Now()

	// Capture stdout and stderr
	output, err := session.CombinedOutput(command)
	duration := time.Since(start)

	result := &CommandResult{
		Stdout:     string(output),
		Duration:   duration,
		ExecutedAt: start,
	}

	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			result.ExitCode = exitErr.ExitStatus()
		} else {
			return result, err
		}
	}

	return result, nil
}

// Close terminates the SSH connection
func (e *SSHExecutor) Close() error {
	if e.client != nil {
		return e.client.Close()
	}
	return nil
}

// Type returns the executor type
func (e *SSHExecutor) Type() string {
	return "ssh"
}
