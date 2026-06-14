package sonar

import (
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/config"
)

func TestNewOrchestrator(t *testing.T) {
	secrets := &config.SecretBundle{
		ShodanKey: []byte("dummy_key"),
	}

	runtime := NewOrchestrator(secrets)
	if runtime == nil {
		t.Fatal("Failed to create Orchestrator")
	}
	// secrets field was removed from SonarRuntime (OSINT/Shodan telemetry eliminated).
	// NewOrchestrator accepts the parameter for API compatibility but ignores it.
}

func TestRunActiveScan_Localhost(t *testing.T) {
	// No secrets -> Local scan only
	runtime := NewOrchestrator(nil)

	// Scan localhost (should be fast and safe)
	// We set a timeout channel to ensure test doesn't hang
	done := make(chan ActiveScanResult)
	go func() {
		done <- runtime.RunActiveScan("127.0.0.1")
	}()

	select {
	case res := <-done:
		// Basic assertions
		if res.Target != "127.0.0.1" {
			t.Errorf("Expected target 127.0.0.1, got %s", res.Target)
		}
		if res.PortResults == nil {
			t.Error("PortResults should be initialized (even if empty)")
		}
		// Note: We can't guarantee open ports on the test runner,
		// but getting a result confirms the flow worked without panic.

	case <-time.After(10 * time.Second):
		t.Fatal("Scan timed out")
	}
}
