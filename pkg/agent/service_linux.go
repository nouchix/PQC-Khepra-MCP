//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/intel"
)

const (
	ServiceName = "AdinKhepraSonarAgent"
	DisplayName = "AdinKhepra Protocol Sonar Agent"
	Description = "Continuous Monitoring Security Engine for Zero-Trust Environments."
)

// AgentService implements logic for Linux
type AgentService struct {
	BaseDir string
}

// RunLoop is the core security logic (Adapted for Linux/Container)
func (m *AgentService) RunLoop(ctx context.Context) {
	log.Println("AdinKhepra Sonar Agent Started (Linux/Container Mode).")

	// 1. Load Baseline
	baselinePath := filepath.Join(m.BaseDir, "adinkhepra_baseline.json")
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		log.Printf("FAILED TO LOAD BASELINE: %v\n", err)
		// Can't run without baseline
		return
	}
	var baseline audit.AuditSnapshot
	if err := json.Unmarshal(baselineData, &baseline); err != nil {
		log.Println("Invalid Baseline JSON")
		return
	}

	driftEngine := intel.NewDriftEngine()

	// 2. Continuous Loop
	ticker := time.NewTicker(2 * time.Minute) // 2-minute polling interval (CMMC SI.2.217 continuous monitoring)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Agent Stopping...")
			return
		case <-ticker.C:
			// A. Take Snapshot
			snap, err := audit.NewSnapshot()
			if err != nil {
				log.Printf("Scan Failed: %v\n", err)
				continue
			}

			// B. Compare
			report := driftEngine.Compare(&baseline, snap)

			// C. Alert
			if report.HasDrift {
				msg := fmt.Sprintf("SECURITY DRIFT DETECTED:\n%s", report.String())
				log.Printf("WARNING: %s\n", msg)
			} else {
				// Heartbeat
				// log.Println("Integrity Verified.")
			}
		}
	}
}

// InstallService registers the service
func InstallService(exePath string) error {
	return fmt.Errorf("service installation not supported on Linux via this command. Use systemd.")
}

// RemoveService deletes it
func RemoveService() error {
	return fmt.Errorf("service removal not supported on Linux via this command.")
}

// StartServiceInstance manually starts it
func StartServiceInstance() error {
	return fmt.Errorf("manual service start not supported on Linux via this command.")
}

// Run is the entrypoint called by `khepra agent start`
func Run(baseDir string) {
	// Treat as interactive/foreground for Container
	log.Println("[SONAR AGENT] Running in Foreground Mode (Linux)...")
	log.Println("[INFO] Press Ctrl+C to stop.")

	svc := &AgentService{BaseDir: baseDir}
	svc.RunLoop(context.Background()) // Blocking
}
