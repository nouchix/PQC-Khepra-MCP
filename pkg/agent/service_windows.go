//go:build windows

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
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	ServiceName = "AdinKhepraSonarAgent"
	DisplayName = "AdinKhepra Protocol Sonar Agent"
	Description = "Continuous Monitoring Security Engine for Zero-Trust Environments."
)

// AgentService implements svc.Handler
type AgentService struct {
	BaseDir string
}

func (m *AgentService) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}
	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Start the Monitoring Loop in a goroutine
	ctx, cancel := context.WithCancel(context.Background())
	go m.RunLoop(ctx)

loop:
	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			cancel() // Stop the loop
			break loop
		}
	}

	s <- svc.Status{State: svc.StopPending}
	return false, 0
}

// RunLoop is the core security logic
func (m *AgentService) RunLoop(ctx context.Context) {
	// Setup Logging
	elog, err := eventlog.Open(ServiceName)
	if err != nil {
		return // Can't log, vital failure
	}
	defer elog.Close()
	elog.Info(1, "AdinKhepra Sonar Agent Started.")

	// 1. Load Baseline
	baselinePath := filepath.Join(m.BaseDir, "adinkhepra_baseline.json")
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		elog.Error(1, fmt.Sprintf("FAILED TO LOAD BASELINE: %v", err))
		// Can't run without baseline
		return
	}
	var baseline audit.AuditSnapshot
	if err := json.Unmarshal(baselineData, &baseline); err != nil {
		elog.Error(1, "Invalid Baseline JSON")
		return
	}

	driftEngine := intel.NewDriftEngine()

	// 2. Continuous Loop
	ticker := time.NewTicker(2 * time.Minute) // 2-minute polling interval (CMMC SI.2.217 continuous monitoring)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			elog.Info(1, "Agent Stopping...")
			return
		case <-ticker.C:
			// A. Take Snapshot
			snap, err := audit.NewSnapshot()
			if err != nil {
				elog.Error(1, fmt.Sprintf("Scan Failed: %v", err))
				continue
			}

			// B. Compare
			report := driftEngine.Compare(&baseline, snap)

			// C. Alert
			if report.HasDrift {
				msg := fmt.Sprintf("SECURITY DRIFT DETECTED:\n%s", report.String())
				elog.Warning(1, msg)
				// Here we would also push to the "Ghost" (Proton) or Lock Down via Firewalls
			} else {
				// Heartbeat
				// elog.Info(1, "Integrity Verified.")
			}
		}
	}
}

// InstallService registers the service
func InstallService(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ServiceName)
	}

	// Ensure absolute path and arguments
	config := mgr.Config{
		DisplayName: DisplayName,
		Description: Description,
		StartType:   mgr.StartAutomatic,
	}

	// The service command is "khepra.exe agent start"
	// SCM passes the executable path automatically, we just need arguments?
	// Actually, standard practice for Go services is the binary detects if it's running as service.
	// But our CLI uses `khepra agent start`.
	// We need to register the binary path with arguments.
	// However, `CreateService` takes binary path. Arguments are tricky.
	// Allow specifying custom args in SetConfig or path.

	// Simplification: We will register "C:\path\to\khepra.exe" but Main() needs to auto-detect service mode?
	// OR: We set BinaryPathName to "C:\path\to\khepra.exe agent start"

	fullCmd := fmt.Sprintf(`"%s" agent start`, exePath)

	s, err = m.CreateService(ServiceName, fullCmd, config)
	if err != nil {
		return err
	}
	defer s.Close()

	// Setup Event Log
	eventlog.InstallAsEventCreate(ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	return nil
}

// RemoveService deletes it
func RemoveService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", ServiceName)
	}
	defer s.Close()
	eventlog.Remove(ServiceName)
	return s.Delete()
}

// StartServiceInstance manually starts it
func StartServiceInstance() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

// Run is the entrypoint called by `khepra agent start`
func Run(baseDir string) {
	// Interactive check?
	isInteractive, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("failed to determine session: %v", err)
	}

	if isInteractive {
		// Run in console mode for debugging
		log.Println("[SONAR AGENT] Running in Interactive Mode (Console)...")
		log.Println("[INFO] Press Ctrl+C to stop.")

		svc := &AgentService{BaseDir: baseDir}
		svc.RunLoop(context.Background()) // Blocking
	} else {
		// Run as Service
		runService(ServiceName, false, baseDir)
	}
}

func runService(name string, isDebug bool, baseDir string) {
	var el debug.Log
	if isDebug {
		el = debug.New(name)
	} else {
		el, _ = eventlog.Open(name)
	}
	defer el.Close()

	run := svc.Run
	if isDebug {
		run = debug.Run
	}

	err := run(name, &AgentService{BaseDir: baseDir})
	if err != nil {
		el.Error(1, fmt.Sprintf("%s service failed: %v", name, err))
		return
	}
	el.Info(1, fmt.Sprintf("%s service stopped", name))
}
