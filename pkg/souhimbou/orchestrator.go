// Package souhimbou — SouHimBou AI Agentic SOC Platform.
//
// orchestrator.go wires the complete KHEPRA intelligence stack into the
// SouHimBou Core Agent:
//
//   Polymorphic API Engine  (pkg/api)      — PQC sign/verify every boundary
//   Mitochondrial Gateway   (pkg/gateway)  — 4-layer DMZ (Firewall/Auth/Anomaly/Control)
//   SEKHEM Triad            (pkg/sekhem)   — Duat/Aaru/Aten realms + WAFShield L7
//   KASA Engine             (pkg/agi)      — Khepra Agentic Security Auditor
//   Maat Guardian           (pkg/maat)     — Isfet→Heka deliberation engine
//   Ouroboros Cycle         (pkg/ouroboros)— 10s Perceive→Manifest→Verify loop
//   Seshat Chronicle        (pkg/seshat)   — DAG audit chain writer
//   Flight Recorder         (pkg/flight)   — ML-DSA-65 signed NDJSON action log
//   DAG                     (pkg/dag)      — Global immutable ledger
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.
package souhimbou

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/agi"
	apiengine "github.com/nouchix/PQC-Khepra-MCP/pkg/api"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/gateway"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/maat"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ouroboros"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/seshat"
)

// ─── Orchestrator ─────────────────────────────────────────────────────────────

// Orchestrator is the full-stack intelligence harness for SouHimBou AI.
// It initialises and connects every KHEPRA subsystem, then exposes a
// unified interface the Agent uses for its SOC loop.
type Orchestrator struct {
	log *slog.Logger

	// ── Core subsystems ────────────────────────────────────────────────
	DAG        *dag.PersistentMemory
	Flight     *flight.Recorder
	Chronicle  *seshat.Chronicle

	// ── KASA intelligence stack ────────────────────────────────────────
	KASA       *agi.Engine
	KASACrypto *agi.KASACryptoAgent

	// ── Maat deliberation layer ────────────────────────────────────────
	Guardian   *maat.Guardian

	// ── Ouroboros continuous cycle ─────────────────────────────────────
	Cycle      *ouroboros.Cycle

	// ── SEKHEM Triad (perimeter + realms) ─────────────────────────────
	Triad      *sekhem.SekhemTriad

	// ── Mitochondrial Gateway (DEMARC DMZ) ────────────────────────────
	Gateway    *gateway.Gateway

	// ── Polymorphic API Engine (PQC boundary signing) ─────────────────
	Poly       *apiengine.PolymorphicEngine

	// mode controls which realms are active
	mode sekhem.DeploymentMode
}

// OrchestratorConfig holds optional overrides. Zero value uses env-var defaults.
type OrchestratorConfig struct {
	// Mode overrides KHEPRA_MODE env var. Default: reads KHEPRA_MODE.
	Mode sekhem.DeploymentMode

	// DAG is the global DAG. If nil, uses dag.GlobalDAG().
	DAG *dag.PersistentMemory

	// Flight is the flight recorder. If nil, built from env vars.
	Flight *flight.Recorder

	// PolySymbol is the Adinkra symbol for the PolymorphicEngine. Default: "Eban".
	PolySymbol string

	// PolyExpirationMonths sets key rotation period. Default: 12.
	PolyExpirationMonths int

	// GatewayCfg overrides the Mitochondrial Gateway config.
	GatewayCfg *gateway.Config

	// DisableGateway skips gateway init (for edge/SaaS-only deployments).
	DisableGateway bool
}

// NewOrchestrator initialises the full KHEPRA intelligence stack.
// Non-fatal subsystem failures are logged as warnings; the orchestrator
// always returns usable (even if degraded) subsystems.
func NewOrchestrator(cfg OrchestratorConfig) (*Orchestrator, error) {
	log := slog.With("component", "souhimbou-orchestrator")

	// ── Mode ──────────────────────────────────────────────────────────
	mode := cfg.Mode
	if mode == "" {
		mode = sekhem.ModeFromEnv()
	}
	log.Info("orchestrator init", "mode", mode)

	// ── DAG ───────────────────────────────────────────────────────────
	globalDAG := cfg.DAG
	if globalDAG == nil {
		globalDAG = dag.GlobalDAG()
	}

	// ── Flight Recorder ───────────────────────────────────────────────
	fr := cfg.Flight
	if fr == nil {
		fr, _ = flight.New(flight.RecorderConfig{}) // graceful if key absent
	}

	// ── Seshat Chronicle ──────────────────────────────────────────────
	chronicle := seshat.NewChronicle(globalDAG, nil)

	// ── Polymorphic API Engine ────────────────────────────────────────
	polySymbol := cfg.PolySymbol
	if polySymbol == "" {
		polySymbol = "Eban"
	}
	polyMonths := cfg.PolyExpirationMonths
	if polyMonths == 0 {
		polyMonths = 12
	}
	poly, err := apiengine.NewPolymorphicEngine(polySymbol, polyMonths)
	if err != nil {
		log.Warn("PolymorphicEngine init failed — running without PQC boundary signing", "err", err)
		poly = nil
	} else {
		log.Info("PolymorphicEngine online", "symbol", polySymbol)
	}

	// ── KASA Engine ───────────────────────────────────────────────────
	kasaEngine := buildKASAEngine(globalDAG, log)

	// ── KASA Crypto Agent ─────────────────────────────────────────────
	keys, _ := license.GenerateProtectionKeys("Eban")
	kasaCrypto := agi.NewKASACryptoAgent(keys)

	// ── Maat Guardian ─────────────────────────────────────────────────
	guardian := maat.NewGuardian("souhimbou", kasaEngine, chronicle)
	// Only allow autonomous remediation in IronBank / sovereign air-gapped mode
	if mode == sekhem.ModeIronBank {
		guardian.WithAutonomousRemediation(true)
	}

	// ── Ouroboros Eyes ────────────────────────────────────────────────
	eyes := []ouroboros.WedjatEye{
		ouroboros.NewSTIGEye(),
		ouroboros.NewVulnEye(),
		ouroboros.NewDriftEye(),
		ouroboros.NewFIMEye(),
		// Flight Recorder eye — watches for anomalous agent tool call patterns
		newFlightRecorderEye(fr),
	}

	// ── Ouroboros Blades ──────────────────────────────────────────────
	blades := []ouroboros.KhopeshBlade{
		ouroboros.NewRemediationBlade(),
		ouroboros.NewFirewallBlade(),  // blocks attacker IPs
		ouroboros.NewIsolationBlade(), // network segmentation
		ouroboros.NewMonitorBlade(),   // passive observation mode
	}

	// ── Ouroboros Cycle ───────────────────────────────────────────────
	cycle := ouroboros.NewCycle(eyes, guardian, blades)

	// ── SEKHEM Triad ──────────────────────────────────────────────────
	triad, err := sekhem.NewSekhemTriad(kasaEngine, globalDAG, mode)
	if err != nil {
		log.Warn("SEKHEM Triad init failed — running in degraded perimeter mode", "err", err)
		triad = nil
	} else {
		if hErr := triad.Harmonize(); hErr != nil {
			log.Warn("SEKHEM Triad harmonize failed", "err", hErr)
		} else {
			log.Info("SEKHEM Triad harmonized", "realms", triad.GetActiveRealmCount(), "mode", mode)
		}
	}

	// ── Mitochondrial Gateway ─────────────────────────────────────────
	var gw *gateway.Gateway
	if !cfg.DisableGateway && mode.IsSaaS() {
		gwCfg := cfg.GatewayCfg
		if gwCfg == nil {
			gwCfg = gateway.DefaultConfig()
		}
		gw, err = gateway.New(gwCfg)
		if err != nil {
			log.Warn("Mitochondrial Gateway init failed — perimeter will run without L4 control", "err", err)
			gw = nil
		} else {
			log.Info("Mitochondrial Gateway online (4-layer DEMARC active)")
		}
	}

	return &Orchestrator{
		log:        log,
		DAG:        globalDAG,
		Flight:     fr,
		Chronicle:  chronicle,
		KASA:       kasaEngine,
		KASACrypto: kasaCrypto,
		Guardian:   guardian,
		Cycle:      cycle,
		Triad:      triad,
		Gateway:    gw,
		Poly:       poly,
		mode:       mode,
	}, nil
}

// StartCycle launches the Ouroboros 10-second Perceive→Manifest→Verify loop
// in a background goroutine. Returns immediately.
func (o *Orchestrator) StartCycle() {
	o.log.Info("Ouroboros Cycle spinning up")
	go o.Cycle.Spin()
}

// Stop shuts down all active subsystems.
func (o *Orchestrator) Stop() {
	o.log.Info("Orchestrator shutting down")
	if o.Cycle != nil {
		o.Cycle.Stop()
	}
	if o.Triad != nil {
		o.Triad.Stop()
	}
	if o.Gateway != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = o.Gateway.Stop(ctx)
	}
}

// WrapRequest signs an outgoing API payload with the PolymorphicEngine.
// No-op (returns payload unchanged) if engine is unavailable.
func (o *Orchestrator) WrapRequest(payload []byte, agentID string) ([]byte, error) {
	if o.Poly == nil {
		return payload, nil
	}
	signed, err := o.Poly.WrapRequest(payload, agentID)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: polymorphic wrap: %w", err)
	}
	return json.Marshal(signed)
}

// DetectTampering runs KASA tamper analysis on arbitrary data.
// Returns (isTampered, humanReadableReason).
func (o *Orchestrator) DetectTampering(data interface{}, componentID string) (bool, string) {
	if o.KASACrypto == nil {
		return false, ""
	}
	isTampering, report := o.KASACrypto.DetectTampering(data, componentID)
	if isTampering && report != nil {
		return true, fmt.Sprintf("KASA: anomaly_score=%.2f flags=%v",
			report.AnomalyScore, report.BehaviorFlags)
	}
	return false, ""
}

// Mode returns the active deployment mode.
func (o *Orchestrator) Mode() sekhem.DeploymentMode { return o.mode }

// WAFShield returns the L7 WAF from the Duat realm (nil if unavailable).
func (o *Orchestrator) WAFShield() *sekhem.WAFShield {
	if o.Triad == nil || o.Triad.DuatRealm == nil {
		return nil
	}
	return o.Triad.DuatRealm.WAFShield
}

// ─── Private helpers ──────────────────────────────────────────────────────────

// buildKASAEngine constructs the KASA Engine from the DAG store.
func buildKASAEngine(store dag.Store, log *slog.Logger) *agi.Engine {
	engine := agi.NewEngine(store)
	if engine == nil {
		log.Warn("KASA Engine init returned nil — running without AI reasoning")
		return nil
	}
	log.Info("KASA Engine online")
	return engine
}

// ─── Flight Recorder WedjatEye ────────────────────────────────────────────────
// Adapts the FlightRecorder into the ouroboros.WedjatEye interface so the
// Ouroboros Cycle can directly perceive agent tool call anomalies.

type flightRecorderEye struct {
	fr *flight.Recorder
}

func newFlightRecorderEye(fr *flight.Recorder) ouroboros.WedjatEye {
	return &flightRecorderEye{fr: fr}
}

func (e *flightRecorderEye) Name() string { return "FlightRecorderEye" }

func (e *flightRecorderEye) Gaze() []maat.Isfet {
	if e.fr == nil {
		return nil
	}
	frames, err := e.fr.Recent(50)
	if err != nil || len(frames) == 0 {
		return nil
	}

	var isfet []maat.Isfet
	for _, f := range frames {
		if f.RiskClass != flight.RiskDestructive {
			continue
		}
		isfet = append(isfet, maat.Isfet{
			ID:        f.FrameID,
			Severity:  maat.SeveritySevere,
			Source:    "FlightRecorder:" + f.AgentID,
			Certainty: 0.80,
			Omens: []maat.Omen{
				{Name: "tool",  Value: f.ToolName, Malevolence: riskToMalevolence(f.RiskClass)},
				{Name: "agent", Value: f.AgentID,  Malevolence: 0.0},
			},
		})
	}
	return isfet
}

func riskToMalevolence(rc flight.RiskClass) float64 {
	if rc == flight.RiskDestructive {
		return 0.9
	}
	return 0.3
}
