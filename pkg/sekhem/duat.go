package sekhem

import (
	"fmt"
	"log"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/agi"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/ouroboros"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/seshat"
)

// DuatRealm is the foundational realm of defense
// Duat (Egyptian): Underworld, foundation, where souls are tested
type DuatRealm struct {
	name     string
	Guardian *maat.Guardian
	Cycle    *ouroboros.Cycle
	Eyes     []ouroboros.WedjatEye
	Blades   []ouroboros.KhopeshBlade

	// WAFShield is the Merkaba L7 perimeter guard. Initialized during Awaken().
	// Exposed so apiserver.Server can pass it into WAFMiddleware.
	WAFShield *WAFShield

	// Service integrations
	KASA      *agi.Engine
	DAGStore  dag.Store
	Chronicle *seshat.Chronicle
}

// NewDuatRealm creates the foundational defense realm
func NewDuatRealm(kasa *agi.Engine, dagStore dag.Store) *DuatRealm {
	// Create Seshat Chronicle
	chronicle := seshat.NewChronicle(dagStore, nil) // Signer can be added later

	// Create Maat Guardian
	guardian := maat.NewGuardian("duat", kasa, chronicle)

	realm := &DuatRealm{
		name:      "duat",
		Guardian:  guardian,
		KASA:      kasa,
		DAGStore:  dagStore,
		Chronicle: chronicle,
		Eyes:      []ouroboros.WedjatEye{},
		Blades:    []ouroboros.KhopeshBlade{},
	}

	return realm
}

// Awaken initializes the Duat Realm
func (dr *DuatRealm) Awaken() error {
	log.Printf("[Duat] Awakening the foundational realm...")

	// Initialize WAFShield (Merkaba L7 perimeter).
	// Config is read from environment: CROWDSEC_LAPI_URL, CROWDSEC_BOUNCER_KEY.
	waf, err := NewWAFShield(WAFShieldConfig{})
	if err != nil {
		return fmt.Errorf("duat: WAFShield init failed: %w", err)
	}
	dr.WAFShield = waf
	log.Printf("[Duat] WAFShield online")

	// Initialize Wedjat Eyes (sensors)
	// WAFEye drains the WAFShield threat channel + tails Suricata EVE JSON.
	wafEye := ouroboros.NewWAFEye(dr.WAFShield.ThreatChan(), "")
	dr.Eyes = append(dr.Eyes,
		wafEye,
		ouroboros.NewSTIGEye(),
		ouroboros.NewVulnEye(),
		ouroboros.NewDriftEye(),
		ouroboros.NewFIMEye(),
	)

	// Initialize Khopesh Blades (actuators)
	dr.Blades = append(dr.Blades,
		ouroboros.NewRemediationBlade(),
		ouroboros.NewFirewallBlade(),
		ouroboros.NewIsolationBlade(),
		ouroboros.NewMonitorBlade(),
		ouroboros.NewConfigBlade(),
	)

	// Create Ouroboros Cycle
	dr.Cycle = ouroboros.NewCycle(dr.Eyes, dr.Guardian, dr.Blades)

	// Start the eternal cycle
	go dr.Cycle.Spin()

	log.Printf("[Duat] Realm awakened with %d eyes and %d blades", len(dr.Eyes), len(dr.Blades))

	return nil
}

// Perceive gathers Isfet from Wedjat Eyes
func (dr *DuatRealm) Perceive() []maat.Isfet {
	isfet := []maat.Isfet{}

	for _, eye := range dr.Eyes {
		detected := eye.Gaze()
		isfet = append(isfet, detected...)
	}

	return isfet
}

// Deliberate invokes Maat Guardian to weigh options
func (dr *DuatRealm) Deliberate(isfet []maat.Isfet) []maat.Heka {
	return dr.Guardian.WeighAndDecide(isfet)
}

// Manifest executes Heka through Khopesh Blades
func (dr *DuatRealm) Manifest(heka []maat.Heka) error {
	for _, h := range heka {
		for _, blade := range dr.Blades {
			if blade.CanStrike(h) {
				if err := blade.Strike(h); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Transcribe records actions to Seshat Chronicle
func (dr *DuatRealm) Transcribe(actions []maat.Heka) error {
	for _, action := range actions {
		err := dr.Chronicle.Inscribe("duat-action", map[string]any{
			"isfet_id":   action.Isfet.ID,
			"action":     action.Action,
			"autonomous": action.Autonomous,
			"potency":    action.Potency,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// GetName returns the realm name
func (dr *DuatRealm) GetName() string {
	return dr.name
}

// Stop halts the Ouroboros Cycle and closes all resources.
func (dr *DuatRealm) Stop() {
	if dr.Cycle != nil {
		dr.Cycle.Stop()
	}
	// Close WAFShield rotation goroutine and file handles on Eyes.
	if dr.WAFShield != nil {
		dr.WAFShield.Close()
	}
	for _, eye := range dr.Eyes {
		if closer, ok := eye.(interface{ Close() }); ok {
			closer.Close()
		}
	}
}
