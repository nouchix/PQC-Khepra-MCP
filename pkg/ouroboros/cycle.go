package ouroboros

import (
	"log"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
)

// Cycle represents the eternal feedback loop
// Ouroboros: Snake eating its own tail, eternal cycle
type Cycle struct {
	Eyes     []WedjatEye
	Guardian *maat.Guardian
	Blades   []KhopeshBlade
	Spinning bool
	stopChan chan bool
}

// NewCycle creates an Ouroboros Cycle
func NewCycle(eyes []WedjatEye, guardian *maat.Guardian, blades []KhopeshBlade) *Cycle {
	return &Cycle{
		Eyes:     eyes,
		Guardian: guardian,
		Blades:   blades,
		Spinning: false,
		stopChan: make(chan bool),
	}
}

// Spin starts the eternal cycle
func (c *Cycle) Spin() {
	c.Spinning = true
	log.Printf("[Ouroboros] Cycle begins spinning...")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for c.Spinning {
		select {
		case <-c.stopChan:
			log.Printf("[Ouroboros] Cycle stopped")
			return
		case <-ticker.C:
			c.iterate()
		}
	}
}

// iterate performs one cycle iteration
func (c *Cycle) iterate() {
	// 1. PERCEIVE: Wedjat Eyes gaze upon the realm
	isfet := c.perceive()

	if len(isfet) == 0 {
		return // No chaos detected
	}

	log.Printf("[Ouroboros] Detected %d Isfet", len(isfet))

	// 2. DELIBERATE: Maat Guardian weighs options
	heka := c.Guardian.WeighAndDecide(isfet)

	// 3. MANIFEST: Khopesh Blades strike
	c.manifest(heka)

	// 4. VERIFY: Confirm restoration of Maat
	c.verify()
}

// perceive gathers Isfet from all Wedjat Eyes
func (c *Cycle) perceive() []maat.Isfet {
	isfet := []maat.Isfet{}

	for _, eye := range c.Eyes {
		detected := eye.Gaze()
		if len(detected) > 0 {
			log.Printf("[Ouroboros] %s detected %d Isfet", eye.Name(), len(detected))
			isfet = append(isfet, detected...)
		}
	}

	return isfet
}

// manifest executes Heka through Khopesh Blades
func (c *Cycle) manifest(heka []maat.Heka) {
	for _, h := range heka {
		for _, blade := range c.Blades {
			if blade.CanStrike(h) {
				err := blade.Strike(h)
				if err != nil {
					log.Printf("[Ouroboros] %s failed to strike: %v", blade.Name(), err)
				}
			}
		}
	}
}

// verify confirms restoration of Maat by re-scanning all eyes
// and checking that Isfet levels have decreased after remediation.
func (c *Cycle) verify() {
	// Post-remediation scan: check if chaos was reduced
	remainingIsfet := c.perceive()
	count := len(remainingIsfet)

	if count == 0 {
		log.Printf("[Ouroboros] Maat verification: PASS — no remaining Isfet")
		return
	}

	// Classify remaining threats by severity for reporting
	severityCounts := make(map[maat.Severity]int)
	for _, chaos := range remainingIsfet {
		severityCounts[chaos.Severity]++
	}

	log.Printf("[Ouroboros] Maat verification: %d Isfet remain after remediation (breakdown: %v)",
		count, severityCounts)
}

// Stop halts the cycle
func (c *Cycle) Stop() {
	c.Spinning = false
	close(c.stopChan)
}
