package maat

// Heka represents restorative magic/action
// Heka (Egyptian): Magic, power, activation
type Heka struct {
	Isfet      Isfet
	Action     string
	Potency    float64 // 0.0 = weak, 1.0 = powerful
	Autonomous bool    // true = auto-execute, false = seek approval
	Khopesh    string  // Which blade will strike
	Wisdom     string  // AI reasoning from KASA
}

// Actions (poetic names for remediation)
const (
	ActionBanish  = "banish"  // Block/remove
	ActionSeal    = "seal"    // Isolate/quarantine
	ActionPurify  = "purify"  // Clean/remediate
	ActionIsolate = "isolate" // Network segmentation
	ActionObserve = "observe" // Monitor only
)
