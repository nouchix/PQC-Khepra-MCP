package maat

// AnubisWeigher performs the weighing of hearts (tradeoff analysis)
// Anubis (Egyptian): God who weighs hearts against the feather of Maat
type AnubisWeigher struct {
	Feather *MaatFeather
}

// MaatFeather represents the ideal balance
type MaatFeather struct {
	Weight float64 // The perfect weight (1.0)
}

// HeartOption represents a possible response
type HeartOption struct {
	Action            string
	OperationalBurden float64 // 0.0 = no burden, 1.0 = catastrophic
	RestorationPower  float64 // 0.0 = no effect, 1.0 = complete restoration
	Certainty         float64 // 0.0 = uncertain, 1.0 = certain
	Potency           float64 // Calculated balance score
}

// NewAnubisWeigher creates the weigher
func NewAnubisWeigher() *AnubisWeigher {
	return &AnubisWeigher{
		Feather: &MaatFeather{Weight: 1.0},
	}
}

// WeighHeart evaluates options against the Feather of Maat
func (aw *AnubisWeigher) WeighHeart(isfet Isfet) []HeartOption {
	options := []HeartOption{}

	// Determine options based on severity
	switch isfet.Severity {
	case SeverityCatastrophic:
		// Immediate isolation required
		options = append(options, HeartOption{
			Action:            ActionSeal,
			OperationalBurden: 0.8,
			RestorationPower:  1.0,
			Certainty:         0.95,
		})
		options = append(options, HeartOption{
			Action:            ActionBanish,
			OperationalBurden: 0.5,
			RestorationPower:  0.9,
			Certainty:         0.9,
		})

	case SeveritySevere:
		// Strong action needed.
		// Banish (IP block via Crowdsec) is cheap and reversible — low burden.
		// Purify (package install, service enable, kernel change) is expensive
		// and potentially disruptive — burden 0.6 prevents autonomous execution
		// on all deployment targets. Human approval required before purification.
		options = append(options, HeartOption{
			Action:            ActionBanish,
			OperationalBurden: 0.3,
			RestorationPower:  0.9,
			Certainty:         0.8,
		})
		options = append(options, HeartOption{
			Action:            ActionPurify,
			OperationalBurden: 0.6,
			RestorationPower:  0.7,
			Certainty:         0.7,
		})

	case SeverityModerate:
		// Remediation preferred but not autonomous — system-level changes
		// (package installs, sysctl, service enables) risk breaking production
		// regardless of deployment mode. Burden 0.5 keeps them in the queue
		// for human review while Observe runs autonomously as a safe fallback.
		options = append(options, HeartOption{
			Action:            ActionPurify,
			OperationalBurden: 0.5,
			RestorationPower:  0.8,
			Certainty:         0.75,
		})
		options = append(options, HeartOption{
			Action:            ActionObserve,
			OperationalBurden: 0.0,
			RestorationPower:  0.3,
			Certainty:         1.0,
		})

	case SeverityMinor:
		// Monitor autonomously; light remediation queued for human review.
		options = append(options, HeartOption{
			Action:            ActionObserve,
			OperationalBurden: 0.0,
			RestorationPower:  0.2,
			Certainty:         1.0,
		})
		options = append(options, HeartOption{
			Action:            ActionPurify,
			OperationalBurden: 0.45,
			RestorationPower:  0.6,
			Certainty:         0.8,
		})
	}

	// Calculate potency for all options
	for i := range options {
		options[i].Potency = aw.calculateBalance(options[i])
	}

	return options
}

// calculateBalance determines how close to Maat's feather
func (aw *AnubisWeigher) calculateBalance(option HeartOption) float64 {
	// Balance = (RestorationPower * Certainty) - OperationalBurden
	score := (option.RestorationPower * option.Certainty) - option.OperationalBurden

	// Normalize to 0.0-1.0
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}
