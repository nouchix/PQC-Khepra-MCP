package maat

import (
	"fmt"
	"sort"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/agi"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/seshat"
)

// Guardian maintains Maat (cosmic order/balance)
// Maat (Egyptian): Truth, justice, harmony, balance
type Guardian struct {
	Realm     string
	Anubis    *AnubisWeigher
	Chronicle *seshat.Chronicle
	KASA      *agi.Engine

	// AllowAutonomousRemediation gates whether RemediationBlade actions execute
	// without human approval. Must be explicitly enabled — defaults to false.
	//
	// Set true only in ModeIronBank where the host is a hardened DoD image with
	// the required packages and capabilities pre-installed. In ModeEdge (Hostinger
	// VPS) remediation attempts for STIG controls (scap-security-guide, firewalld,
	// FIPS) fail with exit status 1 on every Ouroboros tick — enabling this on
	// a standard Linux host produces noisy failures with no security benefit.
	AllowAutonomousRemediation bool
}

// NewGuardian creates a Maat Guardian for a realm.
// Autonomous remediation is disabled by default — call WithAutonomousRemediation(true)
// only for Iron Bank / DoD hardened deployments.
func NewGuardian(realm string, kasa *agi.Engine, chronicle *seshat.Chronicle) *Guardian {
	return &Guardian{
		Realm:                      realm,
		Anubis:                     NewAnubisWeigher(),
		Chronicle:                  chronicle,
		KASA:                       kasa,
		AllowAutonomousRemediation: false,
	}
}

// WithAutonomousRemediation enables autonomous execution of RemediationBlade actions.
// Only call this in ModeIronBank deployments.
func (g *Guardian) WithAutonomousRemediation(enabled bool) *Guardian {
	g.AllowAutonomousRemediation = enabled
	return g
}

// WeighAndDecide evaluates Isfet and determines Heka
func (g *Guardian) WeighAndDecide(isfet []Isfet) []Heka {
	heka := []Heka{}

	for _, chaos := range isfet {
		// 1. Anubis weighs the options
		options := g.Anubis.WeighHeart(chaos)

		// 2. Consult KASA for AI-powered recommendation
		kasaWisdom := g.consultKASA(chaos, options)

		// 3. Select best option
		selected := g.selectBestOption(options)

		// 4. Create Heka (restorative action)
		h := Heka{
			Isfet:      chaos,
			Action:     selected.Action,
			Potency:    selected.Potency,
			Autonomous: g.shouldAutomate(selected),
			Khopesh:    g.selectKhopesh(selected.Action),
			Wisdom:     kasaWisdom,
		}

		heka = append(heka, h)

		// 5. Transcribe to Seshat Chronicle
		if g.Chronicle != nil {
			g.Chronicle.Inscribe("maat-decision", map[string]any{
				"realm":       g.Realm,
				"isfet_id":    chaos.ID,
				"severity":    chaos.Severity,
				"action":      h.Action,
				"autonomous":  h.Autonomous,
				"kasa_wisdom": kasaWisdom,
			})
		}
	}

	return heka
}

// consultKASA asks the AGI engine for recommendations
func (g *Guardian) consultKASA(isfet Isfet, options []HeartOption) string {
	if g.KASA == nil {
		return "KASA unavailable"
	}

	// Format query for KASA
	query := fmt.Sprintf(
		"Isfet detected: %s (Severity: %s, Certainty: %.2f). Options: %v. Recommend best action.",
		isfet.ID, isfet.Severity, isfet.Certainty, options,
	)

	// KASA Chat provides AI-powered analysis
	wisdom := g.KASA.Chat(query)

	return wisdom
}

// selectBestOption chooses the option with highest potency
func (g *Guardian) selectBestOption(options []HeartOption) HeartOption {
	if len(options) == 0 {
		// Default to observe
		return HeartOption{
			Action:            ActionObserve,
			OperationalBurden: 0.0,
			RestorationPower:  0.1,
			Certainty:         1.0,
			Potency:           0.1,
		}
	}

	// Sort by potency (descending)
	sort.Slice(options, func(i, j int) bool {
		return options[i].Potency > options[j].Potency
	})

	return options[0]
}

// shouldAutomate determines if action should be automated.
//
// Remediation actions (ActionPurify) additionally require AllowAutonomousRemediation
// to be set — otherwise they are logged as "requires manual approval" and skipped.
// This prevents the Ouroboros cycle from attempting to install DoD packages
// (scap-security-guide, firewalld, FIPS mode) on standard Linux hosts where
// they are unavailable, producing noisy failures with no security benefit.
func (g *Guardian) shouldAutomate(option HeartOption) bool {
	// Never auto-execute seal/isolate (too disruptive regardless of mode)
	if option.Action == ActionSeal || option.Action == ActionIsolate {
		return false
	}

	// Remediation requires explicit opt-in (Iron Bank only)
	if option.Action == ActionPurify && !g.AllowAutonomousRemediation {
		return false
	}

	// Automate if: high certainty + low operational burden
	return option.Certainty >= 0.8 && option.OperationalBurden <= 0.3
}

// selectKhopesh determines which blade should execute the action
func (g *Guardian) selectKhopesh(action string) string {
	switch action {
	case ActionBanish:
		return "khopesh-firewall"
	case ActionSeal:
		return "khopesh-isolation"
	case ActionPurify:
		return "khopesh-remediation"
	case ActionIsolate:
		return "khopesh-network"
	case ActionObserve:
		return "khopesh-monitor"
	default:
		return "khopesh-unknown"
	}
}
