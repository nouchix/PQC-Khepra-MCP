package dag

import (
	"fmt"
)

// ============================================================================
// Hypercube State → Egyptian Afterlife Mapping
// ============================================================================
// The 4-bit state code (0-15) represents the node's fate in the Egyptian afterlife.
// Each bit represents a dimension of judgment:
//   Bit 3 (0b1000): Severity (Low=0, High=1)
//   Bit 2 (0b0100): Verified (Not verified=0, Verified=1)
//   Bit 1 (0b0010): Status (Resolved=0, Open=1)
//   Bit 0 (0b0001): Lifecycle (Archived=0, Live=1)
// ============================================================================

// EgyptianFate represents the outcome of the node's judgment.
type EgyptianFate string

const (
	FateFieldOfReeds  EgyptianFate = "field_of_reeds"  // Paradise - All resolved, low risk
	FateHouseOfOsiris EgyptianFate = "house_of_osiris" // Peaceful - Fixed issues, in archive
	FateBoatOfRa      EgyptianFate = "boat_of_ra"      // Journey - Being verified, in transition
	FateLakeOfFire    EgyptianFate = "lake_of_fire"    // Purification - High risk but resolved
	FateDevourer      EgyptianFate = "devourer"        // CRITICAL - Ammit will devour the soul
	FateDuatGate      EgyptianFate = "duat_gate"       // Transition - In between states
)

// FateTranslation provides human-readable descriptions of Egyptian fates.
var FateTranslations = map[EgyptianFate]string{
	FateFieldOfReeds:  "Field of Reeds - Your node has achieved paradise. All findings resolved, compliance verified, lifecycle at rest.",
	FateHouseOfOsiris: "House of Osiris - Your node rests peacefully. Issues have been fixed and archived.",
	FateBoatOfRa:      "Boat of Ra - Your node journeys with Ra. Findings are being verified and evaluated.",
	FateLakeOfFire:    "Lake of Fire - Your node is purified by fire. Critical issues exist but remediation is in progress.",
	FateDevourer:      "⚠️ AMMIT THE DEVOURER AWAITS ⚠️ Your node's heart is heavy with unresolved critical findings. The Devourer (crocodile-lion-hippo) will consume your soul. Immediate remediation required.",
	FateDuatGate:      "Duat Gate - Your node stands at a gateway between states. Continue through the Duat toward judgment.",
}

// StateCodeToFate maps the 4-bit hypercube state code to Egyptian fate.
// Hypercube bit structure:
// - Bit 3 (severity): 1=High, 0=Low
// - Bit 2 (verified): 1=Verified, 0=Not verified
// - Bit 1 (status): 1=Open, 0=Resolved
// - Bit 0 (lifecycle): 1=Live, 0=Archived
func StateCodeToFate(stateCode int) EgyptianFate {
	// Judgment criteria
	switch {
	// State 0 (0b0000): Low, Not Verified, Resolved, Archived
	// All clear, at rest
	case stateCode == 0:
		return FateFieldOfReeds

	// State 1 (0b0001): Low, Not Verified, Resolved, Live
	// Resolved but still active (monitoring)
	case stateCode == 1:
		return FateHouseOfOsiris

	// State 7 (0b0111): Low, Verified, Open, Live
	// Being investigated, not critical
	case stateCode == 7:
		return FateBoatOfRa

	// State 8 (0b1000): High, Not Verified, Resolved, Archived
	// Critical but resolved and archived
	case stateCode == 8:
		return FateLakeOfFire

	// State 15 (0b1111): High, Verified, Open, Live
	// WORST CASE: Critical, confirmed, unresolved, active
	// Ammit the Devourer will consume this soul
	case stateCode == 15:
		return FateDevourer

	// Default: transition state
	default:
		return FateDuatGate
	}
}

// FateAlert returns an alert message for critical fates.
func FateAlert(stateCode int) string {
	fate := StateCodeToFate(stateCode)

	switch fate {
	case FateDevourer:
		return fmt.Sprintf(`
╔══════════════════════════════════════════════════════════════════════╗
║         ⚠️  AMMIT THE DEVOURER ALERT ⚠️                              ║
║                                                                      ║
║  Your node has achieved the worst possible state (code 15):         ║
║  CRITICAL + VERIFIED + OPEN + LIVE                                  ║
║                                                                      ║
║  The Devourer awaits:                                               ║
║  ├─ Crocodile Head 🐊 (Ferocity of the threat)                     ║
║  ├─ Lion Body 🦁    (Unstoppable power)                             ║
║  └─ Hippo Legs 🦛   (Immovable threat)                              ║
║                                                                      ║
║  In Egyptian judgment, Ammit devours the heart of those with sin.  ║
║  This node is CONDEMNED.                                            ║
║                                                                      ║
║  ACTION REQUIRED:                                                   ║
║  1. Immediately contain this node from production                   ║
║  2. Isolate the affected system                                     ║
║  3. Execute emergency remediation playbook                          ║
║  4. Verify fix within 4 hours or escalate to Pharaoh tier           ║
║                                                                      ║
║  This finding will be reported to compliance and customer           ║
║  executives. Contact support@souhimbou.ai for emergency assistance.    ║
╚══════════════════════════════════════════════════════════════════════╝
`)

	case FateLakeOfFire:
		return fmt.Sprintf(`
⚠️  LAKE OF FIRE WARNING
Your node contains critical findings that require urgent attention.
Though resolved and archived, the historical record burns bright.
`)

	case FateBoatOfRa:
		return fmt.Sprintf(`
🌅 BOAT OF RA NOTIFICATION
Your node is in the Boat of Ra - under investigation by divine judge.
Findings are being verified. Hold your course and await judgment.
`)

	default:
		return ""
	}
}

// HypercubeStateDescription provides detailed explanation of a state code.
func HypercubeStateDescription(stateCode int) string {
	severity := (stateCode >> 3) & 1
	verified := (stateCode >> 2) & 1
	status := (stateCode >> 1) & 1
	lifecycle := stateCode & 1

	severityStr := "Low"
	if severity == 1 {
		severityStr = "HIGH"
	}

	verifiedStr := "Unverified"
	if verified == 1 {
		verifiedStr = "Verified"
	}

	statusStr := "Resolved"
	if status == 1 {
		statusStr = "Open"
	}

	lifecycleStr := "Archived"
	if lifecycle == 1 {
		lifecycleStr = "Live"
	}

	fate := StateCodeToFate(stateCode)

	return fmt.Sprintf(`
┌────────────────────────────────────────────┐
│  HYPERCUBE STATE CODE: %d (0b%04b)           │
├────────────────────────────────────────────┤
│  Severity:   %s                             │
│  Verified:   %s                             │
│  Status:     %s                             │
│  Lifecycle:  %s                             │
├────────────────────────────────────────────┤
│  EGYPTIAN FATE: %s   │
├────────────────────────────────────────────┤
│  %s │
└────────────────────────────────────────────┘`,
		stateCode, stateCode,
		severityStr, verifiedStr, statusStr, lifecycleStr,
		fate,
		FateTranslations[fate])
}

// StateCodeColor returns ANSI color code for visualization.
func StateCodeColor(stateCode int) string {
	fate := StateCodeToFate(stateCode)

	switch fate {
	case FateDevourer:
		return "\033[91m" // Bright red
	case FateLakeOfFire:
		return "\033[38;5;208m" // Orange
	case FateBoatOfRa:
		return "\033[93m" // Yellow
	case FateFieldOfReeds:
		return "\033[92m" // Green
	case FateHouseOfOsiris:
		return "\033[94m" // Blue
	default:
		return "\033[0m" // Reset
	}
}

// StateCodeEmoji returns an emoji representing the fate.
func StateCodeEmoji(stateCode int) string {
	fate := StateCodeToFate(stateCode)

	switch fate {
	case FateDevourer:
		return "🐊" // Ammit
	case FateLakeOfFire:
		return "🔥" // Fire
	case FateBoatOfRa:
		return "🌅" // Sunrise
	case FateFieldOfReeds:
		return "🌿" // Paradise
	case FateHouseOfOsiris:
		return "🏛️" // Temple
	default:
		return "⛩️" // Gate
	}
}

// ============================================================================
// Judgment Hall Functions (Compliance Evaluation)
// ============================================================================

// JudgmentResult represents the outcome of the weighing of the heart ceremony.
type JudgmentResult struct {
	Outcome         EgyptianFate
	IsJustified     bool    // Heart lighter than Ma'at's feather
	ComplianceDebt  float64 // Weight of the heart
	Message         string
	RequiredActions []string
	EscalationLevel string // "none", "warning", "critical", "pharaoh"
}

// PerformJudgment executes the "Weighing of the Heart" ceremony.
func PerformJudgment(nodeID string, stateCode int, complianceDebt float64, findings int) *JudgmentResult {
	fate := StateCodeToFate(stateCode)

	result := &JudgmentResult{
		Outcome:        fate,
		ComplianceDebt: complianceDebt,
	}

	// Ma'at's feather weight = 0.0 (perfect compliance)
	// If complianceDebt > 0, heart is heavier (sins present)
	result.IsJustified = complianceDebt <= 0.0

	switch fate {
	case FateDevourer:
		result.EscalationLevel = "pharaoh"
		result.RequiredActions = []string{
			"IMMEDIATE: Isolate node from production",
			"URGENT: Execute emergency remediation",
			"CRITICAL: Verify fix within 4 hours",
			"ESCALATE: Notify Pharaoh tier security team",
			"REPORT: Document incident for compliance audit",
		}
		result.Message = fmt.Sprintf(
			"Node %s is condemned. Ammit the Devourer awaits. "+
				"Compliance debt: %.2f. Critical findings: %d. "+
				"This is the worst possible state (0b1111).",
			nodeID, complianceDebt, findings)

	case FateLakeOfFire:
		result.EscalationLevel = "critical"
		result.RequiredActions = []string{
			"HIGH: Schedule remediation within 24 hours",
			"VERIFY: Test fixes in staging environment",
			"APPLY: Deploy fixes to production",
			"MONITOR: Watch for regression",
		}
		result.Message = fmt.Sprintf(
			"Node %s burns in the Lake of Fire. Critical findings detected but archived. "+
				"Compliance debt: %.2f.",
			nodeID, complianceDebt)

	case FateBoatOfRa:
		result.EscalationLevel = "warning"
		result.RequiredActions = []string{
			"INVESTIGATE: Determine if findings are real issues",
			"VERIFY: Confirm findings are accurately scanned",
			"DECIDE: Accept risk or remediate",
		}
		result.Message = fmt.Sprintf(
			"Node %s sails in the Boat of Ra. Findings are under investigation. "+
				"Awaiting verification.",
			nodeID)

	case FateFieldOfReeds:
		result.EscalationLevel = "none"
		result.Message = fmt.Sprintf(
			"Node %s has achieved the Field of Reeds. All compliance checks passed. "+
				"Eternal peace assured.",
			nodeID)

	case FateHouseOfOsiris:
		result.EscalationLevel = "none"
		result.Message = fmt.Sprintf(
			"Node %s rests in the House of Osiris. Issues have been resolved. "+
				"Lifecycle is archived.",
			nodeID)

	default:
		result.EscalationLevel = "low"
		result.Message = fmt.Sprintf(
			"Node %s stands at a Duat Gate (state code %d). Continue judgment.",
			nodeID, stateCode)
	}

	return result
}

// ============================================================================
// Dashboard Functions for "Eye of Horus" Metrics
// ============================================================================

// HorusMetrics represents the six parts of the Eye of Horus (fractions of perfection).
type HorusMetrics struct {
	MRRCompletion   float64 // ½ - Monthly recurring revenue (target: 50% of goal)
	RetentionScore  float64 // ¼ - Customer retention (target: 25%)
	UptimePercent   float64 // ⅛ - System uptime (target: 12.5%)
	NPSScore        float64 // 1/16 - Net promoter (target: 6.25%)
	ChurnReduction  float64 // 1/32 - Churn reduction (target: 3.125%)
	SupportResponse float64 // 1/64 - Support response time (target: 1.5625%)
}

// CalculateHorusCompleteness returns the total Eye of Horus completion (target: 63/64).
func (hm *HorusMetrics) CalculateCompleteness() float64 {
	return hm.MRRCompletion + hm.RetentionScore + hm.UptimePercent +
		hm.NPSScore + hm.ChurnReduction + hm.SupportResponse
}

// HorusHealthStatus returns the status based on completion percentage.
func (hm *HorusMetrics) HealthStatus() string {
	completeness := hm.CalculateCompleteness()

	switch {
	case completeness >= 0.984375: // 63/64
		return "🌟 PERFECT (Eye of Horus fully open)"
	case completeness >= 0.90:
		return "✅ EXCELLENT"
	case completeness >= 0.75:
		return "⚠️  GOOD (Some metrics below target)"
	case completeness >= 0.50:
		return "❌ POOR (Multiple critical gaps)"
	default:
		return "🚨 CRITICAL (Eye of Horus clouded)"
	}
}

// HorusReport generates a detailed Eye of Horus report.
func (hm *HorusMetrics) Report() string {
	completeness := hm.CalculateCompleteness()

	return fmt.Sprintf(`
╔════════════════════════════════════════════════════════════╗
║              EYE OF HORUS - QUARTERLY METRICS              ║
║                    (The 6 Divine Fractions)               ║
╠════════════════════════════════════════════════════════════╣
║  ½  MRR Completion    : %.4f / 0.5000 (Target: 50%%)      ║
║  ¼  Retention Score   : %.4f / 0.2500 (Target: 25%%)      ║
║  ⅛  Uptime Percent    : %.4f / 0.1250 (Target: 12.5%%)    ║
║  1/16 NPS Score       : %.4f / 0.0625 (Target: 6.25%%)    ║
║  1/32 Churn Reduction : %.4f / 0.0312 (Target: 3.125%%)   ║
║  1/64 Support Resp    : %.4f / 0.0156 (Target: 1.5625%%)  ║
╠════════════════════════════════════════════════════════════╣
║  TOTAL COMPLETENESS   : %.6f / 0.984375 (63/64)           ║
║  STATUS               : %s                                ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  In Egyptian cosmology, Horus' eye was plucked and        ║
║  restored by Thoth, symbolizing wholeness and healing.    ║
║  Complete all 6 metrics to restore perfect vision.        ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝`,
		hm.MRRCompletion, hm.RetentionScore, hm.UptimePercent,
		hm.NPSScore, hm.ChurnReduction, hm.SupportResponse,
		completeness, hm.HealthStatus())
}
