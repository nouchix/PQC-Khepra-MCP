package adinkra

import (
	"fmt"
	"math/rand"
	"time"
)

// =============================================================================
// KHEPRA NSOHIA: SACRED SURVIVAL ARCHITECTURE
// "The hen treads upon her chicks, but she does not kill them."
// =============================================================================

// VesselType (formerly ICSComponentType) represents the physical shells in the Pod.
type VesselType string

const (
	VesselOracle    VesselType = "ORACLE"    // Formerly PLC (Logic)
	VesselScribe    VesselType = "SCRIBE"    // Formerly HMI (Interface)
	VesselGate      VesselType = "GATE"      // Formerly Relay (Switching)
	VesselMessenger VesselType = "MESSENGER" // Formerly Switch (Network)
	VesselGuard     VesselType = "GUARD"     // Formerly MCB/PSU
)

// NsohiaTier (formerly 3-Prong Tiers) represents the Akoko Nan hierarchy levels.
type NsohiaTier string

const (
	TierKotoko  NsohiaTier = "KOTOKO"  // Distributed (Porcupine: Self-Defense)
	TierMpuanum NsohiaTier = "MPUANUM" // Intermediate (Five Tufts: Guidance)
	TierNyame   NsohiaTier = "NYAME"   // Centralized (Supreme: Oversight)
)

// SunsumProfile (formerly ResilienceMetrics) implements the Five Vital Forces.
type SunsumProfile struct {
	Eban       float64 // Robustness (Resistance)
	Nkyinkyim  float64 // Agility (Auto-correction)
	AsaseYaa   float64 // Normalcy (Baseline Stability)
	Bere       float64 // Latency (Time Flow)
	Dwennimmen float64 // Digression (Data Integrity)
}

// SacredVessel (formerly SCADAAsset) represents a component bound to the board.
type SacredVessel struct {
	ID        string
	Kind      VesselType
	Symbol    string     // Adinkra Symbol protecting this vessel
	FlowState string     // Current operational state
	Hierarchy NsohiaTier // NSOHIA level for response
	LastAudit time.Time
	Vitality  SunsumProfile // The Five Vital Forces (Resilience)
}

// AkokoNanPod (formerly SCADAPod) represents the hierarchical multi-agent system.
type AkokoNanPod struct {
	Name           string
	Vessels        []SacredVessel
	OraclesAligned bool
}

// NewAkokoNanPod initializes a pod with vessels distributed across the Nsohia tiers.
func NewAkokoNanPod(name string) *AkokoNanPod {
	return &AkokoNanPod{
		Name: name,
		Vessels: []SacredVessel{
			{
				ID:        "gate-alpha",
				Kind:      VesselGate,
				Symbol:    "Dwennimmen",
				Hierarchy: TierKotoko,
				Vitality:  SunsumProfile{Eban: 0.95, Nkyinkyim: 0.90, AsaseYaa: 1.0},
			},
			{
				ID:        "messenger-alpha",
				Kind:      VesselMessenger,
				Symbol:    "Eban",
				Hierarchy: TierMpuanum,
				Vitality:  SunsumProfile{Eban: 0.85, Nkyinkyim: 0.80, AsaseYaa: 1.0},
			},
			{
				ID:        "oracle-prime",
				Kind:      VesselOracle,
				Symbol:    "Nkyinkyim",
				Hierarchy: TierKotoko,
				Vitality:  SunsumProfile{Eban: 0.90, Nkyinkyim: 0.85, AsaseYaa: 1.0},
			},
			{
				ID:        "scribe-central",
				Kind:      VesselScribe,
				Symbol:    "Fawohodie",
				Hierarchy: TierNyame,
				Vitality:  SunsumProfile{Eban: 0.75, Nkyinkyim: 0.70, AsaseYaa: 1.0},
			},
		},
		OraclesAligned: true,
	}
}

// MmereDane (formerly SystemicFuzz) explores the trade-off space between Benefit and Impact.
func (p *AkokoNanPod) MmereDane(vesselID string) (float64, float64) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	merit := 0.6 + (r.Float64() * 0.4) // Security Benefit
	burden := r.Float64() * 0.5        // Stability Impact
	return merit, burden
}

// AttestVitality (formerly AttestState) binds a vessel's force to the ASAF framework.
func (p *AkokoNanPod) AttestVitality(vesselID string, priv *AdinkhepraPQCPrivateKey, disturbance bool) (*AdinkhepraAttestation, error) {
	var target *SacredVessel
	for i := range p.Vessels {
		if p.Vessels[i].ID == vesselID {
			target = &p.Vessels[i]
			break
		}
	}

	if target == nil {
		return nil, fmt.Errorf("vessel %s is lost in the void", vesselID)
	}

	if disturbance {
		target.Vitality.AsaseYaa -= 0.1
		target.FlowState = "VOID_JITTER"
	}

	// ASAF Attestation Payload: Attests that the Akofena (Surgical Response) is compatible.
	context := fmt.Sprintf("Tier: %s | Sunsum: %.2f | Nkyinkyim: %.2f | State: %s",
		target.Hierarchy, target.Vitality.Eban, target.Vitality.Nkyinkyim, target.FlowState)

	resonance := int(target.Vitality.AsaseYaa * 100)

	return SignAgentAction(
		priv,
		target.ID,
		fmt.Sprintf("nsohia-%d", time.Now().UnixNano()),
		target.Symbol,
		resonance,
		context,
	)
}

// InvokeAkofena (formerly PerformReactiveAction) implements the Hierarchy Mitigation.
func (p *AkokoNanPod) InvokeAkofena(vesselID string) string {
	for _, v := range p.Vessels {
		if v.ID == vesselID {
			if v.Hierarchy == TierKotoko {
				return "KOTOKO DEFENSE: Localizing vessel and shifting to redundant flow."
			}
			return "MPUANUM GUIDANCE: Adjusting network currents to contain the void."
		}
	}
	return "STILLNESS"
}

// MapVesselToSacredCode (formerly MapICSToCompliance)
func MapVesselToSacredCode(v VesselType) []string {
	switch v {
	case VesselOracle, VesselGate:
		return []string{"Ancient Order 62443", "NIST Path 800-82", "Integrity Level (SIL)"}
	case VesselScribe, VesselMessenger:
		return []string{"Sovereign CIP", "Tribal Maturity L3", "Flow Segmentation"}
	case VesselGuard:
		return []string{"Primal Safety Code", "Core Infrastructure Shield"}
	default:
		return []string{"General Protection"}
	}
}
