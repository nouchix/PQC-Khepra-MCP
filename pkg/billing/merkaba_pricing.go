package billing

import (
	"fmt"
	"time"
)

// ============================================================================
// Merkaba Polarity → Hybrid Billing Model
// ============================================================================
// The Merkaba dual-tetrahedron (Star of David) has two polarities:
//   ☀️ SUN (Forward Spin ⟳): Active threats, findings, scans
//   🌍 EARTH (Reverse Spin ⟲): Assets, controls, protection
//   ⚪ SEED (Stillness): Attestations, logs, evidence
// ============================================================================

// Polarity represents Merkaba spin direction and revenue model.
type Polarity string

const (
	PolaritySun   Polarity = "sun"   // Forward spin: Consumption (threats/findings)
	PolarityEarth Polarity = "earth" // Reverse spin: Seat-based (assets/nodes)
	PolaritySeed  Polarity = "seed"  // Stillness: Storage-based (retention/compliance)
)

// BillingMetric tracks usage across the three revenue dimensions.
type BillingMetric struct {
	MetricType Polarity
	Quantity   float64
	Unit       string
	Price      float64
	Total      float64
	Period     time.Time
}

// MonthlyCost represents the hybrid billing formula output.
type MonthlyCost struct {
	BaseTier        float64 // Tier subscription cost
	SunRevenue      float64 // Threat-based consumption
	EarthRevenue    float64 // Asset-based seats
	SeedRevenue     float64 // Storage-based retention
	Total           float64
	Metrics         []BillingMetric
	Period          string
	Breakdown       string
	EgyptianBalance string
}

// ============================================================================
// Sun Revenue: Threat-Based Consumption Pricing
// ============================================================================

// SunMetrics tracks threat-related consumption.
type SunMetrics struct {
	TotalScans       int     // Number of scans executed
	CriticalFindings int     // Critical severity findings
	HighFindings     int     // High severity findings
	MediumFindings   int     // Medium severity findings
	LowFindings      int     // Low severity findings
	PricePerScan     float64 // Default: $0.10
	PricePerCritical float64 // Default: $1.00
	PricePerHigh     float64 // Default: $0.25
	PricePerMedium   float64 // Default: $0.05
}

// CalculateSunRevenue computes threat-based consumption cost.
func (sm *SunMetrics) CalculateSunRevenue() float64 {
	sun := 0.0
	sun += float64(sm.TotalScans) * sm.PricePerScan
	sun += float64(sm.CriticalFindings) * sm.PricePerCritical
	sun += float64(sm.HighFindings) * sm.PricePerHigh
	sun += float64(sm.LowFindings) * sm.PricePerMedium
	return sun
}

// SunDetails returns a detailed breakdown of sun revenue.
func (sm *SunMetrics) Details() string {
	sunTotal := sm.CalculateSunRevenue()

	return fmt.Sprintf(`
☀️ SUN REVENUE (Active Threats)
├─ %d scans × $%.2f       = $%.2f
├─ %d critical × $%.2f    = $%.2f
├─ %d high × $%.2f        = $%.2f
└─ %d medium × $%.2f      = $%.2f
                         ─────────
   SUN TOTAL             $%.2f`,
		sm.TotalScans, sm.PricePerScan, float64(sm.TotalScans)*sm.PricePerScan,
		sm.CriticalFindings, sm.PricePerCritical, float64(sm.CriticalFindings)*sm.PricePerCritical,
		sm.HighFindings, sm.PricePerHigh, float64(sm.HighFindings)*sm.PricePerHigh,
		sm.LowFindings, sm.PricePerMedium, float64(sm.LowFindings)*sm.PricePerMedium,
		sunTotal)
}

// ============================================================================
// Earth Revenue: Seat-Based Asset Protection
// ============================================================================

// EarthMetrics tracks asset-based seat consumption.
type EarthMetrics struct {
	ActiveNodes      int     // Number of protected nodes/assets
	PricePerNode     float64 // Default: $50.00 per node per month
	SANDocuments     int     // SANs (Subject Alternative Names) in certs
	PricePerSAN      float64 // Default: $5.00 per SAN
	VirtualInstances int     // VMs/containers
	PricePerInstance float64 // Default: $25.00
}

// CalculateEarthRevenue computes seat-based asset protection cost.
func (em *EarthMetrics) CalculateEarthRevenue() float64 {
	earth := 0.0
	earth += float64(em.ActiveNodes) * em.PricePerNode
	earth += float64(em.SANDocuments) * em.PricePerSAN
	earth += float64(em.VirtualInstances) * em.PricePerInstance
	return earth
}

// EarthDetails returns a detailed breakdown of earth revenue.
func (em *EarthMetrics) Details() string {
	earthTotal := em.CalculateEarthRevenue()

	return fmt.Sprintf(`
🌍 EARTH REVENUE (Asset Protection)
├─ %d active nodes × $%.2f   = $%.2f
├─ %d SANs × $%.2f           = $%.2f
└─ %d virt instances × $%.2f = $%.2f
                             ─────────
   EARTH TOTAL               $%.2f`,
		em.ActiveNodes, em.PricePerNode, float64(em.ActiveNodes)*em.PricePerNode,
		em.SANDocuments, em.PricePerSAN, float64(em.SANDocuments)*em.PricePerSAN,
		em.VirtualInstances, em.PricePerInstance, float64(em.VirtualInstances)*em.PricePerInstance,
		earthTotal)
}

// ============================================================================
// Seed Revenue: Storage-Based Compliance Evidence
// ============================================================================

// SeedMetrics tracks storage and retention-based costs.
type SeedMetrics struct {
	DAGStorageGB      float64 // Gigabytes of DAG data
	RetentionDays     int     // Days to retain (default: tier-specific)
	PricePerGBDay     float64 // Default: $0.01 per GB-day
	ComplianceReports int     // Number of exported reports
	PricePerReport    float64 // Default: $10.00
	ArchiveStorage    float64 // Archived compliance data in GB
	PricePerArchiveGB float64 // Default: $0.005
}

// CalculateSeedRevenue computes storage and evidence retention cost.
func (sm *SeedMetrics) CalculateSeedRevenue() float64 {
	seed := 0.0
	seed += sm.DAGStorageGB * float64(sm.RetentionDays) * sm.PricePerGBDay
	seed += float64(sm.ComplianceReports) * sm.PricePerReport
	seed += sm.ArchiveStorage * sm.PricePerArchiveGB
	return seed
}

// SeedDetails returns a detailed breakdown of seed revenue.
func (sm *SeedMetrics) Details() string {
	seedTotal := sm.CalculateSeedRevenue()

	return fmt.Sprintf(`
⚪ SEED REVENUE (Compliance Evidence)
├─ %.1f GB × %d days × $%.4f = $%.2f
├─ %d reports × $%.2f         = $%.2f
└─ %.1f GB archive × $%.4f   = $%.2f
                             ─────────
   SEED TOTAL                 $%.2f`,
		sm.DAGStorageGB, sm.RetentionDays, sm.PricePerGBDay,
		sm.DAGStorageGB*float64(sm.RetentionDays)*sm.PricePerGBDay,
		sm.ComplianceReports, sm.PricePerReport,
		float64(sm.ComplianceReports)*sm.PricePerReport,
		sm.ArchiveStorage, sm.PricePerArchiveGB,
		sm.ArchiveStorage*sm.PricePerArchiveGB,
		seedTotal)
}

// ============================================================================
// Unified Hybrid Pricing Calculator
// ============================================================================

// HybridBillingCalculator computes the monthly cost using the Merkaba model.
type HybridBillingCalculator struct {
	BaseTierCost float64 // From tier configuration
	SunMetrics   *SunMetrics
	EarthMetrics *EarthMetrics
	SeedMetrics  *SeedMetrics
}

// NewHybridBillingCalculator creates a new billing calculator.
func NewHybridBillingCalculator(baseTierCost float64) *HybridBillingCalculator {
	return &HybridBillingCalculator{
		BaseTierCost: baseTierCost,
		SunMetrics: &SunMetrics{
			PricePerScan:     0.10,
			PricePerCritical: 1.00,
			PricePerHigh:     0.25,
			PricePerMedium:   0.05,
		},
		EarthMetrics: &EarthMetrics{
			PricePerNode:     50.00,
			PricePerSAN:      5.00,
			PricePerInstance: 25.00,
		},
		SeedMetrics: &SeedMetrics{
			PricePerGBDay:     0.01,
			PricePerReport:    10.00,
			PricePerArchiveGB: 0.005,
		},
	}
}

// CalculateMonthlyCost computes total monthly cost using Merkaba formula.
func (hbc *HybridBillingCalculator) CalculateMonthlyCost() *MonthlyCost {
	sunRevenue := hbc.SunMetrics.CalculateSunRevenue()
	earthRevenue := hbc.EarthMetrics.CalculateEarthRevenue()
	seedRevenue := hbc.SeedMetrics.CalculateSeedRevenue()

	totalCost := hbc.BaseTierCost + sunRevenue + earthRevenue + seedRevenue

	monthCost := &MonthlyCost{
		BaseTier:     hbc.BaseTierCost,
		SunRevenue:   sunRevenue,
		EarthRevenue: earthRevenue,
		SeedRevenue:  seedRevenue,
		Total:        totalCost,
		Period:       time.Now().Format("January 2006"),
	}

	monthCost.Breakdown = fmt.Sprintf(`
╔═════════════════════════════════════════════════════════════╗
║          KHEPRA HYBRID BILLING STATEMENT (%s)         ║
╠═════════════════════════════════════════════════════════════╣
║                                                             ║
║  BASE TIER (Scout/Hunter/Hive/Pharaoh)      $%.2f         ║
║                                                             ║
%s
║
%s
║
%s
║
╠═════════════════════════════════════════════════════════════╣
║  TOTAL MONTHLY CHARGE                       $%.2f         ║
╚═════════════════════════════════════════════════════════════╝

MERKABA BALANCE EXPLANATION:
☀️  SUN (Forward ⟳): What harms you        = $%.2f
🌍 EARTH (Reverse ⟲): What shields you     = $%.2f
⚪ SEED (Stillness): What proves you comply = $%.2f

The three forces create perfect Ma'at (cosmic balance).
`,
		monthCost.Period,
		hbc.BaseTierCost,
		hbc.SunMetrics.Details(),
		hbc.EarthMetrics.Details(),
		hbc.SeedMetrics.Details(),
		totalCost,
		sunRevenue, earthRevenue, seedRevenue)

	// Egyptian balance message
	if sunRevenue > earthRevenue {
		monthCost.EgyptianBalance = "⚠️ WARNING: Sun Revenue exceeds Earth Revenue. More threats detected than protection active. Increase Earth investment to balance Merkaba."
	} else if earthRevenue > sunRevenue*2 {
		monthCost.EgyptianBalance = "✅ BALANCED: Your Merkaba is perfectly aligned. Earth energy protects against Sun threats. Ma'at is pleased."
	} else {
		monthCost.EgyptianBalance = "⚖️ NEUTRAL: Merkaba forces are in transition. Monitor for imbalance."
	}

	return monthCost
}

// ============================================================================
// Tier Defaults (for reference)
// ============================================================================

// GetTierBaseCost returns the base cost for a tier.
func GetTierBaseCost(tier string) float64 {
	costs := map[string]float64{
		"khepri": 50,
		"ra":     500,
		"atum":   2000,
		"osiris": 0, // Custom pricing
	}
	return costs[tier]
}

// PricingExample provides example calculations for different scenarios.
func PricingExample(tierName string, scans, criticals, nodes, gbDays int) {
	baseCost := GetTierBaseCost(tierName)

	calc := NewHybridBillingCalculator(baseCost)

	// Set up realistic metrics
	calc.SunMetrics.TotalScans = scans
	calc.SunMetrics.CriticalFindings = criticals
	calc.EarthMetrics.ActiveNodes = nodes
	calc.SeedMetrics.DAGStorageGB = float64(gbDays) / 30 // Approximate
	calc.SeedMetrics.RetentionDays = 30

	result := calc.CalculateMonthlyCost()

	fmt.Println(result.Breakdown)
	fmt.Println(result.EgyptianBalance)
}

// ============================================================================
// Example Usage Function
// ============================================================================

// ExampleHunterTierBilling demonstrates pricing for Hunter tier customer.
func ExampleHunterTierBilling() {
	fmt.Print(`
SCENARIO: Hunter Tier Customer
──────────────────────────────
Base Tier:           $500/month
200 scans:           200 × $0.10 = $20
5 critical findings: 5 × $1.00 = $5
3 active nodes:      3 × $50 = $150
100 GB-days storage: 100 × $0.01 = $1
────────────────────────────────
TOTAL:               $676/month
`)

	calc := NewHybridBillingCalculator(500.0)
	calc.SunMetrics.TotalScans = 200
	calc.SunMetrics.CriticalFindings = 5
	calc.EarthMetrics.ActiveNodes = 3
	calc.SeedMetrics.DAGStorageGB = 100.0 / 30
	calc.SeedMetrics.RetentionDays = 30

	result := calc.CalculateMonthlyCost()
	fmt.Println(result.Breakdown)
	fmt.Println(result.EgyptianBalance)
}
