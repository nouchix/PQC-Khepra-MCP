package billing

import (
	"math"
	"testing"
)

func TestNewHybridBillingCalculator(t *testing.T) {
	calc := NewHybridBillingCalculator(500.0)

	if calc == nil {
		t.Fatal("expected non-nil calculator")
	}
	if calc.BaseTierCost != 500.0 {
		t.Errorf("expected base tier cost 500.0, got %f", calc.BaseTierCost)
	}
	if calc.SunMetrics == nil {
		t.Error("expected non-nil SunMetrics")
	}
	if calc.EarthMetrics == nil {
		t.Error("expected non-nil EarthMetrics")
	}
	if calc.SeedMetrics == nil {
		t.Error("expected non-nil SeedMetrics")
	}
}

func TestSunMetrics_CalculateSunRevenue(t *testing.T) {
	sm := &SunMetrics{
		TotalScans:       100,
		CriticalFindings: 5,
		HighFindings:     10,
		LowFindings:      20,
		PricePerScan:     0.10,
		PricePerCritical: 1.00,
		PricePerHigh:     0.25,
		PricePerMedium:   0.05,
	}

	// Expected: 100*0.10 + 5*1.00 + 10*0.25 + 20*0.05 = 10 + 5 + 2.5 + 1 = 18.5
	expected := 18.5
	got := sm.CalculateSunRevenue()

	if math.Abs(got-expected) > 0.001 {
		t.Errorf("expected sun revenue %f, got %f", expected, got)
	}
}

func TestEarthMetrics_CalculateEarthRevenue(t *testing.T) {
	em := &EarthMetrics{
		ActiveNodes:      10,
		PricePerNode:     50.00,
		SANDocuments:     5,
		PricePerSAN:      5.00,
		VirtualInstances: 3,
		PricePerInstance: 25.00,
	}

	// Expected: 10*50 + 5*5 + 3*25 = 500 + 25 + 75 = 600
	expected := 600.0
	got := em.CalculateEarthRevenue()

	if math.Abs(got-expected) > 0.001 {
		t.Errorf("expected earth revenue %f, got %f", expected, got)
	}
}

func TestSeedMetrics_CalculateSeedRevenue(t *testing.T) {
	sm := &SeedMetrics{
		DAGStorageGB:      100.0,
		RetentionDays:     30,
		PricePerGBDay:     0.01,
		ComplianceReports: 2,
		PricePerReport:    10.00,
		ArchiveStorage:    50.0,
		PricePerArchiveGB: 0.005,
	}

	// Expected: 100*30*0.01 + 2*10 + 50*0.005 = 30 + 20 + 0.25 = 50.25
	expected := 50.25
	got := sm.CalculateSeedRevenue()

	if math.Abs(got-expected) > 0.001 {
		t.Errorf("expected seed revenue %f, got %f", expected, got)
	}
}

func TestHybridBillingCalculator_CalculateMonthlyCost(t *testing.T) {
	calc := NewHybridBillingCalculator(500.0)

	// Set up metrics
	calc.SunMetrics.TotalScans = 200
	calc.SunMetrics.CriticalFindings = 5
	calc.SunMetrics.HighFindings = 10
	calc.SunMetrics.LowFindings = 0

	calc.EarthMetrics.ActiveNodes = 3
	calc.EarthMetrics.SANDocuments = 0
	calc.EarthMetrics.VirtualInstances = 0

	calc.SeedMetrics.DAGStorageGB = 10.0
	calc.SeedMetrics.RetentionDays = 30
	calc.SeedMetrics.ComplianceReports = 0
	calc.SeedMetrics.ArchiveStorage = 0

	result := calc.CalculateMonthlyCost()

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.BaseTier != 500.0 {
		t.Errorf("expected base tier 500.0, got %f", result.BaseTier)
	}

	// Sun: 200*0.10 + 5*1.00 + 10*0.25 = 20 + 5 + 2.5 = 27.5
	expectedSun := 27.5
	if math.Abs(result.SunRevenue-expectedSun) > 0.001 {
		t.Errorf("expected sun revenue %f, got %f", expectedSun, result.SunRevenue)
	}

	// Earth: 3*50 = 150
	expectedEarth := 150.0
	if math.Abs(result.EarthRevenue-expectedEarth) > 0.001 {
		t.Errorf("expected earth revenue %f, got %f", expectedEarth, result.EarthRevenue)
	}

	// Seed: 10*30*0.01 = 3
	expectedSeed := 3.0
	if math.Abs(result.SeedRevenue-expectedSeed) > 0.001 {
		t.Errorf("expected seed revenue %f, got %f", expectedSeed, result.SeedRevenue)
	}

	// Total: 500 + 27.5 + 150 + 3 = 680.5
	expectedTotal := 680.5
	if math.Abs(result.Total-expectedTotal) > 0.001 {
		t.Errorf("expected total %f, got %f", expectedTotal, result.Total)
	}

	// Check that breakdown is populated
	if result.Breakdown == "" {
		t.Error("expected non-empty breakdown")
	}

	// Check Egyptian balance message
	if result.EgyptianBalance == "" {
		t.Error("expected non-empty Egyptian balance message")
	}
}

func TestGetTierBaseCost(t *testing.T) {
	tests := []struct {
		tier     string
		expected float64
	}{
		{"khepri", 50},
		{"ra", 500},
		{"atum", 2000},
		{"osiris", 0},
		{"unknown", 0},
	}

	for _, tt := range tests {
		got := GetTierBaseCost(tt.tier)
		if got != tt.expected {
			t.Errorf("GetTierBaseCost(%s) = %f, want %f", tt.tier, got, tt.expected)
		}
	}
}

func TestSunMetrics_Details(t *testing.T) {
	sm := &SunMetrics{
		TotalScans:       10,
		CriticalFindings: 2,
		HighFindings:     3,
		LowFindings:      5,
		PricePerScan:     0.10,
		PricePerCritical: 1.00,
		PricePerHigh:     0.25,
		PricePerMedium:   0.05,
	}

	details := sm.Details()
	if details == "" {
		t.Error("expected non-empty details string")
	}

	// Check that it contains expected content
	if len(details) < 50 {
		t.Error("details string seems too short")
	}
}

func TestEarthMetrics_Details(t *testing.T) {
	em := &EarthMetrics{
		ActiveNodes:      5,
		PricePerNode:     50.00,
		SANDocuments:     2,
		PricePerSAN:      5.00,
		VirtualInstances: 1,
		PricePerInstance: 25.00,
	}

	details := em.Details()
	if details == "" {
		t.Error("expected non-empty details string")
	}
}

func TestSeedMetrics_Details(t *testing.T) {
	sm := &SeedMetrics{
		DAGStorageGB:      50.0,
		RetentionDays:     30,
		PricePerGBDay:     0.01,
		ComplianceReports: 1,
		PricePerReport:    10.00,
		ArchiveStorage:    10.0,
		PricePerArchiveGB: 0.005,
	}

	details := sm.Details()
	if details == "" {
		t.Error("expected non-empty details string")
	}
}

func TestMerkabaBalance_SunExceedsEarth(t *testing.T) {
	calc := NewHybridBillingCalculator(0)

	// High sun revenue (many threats)
	calc.SunMetrics.TotalScans = 1000
	calc.SunMetrics.CriticalFindings = 50

	// Low earth revenue (few protected assets)
	calc.EarthMetrics.ActiveNodes = 1

	result := calc.CalculateMonthlyCost()

	// Should warn about imbalance
	if result.EgyptianBalance == "" {
		t.Error("expected Egyptian balance message")
	}
}

func TestMerkabaBalance_EarthExceedsSun(t *testing.T) {
	calc := NewHybridBillingCalculator(0)

	// Low sun revenue (few threats)
	calc.SunMetrics.TotalScans = 10

	// High earth revenue (many protected assets)
	calc.EarthMetrics.ActiveNodes = 100

	result := calc.CalculateMonthlyCost()

	// Should indicate balance
	if result.EgyptianBalance == "" {
		t.Error("expected Egyptian balance message")
	}
}

func TestPolarity(t *testing.T) {
	// Test polarity constants
	if PolaritySun != "sun" {
		t.Errorf("expected PolaritySun to be 'sun', got '%s'", PolaritySun)
	}
	if PolarityEarth != "earth" {
		t.Errorf("expected PolarityEarth to be 'earth', got '%s'", PolarityEarth)
	}
	if PolaritySeed != "seed" {
		t.Errorf("expected PolaritySeed to be 'seed', got '%s'", PolaritySeed)
	}
}
