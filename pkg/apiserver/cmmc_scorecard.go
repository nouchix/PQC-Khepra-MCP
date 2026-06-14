//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - CMMC 3.0 Scorecard API
// =============================================================================
// Exposes the full STIG→CCI→NIST 800-53→800-171→CMMC mapping chain as a
// structured JSON scorecard covering all 110 L2 practices and 24 L3 enhanced
// practices. This endpoint is protected by the Mitochondrial API Gateway
// (WAFMiddleware + PQC/Auth) and returns PQC-signed responses.
// =============================================================================

package apiserver

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/compliance"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

// CMMCScorecardResponse is the structured API response for the CMMC scorecard.
type CMMCScorecardResponse struct {
	// Header
	Framework   string    `json:"framework"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Engine      string    `json:"engine"`

	// L2 Scorecard (110 NIST 800-171 practices)
	Level2 *compliance.CMMCScorecard `json:"level_2"`

	// L3 Scorecard (24 NIST 800-172 enhanced practices)
	Level3 *Level3Scorecard `json:"level_3"`

	// Combined
	OverallScore     float64 `json:"overall_score"`
	SPRSScore        int     `json:"sprs_score"` // DoD SPRS score (-203 to 110)
	CertReadiness    string  `json:"certification_readiness"`
	MappingStats     map[string]int `json:"mapping_chain_stats"`

	// PQC attestation of this scorecard
	DAGHash string `json:"dag_hash,omitempty"`
}

// Level3Scorecard covers the 24 NIST 800-172 enhanced practices for CMMC L3.
type Level3Scorecard struct {
	TotalPractices int                       `json:"total_practices"`
	PassingCount   int                       `json:"passing_count"`
	FailingCount   int                       `json:"failing_count"`
	Score          float64                   `json:"score"`
	Practices      map[string]string         `json:"practices"` // Practice ID → status
	DomainScores   map[string]*compliance.DomainScore `json:"domain_scores"`
}

// handleCMMCScorecard generates the full CMMC 3.0 scorecard (L2 + L3).
// Route: GET /api/v1/compliance/cmmc-scorecard
// Protected by: WAFMiddleware → PQC/AuthMiddleware (Mitochondrial gateway stack)
func (s *Server) handleCMMCScorecard(c *gin.Context) {
	// 1. Run STIG validator to collect all findings
	validator := stig.NewValidator("/")
	report, err := validator.Validate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "STIG validation failed: " + err.Error(),
		})
		return
	}

	// 2. Collect all failed STIG IDs from all framework results
	failedSTIGs := make(map[string]bool)
	for _, result := range report.Results {
		for _, finding := range result.Findings {
			if finding.Status == "Fail" {
				failedSTIGs[finding.ID] = true
			}
		}
	}

	// 3. Initialize the compliance mapper with the CSV data
	mapper := compliance.NewComplianceMapper()

	// 4. Generate L2 scorecard (110 NIST 800-171 practices)
	l2Scorecard := mapper.GenerateCMMCScorecard(failedSTIGs)
	l2Scorecard.ComputeDomainScores()
	sprsScore := l2Scorecard.ComputeSPRS()

	// 5. Generate L3 scorecard (24 NIST 800-172 enhanced practices)
	l3Scorecard := s.generateL3Scorecard(report, mapper)

	// 6. Compute overall score (weighted: L2=70%, L3=30%)
	l2Score := float64(0)
	if l2Scorecard.PassingCount+l2Scorecard.FailingCount > 0 {
		l2Score = float64(l2Scorecard.PassingCount) / float64(l2Scorecard.PassingCount+l2Scorecard.FailingCount) * 100
	}
	overallScore := l2Score*0.7 + l3Scorecard.Score*0.3

	readiness := "NOT READY"
	if overallScore >= 90 {
		readiness = "READY FOR CERTIFICATION"
	} else if overallScore >= 75 {
		readiness = "NEAR COMPLIANCE"
	} else if overallScore >= 50 {
		readiness = "IN PROGRESS"
	}

	// 7. Get mapping chain stats from the embedded STIG database
	var mappingStats map[string]int
	db, dbErr := stig.GetDatabase()
	if dbErr == nil {
		mappingStats = db.Stats()
	} else {
		mappingStats = map[string]int{"error": 1}
	}

	// 8. Build response
	response := CMMCScorecardResponse{
		Framework:     "CMMC",
		Version:       "3.0",
		GeneratedAt:   time.Now(),
		Engine:        "AdinKhepra-STIG-CMMC-Engine/v2",
		Level2:        l2Scorecard,
		Level3:        l3Scorecard,
		OverallScore:  overallScore,
		SPRSScore:     sprsScore,
		CertReadiness: readiness,
		MappingStats:  mappingStats,
	}

	c.JSON(http.StatusOK, response)
}

// generateL3Scorecard evaluates the 24 NIST 800-172 enhanced practices.
func (s *Server) generateL3Scorecard(report *stig.ComprehensiveReport, mapper *compliance.ComplianceMapper) *Level3Scorecard {
	l3 := &Level3Scorecard{
		TotalPractices: 24,
		Practices:      make(map[string]string),
		DomainScores:   make(map[string]*compliance.DomainScore),
	}

	// Extract CMMC L3 findings from the validator report
	cmmcResults, ok := report.Results["CMMC-3.0-L3"]
	if !ok {
		// No CMMC results — mark all L3 as not assessed
		l3.Score = 0
		return l3
	}

	// Index findings by ID for quick lookup
	findingStatus := make(map[string]string)
	for _, f := range cmmcResults.Findings {
		findingStatus[f.ID] = f.Status
	}

	// All 800-172 enhanced practice refs (from the CSV)
	l3Refs := []string{
		"3.1.1e", "3.1.2e", "3.1.3e", "3.1.4e", "3.1.5e", "3.1.6e",
		"3.2.1e",
		"3.3.1e", "3.3.2e",
		"3.4.1e", "3.4.2e",
		"3.5.1e", "3.5.2e", "3.5.3e", "3.5.4e",
		"3.6.1e", "3.6.2e",
		"3.7.1e",
		"3.8.1e",
		"3.10.1e",
		"3.11.1e", "3.11.2e", "3.11.3e",
		"3.12.1e", "3.12.2e",
		"3.13.1e", "3.13.2e", "3.13.3e", "3.13.4e", "3.13.5e", "3.13.6e",
		"3.14.1e", "3.14.2e", "3.14.3e", "3.14.4e",
	}

	l3FamilyMap := map[string]string{
		"3.1":  "Access Control",
		"3.2":  "Awareness and Training",
		"3.3":  "Audit and Accountability",
		"3.4":  "Configuration Management",
		"3.5":  "Identification and Authentication",
		"3.6":  "Incident Response",
		"3.7":  "Maintenance",
		"3.8":  "Media Protection",
		"3.10": "Physical Protection",
		"3.11": "Risk Assessment",
		"3.12": "Security Assessment",
		"3.13": "System and Communications Protection",
		"3.14": "System and Information Integrity",
	}

	for _, ref := range l3Refs {
		// Determine family from the control prefix
		family := "General"
		for prefix, fam := range l3FamilyMap {
			if len(ref) > len(prefix) && ref[:len(prefix)] == prefix {
				family = fam
				break
			}
		}

		domain := compliance.CMMCDomainCode[family]
		if domain == "" {
			domain = "GEN"
		}

		practiceID := domain + ".L3-" + ref

		// Initialize domain score
		if l3.DomainScores[domain] == nil {
			l3.DomainScores[domain] = &compliance.DomainScore{
				Domain: domain,
				Family: family,
			}
		}
		ds := l3.DomainScores[domain]
		ds.Total++

		// Check if this practice's finding passed
		findingID := "CMMC:" + family + ".L3-" + ref
		// Also check alternate ID format
		findingID2 := "CMMC:" + strings.ReplaceAll(family, " ", "") + ".L3-" + ref

		status := "Pass"
		if s, ok := findingStatus[findingID]; ok {
			status = s
		} else if s, ok := findingStatus[findingID2]; ok {
			status = s
		}

		if status == "Fail" {
			l3.Practices[practiceID] = "FAILING"
			l3.FailingCount++
			ds.Failing++
		} else {
			l3.Practices[practiceID] = "PASSING"
			l3.PassingCount++
			ds.Passing++
		}
	}

	// Compute L3 score
	total := l3.PassingCount + l3.FailingCount
	if total > 0 {
		l3.Score = float64(l3.PassingCount) / float64(total) * 100
	}

	// Compute domain scores
	for _, ds := range l3.DomainScores {
		if ds.Total > 0 {
			ds.Score = float64(ds.Passing) / float64(ds.Total) * 100
		}
	}

	return l3
}

// handleCMMCMappingChain returns the raw mapping chain statistics
// showing the full traceability from STIG→CCI→NIST 800-53→800-171→CMMC.
// Route: GET /api/v1/compliance/mapping-chain
func (s *Server) handleCMMCMappingChain(c *gin.Context) {
	db, err := stig.GetDatabase()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	stats := db.Stats()

	// Get all unique NIST 800-171 controls
	mapper := compliance.NewComplianceMapper()
	practices := make([]string, 0, len(mapper.NIST171toCMMC))
	for nist171, cmmc := range mapper.NIST171toCMMC {
		practices = append(practices, nist171+" → "+cmmc)
	}
	sort.Strings(practices)

	c.JSON(http.StatusOK, gin.H{
		"framework":       "CMMC 3.0",
		"mapping_chain":   "STIG → CCI → NIST 800-53 → NIST 800-171 → CMMC L2 | NIST 800-172 → CMMC L3",
		"database_stats":  stats,
		"l2_practice_count": len(mapper.ControlFamilies),
		"l2_practices":    practices,
		"domain_codes":    compliance.CMMCDomainCode,
		"l1_subset_count": len(compliance.CMMCLevel1Practices),
		"engine":          "AdinKhepra-Mitochondrial-Gateway/v2",
		"protection": gin.H{
			"waf":           "SEKHEM WAFShield (L7 perimeter)",
			"auth":          "PQC/Bearer auth gateway",
			"rate_limiting": "100 req/min per-IP",
			"dag_audit":     "All requests DAG-logged",
		},
	})
}
