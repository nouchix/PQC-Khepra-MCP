//go:build saas

package apiserver

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// handleHealth returns the health status of the API server
func (s *Server) handleHealth(c *gin.Context) {
	uptime := time.Since(s.startTime).Seconds()

	dagNodeCount := 0
	if s.dagStore != nil {
		dagNodeCount = s.dagStore.NodeCount()
	}

	licenseStatus := "unknown"
	if s.licMgr != nil {
		if valid, _ := s.licMgr.IsValid(); valid {
			licenseStatus = "valid"
		} else {
			licenseStatus = "invalid"
		}
	}

	components := map[string]string{
		"dag_store":       "healthy",
		"license_manager": "healthy",
		"websocket_hub":   "healthy",
	}

	response := HealthResponse{
		Status:     "healthy",
		Version:    s.version,
		Uptime:     uptime,
		DAGNodes:   dagNodeCount,
		License:    licenseStatus,
		Components: components,
		Timestamp:  time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// handleTriggerScan triggers a new security scan
func (s *Server) handleTriggerScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// 1. License + optional public funnel (Fly / marketing)
	// Set ASAF_ALLOW_EVAL_WITHOUT_LICENSE=true to allow eval/basic onboarding scans when telemetry license is invalid.
	// Still requires a valid API key / auth path configured for your deployment.
	status := s.licMgr.GetStatus()
	effectiveTier := status.LicenseTier
	if !status.IsValid {
		allow := strings.EqualFold(os.Getenv("ASAF_ALLOW_EVAL_WITHOUT_LICENSE"), "true") &&
			(req.ScanType == "eval" || req.ScanType == "basic")
		if !allow {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Error:   "license_invalid",
				Message: "A valid license is required to trigger security scans.",
				Code:    http.StatusForbidden,
			})
			return
		}
		effectiveTier = "community"
	}

	// 2. Feature Gating based on Egyptian Tiers
	switch effectiveTier {
	case "community", "khepri":
		if req.ScanType != "eval" && req.ScanType != "basic" {
			c.JSON(http.StatusPaymentRequired, ErrorResponse{
				Error:   "tier_restricted",
				Message: fmt.Sprintf("Scan type '%s' is restricted to Ra (Hunter) tier and above. Please upgrade to access advanced PQC attestation.", req.ScanType),
				Code:    http.StatusPaymentRequired,
			})
			return
		}
	}

	// 3. Generate scan ID
	scanID := uuid.New().String()
	queuedAt := time.Now()
	estimatedCompletion := queuedAt.Add(5 * time.Minute)

	// Register scan in Command Center and run async onboarding assessment (TCP + optional local NemoClaw).
	now := time.Now()
	scan := &ScanResult{
		ID:         scanID,
		StartTime:  now,
		Status:     StatusRunning,
		Framework:  req.ScanType,
		Profile:    req.Profile,
		Platform:   "generic",
		Certified:  false,
		TargetURL:  req.TargetURL,
		Findings:   []Finding{},
		Remediations: []Remediation{},
	}
	commandCenter.mu.Lock()
	commandCenter.scans[scanID] = scan
	commandCenter.mu.Unlock()

	go runASAFOnboardingScan(scanID, req)

	response := ScanResponse{
		ScanID:       scanID,
		Status:       "queued",
		TargetURL:    req.TargetURL,
		ScanType:     req.ScanType,
		QueuedAt:     queuedAt,
		EstimatedAt:  estimatedCompletion,
		WebSocketURL: fmt.Sprintf("wss://%s/ws/scans", c.Request.Host),
	}

	// Broadcast scan queued event via WebSocket
	if s.wsHub != nil {
		s.wsHub.BroadcastScanUpdate(map[string]interface{}{
			"scan_id":    scanID,
			"status":     "queued",
			"target_url": req.TargetURL,
			"scan_type":  req.ScanType,
			"queued_at":  queuedAt,
		})
	}

	c.JSON(http.StatusAccepted, response)
}

// handleGetScanStatus returns the status of a specific scan
func (s *Server) handleGetScanStatus(c *gin.Context) {
	scanID := c.Param("id")

	// Look up the scan from the Command Center's scan registry
	commandCenter.mu.RLock()
	scan, exists := commandCenter.scans[scanID]
	commandCenter.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "scan_not_found",
			Message: fmt.Sprintf("Scan '%s' not found", scanID),
			Code:    http.StatusNotFound,
		})
		return
	}

	// Calculate progress based on scan status
	progress := 0.0
	switch scan.Status {
	case StatusRunning:
		if scan.TotalChecks > 0 {
			progress = float64(scan.PassedChecks+scan.FailedChecks) / float64(scan.TotalChecks)
		} else {
			progress = 0.1 // Scan started but no checks tallied yet
		}
	case StatusCompleted:
		progress = 1.0
	case StatusFailed:
		progress = -1.0
	}

	response := ScanStatus{
		ScanID:    scanID,
		Status:    scan.Status,
		Progress:  progress,
		StartedAt: &scan.StartTime,
		Results: map[string]interface{}{
			"framework":     scan.Framework,
			"total_checks":  scan.TotalChecks,
			"passed_checks": scan.PassedChecks,
			"failed_checks": scan.FailedChecks,
			"findings":      len(scan.Findings),
		},
		Platform:           scan.Platform,
		Certified:        scan.Certified,
		RiskScore:          scan.RiskScore,
		Exposed:            scan.GatewayExposed,
		AuthWeakness:       scan.AuthWeaknessHeuristic,
		OpenIntegrations:   scan.OpenIntegrations,
		Findings:           scan.PresentationFindings,
	}

	if scan.EndTime != nil {
		response.CompletedAt = scan.EndTime
	}

	c.JSON(http.StatusOK, response)
}

// handleGetDAGNodes returns all DAG nodes or filtered nodes
func (s *Server) handleGetDAGNodes(c *gin.Context) {
	if s.dagStore == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Error:   "dag_unavailable",
			Message: "DAG store not initialized",
			Code:    http.StatusServiceUnavailable,
		})
		return
	}

	nodes := s.dagStore.All()

	response := DAGGraphResponse{
		Nodes:       nodes,
		TotalNodes:  len(nodes),
		LastUpdated: time.Now(),
	}

	if len(nodes) > 0 {
		response.LatestNode = nodes[len(nodes)-1].NodeID
		// Assume first nodes are roots for this MVP
		response.RootNodes = []string{nodes[0].NodeID}
	}

	c.JSON(http.StatusOK, response)
}

// handleSTIGValidation performs STIG compliance validation
func (s *Server) handleSTIGValidation(c *gin.Context) {
	var req STIGValidationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// RBAC check: Verify organization access
	apiKey, _ := c.Get("api_key")
	if authorized, err := s.checkOrganizationAccess(apiKey.(string), req.OrganizationID); !authorized || err != nil {
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "access_denied",
			Message: "You are not authorized to perform STIG validation for this organization",
			Code:    http.StatusForbidden,
		})
		return
	}

	// Determine target path from request
	targetPath := "/"
	if req.TargetHost != "" && req.TargetHost != "localhost" {
		targetPath = req.TargetHost
	}

	// Initialize the real STIG validation engine
	validator := stig.NewValidator(targetPath)

	// Enable the requested framework based on STIG version
	validator.EnableFramework(req.STIGVersion)

	// Perform actual validation
	report, err := validator.Validate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "validation_failed",
			Message: fmt.Sprintf("STIG validation failed: %v", err),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	validationID := uuid.New().String()

	// Convert stig.Finding results to API STIGCheckResult format
	results := []STIGCheckResult{}
	passed := 0
	failed := 0
	notApplicable := 0

	for _, vr := range report.Results {
		for _, finding := range vr.Findings {
			severity := mapStigSeverity(finding.Severity)
			status := mapStigStatus(finding.Status)

			results = append(results, STIGCheckResult{
				ControlID:   finding.ID,
				Title:       finding.Title,
				Severity:    severity,
				Status:      status,
				Finding:     finding.Description,
				Remediation: finding.Remediation,
			})

			switch status {
			case "pass":
				passed++
			case "fail":
				failed++
			case "not_applicable":
				notApplicable++
			}
		}
	}

	totalChecks := len(results)
	score := 0.0
	if totalChecks > 0 {
		score = float64(passed) / float64(totalChecks) * 100
	}

	response := STIGValidationResponse{
		ValidationID:  validationID,
		STIGVersion:   req.STIGVersion,
		TargetHost:    req.TargetHost,
		TotalChecks:   totalChecks,
		Passed:        passed,
		Failed:        failed,
		NotApplicable: notApplicable,
		Score:         score,
		Results:       results,
		Timestamp:     time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// mapStigSeverity converts stig.Severity to API severity string
func mapStigSeverity(s stig.Severity) string {
	switch s {
	case stig.SeverityCAT1, stig.SeverityCritical, stig.SeverityHigh:
		return "high"
	case stig.SeverityCAT2, stig.SeverityMedium:
		return "medium"
	case stig.SeverityCAT3, stig.SeverityLow:
		return "low"
	default:
		return "medium"
	}
}

// mapStigStatus converts stig finding status to API status string
func mapStigStatus(status string) string {
	switch status {
	case "Pass":
		return "pass"
	case "Fail":
		return "fail"
	case "Not Applicable":
		return "not_applicable"
	default:
		return "not_applicable"
	}
}

// handleGenerateERT generates an Evidence Recording Token
func (s *Server) handleGenerateERT(c *gin.Context) {
	var req ERTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// 1. Enforce License (Commercial Logic)
	status := s.licMgr.GetStatus()
	if !status.IsValid {
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "license_invalid",
			Message: "A valid license is required to generate Evidence Recording Tokens (ERTs).",
			Code:    http.StatusForbidden,
		})
		return
	}

	// 2. Generate Real Identity
	tokenID := uuid.New().String()
	dagNodeID := "ert-" + uuid.New().String()

	// 3. Persist to DAG Store (SaaS Persistence)
	pqcData := map[string]string{
		"algorithm": "ML-DSA-65",
		"token_id":  tokenID,
		"issued_by": s.licMgr.GetMachineID(),
	}

	err := s.dagStore.Add(dagNodeID, "attestation", []string{}, pqcData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "persistence_failed",
			Message: "Failed to record ERT in the immutable ledger: " + err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	// 4. Generate Real Dilithium3 Signature (TRL10)
	msg := []byte(fmt.Sprintf("%s:%s:%s", tokenID, req.EventType, dagNodeID))
	sig, err := adinkra.Sign(s.sigPrivKey, msg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "signing_failed",
			Message: "PQC signing failed: " + err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	response := ERTResponse{
		TokenID:      tokenID,
		EventType:    req.EventType,
		PQCSignature: fmt.Sprintf("%x", sig), // Hex encoded Dilithium3 signature
		DAGNodeID:    dagNodeID,
		IssuedAt:     time.Now(),
		VerifyURL:    fmt.Sprintf("https://%s/api/v1/ert/verify/%s", c.Request.Host, tokenID),
	}

	// 4. Broadcast Update
	if s.wsHub != nil {
		s.wsHub.BroadcastDAGUpdate(map[string]interface{}{
			"node_id":   dagNodeID,
			"type":      "ert",
			"token_id":  tokenID,
			"timestamp": time.Now(),
		})
	}

	c.JSON(http.StatusCreated, response)
}

// handleGetLicenseStatus returns the current license status
func (s *Server) handleGetLicenseStatus(c *gin.Context) {
	if s.licMgr == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Error:   "license_unavailable",
			Message: "License manager not initialized",
			Code:    http.StatusServiceUnavailable,
		})
		return
	}

	response := s.licMgr.GetStatus()
	c.JSON(http.StatusOK, response)
}

// handleListScans returns a list of all scans from the Command Center registry
func (s *Server) handleListScans(c *gin.Context) {
	// Parse pagination parameters
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "20")
	statusFilter := c.Query("status")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Collect scans from Command Center, apply status filter
	commandCenter.mu.RLock()
	var allScans []*ScanResult
	for _, scan := range commandCenter.scans {
		if statusFilter == "" || scan.Status == statusFilter {
			allScans = append(allScans, scan)
		}
	}
	commandCenter.mu.RUnlock()

	total := len(allScans)

	// Apply pagination
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	pagedScans := allScans[start:end]

	// Convert to ScanResponse format
	scans := make([]ScanResponse, 0, len(pagedScans))
	for _, scan := range pagedScans {
		scans = append(scans, ScanResponse{
			ScanID:   scan.ID,
			Status:   scan.Status,
			ScanType: scan.Framework,
			QueuedAt: scan.StartTime,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"scans":     scans,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// handleCMMCAudit performs a full CMMC Level 2 audit (110 controls)
func (s *Server) handleCMMCAudit(c *gin.Context) {
	// RBAC check: CMMC audits require Commercial or Sovereign tier
	if s.licMgr != nil {
		status := s.licMgr.GetFullStatus()
		if status.LicenseTier == "community" {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Error:   "feature_restricted",
				Message: "CMMC Level 2 audits require a Commercial or Sovereign license",
				Code:    http.StatusForbidden,
			})
			return
		}
	}

	// Initialize STIG/CMMC validator
	validator := stig.NewValidator("/") // Target root for full system audit

	// Perform validation
	report, err := validator.Validate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Extract CMMC results
	cmmcResults, ok := report.Results["CMMC-3.0-L3"]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "CMMC framework results not found in report"})
		return
	}

	c.JSON(http.StatusOK, cmmcResults)
}

// handleSTIGRemediation triggers automated fixes for non-compliant controls
func (s *Server) handleSTIGRemediation(c *gin.Context) {
	var req STIGRemediationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// RBAC check: Verify organization access
	apiKey, _ := c.Get("api_key")
	if authorized, err := s.checkOrganizationAccess(apiKey.(string), req.OrganizationID); !authorized || err != nil {
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "access_denied",
			Message: "You are not authorized to perform STIG remediation for this organization",
			Code:    http.StatusForbidden,
		})
		return
	}

	// Initialize the remediation engine
	checker := stig.NewSystemChecker()
	remediator := stig.NewRemediator(checker)

	// Link Selection: Decide if this is local or across the DEMARC
	if req.TargetHost != "localhost" && req.TargetHost != "" && s.agentMgr != nil {
		remediator.SetLink(&stig.DEMARCLink{
			MachineID: req.TargetHost,
			Manager:   s.agentMgr,
		})
	}

	batchID := uuid.New().String()

	results := []RemediationResult{}
	successCount := 0

	for _, controlID := range req.ControlIDs {
		res, err := remediator.Remediate(controlID)

		status := "failed"
		command := ""
		output := ""
		if err == nil {
			switch res.Status {
			case "Success":
				status = "success"
				successCount++
			case "Requires Manual Intervention":
				status = "requires_manual"
			}
			command = res.Command
			output = res.Output
		} else {
			output = err.Error()
		}

		results = append(results, RemediationResult{
			ControlID: controlID,
			Status:    status,
			Command:   command,
			Output:    output,
			Timestamp: time.Now(),
		})
	}

	status := "completed"
	if successCount == 0 && len(req.ControlIDs) > 0 {
		status = "failed"
	} else if successCount < len(req.ControlIDs) {
		status = "partial"
	}

	response := STIGRemediationResponse{
		BatchID:   batchID,
		Results:   results,
		Summary:   fmt.Sprintf("Successfully remediated %d of %d requested controls.", successCount, len(req.ControlIDs)),
		Status:    status,
		Timestamp: time.Now(),
	}

	c.JSON(http.StatusOK, response)
}
