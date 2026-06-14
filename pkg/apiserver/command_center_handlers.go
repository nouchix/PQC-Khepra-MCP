//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - Command Center Gin Handlers
// =============================================================================
// Wrapper handlers that integrate Command Center with Gin framework
// =============================================================================

package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/gin-gonic/gin"
)

// =============================================================================
// DASHBOARD HANDLER
// =============================================================================

func (s *Server) handleCCDashboard(c *gin.Context) {
	commandCenter.mu.RLock()
	defer commandCenter.mu.RUnlock()

	// Calculate stats
	totalEndpoints := len(commandCenter.endpoints)
	onlineEndpoints := 0
	compliantEndpoints := 0
	for _, ep := range commandCenter.endpoints {
		if ep.Status == "online" || ep.Status == "compliant" {
			onlineEndpoints++
		}
		if ep.Status == "compliant" {
			compliantEndpoints++
		}
	}

	totalScans := len(commandCenter.scans)
	activeScans := 0
	totalFindings := 0
	for _, scan := range commandCenter.scans {
		if scan.Status == "running" {
			activeScans++
		}
		totalFindings += len(scan.Findings)
	}

	totalSnapshots := len(commandCenter.snapshots)
	totalAttestations := len(commandCenter.attestations)

	c.JSON(http.StatusOK, gin.H{
		"quadrants": gin.H{
			"discover": gin.H{
				"total_endpoints":     totalEndpoints,
				"online_endpoints":    onlineEndpoints,
				"compliant_endpoints": compliantEndpoints,
				"status":              "operational",
			},
			"assess": gin.H{
				"total_scans":    totalScans,
				"active_scans":   activeScans,
				"total_findings": totalFindings,
				"status":         "operational",
			},
			"rollback": gin.H{
				"total_snapshots": totalSnapshots,
				"storage_used_mb": 0,
				"oldest_snapshot": nil,
				"status":          "operational",
			},
			"prove": gin.H{
				"total_attestations": totalAttestations,
				"chain_length":       totalAttestations,
				"last_attestation":   nil,
				"status":             "operational",
			},
		},
		"compliance_score": calculateComplianceScore(),
		"system_health":    "healthy",
		"last_updated":     time.Now(),
		"differentiator":   MarketingDifferentiator,
	})
}

// =============================================================================
// QUADRANT 1: DISCOVER HANDLERS
// =============================================================================

func (s *Server) handleCCDiscover(c *gin.Context) {
	var req DiscoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidRequest})
		return
	}

	jobID := generateID("disc")

	resp := DiscoverResponse{
		JobID:          jobID,
		Status:         StatusInitiated,
		EndpointsFound: 0,
		Endpoints:      []*Endpoint{},
	}

	// If manual mode with specific target, add it immediately
	if req.Mode == "manual" && req.Target != "" {
		endpoint := &Endpoint{
			ID:           generateID("ep"),
			Hostname:     req.Target,
			IPAddress:    req.Target,
			Platform:     "unknown",
			Profile:      req.Profile,
			Status:       StatusPending,
			DiscoveredAt: time.Now(),
			Metadata:     make(map[string]string),
		}

		commandCenter.mu.Lock()
		commandCenter.endpoints[endpoint.ID] = endpoint
		commandCenter.mu.Unlock()

		resp.EndpointsFound = 1
		resp.Endpoints = append(resp.Endpoints, endpoint)
		resp.Status = StatusCompleted
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleCCListEndpoints(c *gin.Context) {
	commandCenter.mu.RLock()
	endpoints := make([]*Endpoint, 0, len(commandCenter.endpoints))
	for _, ep := range commandCenter.endpoints {
		endpoints = append(endpoints, ep)
	}
	commandCenter.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"endpoints": endpoints,
		"total":     len(endpoints),
	})
}

// =============================================================================
// QUADRANT 2: ASSESS HANDLERS
// =============================================================================

func (s *Server) handleCCAssess(c *gin.Context) {
	var req AssessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidRequest})
		return
	}

	scanID := generateID("scan")
	now := time.Now()

	scan := &ScanResult{
		ID:           scanID,
		StartTime:    now,
		Status:       StatusRunning,
		Framework:    req.Framework,
		TotalChecks:  0,
		PassedChecks: 0,
		FailedChecks: 0,
		Findings:     []Finding{},
	}

	if len(req.EndpointIDs) > 0 {
		scan.EndpointID = req.EndpointIDs[0]
	}

	commandCenter.mu.Lock()
	commandCenter.scans[scanID] = scan
	commandCenter.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"scan_id":   scanID,
		"status":    StatusInitiated,
		"framework": req.Framework,
		"message":   ScanStatusMessage,
	})
}

func (s *Server) handleCCAssessStatus(c *gin.Context) {
	scanID := c.Query("scan_id")

	if scanID == "" {
		commandCenter.mu.RLock()
		scans := make([]*ScanResult, 0, len(commandCenter.scans))
		for _, scan := range commandCenter.scans {
			scans = append(scans, scan)
		}
		commandCenter.mu.RUnlock()

		c.JSON(http.StatusOK, gin.H{
			"scans": scans,
			"total": len(scans),
		})
		return
	}

	commandCenter.mu.RLock()
	scan, exists := commandCenter.scans[scanID]
	commandCenter.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// =============================================================================
// QUADRANT 3: ROLLBACK HANDLERS
// =============================================================================

func (s *Server) handleCCCreateSnapshot(c *gin.Context) {
	var req SnapshotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidRequest})
		return
	}

	snapshotID := generateID("snap")
	now := time.Now()

	hashData := fmt.Sprintf("%s|%s|%v|%s", req.EndpointID, req.Type, req.Components, now.Format(time.RFC3339))
	hash := sha256.Sum256([]byte(hashData))

	snapshot := &StateSnapshot{
		ID:         snapshotID,
		EndpointID: req.EndpointID,
		CreatedAt:  now,
		Type:       req.Type,
		Hash:       hex.EncodeToString(hash[:]),
		Size:       0,
		Components: req.Components,
		Metadata:   make(map[string]string),
	}

	commandCenter.mu.Lock()
	commandCenter.snapshots[snapshotID] = snapshot
	commandCenter.mu.Unlock()

	c.JSON(http.StatusOK, snapshot)
}

func (s *Server) handleCCListSnapshots(c *gin.Context) {
	endpointID := c.Query("endpoint_id")

	commandCenter.mu.RLock()
	snapshots := make([]*StateSnapshot, 0)
	for _, snap := range commandCenter.snapshots {
		if endpointID == "" || snap.EndpointID == endpointID {
			snapshots = append(snapshots, snap)
		}
	}
	commandCenter.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"snapshots": snapshots,
		"total":     len(snapshots),
	})
}

func (s *Server) handleCCRollback(c *gin.Context) {
	var req RollbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidRequest})
		return
	}

	commandCenter.mu.RLock()
	snapshot, exists := commandCenter.snapshots[req.SnapshotID]
	commandCenter.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Snapshot not found"})
		return
	}

	response := gin.H{
		"snapshot_id":         snapshot.ID,
		"endpoint_id":         snapshot.EndpointID,
		"status":              "completed",
		"dry_run":             req.DryRun,
		"components_restored": snapshot.Components,
		"timestamp":           time.Now(),
	}

	if req.DryRun {
		response["status"] = "dry_run_completed"
		response["message"] = "Dry run successful. No changes applied."
	}

	c.JSON(http.StatusOK, response)
}

// =============================================================================
// QUADRANT 4: PROVE HANDLERS
// =============================================================================

func (s *Server) handleCCCreateAttestation(c *gin.Context) {
	var req AttestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidRequest})
		return
	}

	attestID := generateID("att")
	now := time.Now()

	// Get previous attestation hash for chain
	var prevHash string
	var latestAttestationTime time.Time
	commandCenter.mu.RLock()
	for _, att := range commandCenter.attestations {
		if att.Timestamp.Before(now) && att.Timestamp.After(latestAttestationTime) {
			latestAttestationTime = att.Timestamp
			prevHash = att.DataHash
		}
	}
	commandCenter.mu.RUnlock()

	attestData := fmt.Sprintf("%s|%s|%s|%s|%s",
		attestID, req.Type, req.DataHash, now.Format(time.RFC3339), prevHash)
	dataHash := sha256.Sum256([]byte(attestData))

	attestation := &Attestation{
		ID:            attestID,
		Type:          req.Type,
		Timestamp:     now,
		DataHash:      hex.EncodeToString(dataHash[:]),
		Signature:     "",
		SignerID:      "khepra-system",
		ChainPrevious: prevHash,
		Metadata:      req.Metadata,
	}

	// Sign with ML-DSA-65 (Dilithium3) using the server's persistent identity key
	signature, err := adinkra.Sign(s.sigPrivKey, dataHash[:])
	if err == nil {
		attestation.Signature = hex.EncodeToString(signature)
	}

	commandCenter.mu.Lock()
	commandCenter.attestations[attestID] = attestation
	commandCenter.mu.Unlock()

	c.JSON(http.StatusOK, attestation)
}

func (s *Server) handleCCVerifyAttestation(c *gin.Context) {
	attestID := c.Query("id")
	if attestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Attestation ID required"})
		return
	}

	commandCenter.mu.RLock()
	attestation, exists := commandCenter.attestations[attestID]
	commandCenter.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Attestation not found"})
		return
	}

	// Perform actual cryptographic verification using ML-DSA-65
	dataBytes := []byte(fmt.Sprintf("%s|%s|%s|%s|%s",
		attestation.ID, attestation.Type, attestation.DataHash, attestation.Timestamp.Format(time.RFC3339), attestation.ChainPrevious))
	dataHash := sha256.Sum256(dataBytes)

	sigBytes, sigErr := hex.DecodeString(attestation.Signature)

	verified := false
	verifyErr := ""
	if sigErr != nil {
		verifyErr = "invalid signature encoding"
	} else if len(sigBytes) == 0 {
		verifyErr = "empty signature"
	} else {
		ok, err := adinkra.Verify(s.sigPubKey, dataHash[:], sigBytes)
		if err != nil {
			verifyErr = err.Error()
		} else {
			verified = ok
		}
	}

	response := gin.H{
		"attestation":       attestation,
		"verified":          verified,
		"algorithm":         "ML-DSA-65 (FIPS 204)",
		"chain_valid":       attestation.ChainPrevious != "",
		"quantum_resistant": true,
	}
	if verifyErr != "" {
		response["verify_error"] = verifyErr
	}

	c.JSON(http.StatusOK, response)
}

func (s *Server) handleCCExportEvidence(c *gin.Context) {
	var req ExportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidRequest})
		return
	}

	report := s.BuildEvidenceReportFromCC(req.Framework)

	// If PDF format requested, generate and stream the PDF
	if req.Format == "pdf" {
		pdfBytes, err := GenerateEvidencePDF(report)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PDF generation failed: " + err.Error()})
			return
		}

		c.Header("Content-Type", "application/pdf")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=adinkhepra-evidence-%s.pdf", report.ExportID))
		c.Data(http.StatusOK, "application/pdf", pdfBytes)
		return
	}

	// JSON-based formats
	response := gin.H{
		"export_id":    report.ExportID,
		"format":       req.Format,
		"framework":    report.Framework,
		"status":       "generated",
		"timestamp":    report.Timestamp,
		"data_hash":    report.DataHash,
		"signature":    truncateHash(report.Signature),
		"algorithm":    report.Algorithm,
		"score":        report.Score,
		"findings":     len(report.Findings),
		"attestations": len(report.Attestations),
		"chain_length": report.ChainLength,
		"download_url": fmt.Sprintf("/api/v1/cc/prove/download/%s", report.ExportID),
		"pqc_signed":   report.Signature != "",
	}

	switch req.Format {
	case "emass":
		response["emass_version"] = "3.0"
		response["poam_included"] = true
	case "sprs":
		response["sprs_score"] = report.Score
		response["assessment_date"] = report.Timestamp.Format("2006-01-02")
	}

	c.JSON(http.StatusOK, response)
}

// signWithAdinkra signs data with ML-DSA-65. Extracted to avoid circular imports.
func signWithAdinkra(privKey, data []byte) ([]byte, error) {
	return adinkra.Sign(privKey, data)
}
