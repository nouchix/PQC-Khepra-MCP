//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - Autopilot HTTP Handlers
// =============================================================================
// Gin handlers for the Autopilot continuous compliance engine.
// =============================================================================

package apiserver

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (s *Server) handleAutopilotStart(c *gin.Context) {
	// Parse optional config overrides
	var req struct {
		ScanIntervalMinutes int     `json:"scan_interval_minutes"`
		DriftThreshold      float64 `json:"drift_threshold"`
		Framework           string  `json:"framework"`
		AutoReAttest        *bool   `json:"auto_re_attest"`
	}
	_ = c.ShouldBindJSON(&req)

	config := DefaultAutopilotConfig()
	if req.ScanIntervalMinutes > 0 {
		config.ScanInterval = time.Duration(req.ScanIntervalMinutes) * time.Minute
	}
	if req.DriftThreshold > 0 && req.DriftThreshold <= 1.0 {
		config.DriftThreshold = req.DriftThreshold
	}
	if req.Framework != "" {
		config.Framework = req.Framework
	}
	if req.AutoReAttest != nil {
		config.AutoReAttest = *req.AutoReAttest
	}

	// Create or restart the engine
	if s.autopilot != nil {
		s.autopilot.Stop()
	}

	s.autopilot = NewAutopilotEngine(s, config)
	if err := s.autopilot.Start(); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "started",
		"config":  config,
		"message": "Autopilot continuous compliance engine started",
	})
}

func (s *Server) handleAutopilotStop(c *gin.Context) {
	if s.autopilot == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Autopilot not running"})
		return
	}

	s.autopilot.Stop()
	c.JSON(http.StatusOK, gin.H{
		"status":  "stopped",
		"message": "Autopilot stopped",
	})
}

func (s *Server) handleAutopilotPause(c *gin.Context) {
	if s.autopilot == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Autopilot not running"})
		return
	}

	s.autopilot.Pause()
	c.JSON(http.StatusOK, gin.H{
		"status":  "paused",
		"message": "Autopilot paused — scans suspended",
	})
}

func (s *Server) handleAutopilotResume(c *gin.Context) {
	if s.autopilot == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Autopilot not running"})
		return
	}

	s.autopilot.Resume()
	c.JSON(http.StatusOK, gin.H{
		"status":  "running",
		"message": "Autopilot resumed",
	})
}

func (s *Server) handleAutopilotStatus(c *gin.Context) {
	if s.autopilot == nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  "stopped",
			"message": "Autopilot not initialized. POST /api/v1/autopilot/start to begin.",
		})
		return
	}

	state := s.autopilot.GetState()
	c.JSON(http.StatusOK, state)
}

func (s *Server) handleAutopilotEvents(c *gin.Context) {
	if s.autopilot == nil {
		c.JSON(http.StatusOK, gin.H{"events": []AutopilotEvent{}, "total": 0})
		return
	}

	events := s.autopilot.GetEvents()
	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  len(events),
	})
}
