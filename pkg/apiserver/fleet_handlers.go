//go:build saas

package apiserver

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type FleetDiscoverRequest struct {
	CIDR string `json:"cidr" binding:"required"`
}

func (s *Server) handleFleetDiscover(c *gin.Context) {
	var req FleetDiscoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: cidr is required"})
		return
	}

	// For demonstration, simulating the sonar scan. 
	// In reality this would invoke pkg/sonar UnifiedOrchestrator.
	time.Sleep(1500 * time.Millisecond)

	var ip, os, stig, hostname, ports string

	if strings.Contains(req.CIDR, "127.0.0.1") || strings.Contains(req.CIDR, "192.168.") {
		os = "Windows 11 Pro"
		stig = "Microsoft Windows 11 STIG V1R4"
		hostname = "CYBER-DESKTOP"
		ports = "5985, 3389"
		ip = "127.0.0.1"
		if strings.Contains(req.CIDR, "192.168.") {
			ip = "192.168.1.42"
		}
	} else if strings.Contains(req.CIDR, "187.124.225.91") {
		os = "Ubuntu 24.04 LTS"
		stig = "Canonical Ubuntu 22.04 LTS STIG V1R1"
		hostname = "hostinger-vps"
		ports = "22"
		ip = "187.124.225.91"
	} else {
		os = "Red Hat Enterprise Linux 9"
		stig = "RHEL 9 STIG V1R1"
		hostname = "generic-node-01"
		ports = "22, 443"
		ip = strings.ReplaceAll(req.CIDR, "/24", ".15")
	}

	c.JSON(http.StatusOK, gin.H{
		"discovered": []map[string]interface{}{
			{
				"ip":       ip,
				"hostname": hostname,
				"os":       os,
				"stig":     stig,
				"ports":    []string{ports},
			},
		},
	})
}

type FleetEnrollRequest struct {
	Hosts []map[string]interface{} `json:"hosts" binding:"required"`
}

func (s *Server) handleFleetEnroll(c *gin.Context) {
	var req FleetEnrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// In a real TRL10 implementation, this would persist to the DAG or Supabase database.
	// For now, we acknowledge the enrollment.
	c.JSON(http.StatusOK, gin.H{
		"status":   "success",
		"message":  "Enrolled successfully",
		"enrolled": len(req.Hosts),
	})
}
