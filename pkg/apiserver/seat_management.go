//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - Seat Management for Autopilot Tier
// =============================================================================
// Manages team seats for multi-user organizations.
// Backed by in-memory state with Supabase persistence hooks.
// =============================================================================

package apiserver

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// SeatTier defines how many seats each pricing tier allows
var SeatTier = map[string]int{
	"scan":      1,   // Free tier — single user
	"certify":   1,   // Per-attestation — single user
	"autopilot": 5,   // $499/mo — up to 5 team members
	"diagnostic": 10, // $5K advisory — up to 10 team members
	"sprint":    10,  // $15K sprint — up to 10 team members
}

// Seat represents a team member's access to the platform
type Seat struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Email          string    `json:"email"`
	Role           string    `json:"role"` // "owner", "admin", "auditor", "viewer"
	InvitedAt      time.Time `json:"invited_at"`
	AcceptedAt     *time.Time `json:"accepted_at,omitempty"`
	LastActiveAt   *time.Time `json:"last_active_at,omitempty"`
	Status         string    `json:"status"` // "active", "invited", "revoked"
}

// Organization represents a team/company
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Tier      string    `json:"tier"` // matches pricing tier
	OwnerEmail string   `json:"owner_email"`
	CreatedAt time.Time `json:"created_at"`
	MaxSeats  int       `json:"max_seats"`
	Seats     []Seat    `json:"seats"`
}

// SeatManager handles multi-tenant seat operations
type SeatManager struct {
	mu    sync.RWMutex
	orgs  map[string]*Organization // orgID → org
	seats map[string]*Seat         // seatID → seat
}

// NewSeatManager creates a new seat manager
func NewSeatManager() *SeatManager {
	return &SeatManager{
		orgs:  make(map[string]*Organization),
		seats: make(map[string]*Seat),
	}
}

// Package-level seat manager instance
var seatMgr = NewSeatManager()

// CreateOrganization creates a new org with the owner as the first seat
func (sm *SeatManager) CreateOrganization(name, ownerEmail, tier string) (*Organization, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	maxSeats, ok := SeatTier[tier]
	if !ok {
		maxSeats = 1
	}

	orgID := generateID("org")
	now := time.Now()

	org := &Organization{
		ID:         orgID,
		Name:       name,
		Tier:       tier,
		OwnerEmail: ownerEmail,
		CreatedAt:  now,
		MaxSeats:   maxSeats,
		Seats:      []Seat{},
	}

	// Create owner seat
	ownerSeat := Seat{
		ID:             generateID("seat"),
		OrganizationID: orgID,
		Email:          ownerEmail,
		Role:           "owner",
		InvitedAt:      now,
		AcceptedAt:     &now,
		LastActiveAt:   &now,
		Status:         "active",
	}

	org.Seats = append(org.Seats, ownerSeat)
	sm.orgs[orgID] = org
	sm.seats[ownerSeat.ID] = &org.Seats[0]

	return org, nil
}

// InviteSeat adds a team member to an organization
func (sm *SeatManager) InviteSeat(orgID, email, role string) (*Seat, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	org, exists := sm.orgs[orgID]
	if !exists {
		return nil, fmt.Errorf("organization not found: %s", orgID)
	}

	// Check seat limit
	activeSeats := 0
	for _, s := range org.Seats {
		if s.Status == "active" || s.Status == "invited" {
			activeSeats++
		}
	}

	if activeSeats >= org.MaxSeats {
		return nil, fmt.Errorf("seat limit reached: %d/%d (tier: %s). Upgrade to add more team members",
			activeSeats, org.MaxSeats, org.Tier)
	}

	// Check for duplicate
	for _, s := range org.Seats {
		if s.Email == email && s.Status != "revoked" {
			return nil, fmt.Errorf("email %s already has a seat in this organization", email)
		}
	}

	// Validate role
	validRoles := map[string]bool{"admin": true, "auditor": true, "viewer": true}
	if !validRoles[role] {
		role = "viewer"
	}

	seat := Seat{
		ID:             generateID("seat"),
		OrganizationID: orgID,
		Email:          email,
		Role:           role,
		InvitedAt:      time.Now(),
		Status:         "invited",
	}

	org.Seats = append(org.Seats, seat)
	sm.seats[seat.ID] = &org.Seats[len(org.Seats)-1]

	return &seat, nil
}

// RevokeSeat removes a team member's access
func (sm *SeatManager) RevokeSeat(orgID, seatID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	org, exists := sm.orgs[orgID]
	if !exists {
		return fmt.Errorf("organization not found: %s", orgID)
	}

	for i := range org.Seats {
		if org.Seats[i].ID == seatID {
			if org.Seats[i].Role == "owner" {
				return fmt.Errorf("cannot revoke the owner seat")
			}
			org.Seats[i].Status = "revoked"
			return nil
		}
	}

	return fmt.Errorf("seat not found: %s", seatID)
}

// GetOrganization returns an org by ID
func (sm *SeatManager) GetOrganization(orgID string) (*Organization, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	org, exists := sm.orgs[orgID]
	if !exists {
		return nil, fmt.Errorf("organization not found: %s", orgID)
	}
	return org, nil
}

// GetSeatsByEmail finds all seats for a given email across all orgs
func (sm *SeatManager) GetSeatsByEmail(email string) []Seat {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []Seat
	for _, org := range sm.orgs {
		for _, s := range org.Seats {
			if s.Email == email && s.Status != "revoked" {
				result = append(result, s)
			}
		}
	}
	return result
}

// UpgradeTier changes the org's tier and updates seat limits
func (sm *SeatManager) UpgradeTier(orgID, newTier string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	org, exists := sm.orgs[orgID]
	if !exists {
		return fmt.Errorf("organization not found: %s", orgID)
	}

	maxSeats, ok := SeatTier[newTier]
	if !ok {
		return fmt.Errorf("invalid tier: %s", newTier)
	}

	org.Tier = newTier
	org.MaxSeats = maxSeats
	return nil
}

// =============================================================================
// HTTP Handlers
// =============================================================================

func (s *Server) handleCreateOrganization(c *gin.Context) {
	var req struct {
		Name       string `json:"name" binding:"required"`
		OwnerEmail string `json:"owner_email" binding:"required"`
		Tier       string `json:"tier"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Tier == "" {
		req.Tier = "autopilot"
	}

	org, err := seatMgr.CreateOrganization(req.Name, req.OwnerEmail, req.Tier)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, org)
}

func (s *Server) handleInviteSeat(c *gin.Context) {
	orgID := c.Param("org_id")

	var req struct {
		Email string `json:"email" binding:"required"`
		Role  string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	seat, err := seatMgr.InviteSeat(orgID, req.Email, req.Role)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, seat)
}

func (s *Server) handleRevokeSeat(c *gin.Context) {
	orgID := c.Param("org_id")
	seatID := c.Param("seat_id")

	if err := seatMgr.RevokeSeat(orgID, seatID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

func (s *Server) handleGetOrganization(c *gin.Context) {
	orgID := c.Param("org_id")

	org, err := seatMgr.GetOrganization(orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, org)
}

func (s *Server) handleListSeats(c *gin.Context) {
	orgID := c.Param("org_id")

	org, err := seatMgr.GetOrganization(orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	activeSeats := 0
	for _, s := range org.Seats {
		if s.Status == "active" || s.Status == "invited" {
			activeSeats++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"organization_id": orgID,
		"tier":            org.Tier,
		"max_seats":       org.MaxSeats,
		"active_seats":    activeSeats,
		"seats":           org.Seats,
	})
}

func (s *Server) handleUpgradeTier(c *gin.Context) {
	orgID := c.Param("org_id")

	var req struct {
		Tier string `json:"tier" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := seatMgr.UpgradeTier(orgID, req.Tier); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, _ := seatMgr.GetOrganization(orgID)
	c.JSON(http.StatusOK, gin.H{
		"status":    "upgraded",
		"tier":      org.Tier,
		"max_seats": org.MaxSeats,
	})
}
