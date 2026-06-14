//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - Stripe Subscription Handler
// =============================================================================
// Handles Stripe Checkout sessions and webhook events for the tiered pricing:
//   - Scan ($0)       → no Stripe needed
//   - Certify ($99)   → one-time payment
//   - Autopilot ($499/mo) → recurring subscription
//   - Diagnostic ($5K) → one-time payment
//   - Sprint ($15K)    → one-time payment
// =============================================================================

package apiserver

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// StripeConfig holds Stripe API configuration
type StripeConfig struct {
	SecretKey      string // sk_live_... or sk_test_...
	WebhookSecret  string // whsec_...
	PublishableKey string // pk_live_... or pk_test_...
}

// PriceMapping maps our tier names to Stripe price IDs.
// Set these via env vars or config. Empty string = not configured.
var PriceMapping = map[string]string{
	"certify":    os.Getenv("STRIPE_PRICE_CERTIFY"),    // $99 one-time
	"autopilot":  os.Getenv("STRIPE_PRICE_AUTOPILOT"),  // $499/mo recurring
	"diagnostic": os.Getenv("STRIPE_PRICE_DIAGNOSTIC"), // $5,000 one-time
	"sprint":     os.Getenv("STRIPE_PRICE_SPRINT"),     // $15,000 one-time
}

// CheckoutSession represents a pending or completed checkout
type CheckoutSession struct {
	ID               string    `json:"id"`
	Tier             string    `json:"tier"`
	Email            string    `json:"email"`
	OrganizationID   string    `json:"organization_id,omitempty"`
	StripeSessionID  string    `json:"stripe_session_id,omitempty"`
	Status           string    `json:"status"` // "pending", "completed", "cancelled", "expired"
	Amount           int       `json:"amount"` // cents
	Currency         string    `json:"currency"`
	Recurring        bool      `json:"recurring"`
	CreatedAt        time.Time `json:"created_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
}

// SubscriptionState tracks active subscriptions
type SubscriptionState struct {
	mu            sync.RWMutex
	sessions      map[string]*CheckoutSession  // sessionID → session
	subscriptions map[string]*ActiveSubscription // stripeSubID → sub
}

// ActiveSubscription tracks a live Stripe subscription
type ActiveSubscription struct {
	StripeSubID    string    `json:"stripe_sub_id"`
	OrganizationID string    `json:"organization_id"`
	Tier           string    `json:"tier"`
	Email          string    `json:"email"`
	Status         string    `json:"status"` // "active", "past_due", "cancelled"
	CurrentPeriodEnd time.Time `json:"current_period_end"`
	CreatedAt      time.Time `json:"created_at"`
}

var stripeState = &SubscriptionState{
	sessions:      make(map[string]*CheckoutSession),
	subscriptions: make(map[string]*ActiveSubscription),
}

// =============================================================================
// HTTP Handlers
// =============================================================================

// handleCreateCheckout creates a Stripe Checkout session (or simulates one)
func (s *Server) handleCreateCheckout(c *gin.Context) {
	var req struct {
		Tier           string `json:"tier" binding:"required"`
		Email          string `json:"email" binding:"required"`
		OrganizationID string `json:"organization_id"`
		SuccessURL     string `json:"success_url"`
		CancelURL      string `json:"cancel_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate tier
	priceID, ok := PriceMapping[req.Tier]
	if !ok || req.Tier == "scan" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Tier '%s' does not require payment", req.Tier)})
		return
	}

	sessionID := generateID("cs")
	now := time.Now()

	amount := map[string]int{
		"certify":    9900,    // $99.00
		"autopilot":  49900,   // $499.00
		"diagnostic": 500000,  // $5,000.00
		"sprint":     1500000, // $15,000.00
	}

	session := &CheckoutSession{
		ID:              sessionID,
		Tier:            req.Tier,
		Email:           req.Email,
		OrganizationID:  req.OrganizationID,
		Status:          "pending",
		Amount:          amount[req.Tier],
		Currency:        "usd",
		Recurring:       req.Tier == "autopilot",
		CreatedAt:       now,
	}

	stripeState.mu.Lock()
	stripeState.sessions[sessionID] = session
	stripeState.mu.Unlock()

	response := gin.H{
		"session_id": sessionID,
		"tier":       req.Tier,
		"amount":     session.Amount,
		"currency":   session.Currency,
		"recurring":  session.Recurring,
		"status":     "pending",
	}

	// If Stripe is configured, include the real checkout URL
	if priceID != "" {
		response["stripe_price_id"] = priceID
		response["message"] = "Redirect user to Stripe Checkout"
		// In production: call Stripe API to create a real session
		// stripe.CheckoutSession.Create(...)
	} else {
		response["message"] = "Stripe not configured. Use /api/v1/billing/simulate-complete to test."
		response["simulate_url"] = fmt.Sprintf("/api/v1/billing/simulate-complete?session_id=%s", sessionID)
	}

	c.JSON(http.StatusOK, response)
}

// handleSimulateComplete simulates a successful payment (for testing)
func (s *Server) handleSimulateComplete(c *gin.Context) {
	sessionID := c.Query("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id required"})
		return
	}

	stripeState.mu.Lock()
	session, exists := stripeState.sessions[sessionID]
	if !exists {
		stripeState.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	now := time.Now()
	session.Status = "completed"
	session.CompletedAt = &now

	// If this is a subscription tier, create an active subscription
	if session.Recurring {
		subID := generateID("sub")
		sub := &ActiveSubscription{
			StripeSubID:      subID,
			OrganizationID:   session.OrganizationID,
			Tier:             session.Tier,
			Email:            session.Email,
			Status:           "active",
			CurrentPeriodEnd: now.Add(30 * 24 * time.Hour),
			CreatedAt:        now,
		}
		stripeState.subscriptions[subID] = sub
	}

	// Auto-create organization + seat if org doesn't exist
	if session.OrganizationID == "" {
		org, err := seatMgr.CreateOrganization(
			fmt.Sprintf("%s's Team", session.Email),
			session.Email,
			session.Tier,
		)
		if err == nil {
			session.OrganizationID = org.ID
		}
	} else {
		// Upgrade existing org to the new tier
		_ = seatMgr.UpgradeTier(session.OrganizationID, session.Tier)
	}

	stripeState.mu.Unlock()

	// Start autopilot if tier is autopilot
	if session.Tier == "autopilot" && s.autopilot == nil {
		config := DefaultAutopilotConfig()
		s.autopilot = NewAutopilotEngine(s, config)
		_ = s.autopilot.Start()
	}

	c.JSON(http.StatusOK, gin.H{
		"status":          "completed",
		"session_id":      sessionID,
		"tier":            session.Tier,
		"organization_id": session.OrganizationID,
		"message":         fmt.Sprintf("Payment successful. %s tier activated.", session.Tier),
	})
}

// handleGetSubscriptionStatus returns the current subscription state
func (s *Server) handleGetSubscriptionStatus(c *gin.Context) {
	email := c.Query("email")
	orgID := c.Query("org_id")

	stripeState.mu.RLock()
	defer stripeState.mu.RUnlock()

	var subs []*ActiveSubscription
	for _, sub := range stripeState.subscriptions {
		if (email != "" && sub.Email == email) || (orgID != "" && sub.OrganizationID == orgID) {
			subs = append(subs, sub)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"subscriptions": subs,
		"total":         len(subs),
	})
}

