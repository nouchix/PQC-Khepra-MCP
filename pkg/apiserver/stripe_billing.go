
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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// StripeConfig holds Stripe API configuration
type StripeConfig struct {
	SecretKey      string // stripe live or test secret key
	WebhookSecret  string // whsec_...
	PublishableKey string // pk_live_... or pk_test_...
}

// PriceMapping maps tier/SKU names to Stripe price IDs.
// Last updated: 2026-07-09 — deconflicted SouHimBou AI vs PQC-Khepra-MCP products.
//
// Product ownership:
//
//	prod_UhvNflskmq9PoV  → SouHimBou.AI Flight Recorder  (STRIPE_PRODUCT_SOC)
//	prod_UqvQtvapGfRbcP  → PQC-Khepra-MCP Server          (STRIPE_PRODUCT_MCP)
var PriceMapping = map[string]string{
	// SouHimBou AI hosted tiers (souhimbou.ai)
	"certify":      os.Getenv("STRIPE_PRICE_CERTIFY"),        // $99      one-time
	"starter":      os.Getenv("STRIPE_PRICE_STARTER"),        // $299/mo  recurring → TierPilot
	"enterprise":   os.Getenv("STRIPE_PRICE_ENTERPRISE_SOC"), // $499/mo  recurring → TierEnterprise
	"professional": os.Getenv("STRIPE_PRICE_PROFESSIONAL"),   // $999/mo  recurring → TierEnterprise
	// PQC-Khepra-MCP Server standalone (air-gapped self-hosted)
	"sovereign": os.Getenv("STRIPE_PRICE_MCP_SOVEREIGN"), // $2,999/mo recurring → TierMaster
	// Professional Services (consulting, one-time)
	"diagnostic": os.Getenv("STRIPE_PRICE_DIAGNOSTIC"), // $1,500   one-time
	"advisory":   os.Getenv("STRIPE_PRICE_ADVISORY"),   // $5,000   one-time
	"sprint":     os.Getenv("STRIPE_PRICE_SPRINT"),     // $15,000  one-time
}

// recurringTiers lists which PriceMapping keys are monthly subscriptions vs.
// one-time charges. Kept in sync with PriceMapping above.
var recurringTiers = map[string]bool{
	"starter":      true,
	"enterprise":   true,
	"professional": true,
	"sovereign":    true,
}

// tierAmountCents mirrors PriceMapping's dollar amounts, in cents, for local
// display/tracking only — the actual charge is always driven by the Stripe
// price ID in the real Checkout Session, never by this map.
var tierAmountCents = map[string]int{
	"certify":      9900,
	"starter":      29900,
	"enterprise":   49900,
	"professional": 99900,
	"sovereign":    299900,
	"diagnostic":   150000,
	"advisory":     500000,
	"sprint":       1500000,
}

// CheckoutSession represents a pending or completed checkout
type CheckoutSession struct {
	ID              string     `json:"id"`
	Tier            string     `json:"tier"`
	Email           string     `json:"email"`
	OrganizationID  string     `json:"organization_id,omitempty"`
	StripeSessionID string     `json:"stripe_session_id,omitempty"`
	Status          string     `json:"status"` // "pending", "completed", "cancelled", "expired"
	Amount          int        `json:"amount"` // cents
	Currency        string     `json:"currency"`
	Recurring       bool       `json:"recurring"`
	CreatedAt       time.Time  `json:"created_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

// SubscriptionState tracks active subscriptions
type SubscriptionState struct {
	mu            sync.RWMutex
	sessions      map[string]*CheckoutSession    // sessionID → session
	subscriptions map[string]*ActiveSubscription // stripeSubID → sub
}

// ActiveSubscription tracks a live Stripe subscription
type ActiveSubscription struct {
	StripeSubID      string    `json:"stripe_sub_id"`
	OrganizationID   string    `json:"organization_id"`
	Tier             string    `json:"tier"`
	Email            string    `json:"email"`
	Status           string    `json:"status"` // "active", "past_due", "cancelled"
	CurrentPeriodEnd time.Time `json:"current_period_end"`
	CreatedAt        time.Time `json:"created_at"`
}

var stripeState = &SubscriptionState{
	sessions:      make(map[string]*CheckoutSession),
	subscriptions: make(map[string]*ActiveSubscription),
}

// =============================================================================
// HTTP Handlers
// =============================================================================

// handleCreateCheckout creates a real Stripe Checkout session. If Stripe is not
// configured (no STRIPE_SECRET_KEY), it returns 503 rather than silently
// fabricating a fake session — there is no code path that lets a client mark
// itself paid without Stripe actually confirming the charge.
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
	if priceID == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "tier_not_configured",
			"message": fmt.Sprintf("Tier '%s' has no Stripe price ID configured (missing STRIPE_PRICE_* env var).", req.Tier),
		})
		return
	}

	secretKey := os.Getenv("STRIPE_SECRET_KEY")
	if secretKey == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "stripe_not_configured",
			"message": "STRIPE_SECRET_KEY is not set on the server. Cannot create a real checkout session.",
		})
		return
	}

	sessionID := generateID("cs")
	recurring := recurringTiers[req.Tier]

	session := &CheckoutSession{
		ID:             sessionID,
		Tier:           req.Tier,
		Email:          req.Email,
		OrganizationID: req.OrganizationID,
		Status:         "pending",
		Amount:         tierAmountCents[req.Tier],
		Currency:       "usd",
		Recurring:      recurring,
		CreatedAt:      time.Now(),
	}

	checkoutURL, stripeSessionID, err := createStripeCheckoutSession(secretKey, priceID, sessionID, req.SuccessURL, req.CancelURL, recurring)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error":   "stripe_session_create_failed",
			"message": err.Error(),
		})
		return
	}
	session.StripeSessionID = stripeSessionID

	stripeState.mu.Lock()
	stripeState.sessions[sessionID] = session
	stripeState.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"session_id":        sessionID,
		"tier":              req.Tier,
		"amount":            session.Amount,
		"currency":          session.Currency,
		"recurring":         session.Recurring,
		"status":            "pending",
		"stripe_session_id": stripeSessionID,
		"checkout_url":      checkoutURL,
		"message":           "Redirect the user to checkout_url to complete payment via Stripe. Completion is confirmed only via the verified /api/v1/stripe/webhook — there is no client-side completion path.",
	})
}

// createStripeCheckoutSession calls the real Stripe REST API to create a
// Checkout Session. No SDK dependency required — this is a plain
// application/x-www-form-urlencoded POST per Stripe's documented API.
func createStripeCheckoutSession(secretKey, priceID, internalSessionID, successURL, cancelURL string, recurring bool) (checkoutURL, stripeSessionID string, err error) {
	if successURL == "" {
		successURL = "https://mcp.souhimbou.ai/billing/success?session_id={CHECKOUT_SESSION_ID}"
	}
	if cancelURL == "" {
		cancelURL = "https://mcp.souhimbou.ai/billing/cancelled"
	}

	mode := "payment"
	if recurring {
		mode = "subscription"
	}

	form := url.Values{}
	form.Set("mode", mode)
	form.Set("line_items[0][price]", priceID)
	form.Set("line_items[0][quantity]", "1")
	form.Set("client_reference_id", internalSessionID)
	form.Set("metadata[internal_session_id]", internalSessionID)
	form.Set("success_url", successURL)
	form.Set("cancel_url", cancelURL)

	httpReq, err := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("failed to build Stripe request: %w", err)
	}
	httpReq.SetBasicAuth(secretKey, "")
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", "", fmt.Errorf("Stripe API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return "", "", fmt.Errorf("failed to read Stripe response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("Stripe API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("failed to parse Stripe response: %w", err)
	}
	if result.URL == "" || result.ID == "" {
		return "", "", fmt.Errorf("Stripe response missing session id/url: %s", string(body))
	}
	return result.URL, result.ID, nil
}

// completeCheckoutSession marks a org/seat CheckoutSession completed and
// activates the corresponding organization/tier/autopilot state. This is the
// ONLY place that transitions a session to "completed", and it must only ever
// be called after Stripe's webhook signature has been verified (see
// handleStripeWebhook / handleCheckoutCompleted in licensing_handlers.go), or
// from handleSimulateComplete which is itself gated to KHEPRA_DEV_MODE only.
func (s *Server) completeCheckoutSession(sessionID string) (*CheckoutSession, error) {
	stripeState.mu.Lock()
	session, exists := stripeState.sessions[sessionID]
	if !exists {
		stripeState.mu.Unlock()
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	now := time.Now()
	session.Status = "completed"
	session.CompletedAt = &now

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
		_ = seatMgr.UpgradeTier(session.OrganizationID, session.Tier)
	}
	stripeState.mu.Unlock()

	if session.Tier == "autopilot" && s.autopilot == nil {
		config := DefaultAutopilotConfig()
		s.autopilot = NewAutopilotEngine(s, config)
		_ = s.autopilot.Start()
	}

	return session, nil
}

// handleSimulateComplete fakes a completed payment. SECURITY (TRL10): this
// endpoint does not verify any payment and must never be reachable in
// production — it is gated behind KHEPRA_DEV_MODE=true, mirroring the pattern
// already established for the dev-only auth bypass in pkg/apiserver/integration.go.
// Every use is logged at CRITICAL level. Real completion happens only via the
// signature-verified Stripe webhook (see completeCheckoutSession).
func (s *Server) handleSimulateComplete(c *gin.Context) {
	sessionID := c.Query("session_id")
	if os.Getenv("KHEPRA_DEV_MODE") != "true" {
		fmt.Printf("[CRITICAL] Blocked attempt to use /api/v1/billing/simulate-complete outside KHEPRA_DEV_MODE (session_id=%q)\n", sessionID)
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "disabled_in_production",
			"message": "simulate-complete is disabled. Set KHEPRA_DEV_MODE=true for local testing only. Production completion happens exclusively via the verified Stripe webhook.",
		})
		return
	}
	fmt.Printf("[CRITICAL] /api/v1/billing/simulate-complete invoked in KHEPRA_DEV_MODE (session_id=%q) — this must never happen in production\n", sessionID)

	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id required"})
		return
	}

	session, err := s.completeCheckoutSession(sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":          "completed",
		"session_id":      sessionID,
		"tier":            session.Tier,
		"organization_id": session.OrganizationID,
		"message":         fmt.Sprintf("[DEV MODE ONLY] Payment simulated. %s tier activated.", session.Tier),
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
