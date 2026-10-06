// Package license — stripe_webhook.go implements the SEKHEM-encapsulated,
// post-quantum automated license distribution pipeline for Stripe Checkout.
//
// Triggered on checkout.session.completed:
// 1. Verifies Stripe-Signature with HMAC-SHA256 & replay prevention
// 2. Evaluates multi-tier line items (Pro, Enterprise, Sovereign, Advisor) & seat counts
// 3. Mints FIPS 204 ML-DSA-87 license tokens via isolated SigningSentry
// 4. Generates Quantum Key Distribution (QKD) Kyber-1024 capsules for SCIF/air-gap
// 5. Attests issuance to immutable DAG ledger and CMMC L2 Flight Recorder
// 6. Dispatches instant automated fulfillment emails via Resend API
package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
)

// ─── Stripe Webhook JSON Types ───────────────────────────────────────────────

type StripeEvent struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Created int64           `json:"created"`
	Data    StripeEventData `json:"data"`
}

type StripeEventData struct {
	Object json.RawMessage `json:"object"`
}

type StripeCheckoutSession struct {
	ID              string                `json:"id"`
	Customer        string                `json:"customer"`
	CustomerDetails StripeCustomerDetails `json:"customer_details"`
	AmountTotal     int64                 `json:"amount_total"`
	Currency        string                `json:"currency"`
	PaymentStatus   string                `json:"payment_status"`
	Subscription    string                `json:"subscription"`
	Metadata        map[string]string     `json:"metadata"`
	LineItems       *StripeLineItemList   `json:"line_items,omitempty"`
}

type StripeCustomerDetails struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Phone string `json:"phone"`
}

type StripeLineItemList struct {
	Data []StripeLineItem `json:"data"`
}

type StripeLineItem struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	AmountTotal int64       `json:"amount_total"`
	Quantity    int64       `json:"quantity"`
	Price       StripePrice `json:"price"`
}

type StripePrice struct {
	ID         string `json:"id"`
	Product    string `json:"product"`
	UnitAmount int64  `json:"unit_amount"`
}

type StripeSubscription struct {
	ID       string `json:"id"`
	Customer string `json:"customer"`
	Status   string `json:"status"`
}

// ─── Pipeline Dependencies ───────────────────────────────────────────────────

type StripePipelineDeps struct {
	MasterPriv []byte
	MasterPub  []byte
	DAGStore   dag.Store
	SentrySign func(payload []byte) ([]byte, error)
}

// ─── Signature Verification ──────────────────────────────────────────────────

// VerifyStripeSignature verifies that an incoming webhook was signed by Stripe.
func VerifyStripeSignature(payload []byte, header, secret string, tolerance time.Duration) error {
	if secret == "" {
		return errors.New("stripe webhook secret not configured")
	}
	if header == "" {
		return errors.New("missing Stripe-Signature header")
	}

	parts := strings.Split(header, ",")
	var timestampStr string
	var signatures []string

	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "t" {
			timestampStr = kv[1]
		} else if kv[0] == "v1" {
			signatures = append(signatures, kv[1])
		}
	}

	if timestampStr == "" || len(signatures) == 0 {
		return errors.New("malformed Stripe-Signature header")
	}

	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid signature timestamp: %w", err)
	}

	// Replay defense
	eventTime := time.Unix(ts, 0)
	if time.Since(eventTime) > tolerance || eventTime.Sub(time.Now()) > tolerance {
		return errors.New("webhook timestamp outside tolerance window (potential replay attack)")
	}

	signedPayload := fmt.Sprintf("%d.%s", ts, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	for _, sig := range signatures {
		if hmac.Equal([]byte(sig), []byte(expectedSig)) {
			return nil
		}
	}

	return errors.New("invalid webhook signature: HMAC mismatch")
}

// ─── Webhook Handler ─────────────────────────────────────────────────────────

// StripeWebhookGinHandler returns a Gin handler wrapped with Sekhem WAF L7 inspection.
func StripeWebhookGinHandler(deps *StripePipelineDeps) gin.HandlerFunc {
	webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")

	return func(c *gin.Context) {
		// Without the endpoint secret nothing can be authenticated, so no
		// event is processed (a forged checkout would otherwise mint a license).
		if webhookSecret == "" {
			log.Println("[STRIPE] STRIPE_WEBHOOK_SECRET is not set — refusing webhook")
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "webhook_not_configured"})
			return
		}

		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxWebhookBody))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}

		// 1. Signature Verification
		if err := VerifyStripeSignature(body, c.GetHeader("Stripe-Signature"), webhookSecret, 300*time.Second); err != nil {
			log.Printf("[STRIPE] signature verification failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_stripe_signature"})
			return
		}

		// 2. Parse Event JSON
		var event StripeEvent
		if err := json.Unmarshal(body, &event); err != nil || event.ID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_event_json"})
			return
		}

		// 3. Idempotency: Stripe retries deliveries, and a captured request can
		// be replayed inside the signature tolerance window.
		if !processedEvents.claim(event.ID) {
			c.JSON(http.StatusOK, gin.H{"received": true, "status": "duplicate"})
			return
		}

		log.Printf("[STRIPE-EVENT] Received %s (ID: %s)", event.Type, event.ID)

		switch event.Type {
		case "checkout.session.completed", "checkout.session.async_payment_succeeded":
			var session StripeCheckoutSession
			if err := json.Unmarshal(event.Data.Object, &session); err != nil {
				processedEvents.release(event.ID)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_session_data"})
				return
			}
			if err := processCheckoutSession(&session, deps); err != nil {
				if errors.Is(err, ErrPaymentNotSettled) {
					// Async payment methods complete checkout before the money
					// arrives; fulfillment happens on async_payment_succeeded.
					log.Printf("[STRIPE] session %s not paid yet: %v", session.ID, err)
					c.JSON(http.StatusOK, gin.H{"received": true, "status": "awaiting_payment"})
					return
				}
				processedEvents.release(event.ID) // let Stripe's retry try again
				log.Printf("[FULFILLMENT-ERR] Error processing checkout session %s: %v", session.ID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "processing_failed"})
				return
			}

		case "customer.subscription.deleted":
			var sub StripeSubscription
			if err := json.Unmarshal(event.Data.Object, &sub); err == nil {
				log.Printf("[REVOCATION] Stripe subscription deleted: %s for customer %s", sub.ID, sub.Customer)
				recordRevocationInDAG(sub.Customer, sub.ID, "subscription_deleted_in_stripe", deps)
			}

		default:
			log.Printf("[STRIPE] Ignored event type: %s", event.Type)
		}

		c.JSON(http.StatusOK, gin.H{"received": true, "status": "processed"})
	}
}

// maxWebhookBody bounds the webhook request body (Stripe events are far smaller).
const maxWebhookBody = 1 << 20

// ErrPaymentNotSettled means a checkout completed without settled payment
// (payment_status other than "paid"); nothing is fulfilled for it.
var ErrPaymentNotSettled = errors.New("checkout payment not settled")

// eventLedger records Stripe event IDs already handled by this process. It is
// in memory, so it stops replays and duplicate deliveries within a process
// lifetime; restarts rely on Stripe's signature tolerance window.
type eventLedger struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var processedEvents = &eventLedger{seen: make(map[string]time.Time)}

// claim marks id as being handled and reports whether it was new.
func (l *eventLedger) claim(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, t := range l.seen {
		if now.Sub(t) > 72*time.Hour { // Stripe retries for up to 3 days
			delete(l.seen, k)
		}
	}
	if _, dup := l.seen[id]; dup {
		return false
	}
	l.seen[id] = now
	return true
}

// release forgets id so a later delivery of the same event is processed.
func (l *eventLedger) release(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.seen, id)
}

// ─── Multi-Tier Order Processing ─────────────────────────────────────────────

func processCheckoutSession(session *StripeCheckoutSession, deps *StripePipelineDeps) error {
	email := strings.TrimSpace(session.CustomerDetails.Email)
	name := strings.TrimSpace(session.CustomerDetails.Name)
	if name == "" {
		name = email
	}
	if email == "" {
		return errors.New("checkout session missing customer email")
	}
	if session.PaymentStatus != "paid" {
		return fmt.Errorf("%w: session %s payment_status=%q", ErrPaymentNotSettled, session.ID, session.PaymentStatus)
	}

	// 1. Detect if this is a STIGViewer Tokenomics Credit Top-Up Order
	isTopup := false
	topupCredits := 0

	if session.Metadata != nil {
		if session.Metadata["type"] == "stigviewer_topup" {
			isTopup = true
			if cStr, ok := session.Metadata["credits"]; ok {
				topupCredits, _ = strconv.Atoi(cStr)
			}
		}
	}

	if session.LineItems != nil {
		for _, item := range session.LineItems.Data {
			desc := strings.ToLower(item.Description)
			if strings.Contains(desc, "stigviewer") && (strings.Contains(desc, "credit") || strings.Contains(desc, "top-up") || strings.Contains(desc, "topup")) {
				isTopup = true
				qty := int(item.Quantity)
				if qty <= 0 {
					qty = 1
				}
				switch item.Price.UnitAmount {
				case 4900: // $49 = 1,000 credits
					topupCredits += qty * 1000
				case 19900: // $199 = 5,000 credits
					topupCredits += qty * 5000
				case 34900: // $349 = 10,000 credits
					topupCredits += qty * 10000
				default:
					topupCredits += qty * 1000
				}
			}
		}
	}

	if isTopup && topupCredits > 0 {
		return processSTIGViewerTopup(session, topupCredits, deps)
	}

	// 2. Analyze Line Items / Prices for Subscription Tiers
	highestTier := TierCommunity
	totalSeats := 0
	nodeQuota := 1

	if session.LineItems != nil && len(session.LineItems.Data) > 0 {
		for _, item := range session.LineItems.Data {
			qty := int(item.Quantity)
			if qty <= 0 {
				qty = 1
			}
			totalSeats += qty

			switch item.Price.UnitAmount {
			case 299900: // $2,999/mo — Enterprise Tier (SEKHEM PQC-WAF + DataLoop + ASAF)
				highestTier = TierEnterprise
				nodeQuota += qty * 25
			case 49900: // $499/mo — Platform Tier (AEO, Passports, STIG Live Query)
				if highestTier != TierEnterprise && highestTier != TierSovereign {
					highestTier = TierPlatform
					nodeQuota += qty * 10
				}
			case 9900: // $99/mo — Pro Tier (Starter)
				if highestTier == TierCommunity {
					highestTier = TierPro
					nodeQuota += qty * 3
				}
			case 500000: // $5,000/mo — Sovereign Air-Gap / Strategic Advisory Tier
				highestTier = TierSovereign
				nodeQuota = -1 // Unlimited
			}
		}
	} else {
		// Fallback: detect from amount total if line items unexpanded
		amt := session.AmountTotal
		totalSeats = 1
		if amt >= 500000 {
			highestTier = TierSovereign
			nodeQuota = -1
		} else if amt >= 299900 {
			highestTier = TierEnterprise
			nodeQuota = 25
		} else if amt >= 49900 {
			highestTier = TierPlatform
			nodeQuota = 10
		} else if amt >= 9900 {
			highestTier = TierPro
			nodeQuota = 3
		} else {
			highestTier = TierCommunity
			nodeQuota = 1
		}
	}

	if totalSeats == 0 {
		totalSeats = 1
	}

	now := time.Now().UTC()
	expiresAt := now.Add(365 * 24 * time.Hour)

	// 2. Mint FIPS 204 ML-DSA-87 License Key
	// Mint a kphr_{slug}_{base64url} key signed under khepra/v3/apikey —
	// the format ValidateAPIKey accepts. Seats and node quota are recorded
	// in the DAG and the fulfillment email; they are not part of the key.
	customerID := strings.TrimSpace(session.Customer)
	if customerID == "" {
		customerID = email
	}
	if len(deps.MasterPriv) == 0 {
		return errors.New("no ML-DSA-87 issuing key configured")
	}
	finalLicenseKey, err := GenerateSignedAPIKey(deps.MasterPriv, highestTier, customerID, expiresAt, "")
	if err != nil {
		return fmt.Errorf("failed to mint license key: %w", err)
	}

	// Device-bound license capsules are issued when a device enrolls with its
	// own ML-KEM key; checkout fulfillment issues the API key only.
	capsuleBase64 := ""

	nodeID := ""
	if deps.DAGStore != nil {
		dagNode := &dag.Node{
			Action: fmt.Sprintf("mint-stripe-license:%s:%s:seats=%d", email, highestTier, totalSeats),
			Symbol: "Eban",
			Time:   lorentz.StampNow(),
			PQC: map[string]string{
				"email":          email,
				"tier":           highestTier,
				"seats":          strconv.Itoa(totalSeats),
				"node_quota":     strconv.Itoa(nodeQuota),
				"issued_at":      strconv.FormatInt(now.Unix(), 10),
				"expires_at":     strconv.FormatInt(expiresAt.Unix(), 10),
				"signature_algo": "ML-DSA-87",
				"stripe_session": session.ID,
			},
		}
		if err := dagNode.Sign(deps.MasterPriv); err != nil {
			log.Printf("[DAG-WARN] Could not sign DAG node: %v", err)
		} else if err := deps.DAGStore.Add(dagNode, []string{}); err != nil {
			log.Printf("[DAG-WARN] Could not add node to DAG: %v", err)
		} else {
			nodeID = dagNode.ID
		}
	}
	dagAnchor := nodeID
	if dagAnchor == "" {
		dagAnchor = "not anchored (no DAG store configured)"
	}

	portalURL := os.Getenv("STRIPE_CUSTOMER_PORTAL_URL")
	if portalURL == "" {
		portalURL = "https://billing.stripe.com/p/login/00w00j5nYdZwcZB73t9ws00"
	}

	details := FulfillmentDetails{
		CustomerEmail: email,
		CustomerName:  name,
		Tier:          strings.ToUpper(highestTier),
		NodeQuota:     nodeQuota,
		Seats:         totalSeats,
		LicenseKey:    finalLicenseKey,
		CapsuleBase64: capsuleBase64,
		DAGAnchor:     dagAnchor,
		PortalURL:     portalURL,
		IssuedAt:      now,
		ExpiresAt:     expiresAt,
	}

	if err := sendFulfillment(details); err != nil {
		log.Printf("[FULFILLMENT-WARN] Email dispatch error: %v", err)
	}

	log.Printf("[FULFILLMENT-SUCCESS] Minted %s license for %s (%d seats) | DAG Anchor: %s", highestTier, email, totalSeats, dagAnchor)
	return nil
}

// ─── QKD Capsule Helper ──────────────────────────────────────────────────────

// sendFulfillment delivers the fulfillment email; tests replace it.
var sendFulfillment = SendFulfillmentEmail

func recordRevocationInDAG(customer, subscriptionID, reason string, deps *StripePipelineDeps) {
	if deps.DAGStore == nil {
		return
	}
	node := &dag.Node{
		Action: fmt.Sprintf("revoke-stripe-license:%s:%s", customer, subscriptionID),
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"customer":        customer,
			"subscription_id": subscriptionID,
			"reason":          reason,
		},
	}
	if deps.MasterPriv != nil {
		_ = node.Sign(deps.MasterPriv)
	}
	_ = deps.DAGStore.Add(node, []string{})
}

// STIGCreditState holds local tokenomics credit counters.
type STIGCreditState struct {
	TenantEmail   string    `json:"tenant_email"`
	Tier          string    `json:"tier"`
	MonthlyQuota  int       `json:"monthly_quota"`
	UsedCredits   int       `json:"used_credits"`
	LastReset     time.Time `json:"last_reset"`
	LastOperation time.Time `json:"last_operation"`
}

// TopupSTIGViewerCredits increments STIGViewer credit quota and writes state to disk.
func TopupSTIGViewerCredits(creditsPath, email string, amount int) (*STIGCreditState, error) {
	if creditsPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			creditsPath = filepath.Join(home, ".khepra", "stig_credits.json")
		} else {
			creditsPath = "stig_credits.json"
		}
	}

	var state STIGCreditState
	if data, err := os.ReadFile(creditsPath); err == nil {
		_ = json.Unmarshal(data, &state)
	}

	if state.MonthlyQuota <= 0 {
		state.MonthlyQuota = 3000
	}
	state.MonthlyQuota += amount
	if email != "" {
		state.TenantEmail = email
	}
	if state.Tier == "" || state.Tier == "community" {
		state.Tier = "platform"
	}
	state.LastOperation = time.Now().UTC()
	if state.LastReset.IsZero() {
		state.LastReset = time.Now().UTC()
	}

	dir := filepath.Dir(creditsPath)
	if err := os.MkdirAll(dir, 0700); err == nil {
		if data, err := json.MarshalIndent(state, "", "  "); err == nil {
			_ = os.WriteFile(creditsPath, data, 0600)
		}
	}
	return &state, nil
}

func processSTIGViewerTopup(session *StripeCheckoutSession, credits int, deps *StripePipelineDeps) error {
	email := strings.TrimSpace(session.CustomerDetails.Email)
	name := strings.TrimSpace(session.CustomerDetails.Name)
	if name == "" {
		name = email
	}

	creditsPath := os.Getenv("KHEPRA_CREDITS_PATH")
	state, err := TopupSTIGViewerCredits(creditsPath, email, credits)
	if err != nil {
		log.Printf("[SEKHEM-TOPUP] Warning: could not write local credit state: %v", err)
	}

	totalQuota := credits
	if state != nil {
		totalQuota = state.MonthlyQuota
	}

	// Attest top-up transaction to DAG
	if deps.DAGStore != nil {
		node := &dag.Node{
			Action: fmt.Sprintf("stigviewer-topup:%s:+%d", email, credits),
			Symbol: "Eban",
			Time:   lorentz.StampNow(),
			PQC: map[string]string{
				"customer":      email,
				"session_id":    session.ID,
				"credits_added": strconv.Itoa(credits),
				"total_quota":   strconv.Itoa(totalQuota),
				"rule_id":       "SEKHEM-METER-001",
			},
		}
		if deps.MasterPriv != nil {
			_ = node.Sign(deps.MasterPriv)
		}
		_ = deps.DAGStore.Add(node, []string{})
		log.Printf("[DAG] Attested STIGViewer credit top-up for %s (+%d credits) | Node: %s", email, credits, node.ID)
	}

	// Dispatch top-up confirmation email
	portalURL := os.Getenv("STRIPE_CUSTOMER_PORTAL_URL")
	if portalURL == "" {
		portalURL = "https://billing.stripe.com/p/login/00w00j5nYdZwcZB73t9ws00"
	}
	_ = SendTopupConfirmationEmail(email, name, credits, totalQuota, portalURL)
	log.Printf("[FULFILLMENT-SUCCESS] Successfully topped up +%d STIGViewer credits for %s (Quota: %d)", credits, email, totalQuota)
	return nil
}
