// cmd/webhook/main.go — ASAF Stripe Webhook Receiver
//
// Receives Stripe Payment Link webhooks, verifies signatures,
// and triggers signed PDF certificate delivery via email.
//
// Env (loaded from /opt/asaf/secrets/webhook.env):
//   STRIPE_WEBHOOK_SECRET  — whsec_... from Stripe Dashboard
//   STRIPE_SECRET_KEY      — sk_live_... for Stripe API calls
//   ASAF_NOTIFY_EMAIL      — email to CC on all certs (operator)
//   ASAF_API_URL           — local API server (default: http://localhost:45444)
//   ADDR                   — listen address (default: :4242)
//   SMTP_HOST              — SMTP server (default: smtp.gmail.com)
//   SMTP_PORT              — SMTP port (default: 587)
//   SMTP_USER              — SMTP username
//   SMTP_PASS              — SMTP password / app password

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// ── Stripe event types we care about ─────────────────────────────────────────

const contentTypeJSON = "application/json"
const logInfoFmt = "[webhook] [info] %s id=%s"

type StripeEvent struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Created int64           `json:"created"`
	Data    StripeEventData `json:"data"`
}

type StripeEventData struct {
	Object json.RawMessage `json:"object"`
}

type StripeSession struct {
	ID                string            `json:"id"`
	CustomerEmail     string            `json:"customer_email"`
	CustomerDetails   *CustomerDetails  `json:"customer_details"`
	AmountTotal       int64             `json:"amount_total"`
	Currency          string            `json:"currency"`
	PaymentStatus     string            `json:"payment_status"`
	Metadata          map[string]string `json:"metadata"`
	SubscriptionID    string            `json:"subscription"`
	ClientReferenceID string            `json:"client_reference_id"` // CLI token
}

type CustomerDetails struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	WebhookSecrets []string // all configured whsec_* values, tried in order
	StripeKey      string
	NotifyEmail    string
	APIURL         string
	Addr           string
	SMTPHost       string
	SMTPPort       string
	SMTPUser       string
	SMTPPass       string
}

// loadWebhookSecrets collects every non-empty webhook secret env var.
func loadWebhookSecrets() []string {
	keys := []string{
		"STRIPE_WEBHOOK_SECRET",
		"STRIPE_WEBHOOK_SECRET_LITE",
		"ASAF_STRIPE_WEBHOOK_SECRET",
		"ASAF_STRIPE_WEBHOOK_SECRET_LITE",
	}
	var secrets []string
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			secrets = append(secrets, v)
		}
	}
	return secrets
}

func loadConfig() Config {
	secrets := loadWebhookSecrets()
	if len(secrets) == 0 {
		log.Fatal("[webhook] no STRIPE_WEBHOOK_SECRET* env vars set")
	}
	log.Printf("[webhook] loaded %d webhook secret(s)", len(secrets))
	return Config{
		WebhookSecrets: secrets,
		StripeKey:      mustEnv("STRIPE_SECRET_KEY"),
		NotifyEmail:    getEnv("ASAF_NOTIFY_EMAIL", "support@nouchix.com"),
		APIURL:         getEnv("ASAF_API_URL", "http://localhost:45444"),
		Addr:           getEnv("ADDR", ":4242"),
		SMTPHost:       getEnv("SMTP_HOST", "smtp.hostinger.com"),
		SMTPPort:       getEnv("SMTP_PORT", "465"),
		SMTPUser:       getEnv("SMTP_USER", ""),
		SMTPPass:       getEnv("SMTP_PASS", ""),
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("[webhook] required env var %s is not set", key)
	}
	return v
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var cfg Config

func main() {
	cfg = loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("POST /stripe/webhook", handleStripeWebhook)

	log.Printf("[webhook] ASAF Stripe webhook receiver listening on %s", cfg.Addr)
	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[webhook] server error: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "asaf-webhook"})
}

// ── Stripe webhook handler ────────────────────────────────────────────────────

func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	const maxBody = 65536
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	// Verify Stripe signature — try all configured secrets in order.
	sigHeader := r.Header.Get("Stripe-Signature")
	var sigErr error
	for _, secret := range cfg.WebhookSecrets {
		if sigErr = verifyStripeSignature(body, sigHeader, secret); sigErr == nil {
			break
		}
	}
	if sigErr != nil {
		log.Printf("[webhook] signature verification failed (tried %d secrets): %v",
			len(cfg.WebhookSecrets), sigErr)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var event StripeEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}

	log.Printf("[webhook] received event: %s id=%s", event.Type, event.ID)

	// Idempotency: respond 200 immediately, process async
	w.WriteHeader(http.StatusOK)

	go func() {
		if err := processEvent(event); err != nil {
			log.Printf("[webhook] event processing error (id=%s): %v", event.ID, err)
		}
	}()
}

// verifyStripeSignature implements Stripe webhook signature verification.
// https://stripe.com/docs/webhooks/signatures
func verifyStripeSignature(body []byte, sigHeader, secret string) error {
	if sigHeader == "" {
		return fmt.Errorf("missing Stripe-Signature header")
	}

	parts := strings.Split(sigHeader, ",")
	var timestamp string
	var signatures []string
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			signatures = append(signatures, kv[1])
		}
	}

	if timestamp == "" {
		return fmt.Errorf("missing timestamp in signature")
	}
	if len(signatures) == 0 {
		return fmt.Errorf("no v1 signatures found")
	}

	// Validate timestamp tolerance (5 minutes)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %v", err)
	}
	if time.Now().Unix()-ts > 300 {
		return fmt.Errorf("timestamp too old: replay attack protection")
	}

	// Compute expected signature
	payload := timestamp + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	for _, sig := range signatures {
		if hmac.Equal([]byte(sig), []byte(expected)) {
			return nil
		}
	}
	return fmt.Errorf("signature mismatch")
}

// ── Event processing ──────────────────────────────────────────────────────────

func processEvent(event StripeEvent) error {
	switch event.Type {

	// ── Revenue ───────────────────────────────────────────────────────────────
	case "checkout.session.completed":
		return handleCheckoutComplete(event)
	case "customer.subscription.deleted":
		return handleSubscriptionCanceled(event)

	// ── Subscription lifecycle ────────────────────────────────────────────────
	case "customer.subscription.created":
		log.Printf("[webhook] [info] subscription.created id=%s (cert delivered via checkout.session.completed)", event.ID)
		return nil
	case "customer.subscription.paused":
		return handleSubscriptionPaused(event)
	case "customer.subscription.resumed":
		return handleSubscriptionResumed(event)
	case "customer.subscription.trial_will_end":
		return handleTrialWillEnd(event)
	case "customer.subscription.updated":
		log.Printf("[webhook] [info] subscription.updated id=%s", event.ID)
		return nil
	case "customer.subscription.pending_update_applied",
		"customer.subscription.pending_update_expired":
		log.Printf(logInfoFmt, event.Type, event.ID)
		return nil

	// ── Checkout abandonment ──────────────────────────────────────────────────
	case "checkout.session.expired":
		log.Printf("[webhook] [analytics] checkout.session.expired id=%s — abandoned payment", event.ID)
		return nil
	case "checkout.session.async_payment_failed":
		log.Printf("[webhook] [warn] async_payment_failed id=%s", event.ID)
		return nil
	case "checkout.session.async_payment_succeeded":
		return handleCheckoutComplete(event) // same flow as completed

	// ── Fraud / disputes ──────────────────────────────────────────────────────
	case "charge.dispute.created":
		return handleDisputeCreated(event)

	// ── Customer ──────────────────────────────────────────────────────────────
	case "customer.created":
		log.Printf("[webhook] [info] customer.created id=%s", event.ID)
		return nil
	case "customer.deleted":
		log.Printf("[webhook] [warn] customer.deleted id=%s — possible churn", event.ID)
		return nil
	case "customer.updated",
		"customer.discount.created", "customer.discount.deleted", "customer.discount.updated",
		"customer.source.created", "customer.source.deleted", "customer.source.updated", "customer.source.expiring",
		"customer.tax_id.created", "customer.tax_id.deleted", "customer.tax_id.updated",
		"customer_cash_balance_transaction.created":
		log.Printf(logInfoFmt, event.Type, event.ID)
		return nil

	// ── Payment methods ───────────────────────────────────────────────────────
	case "payment_method.attached", "payment_method.detached":
		log.Printf(logInfoFmt, event.Type, event.ID)
		return nil
	case "payment_intent.partially_funded":
		log.Printf("[webhook] [info] payment_intent partially funded id=%s", event.ID)
		return nil

	// ── Invoices ──────────────────────────────────────────────────────────────
	case "invoice.created", "invoice.deleted", "invoice.finalization_failed", "invoice.upcoming":
		log.Printf("[webhook] [billing] %s id=%s", event.Type, event.ID)
		return nil

	// ── Subscription schedules ────────────────────────────────────────────────
	case "subscription_schedule.aborted", "subscription_schedule.canceled",
		"subscription_schedule.completed", "subscription_schedule.created",
		"subscription_schedule.expiring", "subscription_schedule.released",
		"subscription_schedule.updated":
		log.Printf("[webhook] [schedule] %s id=%s", event.Type, event.ID)
		return nil

	// ── Entitlements ──────────────────────────────────────────────────────────
	case "entitlements.active_entitlement_summary.updated":
		log.Printf("[webhook] [entitlement] updated id=%s", event.ID)
		return nil

	// ── v2 account events (thin payload — no action needed) ───────────────────
	case "v2.core.account[configuration.customer].capability_status_updated",
		"v2.core.account[configuration.customer].updated":
		log.Printf("[webhook] [v2-account] %s id=%s (thin event, no action)", event.Type, event.ID)
		return nil

	default:
		log.Printf("[webhook] [unhandled] %s id=%s", event.Type, event.ID)
		return nil
	}
}

// handleDisputeCreated sends an URGENT operator alert on chargeback.
func handleDisputeCreated(event StripeEvent) error {
	var dispute struct {
		ID     string `json:"id"`
		Amount int64  `json:"amount"`
		Reason string `json:"reason"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(event.Data.Object, &dispute)
	log.Printf("[webhook] [URGENT] charge.dispute.created id=%s amount=%d reason=%s status=%s",
		dispute.ID, dispute.Amount, dispute.Reason, dispute.Status)

	subject := fmt.Sprintf("⚠️ URGENT: Stripe Dispute Filed — $%.2f (%s)",
		float64(dispute.Amount)/100, dispute.Reason)
	body := fmt.Sprintf(`From: ASAF Alerts <alerts@nouchix.com>
To: %s
Subject: %s

A chargeback/dispute has been filed:

  Dispute ID : %s
  Amount     : $%.2f
  Reason     : %s
  Status     : %s
  Event ID   : %s

Action required: Log into Stripe Dashboard and respond within 7 days.
https://dashboard.stripe.com/disputes/%s

— ASAF Webhook (automated)
`,
		cfg.NotifyEmail, subject,
		dispute.ID, float64(dispute.Amount)/100, dispute.Reason, dispute.Status, event.ID,
		dispute.ID)
	return sendMail([]string{cfg.NotifyEmail}, subject, body)
}

// handleSubscriptionPaused notifies operator and flags the license on the API.
func handleSubscriptionPaused(event StripeEvent) error {
	log.Printf("[webhook] subscription paused event=%s — pausing license access", event.ID)
	return callASAFAPI("POST", "/api/v1/license/revoke", map[string]interface{}{
		"stripe_event_id": event.ID,
		"reason":          "subscription_paused",
	})
}

// handleSubscriptionResumed re-activates a paused license (logged; re-activation
// is handled automatically on next API call once Stripe confirms active status).
func handleSubscriptionResumed(event StripeEvent) error {
	log.Printf("[webhook] subscription resumed event=%s — license re-activation pending next auth check", event.ID)
	// Notify operator
	subject := "ASAF: Subscription Resumed"
	body := fmt.Sprintf(`From: ASAF Webhook <webhook@nouchix.com>
To: %s
Subject: %s

A subscription has been resumed.
Event ID: %s

The license will be re-activated on the customer's next certification request.

— ASAF Webhook
`, cfg.NotifyEmail, subject, event.ID)
	sendMail([]string{cfg.NotifyEmail}, subject, body) //nolint:errcheck
	return nil
}

// handleTrialWillEnd sends a renewal reminder to the customer 3 days before trial ends.
func handleTrialWillEnd(event StripeEvent) error {
	var sub struct {
		ID             string `json:"id"`
		TrialEnd       int64  `json:"trial_end"`
		CustomerEmail  string `json:"customer_email"`
	}
	_ = json.Unmarshal(event.Data.Object, &sub)
	log.Printf("[webhook] trial_will_end sub=%s trial_end=%d customer=%s", sub.ID, sub.TrialEnd, sub.CustomerEmail)

	if sub.CustomerEmail == "" {
		return nil // can't email without address
	}
	subject := "Your ASAF trial ends in 3 days — keep your certification active"
	body := fmt.Sprintf(`From: ASAF <support@nouchix.com>
To: %s
Subject: %s

Your ADINKHEPRA trial subscription ends in 3 days.

To keep your post-quantum compliance certification active and continue
accessing the ASAF scan engine, no action is needed — your subscription
will automatically convert to a paid plan.

If you have any questions: security@nouchix.com

— NouchiX / Sacred Knowledge Inc
`, sub.CustomerEmail, subject)
	return sendMail([]string{sub.CustomerEmail, cfg.NotifyEmail}, subject, body)
}

func handleCheckoutComplete(event StripeEvent) error {
	var session StripeSession
	if err := json.Unmarshal(event.Data.Object, &session); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	if session.PaymentStatus != "paid" {
		log.Printf("[webhook] session %s payment_status=%s — skipping", session.ID, session.PaymentStatus)
		return nil
	}

	email := session.CustomerEmail
	if email == "" && session.CustomerDetails != nil {
		email = session.CustomerDetails.Email
	}
	if email == "" {
		return fmt.Errorf("no customer email in session %s", session.ID)
	}

	name := ""
	if session.CustomerDetails != nil {
		name = session.CustomerDetails.Name
	}

	// CLI token from client_reference_id (set by `asaf certify` command)
	cliToken := session.ClientReferenceID

	log.Printf("[webhook] payment confirmed: email=%s token=%s session=%s", email, cliToken, session.ID)

	// 1. Request certificate from ASAF API
	cert, err := requestCertificate(session, email)
	if err != nil {
		log.Printf("[webhook] cert request failed: %v — sending manual follow-up email", err)
		return sendManualFollowUp(email, name, session.ID)
	}

	// 2. Send certificate via email
	if err := sendCertificateEmail(email, name, cliToken, cert); err != nil {
		return fmt.Errorf("send email to %s: %w", email, err)
	}

	// 3. Notify operator
	sendOperatorNotification(email, session.ID, session.AmountTotal)
	return nil
}

func handleSubscriptionCanceled(event StripeEvent) error {
	log.Printf("[webhook] subscription canceled — license revocation: implement via /api/v1/license/revoke")
	// POST to ASAF API to mark license as revoked (DAG-recorded)
	return callASAFAPI("POST", "/api/v1/license/revoke", map[string]interface{}{
		"stripe_event_id": event.ID,
		"reason":          "subscription_canceled",
	})
}

// ── ASAF API integration ──────────────────────────────────────────────────────

type CertificateResponse struct {
	CertificateID string `json:"certificate_id"`
	OrgID         string `json:"org_id"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	Framework     string `json:"framework"`
	Score         int    `json:"score"`
	PDFBase64     string `json:"pdf_base64"`
	DilithiumSig  string `json:"dilithium_signature"`
	DAGNode       string `json:"dag_node"`
}

func requestCertificate(session StripeSession, email string) (*CertificateResponse, error) {
	payload := map[string]interface{}{
		"org_email":    email,
		"session_id":   session.ID,
		"subscription": session.SubscriptionID,
		"framework":    getOrDefault(session.Metadata, "framework", "CMMC_L2"),
		"tier":         getOrDefault(session.Metadata, "tier", "certify"),
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(
		cfg.APIURL+"/api/v1/attestation/issue",
		contentTypeJSON,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("api call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("api returned %d: %s", resp.StatusCode, string(b))
	}

	var cert CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
		return nil, fmt.Errorf("decode cert: %w", err)
	}
	return &cert, nil
}

func callASAFAPI(method, path string, payload map[string]interface{}) error {
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(method, cfg.APIURL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentTypeJSON)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ── Email delivery ────────────────────────────────────────────────────────────

func sendCertificateEmail(to, name, cliToken string, cert *CertificateResponse) error {
	subject := "Your ADINKHEPRA Certificate — NouchiX / ASAF"
	greeting := name
	if greeting == "" {
		greeting = "Security Professional"
	}

	body := fmt.Sprintf(`From: ASAF Certificates <certs@nouchix.com>
To: %s
Subject: %s
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

%s,

Your ADINKHEPRA certificate has been issued and is attached to this email.

Certificate Details:
  ID:         %s
  Framework:  %s
  Issued:     %s
  Expires:    %s
  Score:      %d/100
  DAG Anchor: %s

This certificate is:
  • Cryptographically signed with ML-DSA-65 (NIST FIPS 204 / Dilithium-3)
  • Timestamped and immutable in the ADINKHEPRA DAG chain
  • Verifiable by any assessor using: asaf verify --cert <cert-id>
  • Suitable for C3PAO intake, cyber insurance, and RFP submissions

To verify on the command line:
  asaf verify --cert %s

To renew or upgrade:
  https://app.nouchix.com

Questions? security@nouchix.com

— NouchiX / Sacred Knowledge Inc
  Patent Pending · Post-Quantum Certified

`, to, subject, greeting,
		cert.CertificateID, cert.Framework,
		cert.IssuedAt, cert.ExpiresAt, cert.Score,
		cert.DAGNode, cert.CertificateID)

	// If CLI token present, add unlock note
	if cliToken != "" {
		body += fmt.Sprintf("\nYour CLI session token %s has been activated.\n"+
			"Your certificate is ready — re-run your asaf certify command to download.\n", cliToken)
	}

	return sendMail([]string{to}, subject, body)
}

func sendManualFollowUp(email, name, sessionID string) error {
	subject := "ASAF Certificate — Manual Delivery Required"
	body := fmt.Sprintf(`From: ASAF Support <support@nouchix.com>
To: %s
Subject: %s

%s,

Your payment was received (session: %s).

We encountered a delay generating your certificate automatically.
Our team will deliver it within 24 hours at this email address.

We apologize for the inconvenience.

— NouchiX / Sacred Knowledge Inc
`, email, subject, name, sessionID)
	return sendMail([]string{email, cfg.NotifyEmail}, subject, body)
}

func sendOperatorNotification(customerEmail, sessionID string, amountCents int64) {
	subject := fmt.Sprintf("ASAF: New customer — %s ($%.2f)", customerEmail, float64(amountCents)/100)
	body := fmt.Sprintf(`From: ASAF Webhook <webhook@nouchix.com>
To: %s
Subject: %s

New paying customer:
  Email:   %s
  Session: %s
  Amount:  $%.2f

Certificate issued and emailed automatically.
`, cfg.NotifyEmail, subject, customerEmail, sessionID, float64(amountCents)/100)
	sendMail([]string{cfg.NotifyEmail}, subject, body) //nolint:errcheck
}

// sendMail supports both implicit SSL (port 465, Hostinger) and STARTTLS (port 587, Gmail).
func sendMail(to []string, subject, body string) error {
	if cfg.SMTPUser == "" || cfg.SMTPPass == "" {
		log.Printf("[webhook] SMTP not configured — skipping email to %v", to)
		return nil
	}
	addr := cfg.SMTPHost + ":" + cfg.SMTPPort
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	if cfg.SMTPPort == "465" {
		return sendMailImplicitSSL(addr, auth, to, body)
	}

	// STARTTLS (port 587 — Gmail etc.)
	_ = net.Dial // ensure net is used
	return smtp.SendMail(addr, auth, cfg.SMTPUser, to, []byte(body))
}

// sendMailImplicitSSL sends mail over an implicit TLS connection (port 465).
// Required by Hostinger and other hosts that do not support STARTTLS.
func sendMailImplicitSSL(addr string, auth smtp.Auth, to []string, body string) error {
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := client.Mail(cfg.SMTPUser); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, r := range to {
		if err := client.Rcpt(r); err != nil {
			log.Printf("[webhook] smtp rcpt %s: %v", r, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	_, err = fmt.Fprint(w, body)
	w.Close()
	return err
}

func getOrDefault(m map[string]string, key, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}
