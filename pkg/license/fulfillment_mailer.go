// Package license — fulfillment_mailer.go dispatches automated post-quantum
// license credentials, quickstart configurations, and Customer Portal deep-links
// to customers immediately upon Stripe checkout completion.
package license

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// FulfillmentDetails contains all parameters necessary to deliver an order.
type FulfillmentDetails struct {
	CustomerEmail string
	CustomerName  string
	Tier          string
	NodeQuota     int
	Seats         int
	LicenseKey    string
	CapsuleBase64 string
	DAGAnchor     string
	PortalURL     string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// ResendEmailPayload represents the JSON request sent to the Resend API.
type ResendEmailPayload struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

// SendFulfillmentEmail dispatches the license credentials via Resend.
func SendFulfillmentEmail(details FulfillmentDetails) error {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		log.Printf("[FULFILLMENT] Warning: RESEND_API_KEY is not set. Skipping email delivery for %s", details.CustomerEmail)
		return nil
	}

	fromEmail := os.Getenv("RESEND_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "NouchiX Post-Quantum Licensing <licensing@secredknowledgeinc.tech>"
	}

	portalURL := details.PortalURL
	if portalURL == "" {
		portalURL = os.Getenv("STRIPE_CUSTOMER_PORTAL_URL")
	}
	if portalURL == "" {
		portalURL = "https://billing.stripe.com/p/login/00w00j5nYdZwcZB73t9ws00"
	}

	subject := fmt.Sprintf("Your PQC-Khepra %s License & Quickstart [Order Confirmed]", details.Tier)
	htmlBody := generateFulfillmentHTML(details, portalURL)

	payload := ResendEmailPayload{
		From:    fromEmail,
		To:      []string{details.CustomerEmail},
		Subject: subject,
		HTML:    htmlBody,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal email payload: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create Resend HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to dispatch email via Resend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[FULFILLMENT] Resend API error (Status %d): %s", resp.StatusCode, string(body))
		// If custom domain unverified in test mode, try fallback to onboarding@resend.dev
		if resp.StatusCode == 403 && fromEmail != "onboarding@resend.dev" {
			log.Printf("[FULFILLMENT] Retrying with onboarding@resend.dev fallback...")
			payload.From = "onboarding@resend.dev"
			fallbackBytes, _ := json.Marshal(payload)
			fallbackReq, _ := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(fallbackBytes))
			fallbackReq.Header.Set("Authorization", "Bearer "+apiKey)
			fallbackReq.Header.Set("Content-Type", "application/json")
			fallbackResp, err2 := client.Do(fallbackReq)
			if err2 == nil {
				defer fallbackResp.Body.Close()
				if fallbackResp.StatusCode < 400 {
					log.Printf("[FULFILLMENT] Fallback email dispatched successfully to %s", details.CustomerEmail)
					return nil
				}
				fbBody, _ := io.ReadAll(fallbackResp.Body)
				log.Printf("[FULFILLMENT] Fallback retry error (Status %d): %s", fallbackResp.StatusCode, string(fbBody))
			}
		}
		return fmt.Errorf("resend email dispatch failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[FULFILLMENT] License fulfillment email dispatched successfully to %s (Tier: %s)", details.CustomerEmail, details.Tier)
	return nil
}

func generateFulfillmentHTML(d FulfillmentDetails, portalURL string) string {
	quotaStr := fmt.Sprintf("%d Nodes", d.NodeQuota)
	if d.NodeQuota < 0 {
		quotaStr = "Unlimited Nodes / Seats"
	}

	capsuleSection := ""
	if d.CapsuleBase64 != "" {
		capsuleSection = fmt.Sprintf(`
		<div style="background:#0e1726;border:1px solid #1e293b;border-radius:8px;padding:16px;margin:20px 0;">
			<h3 style="color:#38bdf8;margin-top:0;">🛡️ Post-Quantum Air-Gap Capsule (QKD / ML-KEM-1024)</h3>
			<p style="color:#94a3b8;font-size:14px;margin-bottom:12px;">
				For air-gapped / SCIF environments with zero internet egress, install this Kyber/ML-KEM-encapsulated license capsule:
			</p>
			<pre style="background:#020617;color:#e2e8f0;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;">%s</pre>
			<p style="color:#64748b;font-size:12px;">Install via: <code>adinkhepra license install license.capsule</code></p>
		</div>
		`, d.CapsuleBase64)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #030712; color: #f9fafb; margin: 0; padding: 24px; }
		.card { max-width: 640px; margin: 0 auto; background: #0b0f19; border: 1px solid #1f2937; border-radius: 12px; padding: 32px; }
		.btn { display: inline-block; background: #2563eb; color: #ffffff !important; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; margin: 16px 0; }
		.code-box { background: #030712; border: 1px solid #374151; border-radius: 6px; padding: 14px; font-family: monospace; font-size: 13px; color: #10b981; word-break: break-all; margin: 12px 0; }
		.meta-table { width: 100%%; border-collapse: collapse; margin: 16px 0; font-size: 14px; }
		.meta-table td { padding: 8px 0; border-bottom: 1px solid #1f2937; color: #9ca3af; }
		.meta-table td:last-child { text-align: right; color: #ffffff; font-weight: 500; }
	</style>
</head>
<body>
	<div class="card">
		<h1 style="color:#ffffff;font-size:22px;margin-top:0;">SecRed Knowledge Inc. / NouchiX</h1>
		<h2 style="color:#60a5fa;font-size:18px;margin-bottom:20px;">PQC-Khepra License Provisioned (TRL-10 Hardened)</h2>
		
		<p style="color:#d1d5db;font-size:15px;line-height:1.5;">
			Hello <strong>%s</strong>,<br>
			Thank you for your subscription. Your post-quantum cryptographic license has been minted, verified with <strong>FIPS 204 ML-DSA-87 / ML-DSA-65</strong>, and attested to the immutable DAG ledger.
		</p>

		<table class="meta-table">
			<tr><td>Licensed Tier</td><td>%s</td></tr>
			<tr><td>Purchased Seats</td><td>%d</td></tr>
			<tr><td>Node Quota</td><td>%s</td></tr>
			<tr><td>Issue Date</td><td>%s</td></tr>
			<tr><td>Expires</td><td>%s</td></tr>
			<tr><td>Immutable DAG Anchor</td><td><code style="color:#93c5fd;">%s</code></td></tr>
		</table>

		<h3 style="color:#ffffff;font-size:15px;margin-top:24px;">Your Post-Quantum License Key</h3>
		<div class="code-box">KHEPRA_LICENSE_KEY=%s</div>

		<h3 style="color:#ffffff;font-size:15px;margin-top:24px;">Quick Configuration</h3>
		<p style="color:#9ca3af;font-size:13px;">Add to your AI agent environment, Cursor, Claude Code, or Antigravity IDE config:</p>
		<pre style="background:#030712;border:1px solid #1f2937;border-radius:6px;padding:12px;font-size:12px;color:#cbd5e1;overflow-x:auto;">
{
  "mcpServers": {
    "khepra-mcp": {
      "command": "khepra-mcp",
      "env": {
        "KHEPRA_LICENSE_KEY": "%s"
      }
    }
  }
}</pre>

		%s

		<div style="text-align:center;margin:32px 0 16px 0;">
			<a href="%s" class="btn">Access Stripe Customer Portal</a>
			<p style="color:#6b7280;font-size:12px;margin-top:8px;">
				Manage seats, update payment methods, or download tax invoices anytime via your verified customer portal.
			</p>
		</div>

		<hr style="border:0;border-top:1px solid #1f2937;margin:24px 0;">
		<p style="color:#6b7280;font-size:11px;text-align:center;margin:0;">
			SecRed Knowledge Inc. (operating as NouchiX) • SDVOSB • 169 Madison Ave Ste 2965, New York NY 10016<br>
			U.S. App. No. 63/942,886 • FIPS 204 ML-DSA-87 / FIPS 203 ML-KEM-1024 • Zero Egress Sovereign Engine
		</p>
	</div>
</body>
</html>`,
		d.CustomerName,
		d.Tier,
		d.Seats,
		quotaStr,
		d.IssuedAt.Format("2006-01-02 15:04:05 MST"),
		d.ExpiresAt.Format("2006-01-02 15:04:05 MST"),
		d.DAGAnchor,
		d.LicenseKey,
		d.LicenseKey,
		capsuleSection,
		portalURL,
	)
}

// SendQuotaAlertEmail dispatches an automated notification when STIGViewer API credit quota is depleted.
func SendQuotaAlertEmail(customerEmail, customerName, tier string, usedCredits, monthlyQuota int, portalURL string) error {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		log.Printf("[METER-ALERT] Warning: RESEND_API_KEY not set. Skipping quota email for %s", customerEmail)
		return nil
	}

	fromEmail := os.Getenv("RESEND_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "NouchiX Tokenomics Alert <licensing@secredknowledgeinc.tech>"
	}

	if portalURL == "" {
		portalURL = os.Getenv("STRIPE_CUSTOMER_PORTAL_URL")
	}
	if portalURL == "" {
		portalURL = "https://billing.stripe.com/p/login/00w00j5nYdZwcZB73t9ws00"
	}

	subject := fmt.Sprintf("⚠️ STIGViewer API Quota Alert: %d/%d Credits Used (%s Tier)", usedCredits, monthlyQuota, tier)
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #030712; color: #f9fafb; margin: 0; padding: 24px; }
.card { max-width: 600px; margin: 0 auto; background: #0b0f19; border: 1px solid #1f2937; border-radius: 12px; padding: 32px; }
.btn { display: inline-block; background: #2563eb; color: #ffffff !important; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; margin: 16px 0; }
.badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: #dc2626; color: white; }
</style>
</head>
<body>
<div class="card">
<h2 style="color:#ef4444;margin-top:0;">STIGViewer API Quota Limit Reached</h2>
<p style="color:#d1d5db;font-size:15px;line-height:1.5;">
Hello <strong>%s</strong>,<br>
Your environment has utilized <strong>%d of %d monthly STIGViewer API credits</strong> under your <strong>%s</strong> tier plan.
</p>
<p style="color:#9ca3af;font-size:14px;">
To prevent interruption to automated compliance workflows, C3PAO evidence generation, or live DISA STIG crosswalks, you can top up your token credit allocation or upgrade your plan in the Stripe Customer Portal.
</p>
<div style="text-align:center;margin:24px 0;">
<a href="%s" class="btn">Top Up Credits / Upgrade Plan</a>
</div>
<hr style="border:0;border-top:1px solid #1f2937;margin:24px 0;">
<p style="color:#6b7280;font-size:11px;text-align:center;margin:0;">
SecRed Knowledge Inc. (operating as NouchiX) • STIGViewer Tokenomics Engine • USPTO #73565085
</p>
</div>
</body>
</html>`, customerName, usedCredits, monthlyQuota, tier, portalURL)

	payload := ResendEmailPayload{
		From:    fromEmail,
		To:      []string{customerEmail},
		Subject: subject,
		HTML:    htmlBody,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal quota alert payload: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create Resend HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to dispatch quota email via Resend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend quota alert failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[METER-ALERT] Quota alert email dispatched to %s (%d/%d credits)", customerEmail, usedCredits, monthlyQuota)
	return nil
}

// SendLifecycleRenewalEmail dispatches an automated notification before license expiration.
func SendLifecycleRenewalEmail(customerEmail, customerName, tier string, expiresAt time.Time, portalURL string) error {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		return nil
	}

	fromEmail := os.Getenv("RESEND_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "NouchiX Licensing <licensing@secredknowledgeinc.tech>"
	}

	if portalURL == "" {
		portalURL = os.Getenv("STRIPE_CUSTOMER_PORTAL_URL")
	}
	if portalURL == "" {
		portalURL = "https://billing.stripe.com/p/login/00w00j5nYdZwcZB73t9ws00"
	}

	subject := fmt.Sprintf("Your PQC-Khepra %s License Renews Soon (%s)", tier, expiresAt.Format("Jan 02, 2006"))
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #030712; color: #f9fafb; margin: 0; padding: 24px; }
.card { max-width: 600px; margin: 0 auto; background: #0b0f19; border: 1px solid #1f2937; border-radius: 12px; padding: 32px; }
.btn { display: inline-block; background: #2563eb; color: #ffffff !important; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; margin: 16px 0; }
</style>
</head>
<body>
<div class="card">
<h2 style="color:#60a5fa;margin-top:0;">License Renewal Notice</h2>
<p style="color:#d1d5db;font-size:15px;line-height:1.5;">
Hello <strong>%s</strong>,<br>
This is an automated lifecycle notice confirming that your <strong>PQC-Khepra %s</strong> cryptographic license is scheduled for renewal on <strong>%s</strong>.
</p>
<p style="color:#9ca3af;font-size:14px;">
All DAG attestation chains and STIGViewer API token limits will automatically extend upon billing cycle renewal. You can review seats and billing settings via your portal:
</p>
<div style="text-align:center;margin:24px 0;">
<a href="%s" class="btn">Manage Subscription in Stripe</a>
</div>
<hr style="border:0;border-top:1px solid #1f2937;margin:24px 0;">
<p style="color:#6b7280;font-size:11px;text-align:center;margin:0;">
SecRed Knowledge Inc. (operating as NouchiX) • SDVOSB • USPTO #73565085
</p>
</div>
</body>
</html>`, customerName, tier, expiresAt.Format("Jan 02, 2006"), portalURL)

	payload := ResendEmailPayload{
		From:    fromEmail,
		To:      []string{customerEmail},
		Subject: subject,
		HTML:    htmlBody,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	log.Printf("[LIFECYCLE] Renewal notice dispatched to %s for %s tier", customerEmail, tier)
	return nil
}

// SendTopupConfirmationEmail dispatches a receipt when STIGViewer credits are successfully added.
func SendTopupConfirmationEmail(customerEmail, customerName string, addedCredits, newTotal int, portalURL string) error {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		log.Printf("[FULFILLMENT] Warning: RESEND_API_KEY not set. Skipping topup email for %s", customerEmail)
		return nil
	}

	fromEmail := os.Getenv("RESEND_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "NouchiX Tokenomics Fulfillment <licensing@secredknowledgeinc.tech>"
	}

	if portalURL == "" {
		portalURL = os.Getenv("STRIPE_CUSTOMER_PORTAL_URL")
	}
	if portalURL == "" {
		portalURL = "https://billing.stripe.com/p/login/00w00j5nYdZwcZB73t9ws00"
	}

	subject := fmt.Sprintf("✅ STIGViewer API Credit Top-Up Confirmed: +%d Credits Added", addedCredits)
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #030712; color: #f9fafb; margin: 0; padding: 24px; }
.card { max-width: 600px; margin: 0 auto; background: #0b0f19; border: 1px solid #1f2937; border-radius: 12px; padding: 32px; }
.btn { display: inline-block; background: #10b981; color: #ffffff !important; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; margin: 16px 0; }
.badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 13px; font-weight: 600; background: #065f46; color: #34d399; }
</style>
</head>
<body>
<div class="card">
<h2 style="color:#10b981;margin-top:0;">STIGViewer Token Credits Active</h2>
<p style="color:#d1d5db;font-size:15px;line-height:1.5;">
Hello <strong>%s</strong>,<br>
Your account has been credited with <strong>+%d STIGViewer API credits</strong>. Your new monthly quota is <strong>%d credits</strong>.
</p>
<p style="color:#9ca3af;font-size:14px;">
Your SEKHEM-METER-001 boundary has been automatically updated. All automated agent compliance checks, live DISA benchmark queries, and C3PAO evidence generation pipelines are immediately active.
</p>
<div style="text-align:center;margin:24px 0;">
<a href="%s" class="btn">View Account & Invoices</a>
</div>
<hr style="border:0;border-top:1px solid #1f2937;margin:24px 0;">
<p style="color:#6b7280;font-size:11px;text-align:center;margin:0;">
SecRed Knowledge Inc. (operating as NouchiX) • STIGViewer Tokenomics Engine • USPTO #73565085
</p>
</div>
</body>
</html>`, customerName, addedCredits, newTotal, portalURL)

	payload := ResendEmailPayload{
		From:    fromEmail,
		To:      []string{customerEmail},
		Subject: subject,
		HTML:    htmlBody,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal topup payload: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create Resend request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to dispatch topup email via Resend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend topup email failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[FULFILLMENT] Topup confirmation email dispatched to %s (+%d credits)", customerEmail, addedCredits)
	return nil
}
