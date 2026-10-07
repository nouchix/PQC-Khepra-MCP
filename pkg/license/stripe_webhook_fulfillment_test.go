package license

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func paidPlatformSession(id string) *StripeCheckoutSession {
	return &StripeCheckoutSession{
		ID:              id,
		Customer:        "cus_test_123",
		PaymentStatus:   "paid",
		CustomerDetails: StripeCustomerDetails{Email: "buyer@example.com", Name: "Buyer"},
		LineItems: &StripeLineItemList{Data: []StripeLineItem{{
			Description: "KTOS Platform ($499/mo)", Quantity: 1,
			Price: StripePrice{ID: "price_1ULpbqDqGyad2D3VKcN4xHM3", UnitAmount: 49900},
		}}},
	}
}

// captureFulfillment records fulfillment emails instead of sending them.
func captureFulfillment(t *testing.T) *[]FulfillmentDetails {
	t.Helper()
	var sent []FulfillmentDetails
	prev := sendFulfillment
	sendFulfillment = func(d FulfillmentDetails) error { sent = append(sent, d); return nil }
	t.Cleanup(func() { sendFulfillment = prev })
	return &sent
}

func TestCheckoutMintsValidatorCompatibleKey(t *testing.T) {
	priv := useTestAPIKeyRoot(t)
	sent := captureFulfillment(t)

	if err := processCheckoutSession(paidPlatformSession("cs_mint"), &StripePipelineDeps{MasterPriv: priv}); err != nil {
		t.Fatalf("processCheckoutSession: %v", err)
	}
	if len(*sent) != 1 {
		t.Fatalf("expected one fulfillment, got %d", len(*sent))
	}
	d := (*sent)[0]
	parsed, err := ValidateAPIKey(d.LicenseKey)
	if err != nil {
		t.Fatalf("minted key does not validate: %v", err)
	}
	if parsed.Tier != TierPlatform || parsed.CustomerID != "cus_test_123" {
		t.Fatalf("unexpected key contents: tier=%s customer=%s", parsed.Tier, parsed.CustomerID)
	}
	if d.CapsuleBase64 != "" {
		t.Fatal("checkout must not issue a device capsule")
	}
	if d.DAGAnchor != "not anchored (no DAG store configured)" {
		t.Fatalf("expected an explicit 'not anchored' DAG anchor, got %q", d.DAGAnchor)
	}
}

func TestCheckoutRequiresPaidSession(t *testing.T) {
	priv := useTestAPIKeyRoot(t)
	sent := captureFulfillment(t)

	s := paidPlatformSession("cs_unpaid")
	s.PaymentStatus = "unpaid"
	err := processCheckoutSession(s, &StripePipelineDeps{MasterPriv: priv})
	if !errors.Is(err, ErrPaymentNotSettled) {
		t.Fatalf("expected ErrPaymentNotSettled, got %v", err)
	}
	if len(*sent) != 0 {
		t.Fatal("an unpaid session must not be fulfilled")
	}
}

func webhookRequest(t *testing.T, secret string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("STRIPE_WEBHOOK_SECRET", secret)
	r := gin.New()
	r.POST("/webhook", StripeWebhookGinHandler(&StripePipelineDeps{}))
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	if secret != "" {
		ts := time.Now().Unix()
		mac := hmac.New(sha256.New, []byte(secret))
		fmt.Fprintf(mac, "%d.%s", ts, body)
		req.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil))))
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestWebhookFailsClosedWithoutSecret(t *testing.T) {
	body := []byte(`{"id":"evt_forged","type":"checkout.session.completed","data":{"object":{}}}`)
	if w := webhookRequest(t, "", body); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without STRIPE_WEBHOOK_SECRET, got %d", w.Code)
	}
}

func TestWebhookIgnoresDuplicateEvents(t *testing.T) {
	secret := "whsec_" + "unit_test_only"
	body := []byte(`{"id":"evt_dup_1","type":"invoice.created","data":{"object":{}}}`)
	if w := webhookRequest(t, secret, body); w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"processed"`)) {
		t.Fatalf("first delivery: code=%d body=%s", w.Code, w.Body.String())
	}
	if w := webhookRequest(t, secret, body); !bytes.Contains(w.Body.Bytes(), []byte(`"duplicate"`)) {
		t.Fatalf("second delivery must be a duplicate: %s", w.Body.String())
	}
}
