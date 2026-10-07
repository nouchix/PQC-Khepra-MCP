package license

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	pricePlatform = "price_1ULpbqDqGyad2D3VKcN4xHM3"
	priceAdvisory = "price_1ULpbvDqGyad2D3VkJ8yyrnP"
)

func sessionWithPrice(id, price string) *StripeCheckoutSession {
	return &StripeCheckoutSession{
		ID:              id,
		Customer:        "cus_test_prices",
		PaymentStatus:   "paid",
		CustomerDetails: StripeCustomerDetails{Email: "buyer@example.com"},
		LineItems: &StripeLineItemList{Data: []StripeLineItem{{
			Quantity: 1, Price: StripePrice{ID: price, UnitAmount: 500000},
		}}},
	}
}

// The $5,000 Remediation Advisory is a service: it must not mint a license,
// whatever its amount.
func TestAdvisoryPurchaseMintsNothing(t *testing.T) {
	priv := useTestAPIKeyRoot(t)
	sent := captureFulfillment(t)
	if err := processCheckoutSession(sessionWithPrice("cs_adv", priceAdvisory), &StripePipelineDeps{MasterPriv: priv}); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 0 {
		t.Fatalf("advisory purchase minted %d license(s)", len(*sent))
	}
}

func TestUnmappedPriceIsRejected(t *testing.T) {
	priv := useTestAPIKeyRoot(t)
	captureFulfillment(t)
	err := processCheckoutSession(sessionWithPrice("cs_unknown", "price_not_in_catalog"), &StripePipelineDeps{MasterPriv: priv})
	if err == nil || !strings.Contains(err.Error(), "not mapped") {
		t.Fatalf("expected an unmapped-price error, got %v", err)
	}
}

func TestPriceCatalogEnvOverride(t *testing.T) {
	t.Setenv(StripePriceTiersEnv, "price_custom_ent=enterprise, bogus, price_bad=admin, price_adv2=advisory")
	c := priceCatalog()
	if c["price_custom_ent"] != TierEnterprise || c["price_adv2"] != productAdvisory {
		t.Fatalf("override not applied: %v", c)
	}
	if _, ok := c["price_bad"]; ok {
		t.Fatal("unknown product accepted")
	}
	if c[pricePlatform] != TierPlatform {
		t.Fatal("defaults lost")
	}
}

// When the event omits line items they are fetched from Stripe.
func TestLineItemsFetchedFromStripe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk_test_unit" || !strings.HasSuffix(r.URL.Path, "/v1/checkout/sessions/cs_fetch/line_items") {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"quantity":2,"price":{"id":"` + pricePlatform + `"}}],"has_more":false}`))
	}))
	defer srv.Close()
	prevBase := stripeAPIBase
	stripeAPIBase = srv.URL
	t.Cleanup(func() { stripeAPIBase = prevBase })
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_unit")

	items, err := checkoutLineItems(&StripeCheckoutSession{ID: "cs_fetch"})
	if err != nil || len(items) != 1 || items[0].Price.ID != pricePlatform || items[0].Quantity != 2 {
		t.Fatalf("fetch: items=%v err=%v", items, err)
	}

	t.Setenv("STRIPE_SECRET_KEY", "")
	if _, err := checkoutLineItems(&StripeCheckoutSession{ID: "cs_fetch"}); err == nil {
		t.Fatal("expected an error without line items or a secret key")
	}
}
