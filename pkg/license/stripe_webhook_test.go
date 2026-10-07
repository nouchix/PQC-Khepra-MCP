package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/khepra-pqc/sign"
)

func TestVerifyStripeSignature(t *testing.T) {
	secret := strings.Join([]string{"whsec", "mock", "test", "key", "98765"}, "_")
	payload := []byte(`{"id":"evt_test_123","type":"checkout.session.completed"}`)
	now := time.Now().Unix()

	signedPayload := fmt.Sprintf("%d.%s", now, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	validSig := hex.EncodeToString(mac.Sum(nil))

	header := fmt.Sprintf("t=%d,v1=%s", now, validSig)

	// 1. Valid Signature
	if err := VerifyStripeSignature(payload, header, secret, 300*time.Second); err != nil {
		t.Fatalf("expected valid signature, got: %v", err)
	}

	// 2. Tampered Payload
	tamperedPayload := []byte(`{"id":"evt_test_123","type":"checkout.session.tampered"}`)
	if err := VerifyStripeSignature(tamperedPayload, header, secret, 300*time.Second); err == nil {
		t.Fatalf("expected error for tampered payload, got nil")
	}

	// 3. Expired Timestamp (Replay Attack)
	expiredTimestamp := time.Now().Add(-10 * time.Minute).Unix()
	expiredPayload := fmt.Sprintf("%d.%s", expiredTimestamp, string(payload))
	macExpired := hmac.New(sha256.New, []byte(secret))
	macExpired.Write([]byte(expiredPayload))
	expiredSig := hex.EncodeToString(macExpired.Sum(nil))
	expiredHeader := fmt.Sprintf("t=%d,v1=%s", expiredTimestamp, expiredSig)

	if err := VerifyStripeSignature(payload, expiredHeader, secret, 300*time.Second); err == nil {
		t.Fatalf("expected error for expired timestamp (replay defense), got nil")
	}
}

func TestProcessCheckoutSessionMultiTier(t *testing.T) {
	// Enterprise and sovereign are not sold through Stripe; map test prices.
	t.Setenv(StripePriceTiersEnv, "price_test_enterprise=enterprise,price_test_sovereign=sovereign")
	// Generate ephemeral ML-DSA-87 keypair for testing
	priv, err := sign.GenerateKey()
	if err != nil {
		t.Fatalf("ML-DSA-87 keygen failed: %v", err)
	}
	privBytes := priv.Bytes()
	pubBytes := priv.PublicKey().Bytes()

	t.Run("Platform Tier ($499/mo)", func(t *testing.T) {
		subStore := dag.NewMemory()
		subDeps := &StripePipelineDeps{
			MasterPriv: privBytes,
			MasterPub:  pubBytes,
			DAGStore:   subStore,
		}

		session := &StripeCheckoutSession{
			ID:            "cs_test_platform_order",
			PaymentStatus: "paid",
			CustomerDetails: StripeCustomerDetails{
				Email: "platform-buyer@defense-contractor.mil",
				Name:  "Lead Architect",
			},
			LineItems: &StripeLineItemList{
				Data: []StripeLineItem{
					{
						Description: "KTOS Platform ($499/mo)",
						Quantity:    2,
						Price:       StripePrice{ID: "price_1ULpbqDqGyad2D3VKcN4xHM3", UnitAmount: 49900},
					},
				},
			},
		}

		if err := processCheckoutSession(session, subDeps); err != nil {
			t.Fatalf("processCheckoutSession failed: %v", err)
		}

		allNodes := subStore.All()
		if len(allNodes) == 0 {
			t.Fatalf("expected DAG node to be created, got none")
		}
		lastNode := allNodes[0]
		if lastNode.PQC["email"] != "platform-buyer@defense-contractor.mil" {
			t.Errorf("expected email in DAG node to match, got: %s", lastNode.PQC["email"])
		}
		if lastNode.PQC["tier"] != TierPlatform {
			t.Errorf("expected tier %s, got: %s", TierPlatform, lastNode.PQC["tier"])
		}
	})

	t.Run("Enterprise Tier ($2,999/mo)", func(t *testing.T) {
		subStore := dag.NewMemory()
		subDeps := &StripePipelineDeps{
			MasterPriv: privBytes,
			MasterPub:  pubBytes,
			DAGStore:   subStore,
		}

		session := &StripeCheckoutSession{
			ID:            "cs_test_enterprise_order",
			PaymentStatus: "paid",
			CustomerDetails: StripeCustomerDetails{
				Email: "ciso@defense-prime.com",
				Name:  "Chief Information Security Officer",
			},
			LineItems: &StripeLineItemList{
				Data: []StripeLineItem{
					{
						Description: "KTOS Enterprise Agentic SOC ($2,999/mo)",
						Quantity:    1,
						Price:       StripePrice{ID: "price_test_enterprise", UnitAmount: 299900},
					},
				},
			},
		}

		if err := processCheckoutSession(session, subDeps); err != nil {
			t.Fatalf("processCheckoutSession failed: %v", err)
		}

		allNodes := subStore.All()
		if len(allNodes) == 0 {
			t.Fatalf("expected DAG node to be created, got none")
		}
		lastNode := allNodes[0]
		if lastNode.PQC["tier"] != TierEnterprise {
			t.Errorf("expected tier %s, got: %s", TierEnterprise, lastNode.PQC["tier"])
		}
		if lastNode.PQC["node_quota"] != "26" { // 1 base + 25 per seat
			t.Errorf("expected node quota 26, got: %s", lastNode.PQC["node_quota"])
		}
	})

	t.Run("Sovereign Air-Gap Tier ($5,000/mo)", func(t *testing.T) {
		subStore := dag.NewMemory()
		subDeps := &StripePipelineDeps{
			MasterPriv: privBytes,
			MasterPub:  pubBytes,
			DAGStore:   subStore,
		}

		session := &StripeCheckoutSession{
			ID:            "cs_test_sovereign_order",
			PaymentStatus: "paid",
			CustomerDetails: StripeCustomerDetails{
				Email: "classified-env@aerospace-gov.us",
				Name:  "Special Access Program Lead",
			},
			LineItems: &StripeLineItemList{
				Data: []StripeLineItem{
					{
						Description: "KTOS Sovereign Air-Gap ($5,000/mo)",
						Quantity:    1,
						Price:       StripePrice{ID: "price_test_sovereign", UnitAmount: 500000},
					},
				},
			},
		}

		if err := processCheckoutSession(session, subDeps); err != nil {
			t.Fatalf("processCheckoutSession failed: %v", err)
		}

		allNodes := subStore.All()
		if len(allNodes) == 0 {
			t.Fatalf("expected DAG node to be created, got none")
		}
		lastNode := allNodes[0]
		if lastNode.PQC["tier"] != TierSovereign {
			t.Errorf("expected tier %s, got: %s", TierSovereign, lastNode.PQC["tier"])
		}
		if lastNode.PQC["node_quota"] != "-1" {
			t.Errorf("expected unlimited quota (-1), got: %s", lastNode.PQC["node_quota"])
		}
	})
}
