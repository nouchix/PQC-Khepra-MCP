package apiserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

const testServiceSecretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func init() {
	InitializeServiceAccounts([]ServiceAccount{
		{Name: "cloudflare-telemetry", Permissions: []string{"telemetry:write"}},
	})
}

func TestServiceTokenRoundTrip(t *testing.T) {
	t.Setenv("KHEPRA_SERVICE_SECRET", testServiceSecretHex)
	tok, err := GenerateServiceToken("cloudflare-telemetry")
	if err != nil {
		t.Fatal(err)
	}
	acct, err := validateServiceToken(tok)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if acct.Name != "cloudflare-telemetry" {
		t.Fatalf("got account %q", acct.Name)
	}
}

// The telemetry worker keys HMAC-SHA256 with the hex-decoded secret.
func TestServiceTokenMatchesWorkerKey(t *testing.T) {
	t.Setenv("KHEPRA_SERVICE_SECRET", testServiceSecretHex)
	key, _ := hex.DecodeString(testServiceSecretHex)
	ts := fmt.Sprintf("%016x", time.Now().Unix())
	msg := ServiceTokenPrefix + "cloudflare-telemetry-" + ts
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	tok := msg + "-" + hex.EncodeToString(mac.Sum(nil))
	if _, err := validateServiceToken(tok); err != nil {
		t.Fatalf("worker-format token rejected: %v", err)
	}
}

func TestServiceTokenRejectedWithoutSecret(t *testing.T) {
	t.Setenv("KHEPRA_SERVICE_SECRET", "")
	if _, err := GenerateServiceToken("cloudflare-telemetry"); err == nil {
		t.Fatal("expected GenerateServiceToken to fail without a secret")
	}
	// A token keyed with the former built-in default must not validate.
	ts := fmt.Sprintf("%016x", time.Now().Unix())
	msg := ServiceTokenPrefix + "cloudflare-telemetry-" + ts
	mac := hmac.New(sha256.New, []byte("khepra-service-secret-v1-change-me-in-production"))
	mac.Write([]byte(msg))
	tok := msg + "-" + hex.EncodeToString(mac.Sum(nil))
	if _, err := validateServiceToken(tok); err == nil {
		t.Fatal("token keyed with the old default secret was accepted")
	}
}

func TestServiceSecretTooShort(t *testing.T) {
	t.Setenv("KHEPRA_SERVICE_SECRET", "00112233445566778899")
	if _, err := getServiceSecret(); err == nil {
		t.Fatal("expected a short secret to be rejected")
	}
}
