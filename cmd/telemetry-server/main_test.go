package main

import (
	"testing"
	"time"

	"github.com/nouchix/khepra-pqc/sign"
)

// signedBeacon signs a beacon exactly as pkg/telemetry.SendSovereignBeacon does.
func signedBeacon(t *testing.T) *incomingBeacon {
	t.Helper()
	sk, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := &incomingBeacon{
		TelemetryVersion: "2",
		AnonymousID:      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		ScanCount:        3,
		FindingCount:     7,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	}
	msg, err := b.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if b.Signature, err = sk.Sign(sign.ContextTelemetry, msg); err != nil {
		t.Fatal(err)
	}
	b.SignerPublicKey = sk.PublicKey().Bytes()
	return b
}

func TestVerifyBeacon(t *testing.T) {
	if err := verifyBeacon(signedBeacon(t)); err != nil {
		t.Fatalf("client-signed beacon rejected: %v", err)
	}
}

func TestVerifyBeaconTampered(t *testing.T) {
	b := signedBeacon(t)
	b.FindingCount++
	if verifyBeacon(b) == nil {
		t.Fatal("tampered beacon accepted")
	}
}

func TestVerifyBeaconWrongContext(t *testing.T) {
	sk, _ := sign.GenerateKey()
	b := signedBeacon(t)
	msg, _ := b.canonicalBytes()
	b.Signature, _ = sk.Sign(sign.ContextAdinkra, msg)
	b.SignerPublicKey = sk.PublicKey().Bytes()
	if verifyBeacon(b) == nil {
		t.Fatal("beacon signed under another context accepted")
	}
}
