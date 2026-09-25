package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityPolicyContent(t *testing.T) {
	if !strings.Contains(NouchiXPGPPublicKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatal("expected NouchiXPGPPublicKey to contain BEGIN PGP PUBLIC KEY BLOCK")
	}
	if !strings.Contains(NouchiXPGPPublicKey, "-----END PGP PUBLIC KEY BLOCK-----") {
		t.Fatal("expected NouchiXPGPPublicKey to contain END PGP PUBLIC KEY BLOCK")
	}

	if !strings.Contains(NouchiXSecurityTxt, "Contact: mailto:security@nouchix.com") {
		t.Fatal("expected NouchiXSecurityTxt to contain security contact")
	}
	if !strings.Contains(NouchiXSecurityTxt, "Encryption: https://mcp.souhimbou.ai/.well-known/pgp-key.txt") {
		t.Fatal("expected NouchiXSecurityTxt to contain pgp-key encryption URL")
	}
	if !strings.Contains(NouchiXSecurityTxt, "E9A9 2822 E8B8 4976 E6D5 98C2 1DA1 AF41 D77A 0922") {
		t.Fatal("expected NouchiXSecurityTxt to contain fingerprint")
	}
}

func TestSecurityEndpoints(t *testing.T) {
	transport := &httpTransport{}

	// Test /.well-known/security.txt
	recSec := httptest.NewRecorder()
	reqSec := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	transport.handleSecurityTxt(recSec, reqSec)

	if recSec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recSec.Code)
	}
	if ct := recSec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("expected text/plain content-type, got %s", ct)
	}
	if !strings.Contains(recSec.Body.String(), "mailto:security@nouchix.com") {
		t.Fatal("body does not contain security contact")
	}

	// Test /.well-known/pgp-key.txt
	recKey := httptest.NewRecorder()
	reqKey := httptest.NewRequest(http.MethodGet, "/.well-known/pgp-key.txt", nil)
	transport.handlePGPKey(recKey, reqKey)

	if recKey.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recKey.Code)
	}
	if ct := recKey.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("expected text/plain content-type, got %s", ct)
	}
	if !strings.Contains(recKey.Body.String(), "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatal("body does not contain pgp key block")
	}
}
