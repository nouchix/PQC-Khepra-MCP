package auth

import (
	"strings"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$pbkdf2-sha384$i=600000$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if ok, err := VerifyPassword("correct horse battery staple", h); err != nil || !ok {
		t.Fatalf("VerifyPassword(correct) = %v, %v", ok, err)
	}
	if ok, err := VerifyPassword("wrong", h); err != nil || ok {
		t.Fatalf("VerifyPassword(wrong) = %v, %v", ok, err)
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Error("two hashes of the same password share a salt")
	}
	if _, err := VerifyPassword("x", "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$aGFzaA"); err == nil {
		t.Error("Argon2id hash accepted")
	}
}
