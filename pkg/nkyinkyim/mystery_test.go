package nkyinkyim

import (
	"bytes"
	"testing"
)

func TestTheLattice(t *testing.T) {
	// "Life is a twist"
	secret := []byte("The Stack Will Not Save Us")

	// 1. Shroud the secret
	verse := Shroud(secret)
	t.Logf("The Shroud: %s", verse)

	// Verify alphabet compliance
	for _, r := range verse {
		if !contains("GYENAMKHPRSUTILO", byte(r)) {
			t.Fatalf("Polluted Shroud! Found char: %c", r)
		}
	}

	// 2. Epiphany (Unravel the secret)
	revealed, err := Epiphany(verse)
	if err != nil {
		t.Fatalf("Failed to find epiphany: %v", err)
	}

	// 3. Verify Integrity
	if !bytes.Equal(secret, revealed) {
		t.Fatalf("The lattice is broken. Expected '%s', got '%s'", secret, revealed)
	}
}

func contains(set string, char byte) bool {
	for i := 0; i < len(set); i++ {
		if set[i] == char {
			return true
		}
	}
	return false
}
