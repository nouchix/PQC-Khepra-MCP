package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/nouchix/khepra-pqc/kdf"
)

// Password hashes use PBKDF2-HMAC-SHA-384 (NIST SP 800-132) with a random
// 16-byte salt and kdf.PBKDF2Iterations iterations, encoded as
//
//	$pbkdf2-sha384$i=<iterations>$<base64 salt>$<base64 hash>
//
// Argon2id hashes from earlier builds are not accepted; those accounts must
// reset their passwords.
const (
	passwordScheme  = "pbkdf2-sha384"
	passwordHashLen = 32
)

// HashPassword returns an encoded PBKDF2-HMAC-SHA-384 hash of password.
func HashPassword(password string) (string, error) {
	salt, err := kdf.NewSalt()
	if err != nil {
		return "", err
	}
	hash, err := kdf.PassphraseKey(password, salt, passwordHashLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$%s$i=%d$%s$%s", passwordScheme, kdf.PBKDF2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword reports whether password matches encodedHash.
func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 5 || parts[0] != "" {
		return false, fmt.Errorf("invalid hash format")
	}
	if parts[1] != passwordScheme {
		return false, fmt.Errorf("unsupported password hash scheme %q; reset the password", parts[1])
	}
	if parts[2] != fmt.Sprintf("i=%d", kdf.PBKDF2Iterations) {
		return false, fmt.Errorf("unsupported password hash parameters %q", parts[2])
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("invalid hash salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid hash value: %w", err)
	}
	if len(want) != passwordHashLen {
		return false, fmt.Errorf("invalid hash length %d", len(want))
	}
	got, err := kdf.PassphraseKey(password, salt, passwordHashLen)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
