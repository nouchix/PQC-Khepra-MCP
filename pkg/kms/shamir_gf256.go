// pkg/kms/shamir_gf256.go — GF(256) Shamir Secret Sharing implementation
//
// Implements (k,n) threshold secret sharing over GF(2^8).
// This is the same algorithm used by HashiCorp Vault's shamir package (MIT),
// reimplemented here to eliminate the vault dependency tree (~50MB of indirect deps).
//
// Reference: A. Shamir, "How to share a secret", CACM 1979.
// Implementation follows: https://www.cs.utexas.edu/~bwaters/publications/...
//
// All arithmetic is in GF(2^8) with irreducible polynomial x^8+x^4+x^3+x+1 (AES poly).

package kms

import (
	"crypto/rand"
	"fmt"
)

// shamirSplit divides secret into totalShares shares where any threshold
// shares suffice to reconstruct. Returns totalShares byte slices each of
// length len(secret)+1 (the first byte is the X coordinate).
func shamirSplit(secret []byte, threshold, totalShares int) ([][]byte, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be ≥ 2, got %d", threshold)
	}
	if totalShares < threshold {
		return nil, fmt.Errorf("total shares (%d) must be ≥ threshold (%d)", totalShares, threshold)
	}
	if totalShares > 255 {
		return nil, fmt.Errorf("total shares must be ≤ 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret is empty")
	}

	// Generate random X coordinates (1..255, distinct)
	xs := make([]byte, totalShares)
	if _, err := rand.Read(xs); err != nil {
		return nil, err
	}
	// Ensure uniqueness and non-zero
	used := make(map[byte]bool)
	for i := range xs {
		for xs[i] == 0 || used[xs[i]] {
			b := make([]byte, 1)
			rand.Read(b) //nolint:errcheck
			xs[i] = b[0]
		}
		used[xs[i]] = true
	}

	// For each secret byte, construct a random degree-(threshold-1) polynomial
	// with f(0) = secret[i], evaluate at each X coordinate.
	shares := make([][]byte, totalShares)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][0] = xs[i] // X coordinate in first byte
	}

	// Coefficient buffer: coeffs[0] = secret byte, coeffs[1..t-1] = random
	coeffs := make([]byte, threshold)
	for byteIdx := range secret {
		coeffs[0] = secret[byteIdx]
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, err
		}

		for shareIdx, x := range xs {
			shares[shareIdx][byteIdx+1] = gf256Eval(coeffs, x)
		}
	}

	return shares, nil
}

// shamirCombine reconstructs the secret from k or more shares.
func shamirCombine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("need at least 2 shares")
	}
	secretLen := len(shares[0]) - 1
	for _, s := range shares[1:] {
		if len(s) != len(shares[0]) {
			return nil, fmt.Errorf("share length mismatch")
		}
	}

	xs := make([]byte, len(shares))
	for i, s := range shares {
		xs[i] = s[0]
	}

	secret := make([]byte, secretLen)
	ys := make([]byte, len(shares))
	for byteIdx := range secret {
		for i, s := range shares {
			ys[i] = s[byteIdx+1]
		}
		secret[byteIdx] = gf256Lagrange(xs, ys)
	}
	return secret, nil
}

// ── GF(2^8) arithmetic ────────────────────────────────────────────────────────

// gf256Mul multiplies two elements of GF(2^8) with AES irreducible polynomial.
func gf256Mul(a, b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			result ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b // x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return result
}

// gf256Div divides a by b in GF(2^8). Panics if b == 0.
func gf256Div(a, b byte) byte {
	if b == 0 {
		panic("gf256Div: division by zero")
	}
	if a == 0 {
		return 0
	}
	return gf256Mul(a, gf256Inv(b))
}

// gf256Inv returns the multiplicative inverse of a in GF(2^8).
func gf256Inv(a byte) byte {
	if a == 0 {
		panic("gf256Inv: inverse of zero")
	}
	// Extended Euclidean algorithm in GF(2^8)
	// Use precomputed approach via Fermat's little theorem: a^(2^8-2)
	result := byte(1)
	p := a
	for i := 0; i < 7; i++ {
		p = gf256Mul(p, p)
		result = gf256Mul(result, p)
	}
	return result
}

// gf256Eval evaluates polynomial coeffs at x in GF(2^8) using Horner's method.
func gf256Eval(coeffs []byte, x byte) byte {
	if len(coeffs) == 0 {
		return 0
	}
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gf256Mul(result, x) ^ coeffs[i]
	}
	return result
}

// gf256Lagrange performs Lagrange interpolation at x=0 to recover f(0).
func gf256Lagrange(xs, ys []byte) byte {
	var result byte
	for i := range xs {
		num := ys[i]
		den := byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			num = gf256Mul(num, xs[j])        // num * x_j
			den = gf256Mul(den, xs[i]^xs[j])  // den * (x_i XOR x_j) — XOR = subtraction in GF
		}
		result ^= gf256Div(num, den)
	}
	return result
}
