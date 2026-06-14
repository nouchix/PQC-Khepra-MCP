package nkyinkyim

import (
	"fmt"
	"strings"
)

// The Khepra Lattice Alphabet
// "GYE NYAME KHEPRA SOUL - IT IS LIT... O"
// 0123456789ABCDEF
const latticeAlphabet = "GYENAMKHPRSUTILO"

// Shroud (formerly Weave) transforms raw binary essence into a Poetic Lattice.
// It uses a custom nibble-swap substitution to obfuscate the PQC signature.
func Shroud(strand []byte) string {
	var sb strings.Builder
	// In the spirit of Nkyinkyim (twisting), we weave the strand.
	for _, b := range strand {
		// Upper Nibble (The Spirit)
		upper := (b >> 4) & 0x0F
		// Lower Nibble (The Matter)
		lower := b & 0x0F

		sb.WriteByte(latticeAlphabet[upper])
		sb.WriteByte(latticeAlphabet[lower])
	}
	return sb.String()
}

// Epiphany (formerly Unravel) reveals the hidden truth from the Poetic Lattice.
// It reverses the Khepra Lattice substitution.
func Epiphany(verse string) ([]byte, error) {
	if len(verse)%2 != 0 {
		return nil, fmt.Errorf("the verse is unbalanced (odd length)")
	}

	decodeMap := make(map[byte]byte)
	for i := 0; i < len(latticeAlphabet); i++ {
		decodeMap[latticeAlphabet[i]] = byte(i)
	}

	decoded := make([]byte, 0, len(verse)/2)

	for i := 0; i < len(verse); i += 2 {
		charUpper := verse[i]
		charLower := verse[i+1]

		nibbleUpper, ok1 := decodeMap[charUpper]
		nibbleLower, ok2 := decodeMap[charLower]

		if !ok1 || !ok2 {
			return nil, fmt.Errorf("foreign symbols detected in the lattice")
		}

		// Recombine Spirit and Matter
		b := (nibbleUpper << 4) | nibbleLower
		decoded = append(decoded, b)
	}

	return decoded, nil
}
