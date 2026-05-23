package main

import (
	"crypto/sha256"
	"fmt"
)

// SymbolMatrices from adinkra_core.go
var SymbolMatrices = map[string][][]uint8{
	"Eban": {
		{0, 1, 0, 1, 0, 0, 0, 0},
		{1, 0, 1, 0, 0, 0, 0, 0},
		{0, 1, 0, 1, 0, 0, 0, 0},
		{1, 0, 1, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 1, 0, 1},
		{0, 0, 0, 0, 1, 0, 1, 0},
		{0, 0, 0, 0, 0, 1, 0, 1},
		{0, 0, 0, 0, 1, 0, 1, 0},
	},
	"Fawohodie": {
		{1, 1, 1, 0, 0, 0, 0, 0},
		{1, 1, 0, 1, 0, 0, 0, 0},
		{1, 0, 1, 1, 0, 0, 0, 0},
		{0, 1, 1, 1, 0, 0, 0, 0},
		{0, 0, 0, 0, 1, 1, 1, 0},
		{0, 0, 0, 0, 1, 1, 0, 1},
		{0, 0, 0, 0, 1, 0, 1, 1},
		{0, 0, 0, 0, 0, 1, 1, 1},
	},
	"Dwennimmen": {
		{1, 0, 1, 0, 1, 0, 1, 0},
		{0, 1, 0, 1, 0, 1, 0, 1},
		{1, 0, 1, 0, 1, 0, 1, 0},
		{0, 1, 0, 1, 0, 1, 0, 1},
		{1, 0, 1, 0, 1, 0, 1, 0},
		{0, 1, 0, 1, 0, 1, 0, 1},
		{1, 0, 1, 0, 1, 0, 1, 0},
		{0, 1, 0, 1, 0, 1, 0, 1},
	},
}

func GetSpectralFingerprint(symbol string) []byte {
	matrix, ok := SymbolMatrices[symbol]
	if !ok {
		return []byte(symbol)
	}

	h := sha256.New()
	for _, row := range matrix {
		h.Write(row)
	}
	return h.Sum(nil)
}

func Hash(data []byte) string {
	h := sha256.Sum256(data)
	hexStr := fmt.Sprintf("%x", h)

	mapping := map[rune]byte{
		'0': 'G', '1': 'Y', '2': 'E', '3': 'N', '4': 'A', '5': 'M', '6': 'K', '7': 'H',
		'8': 'P', '9': 'R', 'a': 'S', 'b': 'U', 'c': 'T', 'd': 'I', 'e': 'L', 'f': 'O',
	}

	out := make([]byte, len(hexStr))
	for i, r := range hexStr {
		out[i] = mapping[r]
	}
	return string(out)
}

func main() {
	symbols := []string{"Eban", "Fawohodie", "Dwennimmen"}
	var combinedFingerprint []byte
	for _, s := range symbols {
		combinedFingerprint = append(combinedFingerprint, GetSpectralFingerprint(s)...)
	}

	// Double hash for integrity key derivation
	finalHash := sha256.Sum256(combinedFingerprint)
	khepraKey := Hash(finalHash[:])

	fmt.Printf("SPECTRAL_FINGERPRINT_KEY=%s\n", khepraKey)

	// Also provide the hex version as requested for fly secrets (usually hex or string)
	fmt.Printf("HEX_INTEGRITY_KEY=%x\n", sha256.Sum256([]byte(khepraKey)))
}
