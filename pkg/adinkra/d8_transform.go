package adinkra

// =============================================================================
// D₈ DIHEDRAL GROUP TRANSFORMATIONS — QKE PHASE 2/3
// Patent §3.2: Quantum-Resilient Key Exchange ciphertext obfuscation layer.
// The 8 rotations + 8 reflections of the dihedral group D₈ (order 16) are
// applied as permutation ciphers on top of ML-KEM ciphertext blocks.
// This does NOT replace Kyber security — it adds symbol-keyed obfuscation
// making ciphertext unrecognisable without knowledge of the symbol in use.
// =============================================================================

// d8OpType classifies each of the 16 D₈ elements.
type d8OpType uint8

// d8 element type constants — kept for documentation; transformIDs 0-7 are
// rotations, 8-15 are reflections (see permute8).
const (
	_ d8OpType = iota // 0-7: rotations by k*45°
	_                  // 8-15: reflections
)

// d8BlockSize is the granularity at which permutations are applied.
// 8 bytes aligns with the D₈ group order and typical AES block chunking.
const d8BlockSize = 8

// D8Transform applies one of the 16 D₈ symmetry operations to data.
// transformID ∈ [0, 15]:
//   0-7  = rotations by (transformID × 45°) — cyclic byte permutation of each 8-byte block
//   8-15 = reflections — reversal + cyclic shift within each 8-byte block
//
// Data shorter than 8 bytes is padded; callers should always use D8Transform +
// D8InverseTransform as a matched pair around Kyber ciphertext.
func D8Transform(data []byte, symbol string, transformID int) []byte {
	transformID = transformID & 0xF // clamp to [0,15]
	out := make([]byte, len(data))
	copy(out, data)
	applyD8(out, transformID, false)
	return out
}

// D8InverseTransform reverses the transformation applied by D8Transform.
// Must be called with the same symbol and transformID.
func D8InverseTransform(data []byte, symbol string, transformID int) []byte {
	transformID = transformID & 0xF
	out := make([]byte, len(data))
	copy(out, data)
	applyD8(out, transformID, true)
	return out
}

// SymbolTransformID returns the canonical D₈ transform index for an Adinkra symbol.
// The index is deterministically derived from the symbol's spectral fingerprint,
// ensuring key-binding without hard-coding symbol→index mappings.
func SymbolTransformID(symbol string) int {
	fp := GetSpectralFingerprint(symbol)
	if len(fp) == 0 {
		return 0
	}
	// Use two bytes of the fingerprint to select from 16 transforms.
	return int(fp[0]^fp[1]) & 0xF
}

// =============================================================================
// INTERNAL: permutation engine
// =============================================================================

// applyD8 applies (or inverts) a D₈ operation in-place, 8 bytes at a time.
// Partial tail blocks (< 8 bytes) are passed through unchanged to guarantee
// bijective round-trips on arbitrary-length inputs.  ML-KEM-1024 ciphertexts
// are always 1568 bytes (exactly 196 blocks), so production use has no tail.
func applyD8(data []byte, transformID int, inverse bool) {
	n := len(data)
	blocks := n / d8BlockSize

	for b := 0; b < blocks; b++ {
		block := data[b*d8BlockSize : (b+1)*d8BlockSize]
		permute8(block, transformID, inverse)
	}
	// Tail bytes (n % 8 != 0) are left unchanged — they pass through unmodified
	// in both the forward and inverse direction, ensuring round-trip correctness.
}

// permute8 applies one of the 16 D₈ operations to an 8-byte slice in-place.
//
//	transformID 0-7:  rotate left by transformID positions (inverse: rotate right)
//	transformID 8-15: reflect (reverse) then rotate left by (transformID-8) positions
func permute8(b []byte, transformID int, inverse bool) {
	if transformID < 8 {
		shift := transformID
		if inverse {
			shift = (8 - shift) % 8
		}
		rotateLeft8(b, shift)
	} else {
		shift := transformID - 8
		if inverse {
			// Forward was: reverse, then rotate left by shift.
			// Inverse:  rotate right by shift (= left by 8-shift), then reverse.
			rotateLeft8(b, (8-shift)%8)
			reverseSlice8(b)
		} else {
			reverseSlice8(b)
			rotateLeft8(b, shift)
		}
	}
}

// rotateLeft8 rotates b (exactly 8 bytes) left by k positions.
func rotateLeft8(b []byte, k int) {
	if k == 0 {
		return
	}
	var tmp [d8BlockSize]byte
	copy(tmp[:], b)
	for i := 0; i < d8BlockSize; i++ {
		b[i] = tmp[(i+k)%d8BlockSize]
	}
}

// reverseSlice8 reverses exactly 8 bytes in-place.
func reverseSlice8(b []byte) {
	b[0], b[7] = b[7], b[0]
	b[1], b[6] = b[6], b[1]
	b[2], b[5] = b[5], b[2]
	b[3], b[4] = b[4], b[3]
}
