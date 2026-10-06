package adinkra

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/nouchix/khepra-pqc/envelope"
	"github.com/nouchix/khepra-pqc/kem"
	"github.com/nouchix/khepra-pqc/sign"
)

// Key, ciphertext and signature sizes for the NIST algorithms behind this
// package: ML-KEM-1024 (FIPS 203) and ML-DSA-87 (FIPS 204), both from the Go
// Cryptographic Module via github.com/nouchix/khepra-pqc.
const (
	KEMPublicKeySize      = kem.EncapsulationKeySize // 1568
	KEMPrivateKeySize     = kem.SeedSize             // 64-byte FIPS 203 seed
	KEMCiphertextSize     = kem.CiphertextSize       // 1568
	SigningPublicKeySize  = sign.PublicKeySize       // 2592
	SigningPrivateKeySize = sign.SeedSize            // 32-byte FIPS 204 seed
	SignatureSize         = sign.SignatureSize       // 4627

	// legacyMLDSA65PublicKeySize identifies public keys from before the move
	// to ML-DSA-87. Verify accepts them for historical signatures only.
	legacyMLDSA65PublicKeySize = 1952
)

// kuntinkantanLabel binds Kuntinkantan envelopes to their purpose.
const kuntinkantanLabel = "khepra/v3/kuntinkantan"

// GenerateKEMKey generates an ML-KEM-1024 key pair: the encapsulation key and
// the 64-byte decapsulation key seed.
func GenerateKEMKey() (pub, priv []byte, err error) {
	dk, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

// KEMEncapsulate generates a fresh shared secret for the holder of an
// ML-KEM-1024 encapsulation key. Returns (ciphertext, sharedSecret, error).
func KEMEncapsulate(pubKeyBytes []byte) (ciphertext, sharedSecret []byte, err error) {
	ek, err := kem.NewEncapsulationKey(pubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, ciphertext = ek.Encapsulate()
	return ciphertext, sharedSecret, nil
}

// KEMDecapsulate recovers the shared secret from an ML-KEM-1024 ciphertext.
func KEMDecapsulate(privKeyBytes, ciphertext []byte) (sharedSecret []byte, err error) {
	dk, err := kem.NewDecapsulationKey(privKeyBytes)
	if err != nil {
		return nil, err
	}
	return dk.Decapsulate(ciphertext)
}

// GenerateSigningKey generates an ML-DSA-87 key pair: the public key and the
// 32-byte private key seed.
func GenerateSigningKey() (pub, priv []byte, err error) {
	sk, err := sign.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return sk.PublicKey().Bytes(), sk.Bytes(), nil
}

// Sign signs msg with an ML-DSA-87 private key seed under the
// khepra/v3/adinkra context.
func Sign(skBytes []byte, msg []byte) ([]byte, error) {
	sk, err := sign.NewPrivateKey(skBytes)
	if err != nil {
		return nil, err
	}
	return sk.Sign(sign.ContextAdinkra, msg)
}

// Verify checks a signature made by Sign. It also verifies historical
// ML-DSA-65 signatures (1952-byte public keys, empty context) so that records
// signed before the move to ML-DSA-87 remain checkable; it never creates them.
// An invalid signature returns (false, nil); malformed keys return an error.
func Verify(pkBytes []byte, msg []byte, sig []byte) (bool, error) {
	var err error
	switch len(pkBytes) {
	case SigningPublicKeySize:
		var pk *sign.PublicKey
		pk, err = sign.NewPublicKey(pkBytes)
		if err != nil {
			return false, err
		}
		err = pk.Verify(sign.ContextAdinkra, msg, sig)
	case legacyMLDSA65PublicKeySize:
		err = sign.VerifyMLDSA65(pkBytes, "", msg, sig)
	default:
		return false, fmt.Errorf("invalid public key size: %d bytes (want %d for ML-DSA-87)", len(pkBytes), SigningPublicKeySize)
	}
	if errors.Is(err, sign.ErrInvalidSignature) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Kuntinkantan (Do not be arrogant) seals a message so that only the holder
// of the Okyeame (linguist) decapsulation key can read it. It produces a KHQ3
// envelope: ML-KEM-1024, HKDF-SHA-384 and AES-256-GCM with the header
// authenticated.
func Kuntinkantan(okyeamePub []byte, message []byte) ([]byte, error) {
	ek, err := kem.NewEncapsulationKey(okyeamePub)
	if err != nil {
		return nil, fmt.Errorf("kuntinkantan: %w", err)
	}
	return envelope.Seal(ek, kuntinkantanLabel, message)
}

// Sankofa (Go back and get it) opens an envelope produced by Kuntinkantan.
func Sankofa(okyeamePriv []byte, artifact []byte) ([]byte, error) {
	dk, err := kem.NewDecapsulationKey(okyeamePriv)
	if err != nil {
		return nil, fmt.Errorf("sankofa: %w", err)
	}
	plaintext, err := envelope.Open(dk, kuntinkantanLabel, artifact)
	if err != nil {
		return nil, fmt.Errorf("sankofa: %w", err)
	}
	return plaintext, nil
}

// AdinkraPrecedence defines the authority hierarchy for conflict resolution.
// Eban (Security) > Fawohodie (Privilege) > Nkyinkyim (State/Handoff) > Dwennimmen (Distributed Trust)
var AdinkraPrecedence = map[string]int{
	"Eban":       3,
	"Fawohodie":  2,
	"Nkyinkyim":  1,
	"Dwennimmen": 0,
}

// AdjacencyMatrix represents the symbolic graph of an Adinkra glyph.
// Used for spectral fingerprinting and key derivation (patent §3.1).
type AdjacencyMatrix [][]uint8

// SymbolMatrices holds the complete 8×8 binary adjacency matrices for each Adinkra symbol.
// Each matrix encodes the glyph's graph topology used in spectral fingerprint derivation.
//
// Eban (Fortress) — D₈ bipartite: bosonic nodes {0-3} fully connect to fermionic {4-7}.
// Fawohodie (Emancipation) — asymmetric exit-graph: high-density left side, sparse right side.
// Nkyinkyim (Journey) — twisted non-periodic: diagonal shift, no two rows identical.
// Dwennimmen (Ram's Horns) — near-complete bipartite: each node connects to 6+ others.
var SymbolMatrices = map[string]AdjacencyMatrix{
	// Eban: D₈ symmetric bipartite — bosonic {0-3} ↔ fermionic {4-7} (patent §3.1 AAE)
	"Eban": {
		{0, 0, 0, 0, 1, 1, 1, 1}, // node 0 (bosonic): connects to all fermionic
		{0, 0, 0, 0, 1, 1, 1, 1}, // node 1 (bosonic): connects to all fermionic
		{0, 0, 0, 0, 1, 1, 1, 1}, // node 2 (bosonic): connects to all fermionic
		{0, 0, 0, 0, 1, 1, 1, 1}, // node 3 (bosonic): connects to all fermionic
		{1, 1, 1, 1, 0, 0, 0, 0}, // node 4 (fermionic): connects to all bosonic
		{1, 1, 1, 1, 0, 0, 0, 0}, // node 5 (fermionic): connects to all bosonic
		{1, 1, 1, 1, 0, 0, 0, 0}, // node 6 (fermionic): connects to all bosonic
		{1, 1, 1, 1, 0, 0, 0, 0}, // node 7 (fermionic): connects to all bosonic
	},
	// Fawohodie: asymmetric exit-graph — privilege grant direction (left-dense, right-sparse)
	"Fawohodie": {
		{0, 1, 1, 1, 1, 0, 0, 0}, // node 0: dense left (grant node)
		{1, 0, 1, 1, 1, 0, 0, 0}, // node 1: dense left
		{1, 1, 0, 1, 0, 1, 0, 0}, // node 2: transitional
		{1, 1, 1, 0, 0, 0, 1, 0}, // node 3: transitional
		{1, 1, 0, 0, 0, 0, 0, 1}, // node 4: sparse right (exit node)
		{0, 0, 1, 0, 0, 0, 0, 1}, // node 5: sparse right
		{0, 0, 0, 1, 0, 0, 0, 1}, // node 6: sparse right
		{0, 0, 0, 0, 1, 1, 1, 0}, // node 7: exit sink
	},
	// Nkyinkyim: twisted non-periodic — diagonal shift, no two rows identical
	"Nkyinkyim": {
		{0, 1, 0, 0, 1, 0, 0, 1}, // row 0: 3-connected, twist pattern A
		{1, 0, 1, 0, 0, 1, 0, 0}, // row 1: 3-connected, shift +1
		{0, 1, 0, 1, 0, 0, 1, 0}, // row 2: 3-connected, shift +2
		{0, 0, 1, 0, 1, 0, 0, 1}, // row 3: 3-connected, shift +3
		{1, 0, 0, 1, 0, 1, 0, 0}, // row 4: 3-connected, shift +4
		{0, 1, 0, 0, 1, 0, 1, 0}, // row 5: 3-connected, shift +5
		{0, 0, 1, 0, 0, 1, 0, 1}, // row 6: 3-connected, shift +6
		{1, 0, 0, 1, 0, 0, 1, 0}, // row 7: 3-connected, shift +7 (unique)
	},
	// Dwennimmen: near-complete — each node connects to exactly 6 others (high distributed trust)
	"Dwennimmen": {
		{0, 1, 1, 1, 1, 1, 1, 0}, // node 0: 6-connected
		{1, 0, 1, 1, 1, 1, 0, 1}, // node 1: 6-connected
		{1, 1, 0, 1, 1, 0, 1, 1}, // node 2: 6-connected
		{1, 1, 1, 0, 0, 1, 1, 1}, // node 3: 6-connected
		{1, 1, 1, 0, 0, 1, 1, 1}, // node 4: 6-connected (symmetric to 3)
		{1, 1, 0, 1, 1, 0, 1, 1}, // node 5: 6-connected (symmetric to 2)
		{1, 0, 1, 1, 1, 1, 0, 1}, // node 6: 6-connected (symmetric to 1)
		{0, 1, 1, 1, 1, 1, 1, 0}, // node 7: 6-connected (symmetric to 0)
	},
}

// GetSpectralFingerprint computes a deterministic hash of the symbol's adjacency
// matrix. It is public data: it labels and binds symbols (for example in
// KHEPRA-KDF info strings) but must never be used as key material.
func GetSpectralFingerprint(symbol string) []byte {
	matrix, ok := SymbolMatrices[symbol]
	if !ok {
		return []byte(symbol) // Fallback to name-based entropy
	}

	h := sha256.New()
	for _, row := range matrix {
		h.Write(row)
	}
	return h.Sum(nil)
}

// ResolveConflict compares two symbols and returns the one with higher precedence.
func ResolveConflict(symbolA, symbolB string) string {
	if AdinkraPrecedence[symbolA] >= AdinkraPrecedence[symbolB] {
		return symbolA
	}
	return symbolB
}

// Hash generates a Khepra-standard hash, encoded in the Khepra Lattice.
// This creates the immutable "DNA" of any artifact.
// It wraps SHA-256 but encodes it using the poetic alphabet to obfuscate the structure.
func Hash(data []byte) string {
	h := sha256.Sum256(data)
	hexStr := fmt.Sprintf("%x", h)

	// Transmute standard hex (0-9, a-f) to Khepra Lattice (G-O)
	// Map: 0->G, 1->Y, 2->E, 3->N, 4->A, 5->M, 6->K, 7->H, 8->P, 9->R, a->S, b->U, c->T, d->I, e->L, f->O
	// Note: hexStr from fmt '%x' is lowercase.
	mapping := map[rune]byte{
		'0': 'G', '1': 'Y', '2': 'E', '3': 'N', '4': 'A', '5': 'M', '6': 'K', '7': 'H',
		'8': 'P', '9': 'R', 'a': 'S', 'b': 'U', 'c': 'T', 'd': 'I', 'e': 'L', 'f': 'O',
	}

	out := make([]byte, len(hexStr))
	for i, r := range hexStr {
		if val, ok := mapping[r]; ok {
			out[i] = val
		} else {
			out[i] = byte(r) // Should not happen for sha256 hex output
		}
	}
	return string(out)
}
