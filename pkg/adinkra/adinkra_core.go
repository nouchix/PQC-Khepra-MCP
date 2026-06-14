package adinkra

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// GenerateKyberKey generates a Kyber-1024 key pair.
func GenerateKyberKey() ([]byte, []byte, error) {
	pk, sk, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pkBytes, _ := pk.MarshalBinary()
	skBytes, _ := sk.MarshalBinary()

	return pkBytes, skBytes, nil
}

// GenerateDilithiumKey generates a ML-DSA-65 (Dilithium3) key pair.
func GenerateDilithiumKey() ([]byte, []byte, error) {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pkBytes := make([]byte, mldsa65.PublicKeySize)
	skBytes := make([]byte, mldsa65.PrivateKeySize)
	pk.Pack((*[mldsa65.PublicKeySize]byte)(pkBytes))
	sk.Pack((*[mldsa65.PrivateKeySize]byte)(skBytes))

	return pkBytes, skBytes, nil
}

// Sign signs a message using a ML-DSA-65 private key.
func Sign(skBytes []byte, msg []byte) ([]byte, error) {
	if len(skBytes) != mldsa65.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", mldsa65.PrivateKeySize, len(skBytes))
	}
	var sk mldsa65.PrivateKey
	sk.Unpack((*[mldsa65.PrivateKeySize]byte)(skBytes))

	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(&sk, msg, nil, false, sig)
	return sig, nil
}

// Verify verifies a ML-DSA-65 signature.
func Verify(pkBytes []byte, msg []byte, sig []byte) (bool, error) {
	if len(pkBytes) != mldsa65.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d", mldsa65.PublicKeySize, len(pkBytes))
	}
	var pk mldsa65.PublicKey
	pk.Unpack((*[mldsa65.PublicKeySize]byte)(pkBytes))
	return mldsa65.Verify(&pk, msg, nil, sig), nil
}

// KyberEncapsulate generates a fresh shared secret and encapsulates it with the given
// Kyber-1024 public key. Returns (ciphertext, sharedSecret, error).
func KyberEncapsulate(pubKeyBytes []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(pubKeyBytes) != kyber1024.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid Kyber public key size: expected %d, got %d",
			kyber1024.PublicKeySize, len(pubKeyBytes))
	}
	pk, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Kyber public key: %w", err)
	}
	ct, ss, err := kyber1024.Scheme().Encapsulate(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("Kyber encapsulation failed: %w", err)
	}
	return ct, ss, nil
}

// KyberDecapsulate recovers the shared secret from a Kyber-1024 ciphertext using the private key.
func KyberDecapsulate(privKeyBytes, ciphertext []byte) (sharedSecret []byte, err error) {
	if len(privKeyBytes) != kyber1024.PrivateKeySize {
		return nil, fmt.Errorf("invalid Kyber private key size: expected %d, got %d",
			kyber1024.PrivateKeySize, len(privKeyBytes))
	}
	sk, err := kyber1024.Scheme().UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Kyber private key: %w", err)
	}
	ss, err := kyber1024.Scheme().Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Kyber decapsulation failed: %w", err)
	}
	return ss, nil
}

// Kuntinkantan (Do not be arrogant): Bends the reality of the detailed message
// into a riddle that only the Okyeame (Linguist) can unravel.
// Uses Kyber-1024 for the heavy lifting of the spirit, and the Merkaba Engine (White Box) for the weaving.
func Kuntinkantan(okyeamePub []byte, message []byte) ([]byte, error) {
	// 1. Summon the Sunsum (The Spirit/Ephemeral Key)
	// We use the entropy of the universe to forge a fleeting soul.
	pk, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(okyeamePub)
	if err != nil {
		return nil, fmt.Errorf("the staff is broken: %v", err)
	}

	// Encapsulate the spirit.
	// 'cypher' is the clay vessel (capsule) holding the shared secret.
	// 'sharedSpirit' is the secret itself (the symmetric key).
	cypher, sharedSpirit, err := kyber1024.Scheme().Encapsulate(pk)
	if err != nil {
		return nil, fmt.Errorf("failed to bottle the spirit: %v", err)
	}

	// 2. Weave the Pattern (Merkaba White Box Encryption)
	// The sharedSpirit becomes the Seed for the Sacred Geometry.
	mk := NewMerkaba(sharedSpirit)

	// Cast the Veil (Seal with Sacred Alphabet)
	sealedLattice, err := mk.Seal(message)
	if err != nil {
		return nil, fmt.Errorf("the weaver refused the thread: %v", err)
	}
	wovenMatter := []byte(sealedLattice)

	// 3. The Final Artifact: [Capsule (Clay) | WovenMatter (Sacred Lattice)]
	// We concatenate them for transport across the void.
	// Note: No nonce is passed; randomness is derived deterministically from the SharedSpirit
	// via the ChaosEngine (Tree of Life walk), making it a true White Box implementation.
	artifact := make([]byte, 0, len(cypher)+len(wovenMatter))
	artifact = append(artifact, cypher...)
	artifact = append(artifact, wovenMatter...)

	return artifact, nil
}

// Sankofa (Go back and get it): Retrieves the lost meaning from the artifact.
// Requires the private Okyeame (Private Key) to break the clay vessel.
func Sankofa(okyeamePriv []byte, artifact []byte) ([]byte, error) {
	// 1. Separate the Elements
	// We must know the geometry of the capsule to find where the clay ends.
	capsuleSize := kyber1024.Scheme().CiphertextSize()
	if len(artifact) < capsuleSize {
		return nil, fmt.Errorf("artifact is dust")
	}

	clay := artifact[:capsuleSize]
	wovenMatter := artifact[capsuleSize:]

	// 2. Break the Clay (Decapsulate)
	sk, err := kyber1024.Scheme().UnmarshalBinaryPrivateKey(okyeamePriv)
	if err != nil {
		return nil, fmt.Errorf("the hand does not fit the glove: %v", err)
	}

	sharedSpirit, err := kyber1024.Scheme().Decapsulate(sk, clay)
	if err != nil {
		return nil, fmt.Errorf("the spirit has fled: %v", err)
	}

	// 3. Unweave the Pattern (Merkaba White Box Decryption)
	mk := NewMerkaba(sharedSpirit)

	plaintext, err := mk.Unseal(string(wovenMatter))
	if err != nil {
		return nil, fmt.Errorf("the weave is tangled (auth failed): %v", err)
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

// GetSpectralFingerprint computes a deterministic hash of the symbol's adjacency matrix
// to seed the DRBG for key generation.
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
