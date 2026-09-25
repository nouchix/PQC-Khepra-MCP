// Command root-ceremony performs the one-time generation of the KHEPRA license
// signing root key, the actual trust anchor that ParseMCPLicense pins against.
//
// It is intentionally separate from cmd/root-keygen (which writes the private
// key to disk unencrypted) and from any per-device identity key (e.g.
// Adinkhepra-ASAF/bin/keys/mynode_dilithium, which rotates every 90 days and
// must never be used as a long-lived signing root).
//
// Output:
//   - stdout: the public key (safe to commit) and the exact Go snippet for
//     pkg/license/master_pubkey.go
//   - <out>/shard-N-of-M.json: Shamir shards of the private key (AES-GCM +
//     Argon2id encrypted per shard)
//   - <out>/PASSPHRASES_MOVE_TO_PASSWORD_MANAGER_THEN_DELETE.txt: the
//     auto-generated per-shard passphrases, written to disk (never to stdout)
//     so they don't end up in terminal scrollback or logs
//
// Usage:
//
//	go run ./cmd/root-ceremony -threshold 3 -total 5 -out keys/root-ceremony
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/kms"
)

func main() {
	threshold := flag.Int("threshold", 3, "shards required to reconstruct the root key")
	total := flag.Int("total", 5, "total shards generated")
	outDir := flag.String("out", "keys/root-ceremony", "output directory (gitignored: keys/)")
	flag.Parse()

	fmt.Println("Generating dedicated license-signing root key (ML-DSA-65)...")
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		fmt.Printf("keygen failed: %v\n", err)
		os.Exit(1)
	}

	passphrases := make([]string, *total)
	for i := range passphrases {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			fmt.Printf("passphrase generation failed: %v\n", err)
			os.Exit(1)
		}
		passphrases[i] = base64.RawURLEncoding.EncodeToString(buf)
	}

	idx := 0
	promptFn := func(_ string) (string, error) {
		p := passphrases[idx]
		idx++
		return p, nil
	}

	if err := kms.SplitAndEncrypt(priv, *threshold, *total, *outDir, promptFn); err != nil {
		fmt.Printf("shamir split failed: %v\n", err)
		os.Exit(1)
	}

	passFile := filepath.Join(*outDir, "PASSPHRASES_MOVE_TO_PASSWORD_MANAGER_THEN_DELETE.txt")
	var passContent string
	for i, p := range passphrases {
		passContent += fmt.Sprintf("shard-%d-of-%d.json passphrase: %s\n", i+1, *total, p)
	}
	if err := os.WriteFile(passFile, []byte(passContent), 0600); err != nil {
		fmt.Printf("failed to write passphrase file: %v\n", err)
		os.Exit(1)
	}

	// Best-effort zeroing of the in-memory private key now that it's been split.
	for i := range priv {
		priv[i] = 0
	}

	pubHex := hex.EncodeToString(pub)
	fmt.Println()
	fmt.Println("✅ Root key generated and split. The private key was NOT written to disk in")
	fmt.Println("   raw form — only Shamir shards, individually passphrase-encrypted, in:")
	fmt.Printf("     %s\n", *outDir)
	fmt.Println()
	fmt.Printf("⚠️  Passphrases (one per shard) were written to:\n     %s\n", passFile)
	fmt.Println("   Move each shard file + its passphrase to a SEPARATE secure location")
	fmt.Println("   (password manager entries, separate USB drives, etc.), then delete")
	fmt.Println("   this passphrase file from disk.")
	fmt.Println()
	fmt.Println("Public key (safe to commit) — paste into pkg/license/master_pubkey.go:")
	fmt.Println()
	fmt.Println("package license")
	fmt.Println()
	fmt.Println(`import "encoding/hex"`)
	fmt.Println()
	fmt.Println("// MasterPublicKey is the ML-DSA-65 public key for the KHEPRA license")
	fmt.Println("// signing root. Generated via cmd/root-ceremony; the corresponding")
	fmt.Println("// private key exists only as Shamir shards (see keys/root-ceremony/,")
	fmt.Println("// not committed). ParseMCPLicense pins against this constant — do not")
	fmt.Println("// remove the pinning in VerifySovereignLicense.")
	fmt.Println("var MasterPublicKey = mustDecodeHex(")
	fmt.Printf("\t\"%s\")\n", pubHex)
	fmt.Println()
	fmt.Println("func mustDecodeHex(s string) []byte {")
	fmt.Println("\tb, err := hex.DecodeString(s)")
	fmt.Println("\tif err != nil {")
	fmt.Println("\t\tpanic(\"license: invalid MasterPublicKey hex: \" + err.Error())")
	fmt.Println("\t}")
	fmt.Println("\treturn b")
	fmt.Println("}")
}
