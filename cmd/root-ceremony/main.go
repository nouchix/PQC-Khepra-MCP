// Command root-ceremony runs the offline key ceremony for a KHEPRA license
// root (ML-DSA-87, FIPS 204) and delegates day-to-day signing to issuer keys.
//
// Run it on an offline machine (live USB, networking disabled). The root
// private key never touches disk in raw form: it exists only as Shamir shards,
// each encrypted under its own passphrase (PBKDF2-HMAC-SHA-384 + AES-256-GCM).
//
// Subcommands:
//
//	generate       create a root key and split it into shards
//	verify         rebuild the root from shards and check it against its public key
//	issuer-keygen  create an issuer key pair (run where the issuer key will live)
//	delegate       rebuild the root and sign an issuer certificate
//
// Typical sequence:
//
//	root-ceremony generate -label giza -out /media/ceremony
//	root-ceremony verify -root-pub /media/ceremony/giza-root.pub.pem -shards s1.json,s2.json,s3.json
//	root-ceremony issuer-keygen -out /etc/khepra/issuer          # on the issuing host
//	root-ceremony delegate -root-pub ... -shards ... -issuer-pub issuer.pub.pem \
//	    -purposes apikey,license -days 365 -out issuer-2026.json
//
// Commit only public material: the root public key (pkg/license/master_pubkey.go)
// and issuer certificates (pkg/license/trust/issuers/). Shards and passphrases
// go to separate locations; no single location may hold enough shards to
// rebuild the root, or a shard together with its passphrase.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/kms"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
	"github.com/nouchix/khepra-pqc/keyfile"
	"github.com/nouchix/khepra-pqc/sign"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = cmdGenerate(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "issuer-keygen":
		err = cmdIssuerKeygen(os.Args[2:])
	case "delegate":
		err = cmdDelegate(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "root-ceremony: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: root-ceremony generate|verify|issuer-keygen|delegate [flags]  (-h for flags)")
}

// ── generate ─────────────────────────────────────────────────────────────────

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	label := fs.String("label", "", "root name, e.g. giza, mcp, trust-os (required)")
	threshold := fs.Int("threshold", 3, "shards required to rebuild the root")
	total := fs.Int("total", 5, "shards generated")
	out := fs.String("out", "", "output directory on removable media (required)")
	allowRepo := fs.Bool("allow-in-repo", false, "allow -out inside a git working tree (not recommended)")
	_ = fs.Parse(args)
	if *label == "" || *out == "" {
		return errors.New("generate: -label and -out are required")
	}
	if *threshold < 2 || *total < *threshold || *total > 255 {
		return fmt.Errorf("generate: need 2 <= threshold <= total <= 255 (got %d of %d)", *threshold, *total)
	}
	if repo := gitWorkTree(*out); repo != "" && !*allowRepo {
		return fmt.Errorf("generate: %s is inside the git working tree %s; write shards to removable media", *out, repo)
	}

	shardDir := filepath.Join(*out, *label+"-shards")
	passDir := filepath.Join(*out, *label+"-passphrases")
	for _, d := range []string{shardDir, passDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}

	root, err := sign.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate: keygen: %w", err)
	}
	seed := root.Bytes()
	defer zero(seed)
	pub := root.PublicKey()

	passphrases := make([]string, *total)
	for i := range passphrases {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		passphrases[i] = base64.RawURLEncoding.EncodeToString(b)
	}
	next := 0
	if err := kms.SplitAndEncrypt(seed, *threshold, *total, shardDir, func(string) (string, error) {
		p := passphrases[next]
		next++
		return p, nil
	}); err != nil {
		return fmt.Errorf("generate: split: %w", err)
	}
	// One passphrase per file, so each can be moved to its own location.
	for i, p := range passphrases {
		name := filepath.Join(passDir, fmt.Sprintf("shard-%d-of-%d.passphrase.txt", i+1, *total))
		if err := os.WriteFile(name, []byte(p+"\n"), 0o600); err != nil {
			return err
		}
	}

	pubPath := filepath.Join(*out, *label+"-root.pub.pem")
	if err := keyfile.WriteVerifyingKey(pubPath, pub); err != nil {
		return err
	}
	fp := license.KeyFingerprint(pub.Bytes())

	fmt.Printf("Root %q generated (ML-DSA-87). %d shards, any %d rebuild it.\n\n", *label, *total, *threshold)
	fmt.Printf("  shards:       %s\n", shardDir)
	fmt.Printf("  passphrases:  %s\n", passDir)
	fmt.Printf("  public key:   %s\n", pubPath)
	fmt.Printf("  fingerprint:  %s\n\n", fp)
	fmt.Println("Next: run `verify` with any", *threshold, "shards, then move each shard and each")
	fmt.Println("passphrase to its own location and delete these copies.")
	fmt.Println()
	fmt.Println("pkg/license/master_pubkey.go value (public, safe to commit):")
	fmt.Printf("var MasterPublicKey = mustDecodeHex(\n\t\"%s\")\n", hex.EncodeToString(pub.Bytes()))
	return nil
}

// ── verify ───────────────────────────────────────────────────────────────────

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	rootPub := fs.String("root-pub", "", "root public key PEM (required)")
	shards := fs.String("shards", "", "comma-separated shard files (at least the threshold)")
	_ = fs.Parse(args)
	root, err := rebuildRoot(*rootPub, *shards)
	if err != nil {
		return err
	}
	defer zero(root)
	fmt.Println("OK: the shards rebuild the root; fingerprint", mustFingerprint(*rootPub))
	return nil
}

// ── issuer-keygen ────────────────────────────────────────────────────────────

func cmdIssuerKeygen(args []string) error {
	fs := flag.NewFlagSet("issuer-keygen", flag.ExitOnError)
	out := fs.String("out", "", "directory for issuer.key.pem (0600) and issuer.pub.pem (required)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("issuer-keygen: -out is required")
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	k, err := sign.GenerateKey()
	if err != nil {
		return err
	}
	keyPath := filepath.Join(*out, "issuer.key.pem")
	pubPath := filepath.Join(*out, "issuer.pub.pem")
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("issuer-keygen: %s exists; refusing to overwrite", keyPath)
	}
	if err := keyfile.WriteSigningKey(keyPath, k); err != nil {
		return err
	}
	if err := keyfile.WriteVerifyingKey(pubPath, k.PublicKey()); err != nil {
		return err
	}
	fmt.Printf("Issuer key written:\n  private (keep on this host): %s\n  public  (take to the ceremony): %s\n  fingerprint: %s\n",
		keyPath, pubPath, license.KeyFingerprint(k.PublicKey().Bytes()))
	return nil
}

// ── delegate ─────────────────────────────────────────────────────────────────

func cmdDelegate(args []string) error {
	fs := flag.NewFlagSet("delegate", flag.ExitOnError)
	rootPub := fs.String("root-pub", "", "root public key PEM (required)")
	shards := fs.String("shards", "", "comma-separated shard files (at least the threshold)")
	issuerPub := fs.String("issuer-pub", "", "issuer public key PEM (required)")
	purposes := fs.String("purposes", license.PurposeAPIKey, "comma-separated: apikey, license")
	days := fs.Int("days", 365, "validity in days (1–825)")
	out := fs.String("out", "", "output certificate JSON (required)")
	_ = fs.Parse(args)
	if *issuerPub == "" || *out == "" {
		return errors.New("delegate: -issuer-pub and -out are required")
	}
	if *days < 1 || *days > 825 {
		return fmt.Errorf("delegate: -days must be 1–825 (got %d)", *days)
	}
	ik, err := keyfile.ReadVerifyingKey(*issuerPub)
	if err != nil {
		return fmt.Errorf("delegate: issuer key: %w", err)
	}
	root, err := rebuildRoot(*rootPub, *shards)
	if err != nil {
		return err
	}
	defer zero(root)

	now := time.Now().UTC()
	cert, err := license.IssueIssuerCertificate(root, ik.Bytes(), splitList(*purposes), now.Add(-5*time.Minute), now.AddDate(0, 0, *days))
	if err != nil {
		return err
	}
	rk, err := keyfile.ReadVerifyingKey(*rootPub)
	if err != nil {
		return err
	}
	parsed, err := license.ParseIssuerCertificate(cert, rk.Bytes(), now)
	if err != nil {
		return fmt.Errorf("delegate: self-check failed: %w", err)
	}
	if err := os.WriteFile(*out, cert, 0o644); err != nil {
		return err
	}
	fmt.Printf("Issuer certificate %s written to %s\n  purposes: %s\n  valid: %s → %s\n  issuer fingerprint: %s\n",
		parsed.Serial, *out, strings.Join(parsed.Purposes, ","), parsed.NotBefore.Format(time.RFC3339),
		parsed.NotAfter.Format(time.RFC3339), license.KeyFingerprint(parsed.IssuerPublicKey))
	fmt.Println("Commit it to pkg/license/trust/issuers/ (public), or point KHEPRA_ISSUER_CERTS at it.")
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// rebuildRoot recombines shards (prompting for each passphrase) and checks the
// result against the root public key. It returns the 32-byte root seed.
func rebuildRoot(rootPubPath, shardList string) ([]byte, error) {
	if rootPubPath == "" || shardList == "" {
		return nil, errors.New("-root-pub and -shards are required")
	}
	want, err := keyfile.ReadVerifyingKey(rootPubPath)
	if err != nil {
		return nil, fmt.Errorf("root public key: %w", err)
	}
	seed, err := kms.RecoverKey(splitList(shardList), promptPassphrase)
	if err != nil {
		return nil, fmt.Errorf("rebuild root: %w", err)
	}
	k, err := sign.NewPrivateKey(seed)
	if err != nil {
		zero(seed)
		return nil, fmt.Errorf("rebuild root: %w", err)
	}
	if !bytes.Equal(k.PublicKey().Bytes(), want.Bytes()) {
		zero(seed)
		return nil, errors.New("rebuild root: the shards do not rebuild this root (fewer shards than the threshold, or shards from another root)")
	}
	return seed, nil
}

// stdinLines reads piped passphrases, one per line, across prompts.
var stdinLines = bufio.NewReader(os.Stdin)

// promptPassphrase reads a passphrase without echo when stdin is a terminal.
func promptPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	line, err := stdinLines.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func mustFingerprint(pubPath string) string {
	k, err := keyfile.ReadVerifyingKey(pubPath)
	if err != nil {
		return "?"
	}
	return license.KeyFingerprint(k.Bytes())
}

// gitWorkTree returns the enclosing git working tree of dir, or "".
func gitWorkTree(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
