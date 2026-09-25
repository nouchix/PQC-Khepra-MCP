// Command issue-license generates a device-bound KhepraLicense for the current machine.
//
// Unlike the original version of this tool, it does NOT generate a throwaway
// ML-DSA-65 keypair and self-sign with it — that produced a license that only
// ever verified against itself. Real licenses must be signed with the actual
// root private key, which exists only as Shamir shards under
// keys/root-ceremony/ (see cmd/root-ceremony). You need -threshold of those
// shard files and their passphrases to run this tool.
//
// Usage:
//
//	go run ./cmd/issue-license -tier master -tenant "SecRed Knowledge Inc." \
//	  -shards keys/root-ceremony/shard-1-of-5.json,keys/root-ceremony/shard-2-of-5.json,keys/root-ceremony/shard-3-of-5.json
//
// You will be prompted on stdin for each shard's passphrase.
//
// Output format defaults to raw JSON — boring, debuggable, and what real
// enterprise/DoD customers and their security reviewers expect. Pass
// -format=sacred to get the Sacred Runes encoding instead, for marketing
// screenshots / demo material / community-tier use — never as the documented
// default for paying customers. See pkg/license/sacred_license.go for why.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/fingerprint"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/kms"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
)

func main() {
	tier := flag.String("tier", "master", "License tier: community, pilot, enterprise, master")
	tenant := flag.String("tenant", "SecRed Knowledge Inc.", "Tenant name")
	ttl := flag.Duration("ttl", 365*24*time.Hour, "License validity duration (e.g. 8760h = 1 year)")
	shardsFlag := flag.String("shards", "", "comma-separated paths to root-key Shamir shard files (need >= threshold)")
	format := flag.String("format", "json", "output format for KHEPRA_LICENSE_KEY: json (default, primary) or sacred (opt-in, cosmetic)")
	flag.Parse()

	if *format != "json" && *format != "sacred" {
		fmt.Fprintf(os.Stderr, "invalid -format %q: must be \"json\" or \"sacred\"\n", *format)
		os.Exit(1)
	}

	logger := log.New(os.Stderr, "[issue-license] ", log.LstdFlags)

	if *shardsFlag == "" {
		logger.Fatalf("missing -shards: real licenses require reconstructing the root key from Shamir shards (see cmd/root-ceremony)")
	}
	shardPaths := strings.Split(*shardsFlag, ",")

	stdin := bufio.NewReader(os.Stdin)
	promptFn := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		line, err := stdin.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}

	rootPriv, err := kms.RecoverKey(shardPaths, promptFn)
	if err != nil {
		logger.Fatalf("root key reconstruction failed: %v", err)
	}
	defer func() {
		for i := range rootPriv {
			rootPriv[i] = 0
		}
	}()
	logger.Printf("root key reconstructed from %d shards", len(shardPaths))

	// Collect device fingerprint for binding
	fp, err := fingerprint.CollectDeviceFingerprint()
	if err != nil {
		logger.Fatalf("device fingerprint failed: %v", err)
	}
	deviceID := license.GenerateDeviceID(fp)
	logger.Printf("device_id: %s", deviceID[:16]+"…")

	sla := &license.SovereignLicenseAuthority{
		PrivateKey:   rootPriv,
		PublicKey:    license.MasterPublicKey,
		RevocationDB: license.NewRevocationDatabase(),
	}

	lic, err := sla.IssueLicense(deviceID, *tenant, *tier, *ttl)
	if err != nil {
		logger.Fatalf("license issuance failed: %v", err)
	}

	logger.Printf("license issued:")
	logger.Printf("  id:      %s", lic.LicenseID)
	logger.Printf("  tier:    %s (%s)", lic.Tier, license.RequiredTierDisplayName(lic.Tier))
	logger.Printf("  tenant:  %s", lic.Tenant)
	logger.Printf("  device:  %s…", lic.DeviceID[:16])
	logger.Printf("  expires: %s", lic.ExpiresAt.Format("2006-01-02"))

	licJSON, err := json.Marshal(lic)
	if err != nil {
		logger.Fatalf("marshal failed: %v", err)
	}

	sacred, err := license.EncodeLicenseDisplay(lic)
	if err != nil {
		logger.Fatalf("sacred encoding failed: %v", err)
	}

	// Self-check BOTH encodings against the pinned master public key
	// regardless of which one is displayed — the same check ParseMCPLicense
	// performs. Confirms the license is something the real server will
	// actually accept, in either format, not just something that verifies
	// against its own embedded key.
	var check license.KhepraLicense
	if err := json.Unmarshal(licJSON, &check); err != nil {
		logger.Fatalf("self-check unmarshal failed: %v", err)
	}
	if err := license.VerifySovereignLicense(&check, license.MasterPublicKey); err != nil {
		logger.Fatalf("self-check verification against pinned master key FAILED: %v", err)
	}

	decoded, err := license.DecodeLicenseDisplay(sacred)
	if err != nil {
		logger.Fatalf("sacred round-trip decode FAILED: %v", err)
	}
	if err := license.VerifySovereignLicense(decoded, license.MasterPublicKey); err != nil {
		logger.Fatalf("sacred round-trip self-check verification FAILED: %v", err)
	}
	logger.Printf("✅ self-verification PASSED for both raw JSON and Sacred Runes encoding")
	logger.Printf("")

	switch *format {
	case "sacred":
		logger.Printf("KHEPRA_LICENSE_KEY (-format=sacred — cosmetic only, see pkg/license/sacred_license.go):")
		fmt.Println(sacred)
		logger.Printf("")
		logger.Printf("⚠️  Sacred Runes format is NOT the documented default — do not hand this to")
		logger.Printf("   enterprise/DoD customers or their security reviewers as the primary value.")
	default:
		logger.Printf("KHEPRA_LICENSE_KEY:")
		fmt.Println(string(licJSON))
	}

	logger.Printf("")
	logger.Printf("Add to Claude Desktop config (claude_desktop_config.json) env block:")
	logger.Printf("  \"KHEPRA_LICENSE_KEY\": \"<the value above>\"")
}
