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
	flag.Parse()

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

	fmt.Println(string(licJSON))

	// Self-check against the pinned master public key — the same check
	// ParseMCPLicense performs. This confirms the license is something the
	// real server will actually accept, not just something that verifies
	// against its own embedded key.
	var check license.KhepraLicense
	if err := json.Unmarshal(licJSON, &check); err != nil {
		logger.Fatalf("self-check unmarshal failed: %v", err)
	}
	if err := license.VerifySovereignLicense(&check, license.MasterPublicKey); err != nil {
		logger.Fatalf("self-check verification against pinned master key FAILED: %v", err)
	}
	logger.Printf("✅ self-verification against pinned MasterPublicKey PASSED")
	logger.Printf("")
	logger.Printf("Add to Claude Desktop config (claude_desktop_config.json) env block:")
	logger.Printf("  \"KHEPRA_LICENSE_KEY\": \"<the JSON above>\"")
}
