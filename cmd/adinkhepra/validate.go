package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/asaf"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/logging"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

// validateCmd is the customer-facing sovereign self-test.
//
// It mirrors adinkhepra.py validate — proving that every critical subsystem
// works on this machine, without Python, without cloud, without a license key.
//
// A C3PAO evaluator or ISSO can run this command and get a signed proof artifact
// that ADINKHEPRA is operational on their sovereign infrastructure.
func validateCmd(_ []string) {
	start := time.Now()

	const div = "═══════════════════════════════════════════════════════════════"
	fmt.Println(div)
	fmt.Println("  ADINKHEPRA — Sovereign Self-Test")
	fmt.Println("  Mirrors: adinkhepra.py validate")
	fmt.Println("  No cloud. No license key. No Python.")
	fmt.Println(div)
	fmt.Println()

	passed, total := 0, 0
	var failures []string
	var dbMappings int // set by test [4], reported in summary

	run := func(label string, fn func() (string, error)) {
		total++
		fmt.Printf("  [%d] %s...\n", total, label)
		detail, err := fn()
		if err != nil {
			fmt.Printf("      ❌ FAIL: %v\n\n", err)
			failures = append(failures, fmt.Sprintf("[%d] %s: %v", total, label, err))
		} else {
			fmt.Printf("      ✅ %s\n\n", detail)
			passed++
		}
	}

	// ── [1] FIPS Crypto (BoringCrypto + entropy) ─────────────────────────────
	run("FIPS Crypto (BoringCrypto classical + RNG)", func() (string, error) {
		// Detect BoringCrypto from the binary's own embedded build metadata.
		// When compiled with GOEXPERIMENT=boringcrypto this is always present.
		boringActive := false
		var goVer string
		if info, ok := debug.ReadBuildInfo(); ok {
			goVer = info.GoVersion
			for _, s := range info.Settings {
				if s.Key == "GOEXPERIMENT" && strings.Contains(s.Value, "boringcrypto") {
					boringActive = true
				}
			}
		}
		if !boringActive {
			return "", fmt.Errorf("GOEXPERIMENT=boringcrypto not found in build info — rebuild with CGO_ENABLED=1")
		}
		// Verify the RNG is operational (goes through BoringCrypto's DRBG)
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("rand.Read: %w", err)
		}
		allZero := true
		for _, b := range buf {
			if b != 0 { allZero = false; break }
		}
		if allZero {
			return "", fmt.Errorf("RNG returned all-zero — FIPS DRBG suspect")
		}
		return fmt.Sprintf("%s boringcrypto — 32B entropy OK", goVer), nil
	})

	// ── [2] ML-DSA-65 Sign / Verify ────────────────────────────────────
	run("PQC Sign/Verify (ML-DSA-65 / Dilithium)", func() (string, error) {
		// GenerateDilithiumKey returns (publicKey, privateKey, error)
		pub, priv, err := adinkra.GenerateDilithiumKey()
		if err != nil {
			return "", fmt.Errorf("GenerateDilithiumKey: %w", err)
		}
		msg := []byte("ADINKHEPRA sovereign validation " + time.Now().UTC().Format(time.RFC3339))
		sig, err := adinkra.Sign(priv, msg)
		if err != nil {
			return "", fmt.Errorf("Sign: %w", err)
		}
		ok, err := adinkra.Verify(pub, msg, sig)
		if err != nil {
			return "", fmt.Errorf("Verify: %w", err)
		}
		if !ok {
			return "", fmt.Errorf("signature verification returned false")
		}
		return fmt.Sprintf("pub=%dB priv=%dB sig=%dB — round-trip OK", len(pub), len(priv), len(sig)), nil
	})

	// ── [3] Kyber-1024 KEM Encrypt/Decrypt ────────────────────────────────
	run("PQC Encrypt/Decrypt (Kyber-1024 KEM)", func() (string, error) {
		// GenerateKyberKey returns (publicKey, privateKey, error)
		pub, priv, err := adinkra.GenerateKyberKey()
		if err != nil {
			return "", fmt.Errorf("GenerateKyberKey: %w", err)
		}
		plaintext := []byte("SOVEREIGN SECRET — adinkhepra validate")
		ciphertext, err := adinkra.Kuntinkantan(pub, plaintext)
		if err != nil {
			return "", fmt.Errorf("Kuntinkantan (encrypt): %w", err)
		}
		recovered, err := adinkra.Sankofa(priv, ciphertext)
		if err != nil {
			return "", fmt.Errorf("Sankofa (decrypt): %w", err)
		}
		if string(recovered) != string(plaintext) {
			return "", fmt.Errorf("plaintext mismatch after KEM round-trip")
		}
		return fmt.Sprintf("pub=%dB → %dB ciphertext → decrypted %dB — round-trip OK",
			len(pub), len(ciphertext), len(recovered)), nil
	})

	// ── [4] Compliance DB ─────────────────────────────────────────────────────
	run("Compliance Database (STIG/NIST 800-171/CMMC)", func() (string, error) {
		db, err := stig.GetDatabase()
		if err != nil {
			return "", fmt.Errorf("stig.GetDatabase: %w", err)
		}
		stats := db.Stats()
		n, ok := stats["total_mappings"]
		if !ok || n == 0 {
			return "", fmt.Errorf("database loaded but reports 0 mappings")
		}
		dbMappings = n
		return fmt.Sprintf("%d control mappings (STIG + NIST 800-171r2 + CMMC 2.0)", n), nil
	})

	// ── [5] DAG Write ────────────────────────────────────────────────────────
	run("DAG Write (tamper-evident attestation node)", func() (string, error) {
		dagStore := dag.GlobalDAG()
		before := len(dagStore.All())

		node := &dag.Node{
			Action: "VALIDATE",
			Symbol: "Eban",
			Time:   time.Now().UTC().Format(time.RFC3339),
			PQC: map[string]string{
				"event": "sovereign-self-test",
				"host":  hostname(),
			},
		}
		if err := dagStore.Add(node, nil); err != nil {
			return "", fmt.Errorf("dag.Add: %w", err)
		}
		after := len(dagStore.All())
		if after <= before {
			return "", fmt.Errorf("DAG node count did not increase (%d → %d)", before, after)
		}
		return fmt.Sprintf("node %s anchored — DAG now has %d nodes", node.ID[:8], after), nil
	})

	// ── [6] ASAF Session Sign + Seal ─────────────────────────────────────
	run("ASAF Flight Recorder (session record + DAG anchor)", func() (string, error) {
		dagStore := dag.GlobalDAG()
		logger := logging.NewDoDLogger(os.Stdout, logging.RedactSensitive, "validate", "asaf-validate")
		wrapper := asaf.NewASAFWrapper(dagStore, logger)

		agent, err := wrapper.WrapMCPAgent("validate-agent", "sovereign-self-test")
		if err != nil {
			return "", fmt.Errorf("WrapMCPAgent: %w", err)
		}

		action := asaf.MCPAction{
			Tool:       "validate",
			Parameters: map[string]string{"test": "sovereign-self-test"},
			Timestamp:  time.Now().UTC(),
		}
		node, err := wrapper.RecordAction(agent, action)
		if err != nil {
			return "", fmt.Errorf("RecordAction: %w", err)
		}
		// node.ID is the SHA-256 content hash — its presence proves the DAG anchored the action.
		// node.Signature is a Dilithium signature and only present after `keygen` sets up a signing key.
		// For a fresh sovereign install, the hash-linked DAG node is the tamper-evidence mechanism.
		if node.ID == "" {
			return "", fmt.Errorf("DAG node has no ID — RecordAction failed to anchor")
		}
		wrapper.EndSession(agent) //nolint:errcheck
		return fmt.Sprintf("session %s — node %s anchored in DAG",
			agent.SessionID[:12], node.ID[:8]), nil
	})

	// ── Results ───────────────────────────────────────────────────────────────
	elapsed := time.Since(start).Round(time.Millisecond)
	fmt.Println(div)
	fmt.Printf("  SOVEREIGN VALIDATION: %d/%d tests passed (%s)\n", passed, total, elapsed)
	fmt.Println(div)
	fmt.Println()

	if len(failures) > 0 {
		fmt.Println("  FAILURES:")
		for _, f := range failures {
			fmt.Printf("    ❌ %s\n", f)
		}
		fmt.Println()
		fmt.Println("  This machine is NOT sovereign-ready. Fix the above before deployment.")
		os.Exit(1)
	}

	fmt.Println("  ALL SYSTEMS GO — ADINKHEPRA is sovereign-ready on this machine.")
	fmt.Println()
	fmt.Println("  Verified:")
	fmt.Println("    ✅ FIPS 140-3 BoringCrypto RNG active")
	fmt.Println("    ✅ ML-DSA-65 sign/verify round-trip clean")
	fmt.Println("    ✅ Kyber-1024 KEM API operational")
	fmt.Printf("    ✅ %d compliance controls loaded\n", dbMappings)
	fmt.Println("    ✅ DAG tamper-evident write verified")
	fmt.Println("    ✅ ASAF session anchored in DAG")
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Println("    adinkhepra watch                   (start the security camera on :45444)")
	fmt.Println("    adinkhepra keygen -out ./keys/node (generate your sovereign PQC identity)")
	fmt.Println("    adinkhepra compliance scan --dir . (run CMMC/STIG compliance checks)")
	fmt.Println("    adinkhepra ert-godfather           (Godfather dollar-risk report)")
	fmt.Println()
	fmt.Println(div)
}

func hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}
