// Service Token Generator for KHEPRA Protocol
//
// Generates HMAC-signed service tokens for service-to-service authentication
// between CloudFlare Worker and DEMARC API server.
//
// Usage:
//   go run cmd/service-token/main.go generate cloudflare-telemetry
//   go run cmd/service-token/main.go validate <token>
//
// Environment:
//   KHEPRA_SERVICE_SECRET - Shared secret for HMAC signing (required for security)

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "generate":
		if len(os.Args) < 3 {
			fmt.Println("Error: service name required")
			fmt.Println("Usage: service-token generate <service-name>")
			fmt.Println("\nAvailable services:")
			fmt.Println("  - cloudflare-telemetry  (for CloudFlare Worker)")
			fmt.Println("  - license-signer        (for local license signer)")
			fmt.Println("  - master-console        (for Master Operator Console)")
			fmt.Println("  - asaf-bridge           (for Supabase MCP transparent proxy)")
			os.Exit(1)
		}
		generateToken(os.Args[2])

	case "validate":
		if len(os.Args) < 3 {
			fmt.Println("Error: token required")
			fmt.Println("Usage: service-token validate <token>")
			os.Exit(1)
		}
		validateToken(os.Args[2])

	case "init-secret":
		initSecret()

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("KHEPRA Service Token Generator")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  generate <service-name>  Generate a new service token")
	fmt.Println("  validate <token>         Validate an existing token")
	fmt.Println("  init-secret              Generate a new service secret")
	fmt.Println()
	fmt.Println("Available services:")
	fmt.Println("  - cloudflare-telemetry")
	fmt.Println("  - license-signer")
	fmt.Println("  - master-console")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  KHEPRA_SERVICE_SECRET - Required for secure token generation")
}

func generateToken(serviceName string) {
	// Validate service name
	validServices := map[string]bool{
		"cloudflare-telemetry": true,
		"license-signer":       true,
		"master-console":       true,
		"asaf-bridge":          true,
	}

	if !validServices[serviceName] {
		fmt.Printf("Error: Unknown service '%s'\n", serviceName)
		fmt.Println("\nValid services: cloudflare-telemetry, license-signer, master-console, asaf-bridge")
		os.Exit(1)
	}

	secret := getServiceSecret()

	// Generate timestamp (8 bytes, big-endian)
	timestamp := time.Now().Unix()
	timestampBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		timestampBytes[i] = byte(timestamp & 0xff)
		timestamp >>= 8
	}
	timestampHex := hex.EncodeToString(timestampBytes)

	// Generate HMAC signature
	message := "khepra-svc-" + serviceName + "-" + timestampHex
	signature := computeHMAC(message, secret)

	// Construct token
	token := "khepra-svc-" + serviceName + "-" + timestampHex + "-" + signature

	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              KHEPRA Service Token Generated                       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Service:    %s\n", serviceName)
	fmt.Printf("Generated:  %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Expires:    %s (5 minute validity window)\n", time.Now().Add(5*time.Minute).Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Token:")
	fmt.Println(token)
	fmt.Println()

	// Instructions based on service
	switch serviceName {
	case "cloudflare-telemetry":
		fmt.Println("To set this as a Cloudflare Worker secret:")
		fmt.Println()
		fmt.Printf("  wrangler secret put DEMARC_SERVICE_TOKEN\n")
		fmt.Println("  # Then paste the token above")
		fmt.Println()
		fmt.Println("Or programmatically:")
		fmt.Printf("  echo \"%s\" | wrangler secret put DEMARC_SERVICE_TOKEN\n", token)

	case "license-signer":
		fmt.Println("Set this as an environment variable for the license signer:")
		fmt.Println()
		fmt.Printf("  $env:KHEPRA_DEMARC_TOKEN = \"%s\"\n", token)

	case "master-console":
		fmt.Println("Configure this in your console environment:")
		fmt.Println()
		fmt.Printf("  KHEPRA_MASTER_TOKEN=%s\n", token)
	}
}

func validateToken(token string) {
	if !strings.HasPrefix(token, "khepra-svc-") {
		fmt.Println("❌ Invalid token format (must start with 'khepra-svc-')")
		os.Exit(1)
	}

	parts := strings.Split(token[11:], "-")
	if len(parts) < 3 {
		fmt.Println("❌ Invalid token structure")
		os.Exit(1)
	}

	serviceName := parts[0]
	timestampHex := parts[1]
	signatureHex := parts[len(parts)-1]

	// Decode and check timestamp
	timestampBytes, err := hex.DecodeString(timestampHex)
	if err != nil || len(timestampBytes) != 8 {
		fmt.Println("❌ Invalid timestamp encoding")
		os.Exit(1)
	}

	var timestamp int64
	for i := 0; i < 8; i++ {
		timestamp = (timestamp << 8) | int64(timestampBytes[i])
	}

	tokenTime := time.Unix(timestamp, 0)
	age := time.Since(tokenTime)

	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              KHEPRA Service Token Validation                      ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Service:     %s\n", serviceName)
	fmt.Printf("Created:     %s\n", tokenTime.Format(time.RFC3339))
	fmt.Printf("Age:         %s\n", age.Round(time.Second))

	// Check if expired
	if age > 5*time.Minute {
		fmt.Println("Status:      ❌ EXPIRED (older than 5 minutes)")
	} else if age < -5*time.Minute {
		fmt.Println("Status:      ❌ FUTURE-DATED (clock skew?)")
	} else {
		fmt.Println("Status:      ✅ Valid time window")
	}

	// Verify signature
	secret := getServiceSecret()
	message := "khepra-svc-" + serviceName + "-" + timestampHex
	expectedSig := computeHMAC(message, secret)

	if hmac.Equal([]byte(signatureHex), []byte(expectedSig)) {
		fmt.Println("Signature:   ✅ Valid HMAC-SHA256")
	} else {
		fmt.Println("Signature:   ❌ Invalid (secret mismatch?)")
	}
}

func initSecret() {
	// Generate 32 bytes of random data
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		fmt.Printf("Error generating random secret: %v\n", err)
		os.Exit(1)
	}

	secretHex := hex.EncodeToString(secret)

	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              KHEPRA Service Secret Generated                      ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("New Service Secret (256-bit):")
	fmt.Println(secretHex)
	fmt.Println()
	fmt.Println("Save this securely and set as environment variable on ALL services:")
	fmt.Println()
	fmt.Println("  # On DEMARC API Server (pkg/apiserver)")
	fmt.Printf("  export KHEPRA_SERVICE_SECRET=%s\n", secretHex)
	fmt.Println()
	fmt.Println("  # On CloudFlare Worker (set via wrangler)")
	fmt.Println("  wrangler secret put KHEPRA_SERVICE_SECRET")
	fmt.Println("  # Then paste the secret above")
	fmt.Println()
	fmt.Println("⚠️  This secret must be the SAME on all services!")
}

func getServiceSecret() []byte {
	secret := os.Getenv("KHEPRA_SERVICE_SECRET")
	if secret == "" {
		fmt.Println("⚠️  Warning: KHEPRA_SERVICE_SECRET not set")
		fmt.Println("   Using default development secret (NOT SECURE FOR PRODUCTION)")
		fmt.Println()
		fmt.Println("   Run 'service-token init-secret' to generate a secure secret")
		fmt.Println()
		secret = "khepra-service-secret-v1-development-only"
	}
	return []byte(secret)
}

func computeHMAC(message string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
