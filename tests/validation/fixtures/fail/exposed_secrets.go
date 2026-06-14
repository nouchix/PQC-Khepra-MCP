//go:build ignore
// This file is a test fixture � excluded from normal builds.

// Exposed secrets - should FAIL validation
package config

// ❌ FAIL: Hardcoded API keys and tokens
const (
	StripeAPIKey      = "REDACTED_PLACEHOLDER"
	TwilioAuthToken   = "REDACTED_PLACEHOLDER"
	SupabaseSecretKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
	AWSSecretKey      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// ❌ FAIL: Hardcoded passwords
var (
	DatabasePassword = "REDACTED_PLACEHOLDER"
	AdminPassword    = "REDACTED_PLACEHOLDER"
)

// ❌ FAIL: Private keys embedded in code
func GetPrivateKey() string {
	privateKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJT...
-----END PRIVATE KEY-----`
	return privateKey
}

// ❌ FAIL: API token in function
func InitializeServices() {
	apiToken := "REDACTED_PLACEHOLDER"
	_ = apiToken
}
