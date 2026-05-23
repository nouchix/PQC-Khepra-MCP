// Hardcoded keys - should FAIL validation
package crypto

// ❌ FAIL: Hardcoded development key (should be detected)
const DevelopmentKey = "khepra-dev-key-12345"

// ❌ FAIL: Hardcoded realm key (should be detected)
var AaruRealmKey = []byte("aaru-realm-key-secret-67890")

// ❌ FAIL: Another hardcoded key (should be detected)
func GetAtenKey() string {
	return "aten-realm-key-hardcoded"
}

// InitCrypto sets up crypto with hardcoded keys
func InitCrypto() {
	// ❌ FAIL: Multiple hardcoded keys
	apiKey := "khepra-dev-key-production-should-fail"
	realmKey := "aaru-realm-key-embedded"

	_ = apiKey
	_ = realmKey
}
