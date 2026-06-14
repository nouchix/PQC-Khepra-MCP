package crypto

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CryptoAsset represents a discovered cryptographic implementation
// This is the "labeled data" in the Scale AI analogy
type CryptoAsset struct {
	// Bounding Box - Scope of Influence
	FilePath     string   `json:"file_path"`
	LineNumber   int      `json:"line_number,omitempty"`
	Dependencies []string `json:"dependencies"` // What breaks if we change this?

	// Semantic Segmentation - Usage Context
	Algorithm    string          `json:"algorithm"`     // RSA, ECDSA, AES, etc.
	KeyLength    int             `json:"key_length"`    // 2048, 256, etc.
	UsageContext CryptoUsageType `json:"usage_context"` // Identity, Transport, Data-at-Rest

	// Metadata Tags - The CBOM DNA
	Vendor          string    `json:"vendor"`           // OpenSSL, Go stdlib, proprietary
	Implementation  string    `json:"implementation"`   // Library/module name
	ExpirationDate  time.Time `json:"expiration_date,omitempty"`
	QuantumRisk     RiskLevel `json:"quantum_risk"`
	MigrationPath   string    `json:"migration_path"` // What to replace it with
	BlastRadius     int       `json:"blast_radius"`   // Number of dependent systems

	// Human-in-the-Loop annotations
	ManualReview    bool      `json:"manual_review"`    // Needs analyst confirmation
	ReviewNotes     string    `json:"review_notes,omitempty"`
	AnalystVerified bool      `json:"analyst_verified"`

	// Provenance tracking
	DiscoveredAt time.Time `json:"discovered_at"`
	DiscoveryMethod string `json:"discovery_method"` // static_analysis, runtime_trace, config_scan

	// Symbol binding (Adinkra integration)
	Symbol string `json:"symbol,omitempty"` // Eban, Nkyinkyim, etc.
}

// CryptoUsageType categorizes how crypto is used
type CryptoUsageType string

const (
	UsageIdentity       CryptoUsageType = "AUTH_SIGNING"        // User/service authentication
	UsageTransport      CryptoUsageType = "DATA_IN_TRANSIT"     // TLS/HTTPS
	UsageDataAtRest     CryptoUsageType = "DATA_AT_REST"        // Database encryption
	UsageKeyExchange    CryptoUsageType = "KEY_EXCHANGE"        // DH, ECDH
	UsageObfuscation    CryptoUsageType = "LOW_RISK_OBFUSCATION" // Non-security XOR, etc.
	UsageIntegrityCheck CryptoUsageType = "INTEGRITY_CHECK"     // HMAC, signatures
	UsageUnknown        CryptoUsageType = "UNKNOWN"             // Needs analysis
)

// RiskLevel quantifies quantum threat
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL" // RSA-1024, broken now
	RiskHigh     RiskLevel = "HIGH"     // RSA-2048, ECC P-256 (breaks <2030)
	RiskMedium   RiskLevel = "MEDIUM"   // RSA-3072, ECC P-384 (breaks 2030-2040)
	RiskLow      RiskLevel = "LOW"      // RSA-4096+ (breaks >2040)
	RiskSafe     RiskLevel = "QUANTUM_SAFE" // Dilithium, Kyber, AES-256
)

// CryptoInventory is the complete "training set" for migration planning
type CryptoInventory struct {
	Assets        []CryptoAsset      `json:"assets"`
	ScanTimestamp time.Time          `json:"scan_timestamp"`
	ScanID        string             `json:"scan_id"`
	Statistics    InventoryStats     `json:"statistics"`
	DAGMap        map[string][]string `json:"dag_map"` // Dependency graph
}

// InventoryStats provides summary metrics
type InventoryStats struct {
	TotalAssets       int            `json:"total_assets"`
	ByAlgorithm       map[string]int `json:"by_algorithm"`
	ByRiskLevel       map[string]int `json:"by_risk_level"`
	ByUsageContext    map[string]int `json:"by_usage_context"`
	RequiresMigration int            `json:"requires_migration"`
	QuantumSafe       int            `json:"quantum_safe"`
	NeedsReview       int            `json:"needs_review"`
}

// DiscoverCryptoAssets performs comprehensive cryptographic asset discovery
// This is the "data labeling engine" for PQC migration
func DiscoverCryptoAssets(rootDir string) (*CryptoInventory, error) {
	inventory := &CryptoInventory{
		Assets:        []CryptoAsset{},
		ScanTimestamp: time.Now().UTC(),
		ScanID:        fmt.Sprintf("CRYPTO-DISCO-%d", time.Now().Unix()),
		DAGMap:        make(map[string][]string),
	}

	// Discovery strategies
	strategies := []DiscoveryStrategy{
		&CertificateScanner{},
		&ConfigFileScanner{},
		&SourceCodeScanner{},
		&BinaryAnalyzer{},
		&NetworkConfigScanner{},
	}

	for _, strategy := range strategies {
		assets, err := strategy.Discover(rootDir)
		if err != nil {
			// Log but continue with other strategies
			fmt.Printf("[WARN] %s failed: %v\n", strategy.Name(), err)
			continue
		}
		inventory.Assets = append(inventory.Assets, assets...)
	}

	// Build dependency graph (DAG)
	inventory.buildDAG()

	// Calculate statistics
	inventory.calculateStats()

	// Assign migration priorities
	inventory.prioritizeMigration()

	return inventory, nil
}

// DiscoveryStrategy defines interface for different discovery methods
type DiscoveryStrategy interface {
	Name() string
	Discover(rootDir string) ([]CryptoAsset, error)
}

// CertificateScanner finds X.509 certificates and keys
type CertificateScanner struct{}

func (s *CertificateScanner) Name() string { return "CertificateScanner" }

func (s *CertificateScanner) Discover(rootDir string) ([]CryptoAsset, error) {
	var assets []CryptoAsset

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Look for certificate/key files
		ext := strings.ToLower(filepath.Ext(path))
		base := strings.ToLower(filepath.Base(path))

		if ext == ".pem" || ext == ".crt" || ext == ".cer" || ext == ".key" ||
			strings.Contains(base, "cert") || strings.Contains(base, "key") {

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			// Parse PEM blocks
			block, _ := pem.Decode(data)
			if block == nil {
				return nil
			}

			switch block.Type {
			case "CERTIFICATE":
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					asset := analyzeCertificate(cert, path)
					assets = append(assets, asset)
				}

			case "RSA PRIVATE KEY", "PRIVATE KEY":
				asset := analyzePrivateKey(block, path)
				assets = append(assets, asset)
			}
		}

		return nil
	})

	return assets, err
}

// analyzeCertificate extracts crypto metadata from X.509 cert
func analyzeCertificate(cert *x509.Certificate, path string) CryptoAsset {
	asset := CryptoAsset{
		FilePath:        path,
		ExpirationDate:  cert.NotAfter,
		DiscoveredAt:    time.Now().UTC(),
		DiscoveryMethod: "x509_parsing",
		Vendor:          "Unknown",
		Implementation:  "X.509 Certificate",
		UsageContext:    UsageTransport, // Certs are typically for TLS
	}

	// Determine algorithm and key size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		asset.Algorithm = "RSA"
		asset.KeyLength = pub.N.BitLen()
		asset.QuantumRisk = classifyRSARisk(asset.KeyLength)
		asset.MigrationPath = "Dilithium3 (NIST FIPS 204)"

	case *ecdsa.PublicKey:
		asset.Algorithm = "ECDSA"
		asset.KeyLength = pub.Curve.Params().BitSize
		asset.QuantumRisk = classifyECCRisk(asset.KeyLength)
		asset.MigrationPath = "Dilithium3 or Kyber-1024"

	case ed25519.PublicKey:
		asset.Algorithm = "Ed25519"
		asset.KeyLength = 256
		asset.QuantumRisk = RiskHigh // Ed25519 is quantum-vulnerable
		asset.MigrationPath = "Dilithium3"

	default:
		asset.Algorithm = "Unknown"
		asset.ManualReview = true
	}

	// Check if expired
	if time.Now().After(cert.NotAfter) {
		asset.ReviewNotes = "Certificate EXPIRED - immediate replacement required"
		asset.ManualReview = true
	}

	return asset
}

// analyzePrivateKey analyzes PEM-encoded private keys
func analyzePrivateKey(block *pem.Block, path string) CryptoAsset {
	asset := CryptoAsset{
		FilePath:        path,
		DiscoveredAt:    time.Now().UTC(),
		DiscoveryMethod: "pem_parsing",
		UsageContext:    UsageIdentity,
	}

	// Attempt to parse as RSA
	if strings.Contains(block.Type, "RSA") {
		asset.Algorithm = "RSA"
		asset.QuantumRisk = RiskHigh // Assume RSA-2048
		asset.MigrationPath = "Dilithium3"
		asset.ManualReview = true // Need to determine exact key size
		asset.ReviewNotes = "Private key detected - verify key strength"
	}

	return asset
}

// ConfigFileScanner finds crypto configuration in config files
type ConfigFileScanner struct{}

func (s *ConfigFileScanner) Name() string { return "ConfigFileScanner" }

func (s *ConfigFileScanner) Discover(rootDir string) ([]CryptoAsset, error) {
	var assets []CryptoAsset

	configPatterns := []string{
		"*.yaml", "*.yml", "*.conf", "*.cfg", "*.ini", "*.json", "*.toml",
	}

	cryptoRegexes := map[string]*regexp.Regexp{
		"RSA":    regexp.MustCompile(`(?i)rsa[-_]?(2048|3072|4096)`),
		"AES":    regexp.MustCompile(`(?i)aes[-_]?(128|192|256)`),
		"TLS":    regexp.MustCompile(`(?i)tls[-_]?version.*1\.[0-3]`),
		"ECDSA":  regexp.MustCompile(`(?i)(ecdsa|ecc)[-_]?(p256|p384|p521)`),
		"SHA":    regexp.MustCompile(`(?i)sha[-_]?(1|256|384|512)`),
	}

	for _, pattern := range configPatterns {
		matches, _ := filepath.Glob(filepath.Join(rootDir, "**", pattern))
		for _, match := range matches {
			data, err := os.ReadFile(match)
			if err != nil {
				continue
			}

			content := string(data)
			scanner := bufio.NewScanner(strings.NewReader(content))
			lineNum := 0

			for scanner.Scan() {
				lineNum++
				line := scanner.Text()

				for alg, regex := range cryptoRegexes {
					if regex.MatchString(line) {
						asset := CryptoAsset{
							FilePath:        match,
							LineNumber:      lineNum,
							Algorithm:       alg,
							DiscoveredAt:    time.Now().UTC(),
							DiscoveryMethod: "config_regex",
							UsageContext:    inferUsageFromContext(line),
						}

						// Extract key size if present
						sizeMatch := regexp.MustCompile(`\d{3,4}`).FindString(line)
						if sizeMatch != "" {
							fmt.Sscanf(sizeMatch, "%d", &asset.KeyLength)
						}

						asset.QuantumRisk = classifyRiskByAlgorithm(alg, asset.KeyLength)
						asset.MigrationPath = suggestMigrationPath(alg, asset.UsageContext)

						assets = append(assets, asset)
					}
				}
			}
		}
	}

	return assets, nil
}

// SourceCodeScanner finds crypto imports and function calls
type SourceCodeScanner struct{}

func (s *SourceCodeScanner) Name() string { return "SourceCodeScanner" }

func (s *SourceCodeScanner) Discover(rootDir string) ([]CryptoAsset, error) {
	var assets []CryptoAsset

	// Language-specific patterns
	patterns := map[string][]string{
		"go":     {"crypto/rsa", "crypto/ecdsa", "crypto/aes", "crypto/tls"},
		"python": {"from cryptography", "import ssl", "import hashlib"},
		"java":   {"javax.crypto", "java.security"},
		"js":     {"require('crypto')", "import crypto"},
	}

	extensions := map[string]string{
		".go": "go", ".py": "python", ".java": "java",
		".js": "js", ".ts": "js",
	}

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		lang, ok := extensions[ext]
		if !ok {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		scanner := bufio.NewScanner(strings.NewReader(content))
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, pattern := range patterns[lang] {
				if strings.Contains(line, pattern) {
					asset := CryptoAsset{
						FilePath:        path,
						LineNumber:      lineNum,
						DiscoveredAt:    time.Now().UTC(),
						DiscoveryMethod: "source_code_import",
						Implementation:  pattern,
					}

					// Infer algorithm from import
					asset.Algorithm = inferAlgorithmFromImport(pattern)
					asset.UsageContext = UsageUnknown
					asset.ManualReview = true
					asset.ReviewNotes = "Manual code review needed to determine usage context"

					assets = append(assets, asset)
				}
			}
		}

		return nil
	})

	return assets, err
}

// BinaryAnalyzer scans compiled binaries for crypto libraries
type BinaryAnalyzer struct{}

func (s *BinaryAnalyzer) Name() string { return "BinaryAnalyzer" }

func (s *BinaryAnalyzer) Discover(rootDir string) ([]CryptoAsset, error) {
	// Simplified binary analysis - in production, use proper binary parsers
	// This would scan ELF/PE/Mach-O symbols for crypto library linkage
	return []CryptoAsset{}, nil
}

// NetworkConfigScanner finds crypto in network/TLS configs
type NetworkConfigScanner struct{}

func (s *NetworkConfigScanner) Name() string { return "NetworkConfigScanner" }

func (s *NetworkConfigScanner) Discover(rootDir string) ([]CryptoAsset, error) {
	var assets []CryptoAsset

	// Scan for common TLS/SSL config files
	tlsConfigs := []string{
		"nginx.conf", "apache2.conf", "httpd.conf", "traefik.yml",
		"haproxy.cfg", "ssl.conf", "tls.conf",
	}

	for _, configFile := range tlsConfigs {
		matches, _ := filepath.Glob(filepath.Join(rootDir, "**", configFile))
		for _, match := range matches {
			data, err := os.ReadFile(match)
			if err != nil {
				continue
			}

			// Check for weak TLS versions
			if regexp.MustCompile(`(?i)ssl_protocol.*TLSv1[^.2-3]`).Match(data) {
				asset := CryptoAsset{
					FilePath:        match,
					Algorithm:       "TLS",
					DiscoveredAt:    time.Now().UTC(),
					DiscoveryMethod: "tls_config_scan",
					UsageContext:    UsageTransport,
					QuantumRisk:     RiskMedium,
					ManualReview:    true,
					ReviewNotes:     "Legacy TLS version detected - upgrade to TLS 1.3 with PQC cipher suites",
				}
				assets = append(assets, asset)
			}
		}
	}

	return assets, nil
}

// Helper functions for risk classification

func classifyRSARisk(keyLength int) RiskLevel {
	switch {
	case keyLength < 2048:
		return RiskCritical
	case keyLength == 2048:
		return RiskHigh
	case keyLength == 3072:
		return RiskMedium
	case keyLength >= 4096:
		return RiskLow
	default:
		return RiskHigh
	}
}

func classifyECCRisk(keyLength int) RiskLevel {
	switch {
	case keyLength < 256:
		return RiskCritical
	case keyLength == 256:
		return RiskHigh
	case keyLength == 384:
		return RiskMedium
	case keyLength >= 521:
		return RiskLow
	default:
		return RiskHigh
	}
}

func classifyRiskByAlgorithm(alg string, keyLength int) RiskLevel {
	switch strings.ToUpper(alg) {
	case "RSA":
		return classifyRSARisk(keyLength)
	case "ECDSA", "ECC":
		return classifyECCRisk(keyLength)
	case "AES":
		if keyLength >= 256 {
			return RiskSafe
		}
		return RiskMedium
	case "SHA":
		if keyLength == 1 {
			return RiskCritical
		}
		return RiskSafe
	case "TLS":
		return RiskMedium // Depends on version
	default:
		return RiskHigh
	}
}

func suggestMigrationPath(alg string, usage CryptoUsageType) string {
	switch strings.ToUpper(alg) {
	case "RSA", "ECDSA":
		if usage == UsageIdentity || usage == UsageIntegrityCheck {
			return "Dilithium3 (NIST FIPS 204)"
		}
		return "Kyber-1024 (NIST FIPS 203)"
	case "AES":
		return "No migration needed (AES-256 is quantum-safe)"
	case "TLS":
		return "TLS 1.3 with hybrid Kyber+X25519 cipher suites"
	default:
		return "Manual assessment required"
	}
}

func inferUsageFromContext(line string) CryptoUsageType {
	line = strings.ToLower(line)
	switch {
	case strings.Contains(line, "auth") || strings.Contains(line, "sign"):
		return UsageIdentity
	case strings.Contains(line, "tls") || strings.Contains(line, "ssl") || strings.Contains(line, "https"):
		return UsageTransport
	case strings.Contains(line, "encrypt") || strings.Contains(line, "decrypt"):
		return UsageDataAtRest
	case strings.Contains(line, "hmac") || strings.Contains(line, "hash"):
		return UsageIntegrityCheck
	default:
		return UsageUnknown
	}
}

func inferAlgorithmFromImport(importPath string) string {
	switch {
	case strings.Contains(importPath, "rsa"):
		return "RSA"
	case strings.Contains(importPath, "ecdsa"):
		return "ECDSA"
	case strings.Contains(importPath, "aes"):
		return "AES"
	case strings.Contains(importPath, "tls"):
		return "TLS"
	default:
		return "Unknown"
	}
}

// buildDAG constructs a file-level dependency graph from the asset inventory.
// Each asset's FilePath is mapped to the set of other asset paths that share
// an import relationship (detected by directory co-location and source pattern).
func (inv *CryptoInventory) buildDAG() {
	pathSet := make(map[string]struct{}, len(inv.Assets))
	for _, a := range inv.Assets {
		pathSet[a.FilePath] = struct{}{}
	}

	for _, a := range inv.Assets {
		dir := filepath.Dir(a.FilePath)
		var deps []string
		for p := range pathSet {
			if p != a.FilePath && filepath.Dir(p) == dir {
				deps = append(deps, p)
			}
		}
		if len(deps) > 0 {
			inv.DAGMap[a.FilePath] = deps
		}
	}
}

// calculateStats computes inventory statistics
func (inv *CryptoInventory) calculateStats() {
	stats := InventoryStats{
		TotalAssets:  len(inv.Assets),
		ByAlgorithm:  make(map[string]int),
		ByRiskLevel:  make(map[string]int),
		ByUsageContext: make(map[string]int),
	}

	for _, asset := range inv.Assets {
		stats.ByAlgorithm[asset.Algorithm]++
		stats.ByRiskLevel[string(asset.QuantumRisk)]++
		stats.ByUsageContext[string(asset.UsageContext)]++

		if asset.QuantumRisk == RiskSafe {
			stats.QuantumSafe++
		} else {
			stats.RequiresMigration++
		}

		if asset.ManualReview {
			stats.NeedsReview++
		}
	}

	inv.Statistics = stats
}

// prioritizeMigration assigns migration priorities based on DAG and risk
func (inv *CryptoInventory) prioritizeMigration() {
	// Calculate blast radius for each asset
	for i := range inv.Assets {
		asset := &inv.Assets[i]
		// Count dependencies
		deps, ok := inv.DAGMap[asset.FilePath]
		if ok {
			asset.BlastRadius = len(deps)
		}
	}
}

