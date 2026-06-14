// Package gateway implements the Khepra Secure Gateway - the DEMARC point
// between customer environments and the Khepra/SouHimBou.AI ecosystem.
//
// "The Scarab Guards the Threshold"
package gateway

import (
	"time"
)

// Config holds all configuration for the secure gateway
type Config struct {
	// Server settings
	ListenAddr    string        `json:"listen_addr"`    // ":8443"
	TLSCertFile   string        `json:"tls_cert_file"`
	TLSKeyFile    string        `json:"tls_key_file"`
	ReadTimeout   time.Duration `json:"read_timeout"`
	WriteTimeout  time.Duration `json:"write_timeout"`

	// Layer 1: Firewall
	Firewall      FirewallConfig `json:"firewall"`

	// Layer 2: Authentication
	Auth          AuthConfig     `json:"auth"`

	// Layer 3: Anomaly Detection
	Anomaly       AnomalyConfig  `json:"anomaly"`

	// Layer 4: Rate Limiting & Logging
	RateLimit     RateLimitConfig `json:"rate_limit"`
	Logging       LoggingConfig   `json:"logging"`

	// Schema Enforcement
	Schema        SchemaConfig    `json:"schema"`

	// Fail-secure settings
	FailSecure    FailSecureConfig `json:"fail_secure"`
}

// FirewallConfig - Layer 1 perimeter defense
type FirewallConfig struct {
	// IP Reputation
	BlockTorExitNodes   bool     `json:"block_tor_exit_nodes"`
	BlockKnownBadIPs    bool     `json:"block_known_bad_ips"`
	IPBlocklistPath     string   `json:"ip_blocklist_path"`
	GeoBlockCountries   []string `json:"geo_block_countries"`
	AllowOnlyCountries  []string `json:"allow_only_countries"` // For DoD: ["US"]

	// Protocol Enforcement
	RequireHTTPS        bool     `json:"require_https"`
	MinTLSVersion       string   `json:"min_tls_version"` // "1.2" or "1.3"
	AllowedMethods      []string `json:"allowed_methods"` // ["GET", "POST"]
	MaxRequestSizeBytes int64    `json:"max_request_size_bytes"`
	MaxHeaderSizeBytes  int64    `json:"max_header_size_bytes"`

	// WAF Rules
	EnableSQLiProtection bool `json:"enable_sqli_protection"`
	EnableXSSProtection  bool `json:"enable_xss_protection"`
	EnableLFIProtection  bool `json:"enable_lfi_protection"`
	EnableRCEProtection  bool `json:"enable_rce_protection"`
	CustomRulesPath      string `json:"custom_rules_path"`
}

// AuthConfig - Layer 2 zero-trust authentication
type AuthConfig struct {
	// mTLS (Mutual TLS)
	RequireMTLS           bool   `json:"require_mtls"`
	ClientCAFile          string `json:"client_ca_file"`
	CertRevocationCheck   bool   `json:"cert_revocation_check"`
	CRLPath               string `json:"crl_path"`

	// API Key Authentication
	APIKeyHeader          string `json:"api_key_header"` // "X-Khepra-API-Key"
	APIKeyHashAlgorithm   string `json:"api_key_hash_algorithm"` // "argon2id"

	// Enrollment Token (for auto-registration)
	EnrollmentTokenHeader string `json:"enrollment_token_header"` // "X-Khepra-Enrollment-Token"

	// PQC Signature Verification
	RequirePQCSignature   bool   `json:"require_pqc_signature"`
	SignatureHeader       string `json:"signature_header"` // "X-Khepra-Signature"
	SignatureAlgorithm    string `json:"signature_algorithm"` // "ML-DSA-65"
	PublicKeyRegistryURL  string `json:"public_key_registry_url"`

	// JWT Settings
	JWTSecret             string        `json:"jwt_secret"`
	JWTIssuer             string        `json:"jwt_issuer"`
	JWTAudience           string        `json:"jwt_audience"`
	JWTMaxAge             time.Duration `json:"jwt_max_age"`

	// License Server Integration
	LicenseServerURL      string `json:"license_server_url"`
}

// AnomalyConfig - Layer 3 ML-based detection
type AnomalyConfig struct {
	// Enable/Disable
	Enabled             bool `json:"enabled"`

	// Baseline Learning
	LearningMode        bool          `json:"learning_mode"`
	LearningDuration    time.Duration `json:"learning_duration"` // 7 days
	BaselineUpdateInterval time.Duration `json:"baseline_update_interval"`

	// ML Service (PyTorch)
	MLServiceEndpoint   string        `json:"ml_service_endpoint"`
	MLServiceTimeout    time.Duration `json:"ml_service_timeout"`
	ModelVersion        string        `json:"model_version"`

	// Thresholds
	BlockThreshold      float64 `json:"block_threshold"`     // 0.9
	AlertThreshold      float64 `json:"alert_threshold"`     // 0.7
	ChallengeThreshold  float64 `json:"challenge_threshold"` // 0.5

	// Feature extraction
	EnableBehavioralAnalysis bool `json:"enable_behavioral_analysis"`
	EnableGeoVelocity        bool `json:"enable_geo_velocity"`
	EnablePayloadAnalysis    bool `json:"enable_payload_analysis"`
}

// RateLimitConfig - Layer 4 abuse prevention
type RateLimitConfig struct {
	// Global Limits
	GlobalRequestsPerSecond int `json:"global_requests_per_second"`

	// Per-Identity Limits
	RequestsPerSecond   int `json:"requests_per_second"`
	RequestsPerMinute   int `json:"requests_per_minute"`
	RequestsPerHour     int `json:"requests_per_hour"`

	// Burst Handling
	BurstAllowance      int           `json:"burst_allowance"`
	BurstWindow         time.Duration `json:"burst_window"`

	// Adaptive Limiting
	TrustScoreMultiplier bool `json:"trust_score_multiplier"`

	// Backoff
	BackoffStrategy     string        `json:"backoff_strategy"` // "exponential"
	MaxBackoffDuration  time.Duration `json:"max_backoff_duration"`

	// Redis Backend (for distributed rate limiting)
	RedisAddr           string `json:"redis_addr"`
	RedisPassword       string `json:"redis_password"`
	RedisDB             int    `json:"redis_db"`
}

// LoggingConfig - comprehensive audit trail
type LoggingConfig struct {
	// Output destinations
	LogToStdout         bool   `json:"log_to_stdout"`
	LogToFile           bool   `json:"log_to_file"`
	LogFilePath         string `json:"log_file_path"`

	// DAG Integration (immutable audit trail)
	LogToDAG            bool   `json:"log_to_dag"`
	DAGEndpoint         string `json:"dag_endpoint"`

	// Telemetry Server
	LogToTelemetry      bool   `json:"log_to_telemetry"`
	TelemetryEndpoint   string `json:"telemetry_endpoint"`

	// SIEM Export
	SIEMEnabled         bool   `json:"siem_enabled"`
	SIEMType            string `json:"siem_type"` // "splunk", "elk", "sentinel"
	SIEMEndpoint        string `json:"siem_endpoint"`
	SIEMAPIKey          string `json:"siem_api_key"`

	// Real-time WebSocket
	WebSocketEnabled    bool   `json:"websocket_enabled"`
	WebSocketPath       string `json:"websocket_path"`

	// Log Level
	Level               string `json:"level"` // "debug", "info", "warn", "error"

	// Privacy
	HashSensitiveFields bool   `json:"hash_sensitive_fields"`
	ExcludeFields       []string `json:"exclude_fields"`

	// Retention
	RetentionDays       int `json:"retention_days"`
}

// SchemaConfig - polymorphic schema enforcement
type SchemaConfig struct {
	// Enable schema learning
	LearningEnabled     bool          `json:"learning_enabled"`
	LearningDuration    time.Duration `json:"learning_duration"`

	// Schema registry
	RegistryPath        string `json:"registry_path"`

	// Auto-evolution
	AutoEvolve          bool   `json:"auto_evolve"`
	RequireApproval     bool   `json:"require_approval"`
	NotifyWebhook       string `json:"notify_webhook"`

	// Validation strictness
	StrictMode          bool    `json:"strict_mode"`
	AnomalyThreshold    float64 `json:"anomaly_threshold"`
}

// FailSecureConfig - behavior when components fail
type FailSecureConfig struct {
	// ML Service Failure
	MLServiceFallback   string        `json:"ml_service_fallback"` // "deny", "allow_with_logging"
	MLServiceTimeout    time.Duration `json:"ml_service_timeout"`

	// Database Failure
	DBFallback          string `json:"db_fallback"`

	// Alert on degradation
	AlertOnDegradation  bool   `json:"alert_on_degradation"`
	AlertWebhook        string `json:"alert_webhook"`

	// Circuit breaker
	CircuitBreakerEnabled    bool          `json:"circuit_breaker_enabled"`
	CircuitBreakerThreshold  int           `json:"circuit_breaker_threshold"`
	CircuitBreakerTimeout    time.Duration `json:"circuit_breaker_timeout"`
}

// DefaultConfig returns a secure default configuration
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:   ":8443",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,

		Firewall: FirewallConfig{
			BlockTorExitNodes:    true,
			BlockKnownBadIPs:     true,
			RequireHTTPS:         true,
			MinTLSVersion:        "1.2",
			AllowedMethods:       []string{"GET", "POST", "PUT", "DELETE"},
			MaxRequestSizeBytes:  1 << 20, // 1MB
			MaxHeaderSizeBytes:   1 << 16, // 64KB
			EnableSQLiProtection: true,
			EnableXSSProtection:  true,
			EnableLFIProtection:  true,
			EnableRCEProtection:  true,
		},

		Auth: AuthConfig{
			RequireMTLS:           false, // Enable for production
			APIKeyHeader:          "X-Khepra-API-Key",
			APIKeyHashAlgorithm:   "argon2id",
			EnrollmentTokenHeader: "X-Khepra-Enrollment-Token",
			RequirePQCSignature:   false, // Enable for high-security
			SignatureHeader:       "X-Khepra-Signature",
			SignatureAlgorithm:    "ML-DSA-65",
			JWTIssuer:             "khepra-gateway",
			JWTAudience:           "khepra-services",
			JWTMaxAge:             24 * time.Hour,
			LicenseServerURL:      "https://telemetry.souhimbou.org",
		},

		Anomaly: AnomalyConfig{
			Enabled:             true,
			LearningMode:        true,
			LearningDuration:    7 * 24 * time.Hour,
			BaselineUpdateInterval: 1 * time.Hour,
			MLServiceTimeout:    100 * time.Millisecond,
			BlockThreshold:      0.9,
			AlertThreshold:      0.7,
			ChallengeThreshold:  0.5,
			EnableBehavioralAnalysis: true,
			EnableGeoVelocity:   true,
			EnablePayloadAnalysis: true,
		},

		RateLimit: RateLimitConfig{
			GlobalRequestsPerSecond: 10000,
			RequestsPerSecond:       10,
			RequestsPerMinute:       100,
			RequestsPerHour:         1000,
			BurstAllowance:          20,
			BurstWindow:             5 * time.Second,
			TrustScoreMultiplier:    true,
			BackoffStrategy:         "exponential",
			MaxBackoffDuration:      5 * time.Minute,
		},

		Logging: LoggingConfig{
			LogToStdout:         true,
			LogToDAG:            true,
			LogToTelemetry:      true,
			WebSocketEnabled:    true,
			WebSocketPath:       "/ws/audit",
			Level:               "info",
			HashSensitiveFields: true,
			RetentionDays:       90,
		},

		Schema: SchemaConfig{
			LearningEnabled:  true,
			LearningDuration: 7 * 24 * time.Hour,
			AutoEvolve:       false,
			RequireApproval:  true,
			StrictMode:       false,
			AnomalyThreshold: 0.3,
		},

		FailSecure: FailSecureConfig{
			MLServiceFallback:       "deny",
			MLServiceTimeout:        500 * time.Millisecond,
			DBFallback:              "deny",
			AlertOnDegradation:      true,
			CircuitBreakerEnabled:   true,
			CircuitBreakerThreshold: 5,
			CircuitBreakerTimeout:   30 * time.Second,
		},
	}
}
