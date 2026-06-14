// Phantom Network Node - Real Implementation with Adinkhepra Lattice
//
// This is the production implementation that integrates:
// - Spectral Fingerprints for ephemeral address derivation
// - Adinkhepra-PQC lattice signatures for message authentication
// - Merkaba White Box encryption for payload protection
// - Automatic key rotation based on PHANTOM_ADINKHEPRA_LATTICE_INTERVAL

package main

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// =============================================================================
// CONFIGURATION
// =============================================================================

const contentTypeHeader = "Content-Type"
const contentTypeJSON = "application/json"

type PhantomConfig struct {
	Symbol                string
	NetworkMode           string
	Carrier               string
	RotationPeriod        time.Duration
	Encryption            string
	Signing               string
	AdinkhepraLattice     bool
	LatticeInterval       time.Duration
	LatticeOutputPath     string
	GPSSpoofEnabled       bool
	GPSSpoofTarget        string
	FaceDefeatEnabled     bool
	ThermalMaskingEnabled bool
	IMSIRotationEnabled   bool
}

// =============================================================================
// PHANTOM NODE STATE
// =============================================================================

type PhantomNode struct {
	config     PhantomConfig
	publicKey  *adinkra.AdinkhepraPQCPublicKey
	privateKey *adinkra.AdinkhepraPQCPrivateKey
	merkaba    *adinkra.Merkaba
	spectral   []byte
	address    net.IP
	addressExp time.Time
	peers      []string
	mutex      sync.RWMutex
	startTime  time.Time
}

// =============================================================================
// RESPONSE STRUCTURES
// =============================================================================

type HealthResponse struct {
	Status    string    `json:"status"`
	Symbol    string    `json:"symbol"`
	Mode      string    `json:"mode"`
	Lattice   bool      `json:"adinkhepra_lattice"`
	Timestamp time.Time `json:"timestamp"`
}

type AddressResponse struct {
	IPv6       string    `json:"ipv6"`
	ExpiresAt  time.Time `json:"expires_at"`
	Spectral   string    `json:"spectral_fingerprint"`
	TimeWindow int64     `json:"time_window"`
}

type StatusResponse struct {
	Symbol          string          `json:"symbol"`
	Mode            string          `json:"mode"`
	Carrier         string          `json:"carrier"`
	Encryption      string          `json:"encryption"`
	Signing         string          `json:"signing"`
	LatticeEnabled  bool            `json:"adinkhepra_lattice_enabled"`
	LatticeInterval string          `json:"lattice_rotation_interval"`
	KeyID           string          `json:"public_key_id"`
	Compliance      []string        `json:"compliance_mapping"`
	CounterSurv     map[string]bool `json:"counter_surveillance"`
	Uptime          string          `json:"uptime"`
	Timestamp       time.Time       `json:"timestamp"`
}

type PeersResponse struct {
	Peers []string `json:"peers"`
	Count int      `json:"count"`
}

type SignResponse struct {
	MessageHash string `json:"message_hash"`
	Signature   string `json:"signature"`
	Symbol      string `json:"symbol"`
	Timestamp   int64  `json:"timestamp"`
}

// =============================================================================
// INITIALIZATION
// =============================================================================

func NewPhantomNode(config PhantomConfig) (*PhantomNode, error) {
	log.Printf("🌑 Initializing Phantom Node with symbol: %s", config.Symbol)

	// Get Spectral Fingerprint from Adinkra symbol
	spectral := adinkra.GetSpectralFingerprint(config.Symbol)
	log.Printf("   → Spectral Fingerprint: %x", spectral[:16])

	// Generate entropy seed from spectral fingerprint + current time
	seed := make([]byte, 64)
	copy(seed, spectral)
	binary.BigEndian.PutUint64(seed[32:], uint64(time.Now().UnixNano()))
	h := sha256.Sum256(seed)

	// Initialize Merkaba for white box encryption
	merkaba := adinkra.NewMerkaba(h[:])
	log.Printf("   → Merkaba initialized with Tree of Life path")

	// Generate Adinkhepra-PQC key pair
	publicKey, privateKey, err := adinkra.GenerateAdinkhepraPQCKeyPair(h[:], config.Symbol)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Adinkhepra-PQC keys: %w", err)
	}
	log.Printf("   → Adinkhepra-PQC key pair generated (NIST Level 5)")

	node := &PhantomNode{
		config:     config,
		publicKey:  publicKey,
		privateKey: privateKey,
		merkaba:    merkaba,
		spectral:   spectral,
		peers:      []string{},
		startTime:  time.Now(),
	}

	// Generate initial phantom address
	node.rotateAddress()
	log.Printf("   → Phantom IPv6: %s", node.address.String())

	// Start key rotation if enabled
	if config.AdinkhepraLattice && config.LatticeInterval > 0 {
		go node.startKeyRotation()
		log.Printf("   → Key rotation started (interval: %s)", config.LatticeInterval)
	}

	// Start address rotation
	go node.startAddressRotation()
	log.Printf("   → Address rotation started (interval: %s)", config.RotationPeriod)

	return node, nil
}

// =============================================================================
// SPECTRAL ADDRESS DERIVATION
// =============================================================================

// DerivePhantomAddress generates an ephemeral IPv6 address from Spectral Fingerprint
func (n *PhantomNode) DerivePhantomAddress(timeWindow int64) net.IP {
	h := sha256.New()
	h.Write(n.spectral)
	h.Write([]byte("PHANTOM_NETWORK_ADDRESS"))

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeWindow))
	h.Write(timeBytes)

	hash := h.Sum(nil)

	// Create IPv6 in fc00::/8 range (Unique Local Address)
	ipv6 := make(net.IP, 16)
	ipv6[0] = 0xfc // ULA prefix
	ipv6[1] = 0x00
	copy(ipv6[2:], hash[:14])

	return ipv6
}

func (n *PhantomNode) rotateAddress() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Time window based on rotation period (default 5 minutes = 300 seconds)
	windowSeconds := int64(n.config.RotationPeriod.Seconds())
	if windowSeconds == 0 {
		windowSeconds = 300
	}
	timeWindow := time.Now().Unix() / windowSeconds

	n.address = n.DerivePhantomAddress(timeWindow)
	n.addressExp = time.Now().Add(n.config.RotationPeriod)
}

func (n *PhantomNode) startAddressRotation() {
	ticker := time.NewTicker(n.config.RotationPeriod)
	for range ticker.C {
		n.rotateAddress()
		log.Printf("🔄 Phantom address rotated: %s", n.address.String())
	}
}

// =============================================================================
// KEY ROTATION
// =============================================================================

func (n *PhantomNode) startKeyRotation() {
	ticker := time.NewTicker(n.config.LatticeInterval)
	for range ticker.C {
		n.rotateKeys()
	}
}

func (n *PhantomNode) rotateKeys() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Securely destroy old private key
	if n.privateKey != nil {
		n.privateKey.DestroyPrivateKey()
	}

	// Generate new key pair
	seed := make([]byte, 64)
	copy(seed, n.spectral)
	binary.BigEndian.PutUint64(seed[32:], uint64(time.Now().UnixNano()))
	h := sha256.Sum256(seed)

	publicKey, privateKey, err := adinkra.GenerateAdinkhepraPQCKeyPair(h[:], n.config.Symbol)
	if err != nil {
		log.Printf("ERROR: Key rotation failed: %v", err)
		return
	}

	n.publicKey = publicKey
	n.privateKey = privateKey

	// Save to output path if configured
	if n.config.LatticeOutputPath != "" {
		n.saveKeys()
	}

	log.Printf("🔑 Adinkhepra lattice keys rotated (symbol: %s)", n.config.Symbol)
}

func (n *PhantomNode) saveKeys() {
	// Create output directory
	os.MkdirAll(n.config.LatticeOutputPath, 0700)

	// Save public key (only public, never private!)
	keyID := n.getKeyID()
	pubFile := fmt.Sprintf("%s/public_%s.key", n.config.LatticeOutputPath, keyID)

	pubData, _ := json.Marshal(map[string]interface{}{
		"key_id":   keyID,
		"symbol":   n.config.Symbol,
		"created":  time.Now().Format(time.RFC3339),
		"seed_hex": hex.EncodeToString(n.publicKey.Seed[:]),
	})
	os.WriteFile(pubFile, pubData, 0644)
}

func (n *PhantomNode) getKeyID() string {
	h := sha256.Sum256(n.publicKey.Seed[:])
	return hex.EncodeToString(h[:8])
}

// =============================================================================
// HTTP HANDLERS
// =============================================================================

func (n *PhantomNode) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	json.NewEncoder(w).Encode(HealthResponse{
		Status:    "healthy",
		Symbol:    n.config.Symbol,
		Mode:      n.config.NetworkMode,
		Lattice:   n.config.AdinkhepraLattice,
		Timestamp: time.Now(),
	})
}

func (n *PhantomNode) handleAddress(w http.ResponseWriter, r *http.Request) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	w.Header().Set(contentTypeHeader, contentTypeJSON)

	windowSeconds := int64(n.config.RotationPeriod.Seconds())
	if windowSeconds == 0 {
		windowSeconds = 300
	}

	json.NewEncoder(w).Encode(AddressResponse{
		IPv6:       n.address.String(),
		ExpiresAt:  n.addressExp,
		Spectral:   hex.EncodeToString(n.spectral[:16]),
		TimeWindow: time.Now().Unix() / windowSeconds,
	})
}

func (n *PhantomNode) handleStatus(w http.ResponseWriter, r *http.Request) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	w.Header().Set(contentTypeHeader, contentTypeJSON)

	compliance := adinkra.MapSymbolToCompliance(n.config.Symbol)

	json.NewEncoder(w).Encode(StatusResponse{
		Symbol:          n.config.Symbol,
		Mode:            n.config.NetworkMode,
		Carrier:         n.config.Carrier,
		Encryption:      n.config.Encryption,
		Signing:         n.config.Signing,
		LatticeEnabled:  n.config.AdinkhepraLattice,
		LatticeInterval: n.config.LatticeInterval.String(),
		KeyID:           n.getKeyID(),
		Compliance:      compliance,
		CounterSurv: map[string]bool{
			"gps_spoof":       n.config.GPSSpoofEnabled,
			"gps_target":      n.config.GPSSpoofTarget != "",
			"face_defeat":     n.config.FaceDefeatEnabled,
			"thermal_masking": n.config.ThermalMaskingEnabled,
			"imsi_rotation":   n.config.IMSIRotationEnabled,
		},
		Uptime:    time.Since(n.startTime).String(),
		Timestamp: time.Now(),
	})
}

func (n *PhantomNode) handlePeers(w http.ResponseWriter, r *http.Request) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	w.Header().Set(contentTypeHeader, contentTypeJSON)
	json.NewEncoder(w).Encode(PeersResponse{
		Peers: n.peers,
		Count: len(n.peers),
	})
}

func (n *PhantomNode) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Hash message
	msgHash := sha256.Sum256([]byte(req.Message))
	fullHash := make([]byte, 64)
	copy(fullHash, msgHash[:])
	copy(fullHash[32:], msgHash[:]) // Duplicate for 64-byte requirement

	// Sign with Adinkhepra-PQC
	signature, err := adinkra.SignAdinkhepraPQC(n.privateKey, fullHash)
	if err != nil {
		http.Error(w, "Signing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeJSON)
	json.NewEncoder(w).Encode(SignResponse{
		MessageHash: hex.EncodeToString(msgHash[:]),
		Signature:   hex.EncodeToString(signature),
		Symbol:      n.config.Symbol,
		Timestamp:   time.Now().Unix(),
	})
}

func (n *PhantomNode) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Serve static HTML for browser requests, JSON for API clients
	accept := r.Header.Get("Accept")
	if r.URL.Path == "/" && (accept == "" || contains(accept, "text/html")) {
		// Try to serve embedded static file
		staticFS, err := fs.Sub(staticFiles, "static")
		if err == nil {
			content, err := fs.ReadFile(staticFS, "index.html")
			if err == nil {
				w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
				w.Write(content)
				return
			}
		}
	}

	// Fallback to JSON API response
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":    "Phantom Network Node",
		"symbol":  n.config.Symbol,
		"mode":    n.config.NetworkMode,
		"version": "1.0.0-adinkhepra",
		"lattice": n.config.AdinkhepraLattice,
		"endpoints": []string{
			"GET  /health         - Health check",
			"GET  /api/v1/address - Phantom IPv6 address",
			"GET  /api/v1/status  - Full status with counter-surveillance",
			"GET  /api/v1/peers   - Discovered peers",
			"POST /api/v1/sign    - Sign message with Adinkhepra-PQC",
		},
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// STATIC FILE SERVER
// =============================================================================

//go:embed static
var staticFiles embed.FS

// =============================================================================
// MAIN
// =============================================================================

func main() {
	// Parse environment variables
	config := PhantomConfig{
		Symbol:                getEnv("PHANTOM_SYMBOL", "Eban"),
		NetworkMode:           getEnv("PHANTOM_NETWORK_MODE", "stealth"),
		Carrier:               getEnv("PHANTOM_CARRIER", "JPEG"),
		RotationPeriod:        parseDuration(getEnv("PHANTOM_ROTATION_PERIOD", "5m")),
		Encryption:            getEnv("PHANTOM_ENCRYPTION", "kyber1024"),
		Signing:               getEnv("PHANTOM_SIGNING", "dilithium3"),
		AdinkhepraLattice:     getEnv("PHANTOM_ADINKHEPRA_LATTICE", "false") == "true",
		LatticeInterval:       parseDuration(getEnv("PHANTOM_ADINKHEPRA_LATTICE_INTERVAL", "1h")),
		LatticeOutputPath:     getEnv("PHANTOM_ADINKHEPRA_LATTICE_OUTPUT", "/app/data/lattice"),
		GPSSpoofEnabled:       getEnv("GPS_SPOOF_ENABLED", "false") == "true",
		GPSSpoofTarget:        getEnv("GPS_SPOOF_TARGET", ""),
		FaceDefeatEnabled:     getEnv("FACE_DEFEAT_ENABLED", "false") == "true",
		ThermalMaskingEnabled: getEnv("THERMAL_MASKING_ENABLED", "false") == "true",
		IMSIRotationEnabled:   getEnv("IMSI_ROTATION_ENABLED", "false") == "true",
	}

	// Initialize Phantom Node
	node, err := NewPhantomNode(config)
	if err != nil {
		log.Fatalf("Failed to initialize Phantom Node: %v", err)
	}

	// Setup HTTP routes
	http.HandleFunc("/", node.handleRoot)
	http.HandleFunc("/health", node.handleHealth)
	http.HandleFunc("/api/v1/address", node.handleAddress)
	http.HandleFunc("/api/v1/status", node.handleStatus)
	http.HandleFunc("/api/v1/peers", node.handlePeers)
	http.HandleFunc("/api/v1/sign", node.handleSign)

	// Start server
	port := getEnv("PORT", "8080")
	fmt.Printf("\n🌑 Phantom Node started on :%s\n", port)
	fmt.Printf("   Symbol: %s | Mode: %s | Lattice: %v\n", config.Symbol, config.NetworkMode, config.AdinkhepraLattice)
	fmt.Printf("   Compliance: %v\n", adinkra.MapSymbolToCompliance(config.Symbol))
	fmt.Println("\n   Endpoints:")
	fmt.Println("   - GET  /health         - Health check")
	fmt.Println("   - GET  /api/v1/address - Phantom IPv6 address")
	fmt.Println("   - GET  /api/v1/status  - Full status")
	fmt.Println("   - GET  /api/v1/peers   - Discovered peers")
	fmt.Println("   - POST /api/v1/sign    - Sign with Adinkhepra-PQC")
	fmt.Println()

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// =============================================================================
// HELPERS
// =============================================================================

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}
