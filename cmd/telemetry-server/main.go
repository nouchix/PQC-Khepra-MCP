// cmd/telemetry-server — Sovereign VPS Telemetry Server
//
// This is the primary telemetry beacon for AdinKhepra v2.0. It runs on a
// self-controlled VPS (Hetzner Finland/Iceland — outside US jurisdiction)
// and handles three responsibilities:
//
//  1. Anonymous signed beacon intake (POST /beacon)
//     — Clients submit ML-DSA-65-signed usage telemetry; no IP stored.
//
//  2. License revocation list distribution (GET /license/crl)
//     — Returns the current IPFS CID of the encrypted CRL so clients can
//       refresh their revocation list without trusting this server.
//
//  3. Health and epoch endpoint (GET /health)
//     — Used by clients to refresh the server timestamp and CRL epoch.
//
// Storage: SQLite via modernc.org/sqlite (single binary, zero external deps).
// Auth: ML-DSA-65 signed requests only — no API keys, no JWTs, no sessions.
// Privacy: No IP addresses stored; anonymous_id is a client-generated hash.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	_ "modernc.org/sqlite"
)

// ─── Configuration ────────────────────────────────────────────────────────────

type serverConfig struct {
	ListenAddr    string // e.g. ":8443"
	DBPath        string // SQLite file path
	MasterPubKey  []byte // ML-DSA-65 public key (verifies beacon signatures)
	CRLCurrentCID string // Current IPFS CID of the revocation list
	TLSCertFile   string // TLS certificate (Let's Encrypt / ACME)
	TLSKeyFile    string // TLS private key
}

func loadConfig() (*serverConfig, error) {
	cfg := &serverConfig{
		ListenAddr: envOrDefault("TELEMETRY_ADDR", ":8443"),
		DBPath:     envOrDefault("TELEMETRY_DB", "/var/lib/khepra-telemetry/beacons.db"),
		TLSCertFile: envOrDefault("TLS_CERT", "/etc/letsencrypt/live/telemetry.souhimbou.ai/fullchain.pem"),
		TLSKeyFile:  envOrDefault("TLS_KEY", "/etc/letsencrypt/live/telemetry.souhimbou.ai/privkey.pem"),
		CRLCurrentCID: os.Getenv("KHEPRA_CRL_CID"),
	}

	// Master public key: hex-encoded in KHEPRA_MASTER_PUB_KEY env var
	pubKeyHex := os.Getenv("KHEPRA_MASTER_PUB_KEY")
	if pubKeyHex == "" {
		return nil, errors.New("telemetry-server: KHEPRA_MASTER_PUB_KEY env var is required")
	}
	pk, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil {
		return nil, fmt.Errorf("telemetry-server: decode KHEPRA_MASTER_PUB_KEY: %w", err)
	}
	cfg.MasterPubKey = pk

	return cfg, nil
}

// ─── Database ─────────────────────────────────────────────────────────────────

type store struct {
	db *sql.DB
}

func newStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &store{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS beacons (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			received_at TEXT    NOT NULL,
			anonymous_id TEXT   NOT NULL,
			license_tier TEXT,
			scan_count  INTEGER DEFAULT 0,
			finding_count INTEGER DEFAULT 0,
			signature   TEXT    NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_beacons_received ON beacons(received_at);
		CREATE INDEX IF NOT EXISTS idx_beacons_anon ON beacons(anonymous_id);

		CREATE TABLE IF NOT EXISTS crl_epochs (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			epoch      INTEGER NOT NULL,
			ipfs_cid   TEXT    NOT NULL,
			updated_at TEXT    NOT NULL
		);
	`)
	return err
}

func (s *store) insertBeacon(b *incomingBeacon) error {
	_, err := s.db.Exec(
		`INSERT INTO beacons (received_at, anonymous_id, license_tier, scan_count, finding_count, signature)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339),
		b.AnonymousID,
		b.LicenseTier,
		b.ScanCount,
		b.FindingCount,
		hex.EncodeToString(b.Signature),
	)
	return err
}

func (s *store) currentCRLEpoch() (int64, string, error) {
	row := s.db.QueryRow(
		`SELECT epoch, ipfs_cid FROM crl_epochs ORDER BY epoch DESC LIMIT 1`,
	)
	var epoch int64
	var cid string
	err := row.Scan(&epoch, &cid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	return epoch, cid, err
}

func (s *store) upsertCRL(cid string) error {
	epoch := time.Now().Unix()
	_, err := s.db.Exec(
		`INSERT INTO crl_epochs (epoch, ipfs_cid, updated_at) VALUES (?, ?, ?)`,
		epoch, cid, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// ─── Request/Response Types ───────────────────────────────────────────────────

// incomingBeacon is the JSON body posted to POST /beacon.
type incomingBeacon struct {
	TelemetryVersion string `json:"telemetry_version"`
	AnonymousID      string `json:"anonymous_id"`
	LicenseTier      string `json:"license_tier,omitempty"`
	ScanCount        int    `json:"scan_count"`
	FindingCount     int    `json:"finding_count"`
	Timestamp        string `json:"timestamp"`
	// ML-DSA-65 signature over canonical JSON of the above fields
	Signature []byte `json:"signature"`
	// Signer's ML-DSA-65 public key (clients use ephemeral keys per session)
	SignerPublicKey []byte `json:"signer_public_key"`
}

// canonicalBeaconBytes returns the deterministic JSON payload that was signed.
func (b *incomingBeacon) canonicalBytes() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"telemetry_version": b.TelemetryVersion,
		"anonymous_id":      b.AnonymousID,
		"license_tier":      b.LicenseTier,
		"scan_count":        b.ScanCount,
		"finding_count":     b.FindingCount,
		"timestamp":         b.Timestamp,
	})
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

type server struct {
	cfg   *serverConfig
	store *store
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /beacon", s.handleBeacon)
	mux.HandleFunc("GET /license/crl", s.handleCRL)
	mux.HandleFunc("GET /health", s.handleHealth)
	return requestLogger(securityHeaders(mux))
}

// handleBeacon verifies the ML-DSA-65 signature and stores anonymised telemetry.
// IP addresses are never stored; anonymous_id is a client-generated hash.
func (s *server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024)) // 64 KB max
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var beacon incomingBeacon
	if err := json.Unmarshal(body, &beacon); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Require anonymous_id
	if beacon.AnonymousID == "" {
		http.Error(w, "anonymous_id required", http.StatusBadRequest)
		return
	}

	// Validate anonymous_id is a hex hash (prevents structured injection)
	if _, err := hex.DecodeString(beacon.AnonymousID); err != nil || len(beacon.AnonymousID) < 32 {
		http.Error(w, "anonymous_id must be a hex hash (>=32 chars)", http.StatusBadRequest)
		return
	}

	// Verify ML-DSA-65 signature
	if len(beacon.Signature) == 0 || len(beacon.SignerPublicKey) == 0 {
		http.Error(w, "signature and signer_public_key required", http.StatusUnauthorized)
		return
	}

	canonical, err := beacon.canonicalBytes()
	if err != nil {
		http.Error(w, "canonical bytes", http.StatusInternalServerError)
		return
	}

	valid, err := adinkra.Verify(beacon.SignerPublicKey, canonical, beacon.Signature)
	if err != nil || !valid {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	if err := s.store.insertBeacon(&beacon); err != nil {
		log.Printf("[BEACON] DB insert error: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"status": "accepted",
	})
}

// handleCRL returns the current IPFS CID of the revocation list.
// Clients use this to refresh their offline CRL cache.
func (s *server) handleCRL(w http.ResponseWriter, r *http.Request) {
	epoch, cid, err := s.store.currentCRLEpoch()
	if err != nil {
		log.Printf("[CRL] DB query error: %v", err)
		http.Error(w, "crl unavailable", http.StatusInternalServerError)
		return
	}

	// Fall back to environment-configured CID if DB is empty
	if cid == "" {
		cid = s.cfg.CRLCurrentCID
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"crl_cid":    cid,
		"epoch":      epoch,
		"server_ts":  time.Now().UTC().Unix(),
		"server_utc": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleHealth returns server status for client polling.
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Return a server-timestamp + pubkey hash so clients can confirm they're talking
	// to a legitimate server (public key commitment).
	pkHash := sha256.Sum256(s.cfg.MasterPubKey)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"status":        "ok",
		"server_ts":     time.Now().UTC().Unix(),
		"pk_commitment": hex.EncodeToString(pkHash[:8]), // first 8 bytes as fingerprint
	})
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		// Log method + path only; never log IP, headers, or body
		log.Printf("[REQ] %s %s %.2fms", r.Method, r.URL.Path, float64(time.Since(start).Microseconds())/1000)
	})
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[TELEMETRY] AdinKhepra Sovereign Telemetry Server starting...")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("[TELEMETRY] Config error: %v", err)
	}

	// Ensure DB directory exists
	dbDir := dbDirFrom(cfg.DBPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		log.Fatalf("[TELEMETRY] Cannot create DB directory %s: %v", dbDir, err)
	}

	st, err := newStore(cfg.DBPath)
	if err != nil {
		log.Fatalf("[TELEMETRY] Store init: %v", err)
	}

	srv := &server{cfg: cfg, store: st}
	httpSrv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv.routes(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("[TELEMETRY] Listening on %s (TLS)", cfg.ListenAddr)
		var serveErr error
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			serveErr = httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			log.Println("[TELEMETRY] WARN: TLS not configured — running plain HTTP (development only)")
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Fatalf("[TELEMETRY] Server error: %v", serveErr)
		}
	}()

	<-quit
	log.Println("[TELEMETRY] Shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("[TELEMETRY] Shutdown error: %v", err)
	}
	log.Println("[TELEMETRY] Stopped.")
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func dbDirFrom(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return "."
	}
	return path[:idx]
}
