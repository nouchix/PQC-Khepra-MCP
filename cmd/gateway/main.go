// Khepra Secure Gateway - The DEMARC Point
// "The Scarab Guards the Threshold Between Worlds"
//
// This is the entry point for the Khepra Secure Gateway, which serves as the
// zero-trust perimeter defense between customer environments and the
// Khepra/SouHimBou.AI ecosystem.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/gateway"
)

func main() {
	// CLI Flags
	configFile := flag.String("config", "", "Path to config file (JSON)")
	listenAddr := flag.String("addr", ":8443", "Listen address")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS key file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	learningMode := flag.Bool("learning", false, "Enable schema learning mode")
	strictMode := flag.Bool("strict", false, "Enable strict validation mode")
	flag.Parse()

	// Banner
	printBanner()

	// Load configuration
	cfg := loadConfig(*configFile)

	// Apply CLI overrides
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *tlsCert != "" {
		cfg.TLSCertFile = *tlsCert
	}
	if *tlsKey != "" {
		cfg.TLSKeyFile = *tlsKey
	}
	if *debug {
		cfg.Logging.Level = "debug"
		cfg.Logging.LogToStdout = true
	}
	if *learningMode {
		cfg.Schema.LearningEnabled = true
		cfg.Anomaly.LearningMode = true
	}
	if *strictMode {
		cfg.Schema.StrictMode = true
	}

	// Create the gateway
	gw, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("[GATEWAY] Failed to create gateway: %v", err)
	}

	// Create upstream handler (the actual API services)
	upstream := createUpstreamHandler()

	// Create HTTP server with gateway middleware
	mux := http.NewServeMux()

	// Gateway metrics endpoint
	mux.HandleFunc("/khepra/metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics := gw.GetMetrics()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
	})

	// Gateway health endpoint
	mux.HandleFunc("/khepra/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "1.0.0",
		})
	})

	// All other requests go through the gateway to upstream
	mux.Handle("/", gw.Handler(upstream))

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		log.Printf("[GATEWAY] Starting Khepra Secure Gateway on %s", cfg.ListenAddr)

		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			log.Printf("[GATEWAY] TLS enabled")
			if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[GATEWAY] Server error: %v", err)
			}
		} else {
			log.Printf("[GATEWAY] WARNING: Running without TLS - development mode only!")
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[GATEWAY] Server error: %v", err)
			}
		}
	}()

	log.Printf("[GATEWAY] Security Layers Active:")
	log.Printf("[GATEWAY]   Layer 1 (Firewall):  WAF, IP Reputation, Geo-blocking")
	log.Printf("[GATEWAY]   Layer 2 (Auth):      mTLS, API Keys, PQC Signatures")
	log.Printf("[GATEWAY]   Layer 3 (Anomaly):   ML-powered behavioral analysis")
	log.Printf("[GATEWAY]   Layer 4 (Control):   Rate limiting, Audit logging")
	log.Printf("[GATEWAY] Ready to protect the threshold.")

	// Wait for shutdown signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("[GATEWAY] Shutting down gracefully...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[GATEWAY] Shutdown error: %v", err)
	}

	log.Println("[GATEWAY] The Scarab rests. Goodbye.")
}

// loadConfig loads configuration from file or returns defaults
func loadConfig(configFile string) *gateway.Config {
	if configFile == "" {
		log.Println("[GATEWAY] Using default configuration")
		return gateway.DefaultConfig()
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("[GATEWAY] Failed to read config file: %v, using defaults", err)
		return gateway.DefaultConfig()
	}

	cfg := gateway.DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		log.Printf("[GATEWAY] Failed to parse config file: %v, using defaults", err)
		return gateway.DefaultConfig()
	}

	log.Printf("[GATEWAY] Loaded configuration from %s", configFile)
	return cfg
}

// createUpstreamHandler creates the handler for upstream services
func createUpstreamHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Routes DAG state/add and attestation endpoints.
		// Register additional upstream services in this switch block.

		switch {
		case r.URL.Path == "/api/v1/dag/state":
			// DAG state endpoint
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(dag.GlobalDAG().All())

		case r.URL.Path == "/api/v1/dag/add" && r.Method == "POST":
			// DAG add endpoint
			var req struct {
				Action  string   `json:"action"`
				Symbol  string   `json:"symbol"`
				Parents []string `json:"parent_ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
				return
			}
			// Add to DAG
			node := &dag.Node{
				Action: req.Action,
				Symbol: req.Symbol,
			}
			if err := dag.GlobalDAG().Add(node, req.Parents); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(node)

		case r.URL.Path == "/api/v1/attest":
			// Attestation endpoint
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"schema":  "https://adinkhepra.dev/attest/v1",
				"symbol":  "Eban",
				"message": "The Scarab has verified your passage",
			})

		default:
			// Default response for unknown endpoints
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "endpoint not found",
				"path":  r.URL.Path,
			})
		}
	})
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     ██╗  ██╗██╗  ██╗███████╗██████╗ ██████╗  █████╗              ║
║     ██║ ██╔╝██║  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗             ║
║     █████╔╝ ███████║█████╗  ██████╔╝██████╔╝███████║             ║
║     ██╔═██╗ ██╔══██║██╔══╝  ██╔═══╝ ██╔══██╗██╔══██║             ║
║     ██║  ██╗██║  ██║███████╗██║     ██║  ██║██║  ██║             ║
║     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝             ║
║                                                                   ║
║              ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗   ║
║              ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝   ║
║              ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗     ║
║              ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝     ║
║              ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗   ║
║              ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ║
║                                                                   ║
║           ██████╗  █████╗ ████████╗███████╗██╗    ██╗ █████╗ ██╗ ║
║          ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██║    ██║██╔══██╗╚██╗║
║          ██║  ███╗███████║   ██║   █████╗  ██║ █╗ ██║███████║ ██║║
║          ██║   ██║██╔══██║   ██║   ██╔══╝  ██║███╗██║██╔══██║ ██║║
║          ╚██████╔╝██║  ██║   ██║   ███████╗╚███╔███╔╝██║  ██║██╔╝║
║           ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝ ║
║                                                                   ║
║               "The Scarab Guards the Threshold"                   ║
║                                                                   ║
║    Zero-Trust DEMARC Point | Post-Quantum Security | ML-Powered  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}
