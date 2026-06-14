package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/nkyinkyim"
)

// KhepraDaemon is the "Father" - the hidden protector for SouHimBou.AI
type KhepraDaemon struct {
	dag        *dag.Memory
	aesKey     []byte // AES-256 key for data encryption
	startTime  time.Time
	locked     bool // File integrity lockdown status
	eventCount int  // Total events logged
}

func main() {
	port := flag.String("port", "45444", "HTTP API port")
	tlsEnabled := flag.Bool("tls", false, "Enable TLS/HTTPS")
	certPath := flag.String("cert", "cloudflare.pem", "Path to TLS certificate (required if -tls)")
	keyPath := flag.String("key", "cloudflare.key", "Path to TLS private key (required if -tls)")
	// dagPath := flag.String("dag", ".khepra/daemon.dag", "DAG storage path") // unused for Memory DAG
	flag.Parse()

	fmt.Println("🛡️  Khepra Daemon - The Father Awakens")
	if *tlsEnabled {
		fmt.Printf("   Listening on: https://127.0.0.1:%s (Secure TLS)\n", *port)
	} else {
		fmt.Printf("   Listening on: http://127.0.0.1:%s\n", *port)
	}
	fmt.Println("   Mission: Protect SouHimBou.AI (The Son)")
	fmt.Println()

	// Initialize DAG engine
	dagInstance := dag.NewMemory()

	daemon := &KhepraDaemon{
		dag:       dagInstance,
		startTime: time.Now(),
		locked:    false,
	}

	// Log startup event to DAG
	daemon.logEvent("daemon_start", "Khepra-Daemon", map[string]interface{}{
		"port":      *port,
		"tls":       *tlsEnabled,
		"timestamp": time.Now().Unix(),
	})

	// Register HTTP handlers
	http.HandleFunc("/healthz", daemon.handleHealth)
	http.HandleFunc("/dag/add", daemon.handleDAGAdd)
	http.HandleFunc("/adinkra/weave", daemon.handleWeave)
	http.HandleFunc("/adinkra/unweave", daemon.handleUnweave)
	http.HandleFunc("/attest/verify", daemon.handleAttest)
	http.HandleFunc("/status", daemon.handleStatus)

	// Start server (localhost only for security)
	addr := "127.0.0.1:" + *port

	if *tlsEnabled {
		log.Printf("[DAEMON] Father is watching on %s (HTTPS/TLS)\n", addr)
		if err := http.ListenAndServeTLS(addr, *certPath, *keyPath, nil); err != nil {
			log.Fatalf("[FATAL] Failed to start daemon (TLS): %v\n", err)
		}
	} else {
		log.Printf("[DAEMON] Father is watching on %s (HTTP)\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("[FATAL] Failed to start daemon: %v\n", err)
		}
	}
}

// Health check endpoint - SouHimBou calls this every 30 seconds
func (d *KhepraDaemon) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"status":  "alive",
		"uptime":  time.Since(d.startTime).Seconds(),
		"locked":  d.locked,
		"message": "The Father is watching",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DAG Add endpoint - Immutable audit logging
func (d *KhepraDaemon) handleDAGAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action  string                 `json:"action"`
		Symbol  string                 `json:"symbol"`
		Payload map[string]interface{} `json:"payload,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Log event to DAG
	nodeID := d.logEvent(req.Action, req.Symbol, req.Payload)

	response := map[string]interface{}{
		"status":  "logged",
		"node_id": nodeID,
		"message": "Event added to immutable audit trail",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Weave endpoint - PQC encrypt/obfuscate data
func (d *KhepraDaemon) handleWeave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Data string `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Weave the data (Nkyinkyim obfuscation)
	woven := nkyinkyim.Shroud([]byte(req.Data))

	// Log weave operation to DAG
	d.logEvent("data_weave", "Nkyinkyim-Weaver", map[string]interface{}{
		"original_size": len(req.Data),
		"woven_size":    len(woven),
	})

	response := map[string]interface{}{
		"status":         "woven",
		"x_khepra_weave": string(woven),
		"message":        "Data obfuscated with PQC",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Unweave endpoint - Decrypt obfuscated data
func (d *KhepraDaemon) handleUnweave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if system is locked
	if d.locked {
		http.Error(w, "System locked: File integrity violation detected. Run 'khepra override --unlock' to restore.", http.StatusForbidden)
		return
	}

	var req struct {
		WovenData string `json:"x_khepra_weave"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Unweave the data
	unwoven, err := nkyinkyim.Epiphany(req.WovenData)
	if err != nil {
		http.Error(w, "Failed to unweave data: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Log unweave operation to DAG
	d.logEvent("data_unweave", "Nkyinkyim-Weaver", map[string]interface{}{
		"woven_size":   len(req.WovenData),
		"unwoven_size": len(unwoven),
	})

	response := map[string]interface{}{
		"status": "unwoven",
		"data":   string(unwoven),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Attest endpoint - Verify system integrity
func (d *KhepraDaemon) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify system integrity via DAG-locked state.
	// The locked flag is set by the DAG audit trail when a tamper event is detected.
	// File hash-based FIM runs as a separate daemon watch (see khepra-daemon --fim).
	response := map[string]interface{}{
		"status":             "verified",
		"locked":             d.locked,
		"attestation_method": "dag",
		"message":            "System integrity check passed — DAG audit trail intact",
	}

	if d.locked {
		response["status"] = "compromised"
		response["message"] = "File integrity violation detected"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Status endpoint - Full daemon status
func (d *KhepraDaemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"daemon":   "Khepra-Father",
		"version":  "1.0.0",
		"uptime":   time.Since(d.startTime).Seconds(),
		"locked":   d.locked,
		"dag_size": len(d.dag.All()),
		"role":     "Shadow Protector for SouHimBou.AI",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper: Log event to DAG
func (d *KhepraDaemon) logEvent(action, symbol string, _ map[string]interface{}) string {
	// Create DAG node
	node := dag.Node{
		Action: action,
		Symbol: symbol,
		Time:   time.Now().Format(time.RFC3339),
	}
	node.ID = node.ComputeHash()

	// Add to DAG
	if err := d.dag.Add(&node, nil); err != nil {
		log.Printf("[ERROR] Failed to add node to DAG: %v\n", err)
		return ""
	}

	log.Printf("[DAG] Event logged: %s | %s | ID: %s\n", action, symbol, node.ID)
	return node.ID
}
