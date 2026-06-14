//go:build saas

package apiserver

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
)

// ExampleUsage demonstrates how to start the Khepra API server
//
// Usage in cmd/agent/main.go:
//
//	import "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/apiserver"
//
//	func main() {
//	    // Initialize DAG (global singleton)
//	    dagStore := dag.GlobalDAG()
//
//	    // Initialize license manager
//	    licMgr, err := license.NewManager("https://telemetry.souhimbou.org")
//	    if err != nil {
//	        log.Fatalf("Failed to create license manager: %v", err)
//	    }
//
//	    if err := licMgr.Initialize(); err != nil {
//	        log.Printf("License validation failed: %v", err)
//	        log.Println("Running in community mode")
//	    }
//
//	    // Create API server
//	    config := &apiserver.Config{
//	        Host:       "0.0.0.0",
//	        Port:       8080,
//	        TLSEnabled: false, // Set to true for production
//	        TLSDomain:  "khepra.example.com",
//	        CertCacheDir: "/var/cache/khepra-certs",
//	        Debug:      false,
//	    }
//
//	    // Create adapters
//	    dagAdapter := apiserver.NewDAGStoreAdapter(dagStore)
//	    licAdapter := apiserver.NewLicenseManagerAdapter(licMgr)
//
//	    // Start server
//	    server := apiserver.NewServer(config, dagAdapter, licAdapter)
//
//	    // Graceful shutdown
//	    go func() {
//	        if err := server.Start(); err != nil {
//	            log.Fatalf("Server error: %v", err)
//	        }
//	    }()
//
//	    // Wait for interrupt signal
//	    quit := make(chan os.Signal, 1)
//	    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
//	    <-quit
//
//	    log.Println("Shutting down server...")
//	    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	    defer cancel()
//
//	    if err := server.Shutdown(ctx); err != nil {
//	        log.Fatalf("Server forced to shutdown: %v", err)
//	    }
//
//	    log.Println("Server exited")
//	}
func ExampleUsage() {
	// Initialize DAG (global singleton)
	dagStore := dag.GlobalDAG()

	// Initialize license manager
	licMgr, err := license.NewManager("https://telemetry.souhimbou.org")
	if err != nil {
		log.Fatalf("Failed to create license manager: %v", err)
	}

	// Initialize license (validates with server and starts heartbeat)
	if err := licMgr.Initialize(); err != nil {
		log.Printf("License validation failed: %v", err)
		log.Println("Running in community mode")
	}

	// Create API server configuration
	config := &Config{
		Host:       "0.0.0.0",
		Port:       8080,
		TLSEnabled: false, // Set to true for production with Let's Encrypt
		TLSDomain:  "khepra.example.com",
		CertCacheDir: "/var/cache/khepra-certs",
		Debug:      false,
	}

	// Create adapters to bridge existing components with API server
	dagAdapter := NewDAGStoreAdapter(dagStore)
	licAdapter := NewLicenseManagerAdapter(licMgr)

	// Create and start server
	server := NewServer(config, dagAdapter, licAdapter)

	// Start server in background
	go func() {
		log.Printf("Starting Khepra API Server on %s:%d", config.Host, config.Port)
		if err := server.Start(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown on interrupt
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Received shutdown signal...")

	// Shutdown with 30-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	// Stop license heartbeat
	licMgr.Stop()

	log.Println("Server exited gracefully")
}

// ExampleWebSocketClient demonstrates how to connect to WebSocket endpoints
//
// JavaScript/TypeScript example for SouHimBou.ai dashboard:
//
//	const ws = new WebSocket('wss://khepra.example.com/ws/scans');
//
//	ws.onopen = () => {
//	    console.log('Connected to Khepra scan updates');
//	};
//
//	ws.onmessage = (event) => {
//	    const message = JSON.parse(event.data);
//	    console.log('Scan update:', message);
//
//	    if (message.type === 'scan_update') {
//	        // Update React state with scan progress
//	        setScanStatus(message.data);
//	    }
//	};
//
//	ws.onerror = (error) => {
//	    console.error('WebSocket error:', error);
//	};
//
//	ws.onclose = () => {
//	    console.log('Disconnected from Khepra');
//	    // Implement reconnection logic
//	};
func ExampleWebSocketClient() {
	// See documentation above for client-side implementation
}

// ExampleAPIRequest demonstrates how to call REST API endpoints
//
// curl examples:
//
// 1. Health check:
//    curl http://localhost:8080/health
//
// 2. Trigger scan:
//    curl -X POST http://localhost:8080/api/v1/scans/trigger \
//      -H "Authorization: Bearer <machine_id>" \
//      -H "Content-Type: application/json" \
//      -d '{
//        "target_url": "https://example.com",
//        "scan_type": "crypto",
//        "priority": 5
//      }'
//
// 3. Get scan status:
//    curl http://localhost:8080/api/v1/scans/<scan_id> \
//      -H "Authorization: Bearer <machine_id>"
//
// 4. Get DAG nodes:
//    curl http://localhost:8080/api/v1/dag/nodes?type=scan&limit=50 \
//      -H "Authorization: Bearer <machine_id>"
//
// 5. STIG validation:
//    curl -X POST http://localhost:8080/api/v1/stig/validate \
//      -H "Authorization: Bearer <machine_id>" \
//      -H "Content-Type: application/json" \
//      -d '{
//        "stig_version": "RHEL9",
//        "target_host": "192.168.1.100"
//      }'
//
// 6. Generate ERT:
//    curl -X POST http://localhost:8080/api/v1/ert/generate \
//      -H "Authorization: Bearer <machine_id>" \
//      -H "Content-Type: application/json" \
//      -d '{
//        "event_type": "scan",
//        "event_data": {
//          "scan_id": "abc-123",
//          "result": "passed"
//        }
//      }'
//
// 7. Get license status:
//    curl http://localhost:8080/api/v1/license/status \
//      -H "Authorization: Bearer <machine_id>"
func ExampleAPIRequest() {
	// See documentation above for curl examples
}
