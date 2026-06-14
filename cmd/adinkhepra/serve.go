package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/webui"
)

// serveCmd starts the DAG visualization web server
func serveCmd(args []string) {
	port := 8080

	// Parse port from args if provided
	if len(args) > 0 && args[0] == "-port" && len(args) > 1 {
		fmt.Sscanf(args[1], "%d", &port)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  🔒 KHEPRA PROTOCOL // Living Trust Constellation")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Printf("  Starting DAG Viewer on port %d...\n", port)
	fmt.Println()
	fmt.Println("  🌐 Web Interface:")
	fmt.Printf("     http://localhost:%d/\n", port)
	fmt.Println()
	fmt.Println("  📊 API Endpoints:")
	fmt.Printf("     http://localhost:%d/api/dag/nodes  - Get all DAG nodes\n", port)
	fmt.Printf("     http://localhost:%d/api/dag/stats  - Get DAG statistics\n", port)
	fmt.Printf("     http://localhost:%d/health         - Health check\n", port)
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop the server")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Use the global singleton immutable DAG (production-grade)
	// This ensures the standalone viewer, agent server, and ERT all
	// share the same cryptographically-secured data structure
	dagMemory := dag.GlobalDAG()

	// Genesis node is automatically created by GlobalDAG()
	fmt.Printf("  ✅ Connected to global DAG (%d nodes)\n", len(dagMemory.All()))

	// Create production DAG provider (not mock!)
	provider := webui.NewProductionDAGProvider(dagMemory)

	// Create and start DAG viewer
	viewer := webui.NewDAGViewer(port, provider)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n🛑 Shutdown signal received...")
		fmt.Println("Stopping DAG Viewer...")
		if err := viewer.Stop(); err != nil {
			log.Printf("Error stopping server: %v\n", err)
		}
		fmt.Println("✅ Server stopped gracefully")
		os.Exit(0)
	}()

	// Start server (blocking)
	if err := viewer.Start(); err != nil {
		log.Fatalf("❌ Failed to start DAG Viewer: %v\n", err)
	}
}
