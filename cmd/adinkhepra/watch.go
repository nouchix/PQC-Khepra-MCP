package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/asaf"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/g0dm0d3"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/logging"
)


//go:embed static/*
var watchStatic embed.FS

const (
	watchDivider     = "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"
	watchContentType = "Content-Type"
	watchAppJSON     = "application/json"
	watchCORSOrigin  = "Access-Control-Allow-Origin"
)

// watchCmd starts the ASAF wrapper + live dashboard
//
// Usage:
//
//	adinkhepra watch [-port 45444]
//
// One command â†’ browser opens â†’ full NLP + DAG constellation at :45444.
func watchCmd(args []string) {
	port := parseWatchPort(args)

	printWatchBanner()

	dagStore := dag.GlobalDAG()
	fmt.Printf("  âœ… DAG connected (%d nodes)\n", len(dagStore.All()))

	logger := logging.NewDoDLogger(os.Stdout, logging.RedactSensitive, "default", "asaf-watch")
	wrapper := asaf.NewASAFWrapper(dagStore, logger)
	recorder := asaf.NewRecorder(wrapper)

	brain := g0dm0d3.NewServer(dagStore)
	fmt.Printf("  ðŸ§  G0DM0D3 AI: %s\n", brain.Provider.Name())

	defaultAgent, err := wrapper.WrapMCPAgent("default-watch", "mcp-interceptor")
	if err != nil {
		log.Printf("  âš ï¸  Could not start default session: %v", err)
	} else {
		fmt.Printf("  ðŸ“¡ ASAF session: %s\n", defaultAgent.SessionID)
	}

	mux := http.NewServeMux()
	registerWatchRoutes(mux, recorder, brain, dagStore, wrapper, defaultAgent, port)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	srv := &http.Server{Addr: addr, Handler: mux}

	printWatchEndpoints(port)

	// Auto-open browser after a brief delay so the server is ready
	go func() {
		time.Sleep(600 * time.Millisecond)
		openBrowser(fmt.Sprintf("http://localhost:%d", port))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\nðŸ›‘ Shutting down ASAF...")
		if defaultAgent != nil {
			wrapper.EndSession(defaultAgent)
		}
		shutCtx, shutCancel := context.WithTimeout(ctx, 3*time.Second)
		defer shutCancel()
		srv.Shutdown(shutCtx) //nolint:errcheck
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("âŒ Server error: %v\n", err)
	}
	fmt.Println("âœ… ASAF stopped. All sessions signed and sealed in DAG.")
}

// parseWatchPort extracts the -port flag value from args (default 45444).
func parseWatchPort(args []string) int {
	port := 45444
	for i, arg := range args {
		if arg == "-port" && i+1 < len(args) {
			fmt.Sscanf(args[i+1], "%d", &port)
		}
	}
	return port
}

// printWatchBanner prints the ASAF startup banner.
func printWatchBanner() {
	fmt.Println(watchDivider)
	fmt.Println("  ðŸ”’ ADINKHEPRA ASAF // Natural Language Security Platform")
	fmt.Println(watchDivider)
	fmt.Println()
	fmt.Println("  AI-powered CyberOps. Every action signed. Auditor-ready.")
	fmt.Println("  DAG constellation is live. NL chat is online.")
	fmt.Println()
}

// printWatchEndpoints prints the listening address and endpoint list.
func printWatchEndpoints(port int) {
	fmt.Println()
	fmt.Println("  ðŸ“Š Endpoints:")
	fmt.Printf("     http://localhost:%d/                  â€” NLP Dashboard (browser)\n", port)
	fmt.Printf("     http://localhost:%d/api/asaf/stream   â€” Live SSE feed\n", port)
	fmt.Printf("     http://localhost:%d/api/asaf/sessions â€” Active sessions\n", port)
	fmt.Printf("     http://localhost:%d/api/g0dm0d3/chat  â€” AI chat\n", port)
	fmt.Printf("     http://localhost:%d/api/dag/nodes     â€” DAG nodes\n", port)
	fmt.Printf("     http://localhost:%d/api/dag/stream    â€” DAG SSE (real-time)\n", port)
	fmt.Printf("     http://localhost:%d/healthz           â€” Health check\n", port)
	fmt.Println()
	fmt.Printf("  ðŸŒ Opening dashboard: http://localhost:%d\n", port)
	fmt.Println("  Press Ctrl+C to stop")
	fmt.Println(watchDivider)
}

// registerWatchRoutes wires all HTTP routes onto mux.
func registerWatchRoutes(
	mux *http.ServeMux,
	recorder *asaf.Recorder,
	brain *g0dm0d3.G0DM0D3Server,
	dagStore *dag.PersistentMemory,
	wrapper *asaf.ASAFWrapper,
	defaultAgent *asaf.WrappedAgent,
	port int,
) {
	// â”€â”€ Static Dashboard (asaf-nlp.html embedded) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	sub, err := fs.Sub(watchStatic, "static")
	if err != nil {
		log.Fatalf("embed FS error: %v", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))

	// Serve index.html at / â€” the full NLP + DAG dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		data, err := watchStatic.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "dashboard not found", http.StatusInternalServerError)
			return
		}
		w.Write(data) //nolint:errcheck
	})

	// Runtime config injection â€” browser reads this as window.ASAF_CONFIG
	mux.HandleFunc("/asaf-config.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `window.ASAF_CONFIG = {
  apiURL: "http://localhost:%d",
  ollamaURL: "http://localhost:11434",
  lmstudioURL: "http://localhost:1234",
  llamafileURL: "",
  version: "1.0",
  os: "%s",
  mode: "sovereign"
};
`, port, runtime.GOOS)
	})

	// â”€â”€ ASAF endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	mux.HandleFunc("/api/asaf/stream", recorder.HandleSSE)
	mux.HandleFunc("/api/asaf/sessions", recorder.HandleSessions)
	mux.HandleFunc("/api/asaf/history", recorder.HandleHistory)
	mux.HandleFunc("/api/asaf/record", buildRecordHandler(wrapper, recorder, defaultAgent))

	// â”€â”€ G0DM0D3 AI endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	mux.HandleFunc("/api/g0dm0d3/chat", brain.HandleChat)
	mux.HandleFunc("/api/g0dm0d3/status", brain.HandleStatus)

	// â”€â”€ DAG endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	mux.HandleFunc("/api/dag/nodes", buildDAGNodesHandler(dagStore))
	mux.HandleFunc("/api/dag/stats", buildDAGStatsHandler(dagStore))
	mux.HandleFunc("/api/dag/stream", buildDAGStreamHandler(dagStore))

	// â”€â”€ Scan API (sovereign offline scanning) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	registerScanRoutes(mux)

	// â”€â”€ Health checks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(watchContentType, watchAppJSON)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"status": "ok", "engine": "AdinKhepra ASAF", "version": "1.0",
			"mode": "sovereign",
		})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(watchContentType, watchAppJSON)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
	})
}

// buildDAGNodesHandler returns the /api/dag/nodes handler.
// Response shape: {"nodes":[...],"count":N} â€” matches asaf-nlp.html expectations.
func buildDAGNodesHandler(dagStore *dag.PersistentMemory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(watchContentType, watchAppJSON)
		w.Header().Set(watchCORSOrigin, "*")
		nodes := dagStore.All()
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"nodes": nodes,
			"count": len(nodes),
		})
	}
}

// buildDAGStatsHandler returns the /api/dag/stats handler.
func buildDAGStatsHandler(dagStore *dag.PersistentMemory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(watchContentType, watchAppJSON)
		w.Header().Set(watchCORSOrigin, "*")
		nodes := dagStore.All()
		signed, asafNodes := 0, 0
		for _, n := range nodes {
			if n.Signature != "" {
				signed++
			}
			if len(n.Action) > 4 && n.Action[:4] == "ASAF" {
				asafNodes++
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"total_nodes": len(nodes), "signed_nodes": signed, "asaf_nodes": asafNodes,
			"fips_enabled": true, "pqc_active": true,
		})
	}
}

// buildDAGStreamHandler returns the /api/dag/stream SSE handler.
// Sends a snapshot on connect, then pushes delta stats every 3 seconds.
// The asaf-nlp.html D3 graph and Security Ledger both consume this stream.
func buildDAGStreamHandler(dagStore *dag.PersistentMemory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set(watchCORSOrigin, "*")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Send full snapshot immediately on connect
		nodes := dagStore.All()
		if data, err := json.Marshal(map[string]interface{}{"type": "snapshot", "nodes": nodes, "count": len(nodes)}); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}

		// Push stats every 3 seconds so the HUD overlay stays live
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				all := dagStore.All()
				signed := 0
				for _, n := range all {
					if n.Signature != "" {
						signed++
					}
				}
				data, _ := json.Marshal(map[string]interface{}{
					"type": "stats", "total_nodes": len(all), "signed_nodes": signed,
					"fips_enabled": true, "pqc_active": true,
					"last_sync": time.Now().UTC().Format(time.RFC3339),
				})
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
}

// buildRecordHandler returns the /api/asaf/record POST handler.
func buildRecordHandler(
	wrapper *asaf.ASAFWrapper,
	recorder *asaf.Recorder,
	defaultAgent *asaf.WrappedAgent,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(watchContentType, watchAppJSON)
		w.Header().Set(watchCORSOrigin, "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		var action asaf.MCPAction
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		if action.Timestamp.IsZero() {
			action.Timestamp = time.Now().UTC()
		}

		agent := defaultAgent
		if action.SessionID != "" {
			if sess, ok := wrapper.GetSession(action.SessionID); ok {
				agent = sess
			}
		}
		if agent == nil {
			http.Error(w, `{"error":"no active session"}`, http.StatusBadRequest)
			return
		}

		node, err := wrapper.RecordAction(agent, action)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		recorder.Broadcast(asaf.ActionEvent{
			Type: "action", NodeID: node.ID, SessionID: agent.SessionID,
			AgentID: agent.AgentID, AgentType: agent.AgentType,
			Tool: action.Tool, Timestamp: action.Timestamp,
		})

		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"status": "recorded", "node_id": node.ID,
		})
	}
}

