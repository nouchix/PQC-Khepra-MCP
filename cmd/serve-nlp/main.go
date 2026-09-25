// cmd/serve-nlp/main.go — ASAF Natural Language Security Platform server
//
// Usage:
//   asaf serve-nlp               # starts on :7777, api on :45444
//   asaf serve-nlp --port 8080   # custom port
//   asaf serve-nlp --no-open     # don't auto-open browser
//
// The asaf-nlp.html is embedded at build time from the static/ subdirectory.
// To update: cp docs/asaf-nlp.html cmd/serve-nlp/static/asaf-nlp.html
//
//go:generate cp ../../docs/asaf-nlp.html static/asaf-nlp.html

package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

//go:embed static
var nlpHTML embed.FS

// initLlamafile detects, starts or reuses a llamafile LLM backend.
// Returns the exec.Cmd (nil if not started) and the base URL (empty if unavailable).
func initLlamafile(ctx context.Context, port int) (*exec.Cmd, string) {
	lf := detectLlamafile()
	if lf == "" {
		log.Printf("[serve-nlp] No llamafile found — LLM detection order: Ollama→LM Studio→OpenRouter")
		log.Printf("[serve-nlp] To ship a bundled LLM: place asaf-phi3-mini.llamafile next to the asaf binary")
		return nil, ""
	}

	log.Printf("[serve-nlp] llamafile detected: %s", lf)
	url := fmt.Sprintf("http://localhost:%d", port)

	if isPortOpen(port) {
		log.Printf("[serve-nlp] llamafile already running on :%d", port)
		return nil, url
	}

	cmd, err := startLlamafile(ctx, lf, port)
	if err != nil {
		log.Printf("[serve-nlp] WARNING: could not start llamafile: %v", err)
		return nil, ""
	}

	log.Printf("[serve-nlp] llamafile started on :%d (PID %d)", port, cmd.Process.Pid)
	waitForPort(port, 10*time.Second)
	return cmd, url
}

// initAPIServer locates the API binary and starts it with polymorphic port negotiation.
// Returns the resolved port and exec.Cmd (nil if not started).
func initAPIServer(ctx context.Context, apiPath string, defaultPort int) (int, *exec.Cmd) {
	apiBin := apiPath
	if apiBin == "" {
		apiBin = detectAPIBinary()
	}
	if apiBin == "" {
		log.Printf("[serve-nlp] No API binary found — NLP UI will prompt for API URL")
		return defaultPort, nil
	}

	resolvedPort, cmd := startAPIPolymorphic(ctx, apiBin, defaultPort)
	if cmd == nil {
		log.Printf("[serve-nlp] WARNING: Could not start API server on any port")
		log.Printf("[serve-nlp] NLP UI will still work — start ASAF manually: %s --port %d", apiBin, defaultPort)
	}
	return resolvedPort, cmd
}

// gracefulStop sends SIGTERM to a process if it is running.
func gracefulStop(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck
	}
}

func main() {
	port := flag.Int("port", 7777, "Port for NLP console")
	apiPort := flag.Int("api-port", 45444, "Port for ASAF API server")
	noOpen := flag.Bool("no-open", false, "Don't auto-open browser")
	apiPath := flag.String("api-bin", "", "Path to asaf-apiserver binary (auto-detected if empty)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	llamaCmd, llamaURL := initLlamafile(ctx, 8080)
	resolvedAPIPort, apiCmd := initAPIServer(ctx, *apiPath, *apiPort)

	// ── Serve asaf-nlp.html ──────────────────────────────────────────────────
	sub, err := fs.Sub(nlpHTML, "static")
	if err != nil {
		log.Fatalf("[serve-nlp] embed.FS error: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Inject runtime config — includes llamafileURL and server-detected OS
	// so the browser Polymorphic Connector can show the correct start command
	// without relying on navigator.userAgent alone.
	mux.HandleFunc("/asaf-config.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `
window.ASAF_CONFIG = {
  apiURL: "http://localhost:%d",
  ollamaURL: "http://localhost:11434",
  lmstudioURL: "http://localhost:1234",
  llamafileURL: "%s",
  version: "%s",
  os: "%s"
};
`, resolvedAPIPort, llamaURL, version(), runtime.GOOS)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		<-ctx.Done()
		log.Println("[serve-nlp] Shutting down...")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutCancel()
		srv.Shutdown(shutCtx) //nolint:errcheck
	}()

	consoleURL := fmt.Sprintf("http://localhost:%d/asaf-nlp.html", *port)
	log.Printf("[serve-nlp] NLP console: %s", consoleURL)
	log.Printf("[serve-nlp] API server:  http://localhost:%d", resolvedAPIPort)
	log.Printf("[serve-nlp] Press Ctrl+C to stop")

	if !*noOpen {
		time.AfterFunc(500*time.Millisecond, func() { openBrowser(consoleURL) })
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[serve-nlp] HTTP server error: %v", err)
	}

	gracefulStop(apiCmd)
	gracefulStop(llamaCmd)
	log.Println("[serve-nlp] Stopped.")
}

// detectLlamafile looks for a llamafile binary adjacent to the asaf executable
// or in the current working directory. Naming convention: asaf-*.llamafile
func detectLlamafile() string {
	// Check same directory as the running binary
	exeDir := ""
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}

	candidates := []string{
		// Specific model names we ship
		filepath.Join(exeDir, "asaf-phi3-mini.llamafile"),
		filepath.Join(exeDir, "asaf-llama3.llamafile"),
		// Generic glob-style fallback (checked by explicit name pattern)
		"./asaf-phi3-mini.llamafile",
		"./asaf-llama3.llamafile",
		// User may have placed any .llamafile here
		filepath.Join(exeDir, "phi3-mini.llamafile"),
		"./phi3-mini.llamafile",
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			// Ensure it's executable
			if info.Mode()&0111 != 0 {
				return c
			}
			// On Windows .llamafile files may lack exec bit — still usable
			if runtime.GOOS == "windows" {
				return c
			}
		}
	}
	return ""
}

// startLlamafile starts the llamafile as a subprocess serving OpenAI-compatible
// API on the given port. llamafile uses --server --port flags.
func startLlamafile(ctx context.Context, path string, port int) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, path,
		"--server",
		"--host", "127.0.0.1",
		"--port", fmt.Sprintf("%d", port),
		"--nobrowser",
		"--log-disable",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exec llamafile: %w", err)
	}
	return cmd, nil
}

func isPortOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func detectAPIBinary() string {
	// Check Windows .exe first when running on Windows (GOOS=windows),
	// then cross-platform names, then PATH lookup.
	candidates := []string{
		// Windows — explicit .exe so AV/EDR whitelisting by name works
		"./bin/asaf-agent.exe",
		"./bin/asaf-apiserver.exe",
		// Linux
		"./bin/asaf-agent-linux-amd64",
		"./bin/asaf-agent-linux-arm64",
		"./bin/asaf-apiserver-linux-amd64",
		// macOS
		"./bin/asaf-agent-darwin-amd64",
		"./bin/asaf-agent-darwin-arm64",
		"./bin/asaf-apiserver-darwin-amd64",
		"./bin/asaf-apiserver-darwin-arm64",
		// Generic (set via PATH or symlink)
		"asaf-agent",
		"asaf-apiserver",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

func waitForPort(port int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("localhost:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	}
	if cmd != nil {
		cmd.Start() //nolint:errcheck
	}
}

// startAPIPolymorphic starts the ASAF API server, trying the primary port first
// and stepping through up to 3 fallback ports (matching browser Polymorphic
// Connector probe order: 45444 → 45445 → 45446 → 45447).
// Returns the resolved port and the running Cmd, or (primaryPort, nil) on failure.
func startAPIPolymorphic(ctx context.Context, apiBin string, primaryPort int) (int, *exec.Cmd) {
	ports := []int{primaryPort, primaryPort + 1, primaryPort + 2, primaryPort + 3}
	for _, port := range ports {
		if isPortOpen(port) {
			log.Printf("[serve-nlp] Port %d already in use — trying next polymorphic port", port)
			continue
		}
		log.Printf("[serve-nlp] Starting API server: %s on :%d", apiBin, port)
		cmd := exec.CommandContext(ctx, apiBin)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("ADINKHEPRA_AGENT_PORT=%d", port),
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Printf("[serve-nlp] WARNING: Could not start API on :%d: %v", port, err)
			continue
		}
		log.Printf("[serve-nlp] API server PID %d on :%d", cmd.Process.Pid, port)
		waitForPort(port, 5*time.Second)
		if isPortOpen(port) {
			return port, cmd
		}
		// Process started but port not answering — kill and try next
		cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck
		log.Printf("[serve-nlp] API on :%d did not become ready — trying next port", port)
	}
	return primaryPort, nil
}

func version() string {
	if v := os.Getenv("ASAF_VERSION"); v != "" {
		return v
	}
	return "dev"
}
