// cmd/adinkhepra/cmd_llm.go — `asaf llm` subcommand group
//
// Commands:
//   asaf llm install          — download phi3-mini.llamafile (default)
//   asaf llm install --model mistral  — download mistral-7b.llamafile
//   asaf llm status          — check what LLM is currently available
//
// The downloaded llamafile is placed next to the asaf binary so
// pkg/llm.Detect() finds it automatically at serve-nlp startup.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// llamafileSpec describes a downloadable llamafile model.
type llamafileSpec struct {
	Name        string
	URL         string
	SHA256      string
	SizeDesc    string
	Description string
}

// Available llamafile models. SHA256 values must be filled from the Mozilla
// release page before shipping: https://github.com/Mozilla-Ocho/llamafile/releases
var llamafileModels = map[string]llamafileSpec{
	"phi3-mini": {
		Name:        "asaf-phi3-mini.llamafile",
		URL:         "https://huggingface.co/Mozilla/Phi-3-mini-4k-instruct-llamafile/resolve/main/Phi-3-mini-4k-instruct.Q4_K_M.llamafile",
		SHA256:      "", // Set from HuggingFace model card SHA256 before release
		SizeDesc:    "~2.3 GB",
		Description: "Fast on CPU, good structured output, default for ASAF",
	},
	"mistral": {
		Name:        "asaf-mistral-7b.llamafile",
		URL:         "https://huggingface.co/Mozilla/Mistral-7B-Instruct-v0.2-llamafile/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.llamafile",
		SHA256:      "", // Set from HuggingFace model card SHA256 before release
		SizeDesc:    "~4.1 GB",
		Description: "Better CMMC/STIG terminology — recommended for compliance use",
	},
}

func llmCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: asaf llm <subcommand>")
		fmt.Println("")
		fmt.Println("Subcommands:")
		fmt.Println("  install [--model phi3-mini|mistral]   Download bundled LLM model")
		fmt.Println("  status                                 Show available LLM backends")
		return
	}
	switch args[0] {
	case "install":
		model := "phi3-mini"
		for i, a := range args {
			if a == "--model" && i+1 < len(args) {
				model = args[i+1]
			}
		}
		if err := cmdLLMInstall(model); err != nil {
			fatal("llm install failed", err)
		}
	case "status":
		cmdLLMStatus()
	default:
		fmt.Printf("Unknown llm subcommand: %s\n", args[0])
	}
}

func cmdLLMInstall(model string) error {
	spec, ok := llamafileModels[model]
	if !ok {
		available := make([]string, 0, len(llamafileModels))
		for k := range llamafileModels {
			available = append(available, k)
		}
		return fmt.Errorf("unknown model %q — available: %s", model, strings.Join(available, ", "))
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	dest := filepath.Join(exeDir, spec.Name)

	// Already installed?
	if _, err := os.Stat(dest); err == nil {
		fmt.Printf("✅ %s already present at %s\n", spec.Name, dest)
		fmt.Printf("   Run 'asaf serve-nlp' to start the NLP platform with this model.\n")
		return nil
	}

	fmt.Printf("📥 Downloading %s (%s)...\n", spec.Name, spec.SizeDesc)
	fmt.Printf("   Model:       %s\n", spec.Description)
	fmt.Printf("   Destination: %s\n", dest)
	fmt.Println()

	tmpPath := dest + ".tmp"
	if err := downloadWithProgress(spec.URL, tmpPath); err != nil {
		os.Remove(tmpPath) //nolint:errcheck
		return fmt.Errorf("download failed: %w", err)
	}

	// SHA-256 verification (skip if SHA256 not yet set in spec)
	if spec.SHA256 != "" {
		fmt.Print("\n🔐 Verifying SHA-256... ")
		if err := verifySHA256(tmpPath, spec.SHA256); err != nil {
			os.Remove(tmpPath) //nolint:errcheck
			return fmt.Errorf("SHA-256 MISMATCH — file corrupted or tampered: %w\n"+
				"   Report to security@nouchix.com if this persists.", err)
		}
		fmt.Println("✓ verified")
	} else {
		fmt.Println("\n⚠️  SHA-256 not configured — skipping verification (development mode)")
	}

	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("install to %s: %w", dest, err)
	}

	// Make executable on Linux/macOS
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dest, 0755); err != nil {
			return fmt.Errorf("chmod +x %s: %w", dest, err)
		}
	}

	fmt.Printf("\n✅ Installed: %s\n", dest)
	fmt.Printf("   Run 'asaf serve-nlp' — local LLM will start automatically\n\n")
	return nil
}

func cmdLLMStatus() {
	fmt.Println("🔍 Checking LLM backends...")
	fmt.Println()

	type check struct{ name, url, path string }
	checks := []check{
		{"Ollama", "http://localhost:11434/api/tags", ""},
		{"LM Studio", "http://localhost:1234/v1/models", ""},
	}

	for _, c := range checks {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(c.url)
		if err == nil && resp.StatusCode < 500 {
			resp.Body.Close()
			fmt.Printf("  ✅ %-16s running at %s\n", c.name, c.url)
		} else {
			fmt.Printf("  ✗  %-16s not running\n", c.name)
		}
	}

	// Check for llamafile
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	for _, spec := range llamafileModels {
		path := filepath.Join(exeDir, spec.Name)
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("  📦 %-16s found at %s\n", spec.Name, path)
		}
	}

	fmt.Println()
	fmt.Println("  Priority order: Ollama → LM Studio → llamafile (auto-start) → OpenRouter")
	fmt.Println("  To install bundled LLM: asaf llm install [--model mistral]")
}

// ── Download helpers ──────────────────────────────────────────────────────────

func downloadWithProgress(url, dest string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)
	lastPrint := time.Now()

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			written, werr := writeChunk(f, buf[:n], downloaded, total, &lastPrint)
			if werr != nil {
				return werr
			}
			downloaded += written
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	fmt.Printf("\r   %s downloaded ✓\n", fmtBytes(downloaded))
	return nil
}

// writeChunk writes a buffer to f, updates the progress counter, and throttle-prints progress.
// Returns the number of bytes written.
func writeChunk(f *os.File, chunk []byte, downloaded, total int64, lastPrint *time.Time) (int64, error) {
	if _, err := f.Write(chunk); err != nil {
		return 0, err
	}
	n := int64(len(chunk))
	if time.Since(*lastPrint) > 2*time.Second {
		printDownloadProgress(downloaded+n, total)
		*lastPrint = time.Now()
	}
	return n, nil
}

// printDownloadProgress prints the current download progress to stdout.
func printDownloadProgress(downloaded, total int64) {
	if total > 0 {
		pct := float64(downloaded) / float64(total) * 100
		fmt.Printf("\r   %s / %s (%.0f%%)   ",
			fmtBytes(downloaded), fmtBytes(total), pct)
	} else {
		fmt.Printf("\r   %s downloaded   ", fmtBytes(downloaded))
	}
}

func verifySHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("got %s\n   want %s", got, expected)
	}
	return nil
}

func fmtBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return strconv.FormatInt(b, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

