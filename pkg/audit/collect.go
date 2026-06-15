package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/types"
)

// collectProcesses returns a live list of running processes.
// Uses ps on Linux/macOS and tasklist on Windows; falls back to just the
// agent's own PID if collection fails.
func collectProcesses() []types.ProcessInfo {
	self := types.ProcessInfo{
		PID:     os.Getpid(),
		Name:    execName(),
		CmdLine: strings.Join(os.Args, " "),
	}

	var out []byte
	var err error

	switch runtime.GOOS {
	case "linux", "darwin":
		out, err = exec.Command("ps", "-e", "-o", "pid=,comm=,args=").Output()
	case "windows":
		out, err = exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	default:
		return []types.ProcessInfo{self}
	}

	if err != nil {
		return []types.ProcessInfo{self}
	}

	var procs []types.ProcessInfo
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch runtime.GOOS {
		case "linux", "darwin":
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pid, _ := strconv.Atoi(fields[0])
			name := fields[1]
			cmdline := ""
			if len(fields) > 2 {
				cmdline = strings.Join(fields[2:], " ")
			}
			procs = append(procs, types.ProcessInfo{PID: pid, Name: name, CmdLine: cmdline})
		case "windows":
			// CSV: "Image Name","PID","Session","#","Mem Usage"
			parts := strings.Split(line, "\",\"")
			if len(parts) < 2 {
				continue
			}
			name := strings.Trim(parts[0], "\"")
			pid, _ := strconv.Atoi(strings.Trim(parts[1], "\""))
			procs = append(procs, types.ProcessInfo{PID: pid, Name: name})
		}
	}

	if len(procs) == 0 {
		return []types.ProcessInfo{self}
	}
	return procs
}

// hashFile computes a SHA-256 hex digest of a file for integrity attestation.
// Returns an error string on failure so callers always get a non-empty checksum field.
func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "hash-error:" + err.Error()
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "hash-error:" + err.Error()
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// execName returns the base name of the running executable.
func execName() string {
	exe, err := os.Executable()
	if err != nil {
		return "khepra-agent"
	}
	parts := strings.Split(strings.ReplaceAll(exe, "\\", "/"), "/")
	return parts[len(parts)-1]
}
