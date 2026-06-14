package dag

import (
	"log"
	"os"
	"path/filepath"
)

// NewStore returns the correct DAG store implementation for the current deployment mode.
//
// This is the single point of storage-backend selection for the entire system.
// All entry points (cmd/agent, cmd/adinkhepra, cmd/khepra-mcp) must call this
// instead of constructing stores directly.
//
// Storage policy by mode (read from KHEPRA_MODE env var):
//
//	sovereign (default) → PersistentMemory at KHEPRA_DAG_PATH (default: ~/.khepra/dag/)
//	ironbank            → PersistentMemory at KHEPRA_DAG_PATH (FIPS hardened path)
//	edge                → Memory (in-process, ephemeral — MCP per-call context)
//	hybrid              → Memory (in-process, ephemeral — SaaS per-session)
//
// Supabase / PostgreSQL backend is never selected here — that lives in pkg/gateway
// under the `saas` build tag and is wired at the application layer only.
//
// Fail-safe: any error initializing PersistentMemory falls back to in-memory
// with a loud warning — the system must never fail to start due to a storage error.
func NewStore() Store {
	mode := dagModeFromEnv()
	switch mode {
	case "sovereign", "ironbank":
		path := sovereignDAGPath()
		pm, err := NewPersistentMemory(path)
		if err != nil {
			log.Printf("[DAG-FACTORY] WARN: PersistentMemory init failed (%v) — falling back to in-memory. DAG will NOT persist across restarts.", err)
			return NewMemory()
		}
		log.Printf("[DAG-FACTORY] Sovereign store: %s (mode=%s)", path, mode)
		return pm
	default:
		// edge, hybrid, unrecognised → stateless in-memory (SaaS / MCP per-call)
		log.Printf("[DAG-FACTORY] In-memory store (mode=%s, ephemeral)", mode)
		return NewMemory()
	}
}

// dagModeFromEnv reads KHEPRA_MODE without importing pkg/sekhem (avoids circular dep).
func dagModeFromEnv() string {
	m := os.Getenv("KHEPRA_MODE")
	if m == "" {
		return "sovereign" // safe default
	}
	return m
}

// sovereignDAGPath returns the on-disk storage path for the DAG in sovereign/ironbank mode.
//
// Resolution order:
//  1. KHEPRA_DAG_PATH env var (explicit override — useful for containerised sovereign deploys)
//  2. ~/.khepra/dag/  (default user-local path — works on Linux, macOS, Windows)
//  3. ./data/dag/     (last resort — working directory, matches legacy behaviour)
func sovereignDAGPath() string {
	if p := os.Getenv("KHEPRA_DAG_PATH"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".khepra", "dag")
	}
	wd, _ := os.Getwd()
	return filepath.Join(wd, "data", "dag")
}
