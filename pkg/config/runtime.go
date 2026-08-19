package config

import (
	"os"
	"path/filepath"
)

// RuntimeConfig is the central deployment configuration for a KHEPRA process.
//
// It is constructed once at startup (cmd/agent, cmd/adinkhepra, cmd/khepra-mcp)
// and passed down through constructors. No scattered os.Getenv() calls in
// business logic — all runtime policy decisions flow from this struct.
//
// Usage:
//
//	cfg := config.LoadRuntime()
//	store := dag.NewStoreForMode(cfg.Mode)
//	sonarLane := ert.NewSonarLane(ert.SonarLaneConfig{NetworkPolicy: cfg.NetworkPolicy})
type RuntimeConfig struct {
	// Mode is the deployment mode — sovereign (default), edge, hybrid, or ironbank.
	// Read from KHEPRA_MODE environment variable.
	// sovereign = bare metal, air-gap, SQLite, no external calls (DEFAULT)
	// edge      = SaaS Fly.io, stateless MCP, no local persistence
	// hybrid    = SaaS with local DAG cache
	// ironbank  = DoD hardened, air-gapped, FIPS-only
	Mode string

	// NetworkPolicy controls what network targets are reachable from this process.
	NetworkPolicy NetworkPolicy

	// DAGPath is the on-disk path for PersistentMemory (sovereign/ironbank only).
	// Empty in edge/hybrid mode (in-memory DAG is used).
	DAGPath string

	// LicensePath is the path to the offline license file (.adinkhepra).
	// Used in sovereign/ironbank mode for air-gap / SCIF delivery.
	// Prefer LicenseKey when not in a classified environment.
	LicensePath string

	// LicenseKey is the API-key format license (kphr_{tier}_{base64url-payload}).
	// Read from KHEPRA_LICENSE_KEY. Takes priority over LicensePath.
	LicenseKey string

	// IsAirGapped is true when no external network calls are permitted.
	IsAirGapped bool

	// IsSaaS is true when the process is running in a cloud/SaaS context.
	IsSaaS bool
}

// NetworkPolicy controls what network targets are reachable from a KHEPRA process.
type NetworkPolicy string

const (
	// NetworkPolicyLocalOnly restricts all network scanning to loopback (127.0.0.1/::1).
	// Used by: sovereign binary when extra-paranoid mode is required.
	NetworkPolicyLocalOnly NetworkPolicy = "local_only"

	// NetworkPolicyLAN restricts network scanning to RFC 1918 private ranges + loopback.
	// Used by: sovereign/ironbank default — scan your own network, not the internet.
	// Ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1, fc00::/7
	NetworkPolicyLAN NetworkPolicy = "lan"

	// NetworkPolicyUnrestricted allows scanning any reachable host including internet IPs.
	// Used by: edge/hybrid SaaS mode (MCP server on Fly.io). Never for sovereign.
	NetworkPolicyUnrestricted NetworkPolicy = "unrestricted"
)

// LoadRuntime reads KHEPRA_MODE and related env vars and returns the RuntimeConfig.
// This is the single point of configuration assembly — call it once at process start.
func LoadRuntime() RuntimeConfig {
	mode := runtimeModeFromEnv()
	isAirGapped := mode == "sovereign" || mode == "ironbank"
	isSaaS := mode == "edge" || mode == "hybrid"

	cfg := RuntimeConfig{
		Mode:        mode,
		IsAirGapped: isAirGapped,
		IsSaaS:      isSaaS,
		LicensePath: runtimeLicensePath(),
		LicenseKey:  os.Getenv("KHEPRA_LICENSE_KEY"),
	}

	if isAirGapped {
		cfg.NetworkPolicy = NetworkPolicyLAN
		cfg.DAGPath = runtimeDAGPath()
	} else {
		cfg.NetworkPolicy = NetworkPolicyUnrestricted
		// DAGPath is empty for SaaS — in-memory store is used
	}

	// Allow explicit override of network policy (e.g., extra-paranoid sovereign)
	if override := os.Getenv("KHEPRA_NETWORK_POLICY"); override != "" {
		cfg.NetworkPolicy = NetworkPolicy(override)
	}

	return cfg
}

// knownModes is the allow-list of valid KHEPRA_MODE values.
// Any other value is rejected at startup with a warning and falls back to sovereign.
var knownModes = map[string]bool{
	"sovereign": true, // Air-gapped, on-prem, SCIF (DEFAULT)
	"ironbank":  true, // DoD/IC hardened, FIPS-only, air-gapped
	"hybrid":    true, // Edge + local DAG cache, SaaS
	"edge":      true, // Fully stateless SaaS (Fly.io)
}

func runtimeModeFromEnv() string {
	m := os.Getenv("KHEPRA_MODE")
	if m == "" {
		return "sovereign" // safe default — air-gapped, zero external calls
	}
	if !knownModes[m] {
		// Unknown mode: log to stderr and fail-closed to sovereign.
		// This prevents a misconfigured deployment from accidentally opening
		// network policy to unrestricted (edge) when an unknown value is set.
		os.Stderr.WriteString("[khepra-mcp] WARNING: unknown KHEPRA_MODE=" + m +
			" — valid modes: sovereign, ironbank, hybrid, edge. Falling back to sovereign.\n")
		return "sovereign"
	}
	return m
}

func runtimeDAGPath() string {
	if p := os.Getenv("KHEPRA_DAG_PATH"); p != "" {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".khepra", "dag")
	}
	wd, _ := os.Getwd()
	return filepath.Join(wd, "data", "dag")
}

func runtimeLicensePath() string {
	if p := os.Getenv("KHEPRA_LICENSE_PATH"); p != "" {
		return p
	}
	// Check working directory first, then exe directory
	if _, err := os.Stat("license.adinkhepra"); err == nil {
		return "license.adinkhepra"
	}
	return "license.adinkhepra" // default (caller resolves relative to exe)
}
