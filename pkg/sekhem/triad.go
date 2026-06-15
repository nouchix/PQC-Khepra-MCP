package sekhem

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/agi"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
)


// DeploymentMode represents the deployment mode
type DeploymentMode string

const (
	ModeEdge      DeploymentMode = "edge"      // Edge Mode — SaaS, Fly.io, no local persistence
	ModeHybrid    DeploymentMode = "hybrid"    // Hybrid Mode — SaaS with local DAG cache
	ModeSovereign DeploymentMode = "sovereign" // Sovereign Mode — air-gapped bare metal (DEFAULT)
	ModeIronBank  DeploymentMode = "ironbank"  // Iron Bank Mode — DoD hardened, air-gapped
)

// ModeFromEnv reads KHEPRA_MODE and returns the corresponding DeploymentMode.
// Sovereign is the explicit default — any unknown or unset value is treated as sovereign
// so that bare-metal deployments are safe-by-default (no accidental external calls).
//
// Callers:
//   - cmd/agent/main.go   — agent server startup
//   - cmd/khepra-mcp/main.go — MCP server startup
//   - pkg/dag/factory.go  — storage backend selection
//   - pkg/ert/lane_sonar.go — network scan scope gating
func ModeFromEnv() DeploymentMode {
	switch strings.ToLower(os.Getenv("KHEPRA_MODE")) {
	case "edge":
		return ModeEdge
	case "hybrid":
		return ModeHybrid
	case "ironbank":
		return ModeIronBank
	case "sovereign", "":
		return ModeSovereign // explicit + unset both → sovereign (safe default)
	default:
		return ModeSovereign // unknown value → sovereign (fail safe)
	}
}

// IsAirGapped reports whether this deployment mode is fully air-gapped.
// Air-gapped modes: sovereign (bare metal), ironbank (DoD).
// Network-connected modes: edge (SaaS Fly.io), hybrid (SaaS with local cache).
//
// LaneSonar uses this to gate internet-routable targets.
// DAG factory uses this to select persistent vs in-memory storage.
func (m DeploymentMode) IsAirGapped() bool {
	return m == ModeSovereign || m == ModeIronBank
}

// IsSaaS reports whether this deployment runs in a cloud/SaaS context.
func (m DeploymentMode) IsSaaS() bool {
	return m == ModeEdge || m == ModeHybrid
}

// String implements Stringer for clean log output.
func (m DeploymentMode) String() string { return string(m) }



// SekhemTriad represents the three-fold power structure
// Sekhem (Egyptian): Power, might, divine authority
type SekhemTriad struct {
	Mode      DeploymentMode
	DuatRealm *DuatRealm // Foundational defense (Edge Mode)
	AaruRealm *AaruRealm // Harmonious coordination (Hybrid Mode)
	AtenRealm *AtenRealm // Supreme orchestration (Sovereign/Iron Bank Mode)
}

// NewSekhemTriad creates the three-fold structure
func NewSekhemTriad(kasa *agi.Engine, dagStore dag.Store, mode DeploymentMode) (*SekhemTriad, error) {
	triad := &SekhemTriad{
		Mode: mode,
	}

	// Always create Duat Realm (foundational)
	triad.DuatRealm = NewDuatRealm(kasa, dagStore)

	// Create Aaru Realm for Hybrid, Sovereign, and Iron Bank modes
	if mode == ModeHybrid || mode == ModeSovereign || mode == ModeIronBank {
		aaru, err := NewAaruRealm(kasa, dagStore)
		if err != nil {
			return nil, fmt.Errorf("failed to create Aaru Realm: %w", err)
		}
		triad.AaruRealm = aaru
	}

	// Create Aten Realm for Sovereign and Iron Bank modes
	if mode == ModeSovereign || mode == ModeIronBank {
		airGapped := (mode == ModeSovereign) // Sovereign mode is air-gapped
		aten, err := NewAtenRealm(kasa, dagStore, airGapped)
		if err != nil {
			return nil, fmt.Errorf("failed to create Aten Realm: %w", err)
		}
		triad.AtenRealm = aten
	}

	return triad, nil
}

// Harmonize aligns all active realms
func (st *SekhemTriad) Harmonize() error {
	log.Printf("[Sekhem] Harmonizing the Triad (Mode: %s)...", st.Mode)

	// Awaken Duat Realm (foundational) - always active
	if err := st.DuatRealm.Awaken(); err != nil {
		return fmt.Errorf("failed to awaken Duat Realm: %w", err)
	}

	// Awaken Aaru Realm (intermediate) - if present
	if st.AaruRealm != nil {
		if err := st.AaruRealm.Awaken(); err != nil {
			return fmt.Errorf("failed to awaken Aaru Realm: %w", err)
		}
	}

	// Awaken Aten Realm (centralized) - if present
	if st.AtenRealm != nil {
		if err := st.AtenRealm.Awaken(); err != nil {
			return fmt.Errorf("failed to awaken Aten Realm: %w", err)
		}
	}

	log.Printf("[Sekhem] Triad harmonized - %d realms active", st.GetActiveRealmCount())

	return nil
}

// Stop halts all realms
func (st *SekhemTriad) Stop() {
	log.Printf("[Sekhem] Stopping the Triad...")

	if st.DuatRealm != nil {
		st.DuatRealm.Stop()
	}

	if st.AaruRealm != nil {
		st.AaruRealm.Sleep()
	}

	if st.AtenRealm != nil {
		st.AtenRealm.Sleep()
	}

	log.Printf("[Sekhem] Triad stopped")
}

// GetActiveRealmCount returns the number of active realms
func (st *SekhemTriad) GetActiveRealmCount() int {
	count := 0
	if st.DuatRealm != nil {
		count++
	}
	if st.AaruRealm != nil {
		count++
	}
	if st.AtenRealm != nil {
		count++
	}
	return count
}

// GetMode returns the current deployment mode
func (st *SekhemTriad) GetMode() DeploymentMode {
	return st.Mode
}
