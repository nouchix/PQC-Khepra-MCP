package intel

import (
	"fmt"
	"log"
	"os"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/intel/registry"
)

// --- MITRE ATT&CK Structure ---

type Tactic struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Techniques  []Technique `json:"techniques"`
}

type Technique struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// --- Multi-Source Vulnerability Database (MITRE-Cyber-Security-CVE-Database) ---

type Vulnerability struct {
	ID          string  `json:"cve_id"`
	Source      string  `json:"source"` // NVD, MITRE, CISA
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss,omitempty"`
	CVSSVector  string  `json:"cvss_vector,omitempty"` // CVSS:3.1/AV:N/AC:L/...
	Description string  `json:"description"`
	IsExploited bool    `json:"is_exploited"` // From CISA KEV
}

// KnowledgeBase holds the loaded threat intelligence (Tactics + CVEs)
type KnowledgeBase struct {
	Tactics         []Tactic                 `json:"tactics"`
	Vulnerabilities map[string]Vulnerability `json:"vulnerabilities"`
	Registry        *registry.Store          `json:"-"` // Persistence store
}

// NewKnowledgeBase initializes the Intel Core with static ATT&CK data
// and prepares the Vulnerability map for dynamic ingestion.
func NewKnowledgeBase() *KnowledgeBase {
	kb := &KnowledgeBase{
		Vulnerabilities: make(map[string]Vulnerability),
		Tactics: []Tactic{
			{
				ID:          "TA0043",
				Name:        "Reconnaissance",
				Description: "The adversary is trying to gather information they can use to plan future operations.",
				Techniques: []Technique{
					{ID: "T1595", Name: "Active Scanning"},
					{ID: "T1592", Name: "Gather Victim Host Information"},
				},
			},
			{
				ID:          "TA0001",
				Name:        "Initial Access",
				Description: "The adversary is trying to get into your network.",
				Techniques: []Technique{
					{ID: "T1190", Name: "Exploit Public-Facing Application"},
					{ID: "T1078", Name: "Valid Accounts"},
				},
			},
			{
				ID:          "TA0002",
				Name:        "Execution",
				Description: "The adversary is trying to run malicious code.",
				Techniques: []Technique{
					{ID: "T1059", Name: "Command and Scripting Interpreter"},
					{ID: "T1204", Name: "User Execution"},
				},
			},
			{
				ID:          "TA0040",
				Name:        "Impact",
				Description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
				Techniques: []Technique{
					{ID: "T1485", Name: "Data Destruction"},
					{ID: "T1486", Name: "Data Encrypted for Impact"},
				},
			},
		},
	}

	// Initialize Registry if possible
	reg, err := registry.NewStore("data/vulnerabilities.db")
	if err == nil {
		kb.Registry = reg
		log.Printf("[INTEL] Vulnerability Registry initialized (SQLite).")
	} else {
		log.Printf("[INTEL] Warning: Registry initialization failed: %v. Using memory-only mode.", err)
	}

	// Attempt to load Enterprise CVE Database if present. Do this asynchronously
	// so engine startup isn't blocked by potentially large on-disk databases.
	go func() {
		if err := kb.LoadExternalData("data/cve-database"); err != nil {
			// Non-fatal, just log that we are running without offline DB
			log.Printf("[INTEL] Enterprise CVE Database not found at data/cve-database. Running in online-only mode.")
			return
		}

		// Load MITRE CVE database with CVSS scores if present
		mitreDBPath := "data/cve-database/cve-data/mitre/cves"
		if _, err := os.Stat(mitreDBPath); err == nil {
			if kb.Registry != nil {
				log.Printf("[INTEL] Processing MITRE database into Registry (one-time or updates)...")
			} else {
				log.Printf("[INTEL] Loading MITRE CVE database (this may take 30-60 seconds)...")
			}

			if err := kb.LoadMITRECVEDatabase(mitreDBPath); err != nil {
				log.Printf("[INTEL] Failed to load MITRE CVEs: %v", err)
			}
		}

		// Load ExploitDB if present
		exploitDBPath := "data/exploitdb"
		if _, err := os.Stat(exploitDBPath); err == nil {
			log.Printf("[INTEL] Loading ExploitDB from %s...", exploitDBPath)
			if err := kb.LoadExploitDB(exploitDBPath); err != nil {
				log.Printf("[INTEL] Failed to load ExploitDB: %v", err)
			}
		}
	}()

	return kb
}

// LoadExternalData ingests real vulnerability data from the local filesystem.
func (kb *KnowledgeBase) LoadExternalData(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", path)
	}

	log.Printf("[INTEL] Ingesting Threat Intelligence from %s...", path)
	return kb.LoadExternalDataWalk(path)
}

// SearchVuln allows the AGI to query the database by CVE ID
func (kb *KnowledgeBase) SearchVuln(cveID string) *Vulnerability {
	// 1. Check in-memory vulnerabilities (CISA KEV or cached)
	if v, ok := kb.Vulnerabilities[cveID]; ok {
		return &v
	}

	// 2. Fallback to SQLite Registry
	if kb.Registry != nil {
		rv, err := kb.Registry.GetVulnerability(cveID)
		if err == nil && rv != nil {
			// Convert registry.Vulnerability to intel.Vulnerability
			v := Vulnerability{
				ID:          rv.ID,
				Source:      rv.Source,
				CVSS:        rv.CVSS,
				Description: rv.Description,
				IsExploited: rv.Exploited,
				Severity:    MapCVSSToSeverity(rv.CVSS),
			}
			return &v
		}
	}

	return nil
}
