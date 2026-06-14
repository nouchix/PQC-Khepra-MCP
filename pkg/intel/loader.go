package intel

import (
	"encoding/json"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// CVEItem represents a generic structure to capture key fields from various JSON formats (MITRE/NVD/CISA)
type CVEItem struct {
	CVEID    string `json:"cveID"`  // Common across formats
	CveIDAlt string `json:"cve_id"` // Alternative key

	// CISA KEV fields
	VulnerabilityName string `json:"vulnerabilityName"`
	ShortDescription  string `json:"shortDescription"`

	// NVD/MITRE often nest these, so we might need custom unmarshalling for full fidelity.
	// For MVP of the "Commando", we focus on CISA KEV which is flat JSON.
}

// CisaKEVCatalog represents the top-level CISA KEV JSON structure
type CisaKEVCatalog struct {
	Title           string    `json:"title"`
	Vulnerabilities []CVEItem `json:"vulnerabilities"`
}

// LoadCisaKEV loads the Known Exploited Vulnerabilities catalog.
// This is the highest priority threat intel for the Commando.
func (kb *KnowledgeBase) LoadCisaKEV(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var catalog CisaKEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		// Try parsing as raw list if catalog fails (resilience)
		return err
	}

	for _, item := range catalog.Vulnerabilities {
		id := item.CVEID
		if id == "" {
			id = item.CveIDAlt
		}
		if id == "" {
			continue
		}

		// Hydrate KB
		kb.Vulnerabilities[id] = Vulnerability{
			ID:          id,
			Source:      "CISA-KEV",
			Severity:    "CRITICAL", // Assumed Critical if in KEV
			Description: item.ShortDescription,
			IsExploited: true,
		}
	}

	log.Printf("[INTEL] Loaded %d CONFIRMED THREATS from CISA KEV.", len(catalog.Vulnerabilities))
	return nil
}

// LoadExternalDataWalk recursively walks the data directory to find intel
func (kb *KnowledgeBase) LoadExternalDataWalk(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// Check for specific known files
		if strings.Contains(path, "known_exploited_vulnerabilities") {
			if err := kb.LoadCisaKEV(path); err != nil {
				log.Printf("[INTEL] Failed to load CISA KEV at %s: %v", path, err)
			}
		}

		// Load MITRE CVE database (CVE 5.1 format JSON files)
		if strings.Contains(path, "mitre/cves") && strings.HasSuffix(path, ".json") {
			// Handled by LoadMITRECVEDatabase (batch loader)
			// Skip individual file loading here to avoid spam
		}

		return nil
	})
}
