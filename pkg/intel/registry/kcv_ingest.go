package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CisaKevCatalog represents the CISA KEV JSON structure
type CisaKevCatalog struct {
	Title           string                 `json:"title"`
	CatalogVersion  string                 `json:"catalogVersion"`
	DateReleased    time.Time              `json:"dateReleased"`
	Count           int                    `json:"count"`
	Vulnerabilities []CisaKevVulnerability `json:"vulnerabilities"`
}

type CisaKevVulnerability struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

// IngestCisaKev loads CISA KEV data into the store
func (s *Store) IngestCisaKev(filePath string) (int, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read CISA KEV file: %w", err)
	}

	var catalog CisaKevCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return 0, fmt.Errorf("failed to unmarshal CISA KEV: %w", err)
	}

	count := 0
	for _, kv := range catalog.Vulnerabilities {
		v := &Vulnerability{
			ID:          kv.CVEID,
			Source:      "CISA_KEV",
			Description: kv.VulnerabilityName + ": " + kv.ShortDescription,
			Exploited:   true,
			UpdatedAt:   time.Now(),
		}

		// Note: CISA KEV doesn't always include CVSS, it focuses on exploitation.
		// We'll set a default high score for KEV items if not already present.
		existing, _ := s.GetVulnerability(kv.CVEID)
		if existing != nil && existing.CVSS > 0 {
			v.CVSS = existing.CVSS
		} else {
			v.CVSS = 7.5 // Default "High" for actively exploited
		}

		if err := s.SaveVulnerability(v); err != nil {
			continue // Skip single failures
		}
		count++
	}

	return count, nil
}
