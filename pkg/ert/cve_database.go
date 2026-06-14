package ert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/intel/registry"
)

// CVEDatabase loads and queries the local CVE database
type CVEDatabase struct {
	KEVs        []KEVEntry          // Known Exploited Vulnerabilities
	NISTEntries map[string]CVEEntry // CVE-ID -> NIST data (Legacy/Fallback)
	Registry    *registry.Store     // SQLite Persistent Store
	loaded      bool
}

// KEVEntry represents a Known Exploited Vulnerability from CISA
type KEVEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
}

// CVEEntry represents NIST NVD data
type CVEEntry struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Published   string  `json:"published"`
	Modified    string  `json:"modified"`
}

// NewCVEDatabase creates an empty CVE database
func NewCVEDatabase() *CVEDatabase {
	return &CVEDatabase{
		KEVs:        []KEVEntry{},
		NISTEntries: make(map[string]CVEEntry),
		loaded:      false,
	}
}

// LoadCVEDatabase loads CVE data from the data directory
func LoadCVEDatabase(dataDir string) (*CVEDatabase, error) {
	db := NewCVEDatabase()

	// Load Known Exploited Vulnerabilities (Keep in memory for fast lookup)
	kevPath := filepath.Join(dataDir, "known_exploited_vulnerabilities_indusface_nov_2025.json")
	if err := db.loadKEVs(kevPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load KEVs: %v\n", err)
	}

	// Connect to shared SQLite Registry
	dbPath := filepath.Join(dataDir, "vulnerabilities.db")
	if reg, err := registry.NewStore(dbPath); err == nil {
		db.Registry = reg
		fmt.Fprintf(os.Stderr, "[ERT] Connected to Vulnerability Registry at %s\n", dbPath)
	} else {
		fmt.Fprintf(os.Stderr, "[ERT] Warning: Failed to connect to registry (using memory mode): %v\n", err)
	}

	// Legacy Support: Check for CVE database subdirectory if Registry is empty/failed
	// Only load if we really have to, to avoid memory exhaustion
	if db.Registry == nil {
		cveDBPath := filepath.Join(dataDir, "cve-database")
		if info, err := os.Stat(cveDBPath); err == nil && info.IsDir() {
			if err := db.loadNISTDatabase(cveDBPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to load NIST database: %v\n", err)
			}
		}
	}

	db.loaded = true
	return db, nil
}

// loadKEVs loads CISA Known Exploited Vulnerabilities
func (db *CVEDatabase) loadKEVs(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Parse JSON structure
	var kevData struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(data, &kevData); err != nil {
		return err
	}

	db.KEVs = kevData.Vulnerabilities
	return nil
}

// loadNISTDatabase loads NIST NVD CVE data
func (db *CVEDatabase) loadNISTDatabase(dir string) error {
	// Walk through all JSON files in cve-database directory
	count := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Read CVE JSON file
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip errors
		}

		// Try to parse as NIST CVE format
		var cveData CVEEntry
		if err := json.Unmarshal(data, &cveData); err != nil {
			return nil // Skip invalid files
		}

		if cveData.ID != "" {
			db.NISTEntries[cveData.ID] = cveData
			count++
		}

		return nil
	})

	if count > 0 {
		fmt.Fprintf(os.Stderr, "Loaded %d CVE entries from NIST database\n", count)
	}

	return err
}

// QueryCVE looks up a CVE by ID
func (db *CVEDatabase) QueryCVE(cveID string) (CVEEntry, bool) {
	// 1. Check in-memory NIST entries (Legacy)
	if entry, exists := db.NISTEntries[cveID]; exists {
		return entry, true
	}

	// 2. Check Registry (Preferred)
	if db.Registry != nil {
		v, err := db.Registry.GetVulnerability(cveID)
		if err == nil && v != nil {
			return CVEEntry{
				ID:          v.ID,
				Description: v.Description,
				CVSS:        v.CVSS,
				Severity:    "UNKNOWN", // registry store doesn't store computed severity string
				Published:   v.PublishedAt.Format("2006-01-02"),
				Modified:    v.UpdatedAt.Format("2006-01-02"),
			}, true
		}
	}

	return CVEEntry{}, false
}

// GetExploits retrieves known exploits for a CVE
func (db *CVEDatabase) GetExploits(cveID string) []registry.Exploit {
	if db.Registry == nil {
		return []registry.Exploit{}
	}
	exploits, err := db.Registry.GetExploits(cveID)
	if err != nil {
		return []registry.Exploit{}
	}
	return exploits
}

// IsKnownExploited checks if a CVE is in CISA's KEV catalog
func (db *CVEDatabase) IsKnownExploited(cveID string) bool {
	for _, kev := range db.KEVs {
		if kev.CVEID == cveID {
			return true
		}
	}
	return false
}

// SearchByPackage finds CVEs affecting a specific package
func (db *CVEDatabase) SearchByPackage(packageName string) []CVEEntry {
	results := []CVEEntry{}
	packageLower := strings.ToLower(packageName)

	// Search NIST database
	for _, entry := range db.NISTEntries {
		if strings.Contains(strings.ToLower(entry.Description), packageLower) {
			results = append(results, entry)
		}
	}

	return results
}

// SearchByKeyword finds CVEs matching a keyword
func (db *CVEDatabase) SearchByKeyword(keyword string) []CVEEntry {
	results := []CVEEntry{}
	keywordLower := strings.ToLower(keyword)

	for _, entry := range db.NISTEntries {
		if strings.Contains(strings.ToLower(entry.Description), keywordLower) {
			results = append(results, entry)
		}
	}

	return results
}

// GetHighSeverityCVEs returns all CVEs with CVSS >= 7.0
func (db *CVEDatabase) GetHighSeverityCVEs() []CVEEntry {
	results := []CVEEntry{}

	for _, entry := range db.NISTEntries {
		if entry.CVSS >= 7.0 {
			results = append(results, entry)
		}
	}

	return results
}

// GetCriticalCVEs returns all CVEs with CVSS >= 9.0
func (db *CVEDatabase) GetCriticalCVEs() []CVEEntry {
	results := []CVEEntry{}

	for _, entry := range db.NISTEntries {
		if entry.CVSS >= 9.0 {
			results = append(results, entry)
		}
	}

	return results
}

// Stats returns database statistics
func (db *CVEDatabase) Stats() map[string]int {
	return map[string]int{
		"total_cves":      len(db.NISTEntries),
		"known_exploited": len(db.KEVs),
		"critical":        len(db.GetCriticalCVEs()),
		"high":            len(db.GetHighSeverityCVEs()),
	}
}
