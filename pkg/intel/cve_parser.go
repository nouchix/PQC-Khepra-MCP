package intel

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/intel/registry"
)

// CVE 5.1 Format structures (MITRE database format)
type CVERecord struct {
	DataType    string      `json:"dataType"`
	DataVersion string      `json:"dataVersion"`
	CVEMetadata CVEMetadata `json:"cveMetadata"`
	Containers  Containers  `json:"containers"`
}

type CVEMetadata struct {
	CVEID string `json:"cveId"`
	State string `json:"state"`
}

type Containers struct {
	CNA CNA   `json:"cna"`
	ADP []ADP `json:"adp,omitempty"` // Additional Data Providers (where CVSS scores live)
}

type CNA struct {
	Title        string        `json:"title"`
	Descriptions []Description `json:"descriptions"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type ADP struct {
	ProviderMetadata ProviderMetadata `json:"providerMetadata"`
	Metrics          []Metric         `json:"metrics,omitempty"`
}

type ProviderMetadata struct {
	OrgID     string `json:"orgId"`
	ShortName string `json:"shortName"`
}

type Metric struct {
	CVSSV31 *CVSSV31 `json:"cvssV3_1,omitempty"`
	CVSSV30 *CVSSV30 `json:"cvssV3_0,omitempty"`
}

type CVSSV31 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"` // CRITICAL, HIGH, MEDIUM, LOW
	VectorString string  `json:"vectorString"` // CVSS:3.1/AV:N/AC:L/...
}

type CVSSV30 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

// LoadMITRECVEDatabase walks the MITRE CVE database directory and loads all CVEs with CVSS scores
func (kb *KnowledgeBase) LoadMITRECVEDatabase(rootPath string) error {
	count := 0
	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// Only process CVE JSON files
		if !strings.HasSuffix(path, ".json") || !strings.Contains(path, "CVE-") {
			return nil
		}

		// Parse the CVE
		vuln, err := parseCVEFile(path)
		if err != nil {
			// Skip malformed CVEs silently (thousands of files, don't spam logs)
			return nil
		}

		// Save to Registry if available (persistence)
		if kb.Registry != nil {
			rv := &registry.Vulnerability{
				ID:          vuln.ID,
				Source:      vuln.Source,
				CVSS:        vuln.CVSS,
				Description: vuln.Description,
				UpdatedAt:   time.Now(),
			}
			if err := kb.Registry.SaveVulnerability(rv); err != nil {
				log.Printf("[INTEL] Failed to save %s to registry: %v", vuln.ID, err)
			}
		}

		// Only store in-memory if Registry is NOT available (fallback to legacy behavior)
		// Or if we want a smaller cache of high-priority items (TBD)
		if kb.Registry == nil && vuln.CVSS > 0 {
			kb.Vulnerabilities[vuln.ID] = *vuln
			count++
		}

		return nil
	})

	if err != nil {
		return err
	}

	log.Printf("[INTEL] Loaded %d CVEs with CVSS scores from MITRE database", count)
	return nil
}

// parseCVEFile parses a single CVE JSON file (CVE 5.1 format)
func parseCVEFile(path string) (*Vulnerability, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var record CVERecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}

	// Extract basic info
	vuln := &Vulnerability{
		ID:     record.CVEMetadata.CVEID,
		Source: "MITRE",
	}

	// Extract description from CNA
	if len(record.Containers.CNA.Descriptions) > 0 {
		vuln.Description = record.Containers.CNA.Descriptions[0].Value
		// Truncate long descriptions
		if len(vuln.Description) > 500 {
			vuln.Description = vuln.Description[:497] + "..."
		}
	}

	// Extract CVSS score from ADP metrics (priority order: v3.1 > v3.0)
	cvssFound := false
	for _, adp := range record.Containers.ADP {
		for _, metric := range adp.Metrics {
			if metric.CVSSV31 != nil {
				vuln.CVSS = metric.CVSSV31.BaseScore
				vuln.Severity = metric.CVSSV31.BaseSeverity
				vuln.CVSSVector = metric.CVSSV31.VectorString
				cvssFound = true
				break
			} else if metric.CVSSV30 != nil && !cvssFound {
				vuln.CVSS = metric.CVSSV30.BaseScore
				vuln.Severity = metric.CVSSV30.BaseSeverity
				vuln.CVSSVector = metric.CVSSV30.VectorString
				cvssFound = true
			}
		}
		if cvssFound {
			break
		}
	}

	// If no CVSS found in ADP, try to infer severity from CVE-ID patterns (older CVEs)
	if vuln.CVSS == 0 {
		return nil, fmt.Errorf("no CVSS score found")
	}

	return vuln, nil
}

// MapCVSSToSeverity converts a CVSS score to a severity level
// https://www.first.org/cvss/v3.1/specification-document
func MapCVSSToSeverity(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	}
	return "LOW"
}
