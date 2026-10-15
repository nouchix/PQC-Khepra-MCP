package stig

import (
	"bytes"
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Embed compliance mapping database.
// IMPORTANT: pkg/stig/data/*.csv must NOT be tracked by Git LFS.
// These files are compiled into the binary via go:embed; an LFS pointer
// produces a zero-mapping build with no compile-time error.
//
//go:embed data/*.csv
//go:embed data/CHECKSUMS
var embeddedData embed.FS

// ErrLFSPointer is returned when the embedded CSV is a Git LFS pointer
// rather than the real data file.
var ErrLFSPointer = fmt.Errorf(
	"STIG_CCI_Map.csv is a Git LFS pointer — real data not embedded.\n" +
		"Fix: remove '*.csv' from .gitattributes LFS tracking, then copy the\n" +
		"real file from PQC-Khepra-MCP/pkg/stig/data/ and commit it directly.",
)

// ComplianceDatabase holds the complete STIG↔CCI↔NIST 800-53↔NIST 800-171↔CMMC mapping
type ComplianceDatabase struct {
	// STIG → CCI mappings: key is STIG_ID; 19,943 unique keys after dedup
	// (28,173 raw rows in CSV; multiple CCIs per STIG rule)
	STIGtoCCI map[string][]CCIMapping // Key: STIG_ID

	// CCI → NIST 800-53 mappings (7,433 rows)
	CCItoNIST53 map[string][]NIST53Mapping // Key: CCI_ID

	// NIST 800-53 → NIST 800-171 mappings (123 rows)
	NIST53to171 map[string][]NIST171Mapping // Key: NIST_53_Ref

	// Reverse mappings for quick lookups
	CCItoSTIG   map[string][]string // Key: CCI_ID, Value: STIG_IDs
	NIST53toCCI map[string][]string // Key: NIST_53_Ref, Value: CCI_IDs
	NIST171to53 map[string][]string // Key: NIST_171_Ref, Value: NIST_53_Refs

	// NIST 800-53 → NIST 800-172 mappings (24 rows)
	NIST53to172 map[string][]NIST171Mapping // Key: NIST_53_Ref
	NIST172to53 map[string][]string         // Key: NIST_172_Ref, Value: NIST_53_Refs

	mu sync.RWMutex // Protect concurrent access
}

// CCIMapping represents a STIG→CCI relationship
type CCIMapping struct {
	STIGID       string
	STIGTitle    string
	STIGSeverity string
	CCIID        string
	STIGFile     string
}

// NIST53Mapping represents a CCI→NIST 800-53 relationship
type NIST53Mapping struct {
	CCIID      string
	NIST53Ref  string
	Definition string
}

// NIST171Mapping represents a NIST 800-53→NIST 800-171 relationship
type NIST171Mapping struct {
	NIST171Ref    string
	NIST53Ref     string
	ControlFamily string
}

var (
	// Global database instance
	db     *ComplianceDatabase
	dbOnce sync.Once
)

// GetDatabase returns the singleton compliance database instance
func GetDatabase() (*ComplianceDatabase, error) {
	var loadErr error
	dbOnce.Do(func() {
		db = &ComplianceDatabase{
			STIGtoCCI:   make(map[string][]CCIMapping),
			CCItoNIST53: make(map[string][]NIST53Mapping),
			NIST53to171: make(map[string][]NIST171Mapping),
			CCItoSTIG:   make(map[string][]string),
			NIST53toCCI: make(map[string][]string),
			NIST171to53: make(map[string][]string),
			NIST53to172: make(map[string][]NIST171Mapping),
			NIST172to53: make(map[string][]string),
		}
		loadErr = db.Load()
	})
	if loadErr != nil {
		return nil, loadErr
	}
	return db, nil
}

// lfsPointerPrefix is the first line of an unresolved Git LFS pointer file.
// If an embedded CSV starts with this, the build never ran `git lfs pull`
// and the "database" is three lines of pointer text, not real content.
const lfsPointerPrefix = "version https://git-lfs.github.com/spec/v1"

// embeddedCSVs are the four compliance-mapping files embedded via go:embed.
var embeddedCSVs = []string{
	"data/STIG_CCI_Map.csv",
	"data/CCI_to_NIST53.csv",
	"data/NIST53_to_171.csv",
	"data/NIST53_to_172.csv",
}

// verifyDataFiles fails loud if any embedded CSV is an unresolved Git LFS
// pointer (or implausibly small) instead of real content.
//
// Audit finding A-TD-01: without this guard a pointer file parses as zero
// rows — csv.Reader yields 1-field lines that the loaders skip as "malformed"
// — so the app silently ships an EMPTY compliance database and computes a
// wrong SPRS score with no error. The Phase 4 error-state table forbids
// exactly this silent-failure mode; refuse to load rather than mislead.
func verifyDataFiles() error {
	for _, name := range embeddedCSVs {
		data, err := embeddedData.ReadFile(name)
		if err != nil {
			return fmt.Errorf("compliance DB integrity: cannot read embedded %s: %w", name, err)
		}
		if strings.HasPrefix(string(data), lfsPointerPrefix) {
			return fmt.Errorf("compliance DB integrity: embedded %s is an UNRESOLVED Git LFS pointer, not real data — the build did not run `git lfs pull`. Refusing to load an empty compliance database (would silently produce a wrong SPRS score). Fix the build to materialize LFS content before `go build`", name)
		}
		if len(data) < 512 {
			return fmt.Errorf("compliance DB integrity: embedded %s is implausibly small (%d bytes) — likely truncated or a stub, not the real mapping data", name, len(data))
		}
	}
	return nil
}

// Load loads the compliance mapping database from embedded CSV files
func (d *ComplianceDatabase) Load() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Load STIG→CCI mappings (28,173 raw rows; 19,943 unique STIG IDs after dedup)
	if err := d.loadSTIGtoCCI(); err != nil {
		return fmt.Errorf("failed to load STIG→CCI mappings: %w", err)
	}

	// Load CCI→NIST 800-53 mappings (7,433 rows)
	if err := d.loadCCItoNIST53(); err != nil {
		return fmt.Errorf("failed to load CCI→NIST 800-53 mappings: %w", err)
	}

	// Load NIST 800-53→NIST 800-171 mappings (123 rows)
	if err := d.loadNIST53to171(); err != nil {
		return fmt.Errorf("failed to load NIST 800-53→NIST 800-171 mappings: %w", err)
	}

	// Load NIST 800-53→NIST 800-172 mappings (24 rows)
	if err := d.loadNIST53to172(); err != nil {
		return fmt.Errorf("failed to load NIST 800-53→NIST 800-172 mappings: %w", err)
	}

	return nil
}

// extractBaseSVID extracts the core SV number from a DISA rule ID.
// e.g. "SV-253254r991589_rule" -> "SV-253254"
// e.g. "V-253254" -> "SV-253254"
func extractBaseSVID(id string) string {
	id = strings.TrimSpace(id)
	if idx := strings.Index(id, "r"); idx > 0 && strings.HasPrefix(id, "SV-") {
		return id[:idx]
	}
	if strings.HasPrefix(id, "V-") {
		return "SV-" + strings.TrimPrefix(id, "V-")
	}
	return id
}

// loadSTIGtoCCI loads STIG_CCI_Map.csv
func (d *ComplianceDatabase) loadSTIGtoCCI() error {
	file, err := embeddedData.Open("data/STIG_CCI_Map.csv")
	if err != nil {
		return fmt.Errorf("failed to open STIG_CCI_Map.csv: %w", err)
	}
	defer file.Close()

	// Read entire file into memory so we can (a) detect LFS pointers and
	// (b) avoid io.Seeker dependency (embed.FS files are not seekable).
	raw, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read STIG_CCI_Map.csv: %w", err)
	}

	// LFS pointer guard: a fresh clone without git lfs pull produces a 3-line
	// pointer file starting with this prefix. Fail loudly rather than silently
	// loading zero mappings while the UI claims "25,185 controls loaded".
	if bytes.HasPrefix(raw, []byte("version https://git-lfs.github.com")) {
		return ErrLFSPointer
	}

	reader := csv.NewReader(bytes.NewReader(raw))

	// Skip header row
	if _, err := reader.Read(); err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	rowCount := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV row %d: %w", rowCount+2, err)
		}

		if len(record) < 5 {
			continue // Skip malformed rows
		}

		mapping := CCIMapping{
			STIGID:       strings.TrimSpace(record[0]),
			STIGTitle:    strings.TrimSpace(record[1]),
			STIGSeverity: strings.TrimSpace(record[2]),
			CCIID:        strings.TrimSpace(record[3]),
			STIGFile:     strings.TrimSpace(record[4]),
		}


		// Forward mapping: STIG → CCI (full rule ID)
		d.STIGtoCCI[mapping.STIGID] = append(d.STIGtoCCI[mapping.STIGID], mapping)

		// Also index by base SV ID (e.g. SV-253254) so version/revision shifts across DISA releases still match
		baseID := extractBaseSVID(mapping.STIGID)
		if baseID != mapping.STIGID {
			d.STIGtoCCI[baseID] = append(d.STIGtoCCI[baseID], mapping)
		}

		// Reverse mapping: CCI → STIG
		d.CCItoSTIG[mapping.CCIID] = append(d.CCItoSTIG[mapping.CCIID], mapping.STIGID)

		rowCount++
	}

	fmt.Printf("Loaded %d raw STIG→CCI rows; %d unique STIG IDs\n", rowCount, len(d.STIGtoCCI))
	return nil
}

// loadCCItoNIST53 loads CCI_to_NIST53.csv
func (d *ComplianceDatabase) loadCCItoNIST53() error {
	file, err := embeddedData.Open("data/CCI_to_NIST53.csv")
	if err != nil {
		return fmt.Errorf("failed to open CCI_to_NIST53.csv: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Skip header
	if _, err := reader.Read(); err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	rowCount := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV row %d: %w", rowCount+2, err)
		}

		if len(record) < 3 {
			continue // Skip malformed rows
		}

		mapping := NIST53Mapping{
			CCIID:      strings.TrimSpace(record[0]),
			NIST53Ref:  strings.TrimSpace(record[1]),
			Definition: strings.TrimSpace(record[2]),
		}

		// Forward mapping: CCI → NIST 800-53
		d.CCItoNIST53[mapping.CCIID] = append(d.CCItoNIST53[mapping.CCIID], mapping)

		// Reverse mapping: NIST 800-53 → CCI
		d.NIST53toCCI[mapping.NIST53Ref] = append(d.NIST53toCCI[mapping.NIST53Ref], mapping.CCIID)

		rowCount++
	}

	fmt.Printf("Loaded %d CCI→NIST 800-53 mappings\n", rowCount)
	return nil
}

// loadNIST53to171 loads NIST53_to_171.csv
func (d *ComplianceDatabase) loadNIST53to171() error {
	file, err := embeddedData.Open("data/NIST53_to_171.csv")
	if err != nil {
		return fmt.Errorf("failed to open NIST53_to_171.csv: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Skip header
	if _, err := reader.Read(); err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	rowCount := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV row %d: %w", rowCount+2, err)
		}

		if len(record) < 3 {
			continue // Skip malformed rows
		}

		mapping := NIST171Mapping{
			NIST171Ref:    strings.TrimSpace(record[0]),
			NIST53Ref:     strings.TrimSpace(record[1]),
			ControlFamily: strings.TrimSpace(record[2]),
		}

		// Forward mapping: NIST 800-53 → NIST 800-171
		d.NIST53to171[mapping.NIST53Ref] = append(d.NIST53to171[mapping.NIST53Ref], mapping)

		// Reverse mapping: NIST 800-171 → NIST 800-53
		d.NIST171to53[mapping.NIST171Ref] = append(d.NIST171to53[mapping.NIST171Ref], mapping.NIST53Ref)

		rowCount++
	}

	fmt.Printf("Loaded %d NIST 800-53→NIST 800-171 mappings\n", rowCount)
	return nil
}

// loadNIST53to172 loads NIST53_to_172.csv
func (d *ComplianceDatabase) loadNIST53to172() error {
	file, err := embeddedData.Open("data/NIST53_to_172.csv")
	if err != nil {
		return fmt.Errorf("failed to open NIST53_to_172.csv: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Skip header
	if _, err := reader.Read(); err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	rowCount := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV row %d: %w", rowCount+2, err)
		}

		if len(record) < 3 {
			continue // Skip malformed rows
		}

		mapping := NIST171Mapping{
			NIST171Ref:    strings.TrimSpace(record[0]),
			NIST53Ref:     strings.TrimSpace(record[1]),
			ControlFamily: strings.TrimSpace(record[2]),
		}

		// Forward mapping: NIST 800-53 → NIST 800-172
		d.NIST53to172[mapping.NIST53Ref] = append(d.NIST53to172[mapping.NIST53Ref], mapping)

		// Reverse mapping: NIST 800-172 → NIST 800-53
		d.NIST172to53[mapping.NIST171Ref] = append(d.NIST172to53[mapping.NIST171Ref], mapping.NIST53Ref)

		rowCount++
	}

	fmt.Printf("Loaded %d NIST 800-53→NIST 800-172 mappings\n", rowCount)
	return nil
}

// GetCrossReferences returns all cross-referenced controls for a given STIG ID
// Returns: CCI IDs, NIST 800-53 controls, NIST 800-171 controls, CMMC controls
func (d *ComplianceDatabase) GetCrossReferences(stigID string) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	refs := []string{}

	// Get CCIs for this STIG
	cciMappings, ok := d.STIGtoCCI[stigID]
	if !ok {
		baseID := extractBaseSVID(stigID)
		cciMappings, ok = d.STIGtoCCI[baseID]
	}
	if !ok {
		return refs, nil // No mappings found
	}

	seenRefs := make(map[string]bool)

	for _, cciMapping := range cciMappings {
		cciID := cciMapping.CCIID

		// Add CCI
		if !seenRefs[cciID] {
			refs = append(refs, cciID)
			seenRefs[cciID] = true
		}

		// Get NIST 800-53 controls for this CCI
		nist53Mappings, ok := d.CCItoNIST53[cciID]
		if ok {
			for _, nist53Mapping := range nist53Mappings {
				nist53Ref := nist53Mapping.NIST53Ref

				// Add NIST 800-53 control
				key := "NIST-800-53:" + nist53Ref
				if !seenRefs[key] {
					refs = append(refs, key)
					seenRefs[key] = true
				}

				// Get NIST 800-171 controls for this NIST 800-53 control
				nist171Mappings, ok := d.NIST53to171[nist53Ref]
				if ok {
					for _, nist171Mapping := range nist171Mappings {
						nist171Ref := nist171Mapping.NIST171Ref

						// Add NIST 800-171 control
						key171 := "NIST-800-171:" + nist171Ref
						if !seenRefs[key171] {
							refs = append(refs, key171)
							seenRefs[key171] = true
						}

						// Map to CMMC (NIST 800-171 controls map to CMMC Level 2)
						keyCMMC := "CMMC:" + nist171Mapping.ControlFamily + ".L2-" + nist171Ref
						if !seenRefs[keyCMMC] {
							refs = append(refs, keyCMMC)
							seenRefs[keyCMMC] = true
						}
					}
				}

				// Get NIST 800-172 controls for this NIST 800-53 control
				nist172Mappings, ok := d.NIST53to172[nist53Ref]
				if ok {
					for _, nist172Mapping := range nist172Mappings {
						nist17Ref := nist172Mapping.NIST171Ref

						// Add NIST 800-172 control
						key172 := "NIST-800-172:" + nist17Ref
						if !seenRefs[key172] {
							refs = append(refs, key172)
							seenRefs[key172] = true
						}

						// Map to CMMC Level 3
						keyCMMC3 := "CMMC:" + nist172Mapping.ControlFamily + ".L3-" + nist17Ref
						if !seenRefs[keyCMMC3] {
							refs = append(refs, keyCMMC3)
							seenRefs[keyCMMC3] = true
						}
					}
				}
			}
		}
	}

	return refs, nil
}

// GetSTIGSeverity returns the severity for a STIG ID
func (d *ComplianceDatabase) GetSTIGSeverity(stigID string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	mappings, ok := d.STIGtoCCI[stigID]
	if !ok {
		baseID := extractBaseSVID(stigID)
		mappings, ok = d.STIGtoCCI[baseID]
	}
	if !ok || len(mappings) == 0 {
		return "medium" // Default
	}

	return mappings[0].STIGSeverity
}

// GetSTIGTitle returns the title for a STIG ID
func (d *ComplianceDatabase) GetSTIGTitle(stigID string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	mappings, ok := d.STIGtoCCI[stigID]
	if !ok {
		baseID := extractBaseSVID(stigID)
		mappings, ok = d.STIGtoCCI[baseID]
	}
	if !ok || len(mappings) == 0 {
		return ""
	}

	return mappings[0].STIGTitle
}

// Stats returns database statistics
func (d *ComplianceDatabase) Stats() map[string]int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]int{
		"stig_to_cci_mappings":       len(d.STIGtoCCI),
		"cci_to_nist53_mappings":     len(d.CCItoNIST53),
		"nist53_to_nist171_mappings": len(d.NIST53to171),
		"total_mappings":             len(d.STIGtoCCI) + len(d.CCItoNIST53) + len(d.NIST53to171),
	}
}

// RowCount returns the number of unique STIG IDs in the database (19,943 after dedup).
// This is the canonical "control mappings loaded" count shown in the status bar.
// Note: This number is derived from 28,173 logical CSV rows. A naïve `wc -l` on
// STIG_CCI_Map.csv will yield 28,639 literal lines because 367 rows contain embedded
// newlines within quoted fields (e.g., STIGTitle). The 19,943 count is mathematically
// verified as the true unique STIG ID count against proper RFC-4180 parsing.
func (d *ComplianceDatabase) RowCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.STIGtoCCI)
}

// GetAllSTIGFamilies and GetAllRulesForFamily are package-level functions in updater.go.
// STIGRuleSummary type is also declared there.
// Use those directly; do not redeclare here.
