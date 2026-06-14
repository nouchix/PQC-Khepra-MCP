package registry

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

// Vulnerability represents a single entry in the registry
type Vulnerability struct {
	ID          string    `json:"id"`          // CVE-ID or other identifier
	Source      string    `json:"source"`      // MITRE, CISA, etc.
	CVSS        float64   `json:"cvss"`        // Severity score
	Description string    `json:"description"` // Brief summary
	Exploited   bool      `json:"exploited"`   // CISA KEV status
	PublishedAt time.Time `json:"published_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Store manages the SQLite database for vulnerabilities
type Store struct {
	db *sql.DB
}

// NewStore initializes a new vulnerability store
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

// initSchema creates the necessary tables and indexes
func (s *Store) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		source TEXT NOT NULL,
		cvss REAL DEFAULT 0.0,
		description TEXT,
		exploited BOOLEAN DEFAULT 0,
		published_at DATETIME,
		updated_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_source ON vulnerabilities(source);
	CREATE INDEX IF NOT EXISTS idx_exploited ON vulnerabilities(exploited);

	-- Compliance Mapping Tables
	CREATE TABLE IF NOT EXISTS compliance_controls (
		id TEXT PRIMARY KEY,
		family TEXT,
		title TEXT,
		description TEXT,
		cmmc_level INTEGER
	);

	CREATE TABLE IF NOT EXISTS stig_cci_map (
		stig_id TEXT,
		cci_id TEXT,
		PRIMARY KEY(stig_id, cci_id)
	);

	CREATE TABLE IF NOT EXISTS cci_nist_map (
		cci_id TEXT,
		nist_53_ref TEXT,
		PRIMARY KEY(cci_id, nist_53_ref)
	);

	CREATE TABLE IF NOT EXISTS nist_hierarchy (
		nist_53_ref TEXT,
		nist_171_ref TEXT,
		PRIMARY KEY(nist_53_ref, nist_171_ref)
	);

	CREATE INDEX IF NOT EXISTS idx_stigs ON stig_cci_map(stig_id);
	CREATE INDEX IF NOT EXISTS idx_ccis ON stig_cci_map(cci_id);
	CREATE INDEX IF NOT EXISTS idx_nist171 ON nist_hierarchy(nist_171_ref);

	-- ExploitDB Table
	CREATE TABLE IF NOT EXISTS exploits (
		id TEXT PRIMARY KEY,
		cve_id TEXT,
		description TEXT,
		file_path TEXT,
		platform TEXT,
		type TEXT,
		published_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploits(cve_id);
	`
	_, err := s.db.Exec(query)
	return err
}

// SaveVulnerability inserts or updates a record
func (s *Store) SaveVulnerability(v *Vulnerability) error {
	query := `
	INSERT INTO vulnerabilities (id, source, cvss, description, exploited, published_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		source = excluded.source,
		cvss = excluded.cvss,
		description = excluded.description,
		exploited = excluded.exploited,
		updated_at = excluded.updated_at
	`
	_, err := s.db.Exec(query, v.ID, v.Source, v.CVSS, v.Description, v.Exploited, v.PublishedAt, v.UpdatedAt)
	return err
}

// GetVulnerability retrieves a record by ID
func (s *Store) GetVulnerability(id string) (*Vulnerability, error) {
	v := &Vulnerability{}
	query := `SELECT id, source, cvss, description, exploited, published_at, updated_at FROM vulnerabilities WHERE id = ?`
	err := s.db.QueryRow(query, id).Scan(&v.ID, &v.Source, &v.CVSS, &v.Description, &v.Exploited, &v.PublishedAt, &v.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// --- ExploitDB Support ---

// Exploit represents an entry from ExploitDB
type Exploit struct {
	ID          string    `json:"id"`     // EDB-ID
	CVEID       string    `json:"cve_id"` // Linked CVE (if any)
	Description string    `json:"description"`
	FilePath    string    `json:"file_path"`
	Platform    string    `json:"platform"`
	Type        string    `json:"type"`
	PublishedAt time.Time `json:"published_at"`
}

// SaveExploit saves an exploit definition to the registry
func (s *Store) SaveExploit(e *Exploit) error {
	query := `
	INSERT INTO exploits (id, cve_id, description, file_path, platform, type, published_at)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		cve_id = excluded.cve_id,
		description = excluded.description,
		file_path = excluded.file_path,
		platform = excluded.platform,
		type = excluded.type,
		published_at = excluded.published_at
	`
	_, err := s.db.Exec(query, e.ID, e.CVEID, e.Description, e.FilePath, e.Platform, e.Type, e.PublishedAt)
	return err
}

// GetExploits returns all exploits linked to a CVE ID
func (s *Store) GetExploits(cveID string) ([]Exploit, error) {
	query := `SELECT id, cve_id, description, file_path, platform, type, published_at FROM exploits WHERE cve_id = ?`
	rows, err := s.db.Query(query, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exploits []Exploit
	for rows.Next() {
		var e Exploit
		if err := rows.Scan(&e.ID, &e.CVEID, &e.Description, &e.FilePath, &e.Platform, &e.Type, &e.PublishedAt); err != nil {
			return nil, err
		}
		exploits = append(exploits, e)
	}
	return exploits, nil
}
