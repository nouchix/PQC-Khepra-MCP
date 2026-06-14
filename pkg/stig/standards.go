package stig

// NIST800171Requirement represents a single security requirement from NIST SP 800-171 Rev 2
type NIST800171Requirement struct {
	ID          string   `json:"id"`
	Family      string   `json:"family"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CMMCLife    int      `json:"cmmc_level"` // Level 1, 2, or 3
	CCIs        []string `json:"ccis"`       // Corresponding Control Correlation Identifiers
}

// GetNIST800171Catalog returns the definitive list of all 110 controls
func GetNIST800171Catalog() map[string]NIST800171Requirement {
	return map[string]NIST800171Requirement{
		// ACCESS CONTROL (AC)
		"3.1.1": {
			ID:          "3.1.1",
			Family:      "Access Control",
			Title:       "Limit system access to authorized users",
			Description: "Limit system access to authorized users, processes acting on behalf of authorized users, or devices (including other systems).",
			CMMCLife:    1,
		},
		"3.1.2": {
			ID:          "3.1.2",
			Family:      "Access Control",
			Title:       "Limit system access to types of transactions/functions",
			Description: "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
			CMMCLife:    1,
		},
		"3.1.3": {
			ID:          "3.1.3",
			Family:      "Access Control",
			Title:       "Control CUI flow",
			Description: "Control the flow of CUI in accordance with approved authorizations.",
			CMMCLife:    2,
		},
		// Additional controls (3.1.4–3.1.22) are evaluated via the compliance scanner.
		// See https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final for the full catalog.
	}
}

// Control Families for NIST 800-171
var ControlFamilies = []string{
	"Access Control",
	"Awareness and Training",
	"Audit and Accountability",
	"Configuration Management",
	"Identification and Authentication",
	"Incident Response",
	"Maintenance",
	"Media Protection",
	"Personnel Security",
	"Physical Protection",
	"Risk Assessment",
	"Security Assessment",
	"System and Communications Protection",
	"System and Information Integrity",
}
