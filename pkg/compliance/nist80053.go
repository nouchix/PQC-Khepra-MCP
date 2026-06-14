package compliance

import "fmt"

// NIST 800-53 Rev 5 Control Mappings for Cryptographic Security

// NIST80053Control represents a security control from NIST 800-53
type NIST80053Control struct {
	ID              string   `json:"id"`
	Family          string   `json:"family"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Impact          string   `json:"impact"` // LOW, MODERATE, HIGH
	Baseline        []string `json:"baseline"` // LOW, MODERATE, HIGH baselines
	RelatedControls []string `json:"related_controls"`
	CCIs            []string `json:"ccis"` // Control Correlation Identifiers
	PQCRelevance    string   `json:"pqc_relevance,omitempty"`
}

// PQCControlMapping maps cryptographic assets to NIST 800-53 controls
var PQCControlMapping = map[string]NIST80053Control{
	"SC-12": {
		ID:     "SC-12",
		Family: "System and Communications Protection",
		Title:  "Cryptographic Key Establishment and Management",
		Description: "The organization establishes and manages cryptographic keys for required cryptography employed within the information system.",
		Impact: "MODERATE",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"SC-13", "SC-17", "SC-37"},
		CCIs: []string{"CCI-000162", "CCI-002450"},
		PQCRelevance: "Critical for post-quantum key management. Requires inventory of all cryptographic keys and migration planning for quantum-vulnerable algorithms.",
	},
	"SC-13": {
		ID:     "SC-13",
		Family: "System and Communications Protection",
		Title:  "Cryptographic Protection",
		Description: "The information system implements FIPS-validated or NSA-approved cryptography to protect information.",
		Impact: "HIGH",
		Baseline: []string{"LOW", "MODERATE", "HIGH"},
		RelatedControls: []string{"SC-12", "SC-28"},
		CCIs: []string{"CCI-002450", "CCI-003123"},
		PQCRelevance: "Mandates use of NIST FIPS 203 (Kyber), FIPS 204 (Dilithium), FIPS 205 (SPHINCS+) for quantum-resistant cryptography.",
	},
	"SC-17": {
		ID:     "SC-17",
		Family: "System and Communications Protection",
		Title:  "Public Key Infrastructure Certificates",
		Description: "The organization issues public key certificates under an organization-defined certificate policy or obtains public key certificates from an approved service provider.",
		Impact: "MODERATE",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"SC-12", "SC-13"},
		CCIs: []string{"CCI-001182"},
		PQCRelevance: "Requires migration of X.509 certificates from RSA/ECDSA to Dilithium3 signatures for quantum resistance.",
	},
	"SA-4": {
		ID:     "SA-4",
		Family: "System and Services Acquisition",
		Title:  "Acquisition Process",
		Description: "The organization includes requirements, descriptions, and criteria for security and privacy functional requirements in the acquisition contract.",
		Impact: "LOW",
		Baseline: []string{"LOW", "MODERATE", "HIGH"},
		RelatedControls: []string{"SA-8", "SA-11", "SA-15"},
		CCIs: []string{"CCI-000192"},
		PQCRelevance: "CBOM (Cryptographic Bill of Materials) must be provided by vendors for procurement transparency.",
	},
	"SA-15": {
		ID:     "SA-15",
		Family: "System and Services Acquisition",
		Title:  "Development Process, Standards, and Tools",
		Description: "The organization requires the developer to follow a documented development process that includes security and privacy.",
		Impact: "LOW",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"SA-3", "SA-8", "SA-11"},
		CCIs: []string{"CCI-002617"},
		PQCRelevance: "Development must include cryptographic dependency scanning and PQC migration planning.",
	},
	"SR-3": {
		ID:     "SR-3",
		Family: "Supply Chain Risk Management",
		Title:  "Supply Chain Controls and Processes",
		Description: "The organization employs processes to detect and prevent counterfeit components from entering the information system.",
		Impact: "MODERATE",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"SA-4", "SA-12", "SR-4"},
		CCIs: []string{"CCI-003194"},
		PQCRelevance: "Third-party cryptographic libraries must be validated for quantum resistance. CBOM provides supply chain visibility.",
	},
	"SR-4": {
		ID:     "SR-4",
		Family: "Supply Chain Risk Management",
		Title:  "Provenance",
		Description: "The organization documents, monitors, and maintains valid provenance of systems and critical system components.",
		Impact: "MODERATE",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"SR-3", "SR-11"},
		CCIs: []string{"CCI-003195"},
		PQCRelevance: "CBOM tracks cryptographic asset provenance and lineage for audit purposes.",
	},
	"SR-11": {
		ID:     "SR-11",
		Family: "Supply Chain Risk Management",
		Title:  "Component Authenticity",
		Description: "The organization employs anti-counterfeit policy and procedures that include requirements for detecting and preventing counterfeit components.",
		Impact: "MODERATE",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"SR-3", "SR-4"},
		CCIs: []string{"CCI-003326"},
		PQCRelevance: "PQC signatures (Dilithium3) provide cryptographic proof of component authenticity.",
	},
	"IA-5": {
		ID:     "IA-5",
		Family: "Identification and Authentication",
		Title:  "Authenticator Management",
		Description: "The organization manages information system authenticators including initial distribution, verification, and revocation.",
		Impact: "LOW",
		Baseline: []string{"LOW", "MODERATE", "HIGH"},
		RelatedControls: []string{"IA-2", "IA-4", "IA-8"},
		CCIs: []string{"CCI-000162", "CCI-000804"},
		PQCRelevance: "Authenticators (keys, certificates) must be migrated to quantum-resistant algorithms to prevent future compromise.",
	},
	"RA-5": {
		ID:     "RA-5",
		Family: "Risk Assessment",
		Title:  "Vulnerability Scanning",
		Description: "The organization scans for vulnerabilities in the information system and hosted applications.",
		Impact: "LOW",
		Baseline: []string{"LOW", "MODERATE", "HIGH"},
		RelatedControls: []string{"CM-6", "SI-2"},
		CCIs: []string{"CCI-001643"},
		PQCRelevance: "Cryptographic vulnerability scanning must identify quantum-vulnerable algorithms (RSA < 3072, ECC < P-384).",
	},
	"SA-22": {
		ID:     "SA-22",
		Family: "System and Services Acquisition",
		Title:  "Unsupported System Components",
		Description: "The organization prevents the use of unsupported information system components.",
		Impact: "MODERATE",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"CM-8", "SA-15"},
		CCIs: []string{"CCI-003194"},
		PQCRelevance: "Legacy cryptographic libraries approaching end-of-life must be identified and replaced with PQC alternatives.",
	},
	"SA-11": {
		ID:     "SA-11",
		Family: "System and Services Acquisition",
		Title:  "Developer Security and Privacy Testing",
		Description: "The organization requires developers to create and execute security assessment and privacy assessment plans.",
		Impact: "MODERATE",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"CA-2", "SA-15", "SI-2"},
		CCIs: []string{"CCI-003217"},
		PQCRelevance: "Security testing must validate quantum-resistant cryptographic implementations (NIST FIPS 203/204/205 compliance).",
	},
	"SC-28": {
		ID:     "SC-28",
		Family: "System and Communications Protection",
		Title:  "Protection of Information at Rest",
		Description: "The information system protects the confidentiality and integrity of information at rest.",
		Impact: "LOW",
		Baseline: []string{"MODERATE", "HIGH"},
		RelatedControls: []string{"AC-3", "AC-6", "SC-13"},
		CCIs: []string{"CCI-001199"},
		PQCRelevance: "Data-at-rest encryption should use AES-256 (quantum-safe) or prepare for post-quantum encryption standards.",
	},
	"AU-2": {
		ID:     "AU-2",
		Family: "Audit and Accountability",
		Title:  "Audit Events",
		Description: "The organization determines that the information system is capable of auditing specific events.",
		Impact: "LOW",
		Baseline: []string{"LOW", "MODERATE", "HIGH"},
		RelatedControls: []string{"AU-3", "AU-12", "PM-14"},
		CCIs: []string{"CCI-000172"},
		PQCRelevance: "Cryptographic operations (key generation, signing, encryption) must be audited for forensic replay and compliance.",
	},
	"CM-6": {
		ID:     "CM-6",
		Family: "Configuration Management",
		Title:  "Configuration Settings",
		Description: "The organization establishes and documents configuration settings for information technology products.",
		Impact: "LOW",
		Baseline: []string{"LOW", "MODERATE", "HIGH"},
		RelatedControls: []string{"CM-2", "CM-3", "CM-7"},
		CCIs: []string{"CCI-000366"},
		PQCRelevance: "Cryptographic configuration (cipher suites, key lengths, algorithm selection) must be centrally managed and enforced.",
	},
	"CP-9": {
		ID:     "CP-9",
		Family: "Contingency Planning",
		Title:  "Information System Backup",
		Description: "The organization conducts backups of information system data, software, and configuration.",
		Impact: "LOW",
		Baseline: []string{"LOW", "MODERATE", "HIGH"},
		RelatedControls: []string{"CP-6", "CP-10", "SC-28"},
		CCIs: []string{"CCI-001190"},
		PQCRelevance: "Migration rollback procedures require secure backup of legacy cryptographic keys and configurations.",
	},
}

// GetControlsByFamily returns all controls in a specific family
func GetControlsByFamily(family string) []NIST80053Control {
	var controls []NIST80053Control
	for _, control := range PQCControlMapping {
		if control.Family == family {
			controls = append(controls, control)
		}
	}
	return controls
}

// GetControlByID retrieves a specific control by ID
func GetControlByID(id string) (NIST80053Control, bool) {
	control, ok := PQCControlMapping[id]
	return control, ok
}

// GetControlsByCCI returns controls that map to a specific CCI
func GetControlsByCCI(cci string) []NIST80053Control {
	var controls []NIST80053Control
	for _, control := range PQCControlMapping {
		for _, controlCCI := range control.CCIs {
			if controlCCI == cci {
				controls = append(controls, control)
				break
			}
		}
	}
	return controls
}

// GenerateRMFPackage creates a RMF (Risk Management Framework) package
// for PQC migration authorization
func GenerateRMFPackage() string {
	pkg := "=================================================================\n"
	pkg += "  NIST RMF AUTHORIZATION PACKAGE - PQC MIGRATION\n"
	pkg += "=================================================================\n\n"

	pkg += "STEP 1: CATEGORIZE (FIPS 199)\n"
	pkg += "  Information Type: Cryptographic Systems\n"
	pkg += "  Confidentiality: HIGH\n"
	pkg += "  Integrity: HIGH\n"
	pkg += "  Availability: MODERATE\n"
	pkg += "  Overall Impact Level: HIGH\n\n"

	pkg += "STEP 2: SELECT (NIST 800-53)\n"
	pkg += "  Baseline: HIGH (NIST 800-53B)\n"
	pkg += "  PQC-Specific Controls:\n\n"

	families := make(map[string][]NIST80053Control)
	for _, control := range PQCControlMapping {
		families[control.Family] = append(families[control.Family], control)
	}

	for family, controls := range families {
		pkg += fmt.Sprintf("  %s:\n", family)
		for _, ctrl := range controls {
			pkg += fmt.Sprintf("    • %s - %s\n", ctrl.ID, ctrl.Title)
		}
		pkg += "\n"
	}

	pkg += "STEP 3: IMPLEMENT\n"
	pkg += "  1. Deploy AdinKhepra SONAR for cryptographic asset discovery\n"
	pkg += "  2. Generate CBOM (Cryptographic Bill of Materials)\n"
	pkg += "  3. Create STIG checklist (.CKL) for compliance tracking\n"
	pkg += "  4. Execute phased migration plan (HIGH-risk assets first)\n"
	pkg += "  5. Validate NIST FIPS 203/204/205 implementations\n\n"

	pkg += "STEP 4: ASSESS\n"
	pkg += "  Assessment Methods:\n"
	pkg += "    • EXAMINE: CBOM, STIG checklist, migration plan\n"
	pkg += "    • INTERVIEW: System owners, developers, security officers\n"
	pkg += "    • TEST: Cryptographic validation, penetration testing\n\n"

	pkg += "STEP 5: AUTHORIZE\n"
	pkg += "  Authorizing Official: [TO BE ASSIGNED]\n"
	pkg += "  Authority to Operate (ATO): [DATE TBD]\n"
	pkg += "  Continuous Monitoring: AdinKhepra DAG provenance tracking\n\n"

	pkg += "STEP 6: MONITOR\n"
	pkg += "  Ongoing Assessment:\n"
	pkg += "    • Daily cryptographic asset scans\n"
	pkg += "    • Quarterly migration progress reports\n"
	pkg += "    • Annual PQC readiness assessment\n"
	pkg += "    • Real-time anomaly detection (Adinkra symbols)\n\n"

	pkg += "=================================================================\n"
	pkg += "Generated by: AdinKhepra™ ASAF - Compliance Export Layer\n"
	pkg += "=================================================================\n"

	return pkg
}
