// Package types holds the data structures for AdinKhepra.
package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// AuditSnapshot represents the comprehensive output from AdinKhepra Sonar.
// Enterprise-grade security audit for DoD/SCIF environments.
// NUCLEAR-GRADE: Device Fingerprinting + CVE + Compliance + Zero Third-Party APIs
type AuditSnapshot struct {
	SchemaVersion string    `json:"schema_version"`
	ScanID        string    `json:"scan_id"`
	Timestamp     time.Time `json:"timestamp"`

	// Device Identity (Anti-Spoofing, License Enforcement)
	DeviceFingerprint DeviceFingerprint `json:"device_fingerprint"`

	// Host Environment Metadata
	Host    InfoHost            `json:"host_info"`
	Network NetworkIntelligence `json:"network_intelligence"`

	// Vulnerability & Software Composition Analysis
	Tags            []string            `json:"tags"`
	Manifests       []FileManifest      `json:"manifests"`
	Vulnerabilities []Vulnerability     `json:"vulnerabilities"`
	Secrets         []SecretFinding     `json:"secrets"`
	Containers      []ContainerFindings `json:"containers"`

	// Compliance & Threat Detection
	Compliance      ComplianceReport   `json:"compliance"`
	ThreatDetection ThreatIntelligence `json:"threat_detection"`

	// Verification
	PQCSignature *PQCSignature `json:"pqc_signature,omitempty"`

	// Network and System intelligence (populated by local collectors)
	System SystemIntelligence `json:"system,omitempty"`

	// Backwards-compatible fields expected by older modules
	PublicKey    string           `json:"public_key,omitempty"`
	NetworkList  []NetworkPort    `json:"network,omitempty"`
	Processes    []ProcessInfo    `json:"processes,omitempty"`
	Intelligence RiskIntelligence `json:"intelligence,omitempty"`
}

type RiskIntelligence struct {
	Shodan *ShodanSummary `json:"shodan,omitempty"`
	Censys *CensysSummary `json:"censys,omitempty"`
}

type ShodanSummary struct {
	ISP   string   `json:"isp"`
	Vulns []string `json:"vulns"`
	Tags  []string `json:"tags"`
}

type CensysSummary struct {
	Services []string `json:"services"`
	Country  string   `json:"country"`
}

// DeviceFingerprint provides cryptographic device identity for license enforcement
// and anti-spoofing protection. Prevents MAC/DNS spoofing to evade node-based licenses.
type DeviceFingerprint struct {
	// Immutable Hardware Identifiers
	MACAddresses  []string `json:"mac_addresses"`            // All physical NICs
	CPUSignature  string   `json:"cpu_signature"`            // CPUID + model info
	DiskSerials   []string `json:"disk_serials"`             // Physical disk serial numbers
	BIOSSerial    string   `json:"bios_serial,omitempty"`    // SMBIOS UUID (Windows/Linux)
	MotherboardID string   `json:"motherboard_id,omitempty"` // Baseboard serial

	// TPM (Trusted Platform Module) - DoD/Enterprise Standard
	TPMPresent     bool   `json:"tpm_present"`
	TPMVersion     string `json:"tpm_version,omitempty"`     // "2.0", "1.2"
	TPMFingerprint string `json:"tpm_fingerprint,omitempty"` // TPM Endorsement Key hash

	// Composite Fingerprint Hash (SHA3-512 of all identifiers)
	// Used for license node binding - cannot be spoofed without physical hardware swap
	CompositeHash string `json:"composite_hash"`

	// Anti-Spoofing Indicators
	SpoofingIndicators []string `json:"spoofing_indicators,omitempty"` // Detected anomalies
}

// InfoHost contains detailed host system information
type InfoHost struct {
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`          // "linux", "windows", "darwin"
	OSVersion  string    `json:"os_version"`  // Full version string
	OSFamily   string    `json:"os_family"`   // "debian", "rhel", "windows_server"
	Kernel     string    `json:"kernel"`      // Kernel version
	Arch       string    `json:"arch"`        // "amd64", "arm64"
	PublicIP   string    `json:"public_ip"`   // External IP (from STUN/echo service)
	PrivateIPs []string  `json:"private_ips"` // All local interface IPs
	Uptime     int64     `json:"uptime_seconds"`
	BootTime   time.Time `json:"boot_time"`
}

// NetworkIntelligence contains comprehensive network reconnaissance
type NetworkIntelligence struct {
	Ports      []NetworkPort      `json:"ports"`
	Interfaces []NetworkInterface `json:"interfaces"`
	Routes     []NetworkRoute     `json:"routes,omitempty"`
	DNSServers []string           `json:"dns_servers"`

	// OS Fingerprinting via TCP/IP Stack Analysis
	OSFingerprint OSFingerprint `json:"os_fingerprint,omitempty"`
}

// NetworkPort represents a discovered network port with service detection
type NetworkPort struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol,omitempty"`  // "tcp", "udp"
	State       string `json:"state,omitempty"`     // "LISTENING", "CLOSED"
	BindAddr    string `json:"bind_addr,omitempty"` // "0.0.0.0"
	PID         int    `json:"pid,omitempty"`
	Service     string `json:"service,omitempty"` // Identified service name
	ProcessName string `json:"process_name,omitempty"`
	User        string `json:"user,omitempty"`
}

// NetworkInterface represents a network interface card
type NetworkInterface struct {
	Name        string   `json:"name"` // "eth0", "en0", "wlan0"
	MACAddress  string   `json:"mac_address"`
	IPAddresses []string `json:"ip_addresses"`
	MTU         int      `json:"mtu"`
	Flags       []string `json:"flags"` // "UP", "BROADCAST", "MULTICAST"
}

// NetworkRoute represents a routing table entry
type NetworkRoute struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

// OSFingerprint uses TCP/IP stack characteristics for passive OS detection
// Based on TTL, Window Size, DF flag, and other TCP/IP implementation quirks
type OSFingerprint struct {
	DetectedOS      string   `json:"detected_os"`      // "Linux 5.x", "Windows 10/11", "FreeBSD"
	Confidence      int      `json:"confidence"`       // 0-100
	TTL             int      `json:"ttl"`              // Initial TTL value
	WindowSize      int      `json:"window_size"`      // TCP window size
	TCPOptions      []string `json:"tcp_options"`      // Ordered TCP options
	DontFragment    bool     `json:"dont_fragment"`    // DF flag
	FingerprintHash string   `json:"fingerprint_hash"` // Hash of all characteristics
}

// SystemIntelligence contains process, service, and kernel module enumeration
type SystemIntelligence struct {
	Processes         []ProcessInfo  `json:"processes"`
	Services          []ServiceInfo  `json:"services"`
	KernelModules     []KernelModule `json:"kernel_modules,omitempty"` // Linux only
	InstalledSoftware []Software     `json:"installed_software,omitempty"`
	Users             []UserInfo     `json:"users,omitempty"`
	CronJobs          []CronJob      `json:"cron_jobs,omitempty"`
	StartupItems      []StartupItem  `json:"startup_items,omitempty"`
}

// ProcessInfo represents a running process
type ProcessInfo struct {
	PID            int       `json:"pid"`
	PPID           int       `json:"ppid"`
	Name           string    `json:"name"`
	CmdLine        string    `json:"cmd_line"`
	User           string    `json:"user"`
	CPUPercent     float64   `json:"cpu_percent,omitempty"`
	MemoryMB       float64   `json:"memory_mb,omitempty"`
	StartTime      time.Time `json:"start_time,omitempty"`
	ExecutablePath string    `json:"executable_path,omitempty"`
	FileHash       string    `json:"file_hash,omitempty"` // SHA256 of executable
}

// ServiceInfo represents a system service (systemd, Windows Service, etc.)
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state"`      // "running", "stopped", "disabled"
	StartMode   string `json:"start_mode"` // "auto", "manual", "disabled"
	User        string `json:"user,omitempty"`
	Path        string `json:"path,omitempty"`
}

// KernelModule represents a loaded kernel module (Linux LKM)
type KernelModule struct {
	Name        string   `json:"name"`
	Size        int      `json:"size"`
	UsedBy      []string `json:"used_by,omitempty"`
	LoadAddress string   `json:"load_address,omitempty"`
	Hidden      bool     `json:"hidden"` // Rootkit detection flag
}

// Software represents installed software/packages
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
}

// UserInfo represents a system user account
type UserInfo struct {
	Username   string   `json:"username"`
	UID        int      `json:"uid,omitempty"`
	GID        int      `json:"gid,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	HomeDir    string   `json:"home_dir,omitempty"`
	Shell      string   `json:"shell,omitempty"`
	Privileged bool     `json:"privileged"` // root, admin, sudoer
}

// CronJob represents a scheduled task (cron/at/Windows Task Scheduler)
type CronJob struct {
	User     string `json:"user"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
}

// StartupItem represents auto-start mechanisms
type StartupItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"` // "registry", "systemd", "rc.local", etc.
	User string `json:"user,omitempty"`
}

// FileManifest represents dependency manifests and configuration files
type FileManifest struct {
	Path        string    `json:"path"`
	Type        string    `json:"type"`              // "npm", "go", "docker", "pip", "helm", etc.
	Content     string    `json:"content,omitempty"` // Truncated or full content
	Checksum    string    `json:"checksum"`          // Adinkra PQC hash
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time,omitempty"`
	Permissions string    `json:"permissions,omitempty"` // "0644", etc.
}

// Vulnerability represents a CVE finding from local database (Grype)
type Vulnerability struct {
	ID          string   `json:"id"`       // "CVE-2024-1234"
	Severity    string   `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	CVSS        float64  `json:"cvss,omitempty"`
	Package     string   `json:"package"`            // Affected package
	Version     string   `json:"version"`            // Installed version
	FixedIn     string   `json:"fixed_in,omitempty"` // Fixed version
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
	Artifact    string   `json:"artifact,omitempty"` // Container image, binary, etc.
}

// ComplianceReport contains CIS, STIG, and NIST compliance findings
type ComplianceReport struct {
	Framework      string              `json:"framework"` // "CIS", "STIG", "NIST"
	Profile        string              `json:"profile"`   // "Level 1", "STIG CAT II"
	Findings       []ComplianceFinding `json:"findings"`
	TotalChecks    int                 `json:"total_checks"`
	PassedChecks   int                 `json:"passed_checks"`
	FailedChecks   int                 `json:"failed_checks"`
	ComplianceRate float64             `json:"compliance_rate"` // Percentage
}

// ComplianceFinding represents a single compliance check result
type ComplianceFinding struct {
	ID          string `json:"id"` // "CIS-1.1.1", "STIG-V-12345"
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`   // "PASS", "FAIL", "NOT_APPLICABLE"
	Severity    string `json:"severity"` // "HIGH", "MEDIUM", "LOW"
	Remediation string `json:"remediation,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

// ContainerFindings represents container/Docker/Kubernetes security analysis
type ContainerFindings struct {
	ImageID           string          `json:"image_id"`
	ImageName         string          `json:"image_name"`
	ImageDigest       string          `json:"image_digest,omitempty"`
	Vulnerabilities   []Vulnerability `json:"vulnerabilities"`
	Misconfigurations []string        `json:"misconfigurations,omitempty"`
	Secrets           []SecretFinding `json:"secrets,omitempty"`
	SBOM              *SBOM           `json:"sbom,omitempty"`
}

// SBOM represents Software Bill of Materials
type SBOM struct {
	Format     string          `json:"format"` // "SPDX", "CycloneDX"
	Version    string          `json:"version"`
	Components []SBOMComponent `json:"components"`
}

// SBOMComponent represents a software component in SBOM
type SBOMComponent struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"` // "library", "application", "os"
	License   string `json:"license,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}

// TLSFindings represents TLS/SSL security analysis
type TLSFindings struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Protocol        string   `json:"protocol"` // "TLS 1.3", "TLS 1.2"
	CipherSuite     string   `json:"cipher_suite"`
	KeyExchange     string   `json:"key_exchange,omitempty"`
	Certificate     CertInfo `json:"certificate"`
	WeakCiphers     []string `json:"weak_ciphers,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"` // "POODLE", "BEAST", "Heartbleed"
	Grade           string   `json:"grade,omitempty"`           // "A+", "B", "F"
}

// CertInfo represents X.509 certificate information
type CertInfo struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Expired       bool      `json:"expired"`
	SelfSigned    bool      `json:"self_signed"`
	KeySize       int       `json:"key_size"`
	SignatureAlgo string    `json:"signature_algo"`
	SANs          []string  `json:"sans,omitempty"` // Subject Alternative Names
}

// SecretFinding represents detected secrets/credentials
type SecretFinding struct {
	File        string  `json:"file"`
	Line        int     `json:"line,omitempty"`
	Type        string  `json:"type"` // "API Key", "AWS Key", "Private Key", "Password"
	Description string  `json:"description"`
	Entropy     float64 `json:"entropy,omitempty"`
	Redacted    string  `json:"redacted,omitempty"` // Partially redacted secret
}

// ThreatIntelligence contains rootkit, malware, and anomaly detection
type ThreatIntelligence struct {
	RootkitIndicators []RootkitIndicator `json:"rootkit_indicators,omitempty"`
	MalwareSignatures []MalwareSignature `json:"malware_signatures,omitempty"`
	Anomalies         []SecurityAnomaly  `json:"anomalies,omitempty"`
	ThreatScore       int                `json:"threat_score"` // 0-100
}

// RootkitIndicator represents potential rootkit detection
type RootkitIndicator struct {
	Type        string `json:"type"` // "hidden_module", "syscall_hook", "hidden_process"
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

// MalwareSignature represents malware detection findings
type MalwareSignature struct {
	File       string   `json:"file"`
	Hash       string   `json:"hash"`
	Signatures []string `json:"signatures"` // Matched YARA rules, heuristics
	Confidence int      `json:"confidence"` // 0-100
}

// SecurityAnomaly represents detected anomalies
type SecurityAnomaly struct {
	Type        string    `json:"type"` // "unexpected_network", "privilege_escalation", etc.
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// PQCSignature provides Dilithium3 post-quantum cryptographic signature
// for non-repudiation and integrity verification
type PQCSignature struct {
	Algorithm string    `json:"algorithm"`  // "Dilithium3"
	PublicKey string    `json:"public_key"` // Base64 encoded
	Signature string    `json:"signature"`  // Base64 encoded
	SignedAt  time.Time `json:"signed_at"`
	SignedBy  string    `json:"signed_by,omitempty"` // Device/Node ID
}

// TelemetryProof represents a sanitized, PQC-signed proof of scan for community telemetry.
// This allows tracking traction without exposing sensitive audit details.
type TelemetryProof struct {
	ScanID         string        `json:"scan_id"`
	Timestamp      time.Time     `json:"timestamp"`
	KhepraVersion  string        `json:"khepra_version"`
	Platform       string        `json:"platform"`
	AssetCount     int           `json:"asset_count"`
	ThreatScore    int           `json:"threat_score"`
	ComplianceRate float64       `json:"compliance_rate"`
	PQCSignature   *PQCSignature `json:"pqc_signature"`
}

// SealWithPQC signs the audit snapshot with Dilithium3 for non-repudiation.
// This ensures the snapshot cannot be tampered with and provides cryptographic proof of origin.
func (a *AuditSnapshot) SealWithPQC(privateKey, publicKey []byte) error {
	// Serialize the snapshot without the signature field
	tempSig := a.PQCSignature
	a.PQCSignature = nil

	data, err := json.Marshal(a)
	if err != nil {
		a.PQCSignature = tempSig
		return fmt.Errorf("failed to serialize snapshot: %v", err)
	}

	// Sign the data
	signature, err := adinkra.Sign(privateKey, data)
	if err != nil {
		a.PQCSignature = tempSig
		return fmt.Errorf("failed to sign snapshot: %v", err)
	}

	// Attach the signature
	a.PQCSignature = &PQCSignature{
		Algorithm: "Dilithium3",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Signature: base64.StdEncoding.EncodeToString(signature),
		SignedAt:  time.Now().UTC(),
		SignedBy:  a.DeviceFingerprint.CompositeHash, // Bind to device
	}

	return nil
}

// VerifyPQC verifies the Dilithium3 signature on the audit snapshot.
// Returns true if the signature is valid and the snapshot has not been tampered with.
func (a *AuditSnapshot) VerifyPQC() (bool, error) {
	if a.PQCSignature == nil {
		return false, fmt.Errorf("snapshot is not signed")
	}

	// Decode the public key and signature
	publicKey, err := base64.StdEncoding.DecodeString(a.PQCSignature.PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key encoding: %v", err)
	}

	signature, err := base64.StdEncoding.DecodeString(a.PQCSignature.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature encoding: %v", err)
	}

	// Serialize the snapshot without the signature field
	tempSig := a.PQCSignature
	a.PQCSignature = nil

	data, err := json.Marshal(a)
	if err != nil {
		a.PQCSignature = tempSig
		return false, fmt.Errorf("failed to serialize snapshot: %v", err)
	}

	// Restore the signature
	a.PQCSignature = tempSig

	// Verify the signature
	return adinkra.Verify(publicKey, data, signature)
}

// GenerateTelemetryProof creates a sanitized, PQC-signed proof of scan.
// It extracts only high-level metrics (no PII, no specific vulnerabilities).
func (a *AuditSnapshot) GenerateTelemetryProof(privateKey, publicKey []byte, version, platform string) (*TelemetryProof, error) {
	proof := &TelemetryProof{
		ScanID:         a.ScanID,
		Timestamp:      a.Timestamp,
		KhepraVersion:  version,
		Platform:       platform,
		AssetCount:     len(a.System.Services) + len(a.System.Processes),
		ThreatScore:    a.ThreatDetection.ThreatScore,
		ComplianceRate: a.Compliance.ComplianceRate,
	}

	// Sign the proof with the same PQC key
	data, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize telemetry proof: %v", err)
	}

	signature, err := adinkra.Sign(privateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign telemetry proof: %v", err)
	}

	proof.PQCSignature = &PQCSignature{
		Algorithm: "Dilithium3",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Signature: base64.StdEncoding.EncodeToString(signature),
		SignedAt:  time.Now().UTC(),
		SignedBy:  "khepra-community-telemetry",
	}

	return proof, nil
}
