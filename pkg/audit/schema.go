package audit

import (
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/types"
)

// Type Aliases for backward compatibility within the package (optional)
// usage: type AuditSnapshot = types.AuditSnapshot
type AuditSnapshot = types.AuditSnapshot
type DeviceFingerprint = types.DeviceFingerprint
type InfoHost = types.InfoHost
type NetworkIntelligence = types.NetworkIntelligence
type NetworkPort = types.NetworkPort
type NetworkInterface = types.NetworkInterface
type NetworkRoute = types.NetworkRoute
type OSFingerprint = types.OSFingerprint
type SystemIntelligence = types.SystemIntelligence
type ProcessInfo = types.ProcessInfo
type ServiceInfo = types.ServiceInfo
type KernelModule = types.KernelModule
type Software = types.Software
type UserInfo = types.UserInfo
type CronJob = types.CronJob
type StartupItem = types.StartupItem
type FileManifest = types.FileManifest
type Vulnerability = types.Vulnerability
type ComplianceReport = types.ComplianceReport
type ComplianceFinding = types.ComplianceFinding
type ContainerFindings = types.ContainerFindings
type SBOM = types.SBOM
type SBOMComponent = types.SBOMComponent
type TLSFindings = types.TLSFindings
type CertInfo = types.CertInfo
type SecretFinding = types.SecretFinding
type ThreatIntelligence = types.ThreatIntelligence
type RootkitIndicator = types.RootkitIndicator
type MalwareSignature = types.MalwareSignature
type SecurityAnomaly = types.SecurityAnomaly
type PQCSignature = types.PQCSignature
type RiskIntelligence = types.RiskIntelligence
type ShodanSummary = types.ShodanSummary
type CensysSummary = types.CensysSummary

// Risk is a type alias for RiskItem for backward compatibility with test files
type Risk = RiskItem
