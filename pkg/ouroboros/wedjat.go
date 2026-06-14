package ouroboros

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/enumerate"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/intel"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/scanners"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

// WedjatEye represents an all-seeing detector
// Wedjat: Eye of Horus, symbol of protection and royal power
type WedjatEye interface {
	Gaze() []maat.Isfet
	Name() string
}

// STIGEye detects STIG non-compliance
type STIGEye struct {
	name string
}

func NewSTIGEye() *STIGEye {
	return &STIGEye{
		name: "wedjat-stig",
	}
}

func (se *STIGEye) Gaze() []maat.Isfet {
	log.Printf("[%s] Scanning STIG compliance...", se.name)
	isfet := []maat.Isfet{}

	// Create real validator
	v := stig.NewValidator(".")
	v.EnableFramework("RHEL-09-STIG-V1R3")

	report, err := v.Validate()
	if err != nil {
		log.Printf("[%s] Scan failed: %v", se.name, err)
		return isfet
	}

	result, ok := report.Results["RHEL-09-STIG-V1R3"]
	if !ok {
		return isfet
	}

	for _, finding := range result.Findings {
		if finding.Status == "Fail" {
			chaos := maat.Isfet{
				ID:        finding.ID,
				Source:    se.name,
				Severity:  mapStigSeverity(finding.Severity),
				Certainty: 1.0,
				Omens: []maat.Omen{
					{Name: "Description", Value: finding.Description, Malevolence: 1.0},
					{Name: "Title", Value: finding.Title, Malevolence: 1.0},
				},
			}
			isfet = append(isfet, chaos)
		}
	}

	return isfet
}

func mapStigSeverity(s stig.Severity) maat.Severity {
	switch s {
	case "CAT1", "Critical":
		return maat.SeveritySevere
	case "CAT2", "High":
		return maat.SeverityModerate
	default:
		return maat.SeverityMinor
	}
}

func (se *STIGEye) Name() string {
	return se.name
}

// VulnEye detects vulnerabilities
type VulnEye struct {
	name string
}

func NewVulnEye() *VulnEye {
	return &VulnEye{
		name: "wedjat-vuln",
	}
}

func (ve *VulnEye) Gaze() []maat.Isfet {
	log.Printf("[%s] Scanning for vulnerabilities...", ve.name)
	isfet := []maat.Isfet{}

	findings, err := scanners.RunBuiltInVulnerabilityScan(".")
	if err != nil {
		log.Printf("[%s] Scan failed: %v", ve.name, err)
		return isfet
	}

	for _, v := range findings {
		chaos := maat.Isfet{
			ID:        v.ID,
			Source:    ve.name,
			Severity:  mapVulnSeverity(v.Severity),
			Certainty: 0.9,
			Omens: []maat.Omen{
				{Name: "Description", Value: v.Description, Malevolence: 1.0},
				{Name: "Package", Value: v.Package, Malevolence: 0.8},
				{Name: "Version", Value: v.Version, Malevolence: 0.5},
			},
		}
		isfet = append(isfet, chaos)
	}

	return isfet
}

func mapVulnSeverity(s string) maat.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return maat.SeverityCatastrophic
	case "HIGH":
		return maat.SeveritySevere
	case "MEDIUM":
		return maat.SeverityModerate
	default:
		return maat.SeverityMinor
	}
}

func (ve *VulnEye) Name() string {
	return ve.name
}

// DriftEye detects system drift
type DriftEye struct {
	name     string
	detector *intel.DriftEngine
	baseline *audit.AuditSnapshot
}

func NewDriftEye() *DriftEye {
	return &DriftEye{
		name:     "wedjat-drift",
		detector: intel.NewDriftEngine(),
	}
}

func (de *DriftEye) Gaze() []maat.Isfet {
	log.Printf("[%s] Checking for configuration drift...", de.name)
	isfet := []maat.Isfet{}

	// 1. Collect current state
	current := &audit.AuditSnapshot{}

	// Only collect network intelligence for drift comparison.
	// Process lists are inherently noisy at 2s cycle intervals: crontab, id, and
	// other short-lived helpers spawn during CollectSystemIntelligence itself and
	// produce a guaranteed "new process" on every second Gaze call.
	// Port changes are stable, meaningful, and worth alerting on.
	ni, _ := enumerate.CollectNetworkIntelligence()
	current.Network = ni

	// 2. Establish baseline if none exists
	if de.baseline == nil {
		log.Printf("[%s] Establishing initial baseline...", de.name)
		de.baseline = current
		return isfet
	}

	// 3. Compare current state against baseline
	report := de.detector.Compare(de.baseline, current)
	if report.HasDrift {
		log.Printf("[%s] DISK/NETWORK DRIFT DETECTED!", de.name)

		// Map drift report to Isfet
		if len(report.AddedPorts) > 0 {
			isfet = append(isfet, maat.Isfet{
				ID:        "DRIFT-NET-PORT",
				Source:    de.name,
				Severity:  maat.SeveritySevere,
				Certainty: 1.0,
				Omens: []maat.Omen{
					{Name: "AddedPorts", Value: strings.Join(report.AddedPorts, ","), Malevolence: 0.9},
				},
			})
		}
		if len(report.AddedProcesses) > 0 {
			isfet = append(isfet, maat.Isfet{
				ID:        "DRIFT-PROC-NEW",
				Source:    de.name,
				Severity:  maat.SeveritySevere,
				Certainty: 1.0,
				Omens: []maat.Omen{
					{Name: "AddedProcesses", Value: strings.Join(report.AddedProcesses, ","), Malevolence: 0.9},
				},
			})
		}
	}

	return isfet
}

func (de *DriftEye) Name() string {
	return de.name
}

// fimWatchPaths returns the list of paths FIMEye monitors.
//
// Monitored: /etc (system config) + the SEKHEM binary.
// NOT monitored: the process working directory (/opt/nouchix/mesh/) — that is a
// deployment artifact directory; binary swaps, log writes, and data file changes
// would all trigger false CATASTROPHIC alerts if we hashed ".".
//
// Override via FIM_WATCH_PATHS (colon-separated) and FIM_BASELINE_PATH env vars.
func fimWatchPaths() []string {
	if v := os.Getenv("FIM_WATCH_PATHS"); v != "" {
		return strings.Split(v, ":")
	}
	// /etc covers all system configuration (passwd, sudoers, sshd_config, systemd units, etc.)
	paths := []string{"/etc"}
	// Add the SEKHEM binary itself — detect tampering of the running binary.
	binary := os.Getenv("FIM_BINARY_PATH")
	if binary == "" {
		binary = "/opt/nouchix/mesh/apiserver"
	}
	if _, err := os.Stat(binary); err == nil {
		paths = append(paths, binary)
	}
	return paths
}

// fimBaselinePath returns the on-disk path for the persisted FIM baseline.
// Persisting to disk means SEKHEM restarts do NOT re-baseline, so a compromised
// file replaced before the service restarts will still be detected.
func fimBaselinePath() string {
	if v := os.Getenv("FIM_BASELINE_PATH"); v != "" {
		return v
	}
	return "/opt/asaf/fim-baseline"
}

// FIMEye monitors file integrity
type FIMEye struct {
	name         string
	baseline     string
	baselinePath string
}

func NewFIMEye() *FIMEye {
	fe := &FIMEye{
		name:         "wedjat-fim",
		baselinePath: fimBaselinePath(),
	}
	// Load persisted baseline so restarts don't re-baseline and miss pre-restart tampering.
	if data, err := os.ReadFile(fe.baselinePath); err == nil {
		fe.baseline = strings.TrimSpace(string(data))
		log.Printf("[%s] Loaded persisted FIM baseline from %s", fe.name, fe.baselinePath)
	}
	return fe
}

func (fe *FIMEye) Gaze() []maat.Isfet {
	log.Printf("[%s] Checking file integrity...", fe.name)
	isfet := []maat.Isfet{}

	currentHash, err := fe.calculatePathsHash(fimWatchPaths())
	if err != nil {
		log.Printf("[%s] FIM failed: %v", fe.name, err)
		return isfet
	}

	if fe.baseline == "" {
		log.Printf("[%s] Establishing initial FIM baseline: %s (watching: %v)",
			fe.name, currentHash, fimWatchPaths())
		fe.baseline = currentHash
		// Persist so the baseline survives restarts.
		if err := os.WriteFile(fe.baselinePath, []byte(currentHash), 0600); err != nil {
			log.Printf("[%s] Warning: could not persist baseline to %s: %v", fe.name, fe.baselinePath, err)
		}
		return isfet
	}

	if currentHash != fe.baseline {
		log.Printf("[%s] FILE INTEGRITY COMPROMISED! (Old: %s, New: %s)", fe.name, fe.baseline, currentHash)
		isfet = append(isfet, maat.Isfet{
			ID:        "FIM-TAMPER-DIR",
			Source:    fe.name,
			Severity:  maat.SeverityCatastrophic,
			Certainty: 1.0,
			Omens: []maat.Omen{
				{Name: "OldHash", Value: fe.baseline, Malevolence: 1.0},
				{Name: "NewHash", Value: currentHash, Malevolence: 1.0},
				{Name: "WatchedPaths", Value: strings.Join(fimWatchPaths(), ":"), Malevolence: 0},
			},
		})
	}

	return isfet
}

// fimSkipFile returns true for files that change legitimately at runtime
// and would produce spurious CATASTROPHIC alerts if included in the FIM hash.
func fimSkipFile(path string) bool {
	base := filepath.Base(path)
	if base == "mtab" || base == "adjtime" || base == ".updated" ||
		strings.HasSuffix(path, "~") || strings.Contains(path, "/run/") {
		return true
	}
	// /etc/resolv.conf is updated by DHCP/NetworkManager dynamically.
	// /etc/cron.d/* and /etc/crontab have their access times updated on reads.
	// /etc/systemd/ contains our own deployed service units — changes here are
	// AUTHORIZED deploys, not tampering; a separate deploy audit covers them.
	if base == "resolv.conf" || base == "crontab" || strings.Contains(path, "/cron") ||
		strings.Contains(path, "/etc/systemd/") {
		return true
	}
	return false
}

// hashFileInto writes path + hash of a single file into hasher.
func hashFileInto(hasher interface{ Write([]byte) (int, error) }, path string) {
	fileHash, err := scanners.CalculateFileHash(path)
	if err != nil {
		return
	}
	hasher.Write([]byte(path))
	hasher.Write([]byte(fileHash))
}

// walkDirInto walks root recursively, hashing each non-skipped file into hasher.
func walkDirInto(hasher interface{ Write([]byte) (int, error) }, root string) error {
	return filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fimSkipFile(path) {
			return nil
		}
		hashFileInto(hasher, path)
		return nil
	})
}

// calculatePathsHash hashes each path in the list; directories are walked recursively.
// High-churn runtime files (mtab, adjtime, etc.) are excluded to prevent spurious alerts.
func (fe *FIMEye) calculatePathsHash(paths []string) (string, error) {
	hasher := sha256.New()
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			continue // path does not exist on this host — skip silently
		}
		if !info.IsDir() {
			hashFileInto(hasher, root)
			continue
		}
		if err := walkDirInto(hasher, root); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (fe *FIMEye) Name() string {
	return fe.name
}
