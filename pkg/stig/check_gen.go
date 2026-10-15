// Package stig — check_gen.go
//
// GenerateCheckTable converts parsed XCCDF STIGRule records into CheckSpec
// rows suitable for the table-driven check engine.  It is a BUILD-TIME
// utility called by cmd/stig-updater --gen-go; it is never compiled into
// the asaf-desktop binary.
//
// Classification heuristic:
//   The DISA STIG CheckText follows very regular patterns (grep sshd_config,
//   sysctl, rpm -q, systemctl is-active, etc.).  We match these patterns in
//   priority order and fall back to CheckManual for anything ambiguous.  A
//   rule classified as CheckManual is still present in the output table so
//   the scan pipeline returns "Manual Review Required" for it rather than
//   silently skipping the control.
package stig

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"
)

// ── Platform detection ────────────────────────────────────────────────────────

// Platform identifies the target OS/runtime of a STIG family.
type Platform int

const (
	PlatformLinux      Platform = iota // RHEL, Ubuntu, Oracle Linux
	PlatformWindows                    // Windows 10/11, Server 2016/2019/2022
	PlatformMacOS                      // macOS 13/14/15
	PlatformKubernetes                 // Kubernetes, OpenShift
	PlatformUnknown
)

// DetectPlatform infers the target platform from the STIG family stem / title.
func DetectPlatform(stigFamily string) Platform {
	f := strings.ToLower(stigFamily)
	switch {
	case strings.Contains(f, "windows") || strings.Contains(f, "ms_win") ||
		strings.Contains(f, "u_ms_win") || strings.Contains(f, "server_20") ||
		strings.Contains(f, "active_directory") || strings.Contains(f, "exchange") ||
		strings.Contains(f, "iis") || strings.Contains(f, "sql_server") ||
		strings.Contains(f, "ms_ie") || strings.Contains(f, "edge"):
		return PlatformWindows
	case strings.Contains(f, "macos") || strings.Contains(f, "apple") ||
		strings.Contains(f, "ventura") || strings.Contains(f, "sonoma") ||
		strings.Contains(f, "sequoia"):
		return PlatformMacOS
	case strings.Contains(f, "kubernetes") || strings.Contains(f, "k8s") ||
		strings.Contains(f, "openshift") || strings.Contains(f, "container_platform"):
		return PlatformKubernetes
	case strings.Contains(f, "rhel") || strings.Contains(f, "ubuntu") ||
		strings.Contains(f, "oracle_linux") || strings.Contains(f, "canonical") ||
		strings.Contains(f, "can_ubuntu"):
		return PlatformLinux
	}
	return PlatformUnknown
}

// ── Classification patterns ───────────────────────────────────────────────────

var (
	// SSH: grep PermitRootLogin /etc/ssh/sshd_config
	reSSHParam = regexp.MustCompile(
		`(?i)grep\s+(?:-i\s+)?(?:-E\s+)?"?(\w[\w-]*)"?\s+/etc/ssh/sshd_config`)

	// sshd -T output check: sshd -T | grep permitrootlogin
	reSSHdT = regexp.MustCompile(
		`(?i)sshd\s+-T\b.*\|\s*grep\s+(-E\s+)?"?(\w[\w-]*)"?`)

	// sysctl key = value
	reSysctl = regexp.MustCompile(
		`(?i)sysctl\s+(net\.\S+|kernel\.\S+|vm\.\S+|fs\.\S+)`)

	// sysctl -a | grep key = value
	reSysctlA = regexp.MustCompile(
		`(?i)sysctl\s+-a\b.*\|\s*grep\s+"?([\w.]+)"?`)

	// rpm -q package or dnf list package
	rePackage = regexp.MustCompile(
		`(?i)rpm\s+-q\s+([\w.+-]+)`)
	rePackageDnf = regexp.MustCompile(
		`(?i)dnf\s+list\s+([\w.+-]+)`)

	// systemctl is-active service
	reServiceActive = regexp.MustCompile(
		`(?i)systemctl\s+is-active\s+([\w.@-]+)`)

	// systemctl is-enabled service
	reServiceEnabled = regexp.MustCompile(
		`(?i)systemctl\s+is-enabled\s+([\w.@-]+)`)

	// modprobe --showconfig | grep install <module>
	reModuleDisabled = regexp.MustCompile(
		`(?i)modprobe\s+--showconfig\b.*install\s+([\w-]+)`)
	// lsmod | grep <module> (blacklist check variant)
	reLsmod = regexp.MustCompile(
		`(?i)(?:modprobe\s+-n\b|lsmod\b).*\b([\w-]+)(?:\s+module|\s+kernel)?`)

	// /proc/cmdline
	reProcCmdline = regexp.MustCompile(
		`(?i)/proc/cmdline\b`)
	// grep argument /proc/cmdline → extract arg name
	reCmdlineArg = regexp.MustCompile(
		`(?i)grep\s+(?:-[a-zA-Z]+\s+)?['""]?([\w.=-]+)['""]?\s+/proc/cmdline`)

	// auditctl -l
	reAuditctl = regexp.MustCompile(`(?i)auditctl\s+-l\b`)
	// Pattern of the rule being checked
	reAuditRule = regexp.MustCompile(
		`(?i)grep\s+(?:-[a-zA-Z]+\s+)?"([^"]+)"\s+/etc/audit`)

	// PAM config: grep module /etc/pam.d/filename
	rePAMConfig = regexp.MustCompile(
		`(?i)grep\s+(?:-[a-zA-Z]+\s+)?"?([^"\s/]+)"?\s+(/etc/pam\.d/[\w.-]+)`)

	// mount | grep /mountpoint
	reMountPoint = regexp.MustCompile(
		`(?i)(?:mount\b.*\|\s*grep\b|/proc/mounts\b.*grep\b|grep\s+\S+\s+/proc/mounts)\s+"?(/[\w/]+)"?`)

	// stat --format "%a" /path
	reFileStat = regexp.MustCompile(
		`(?i)stat\s+(?:--format[= ]['""]%a['""]|-c\s+['""]?%a['""]?)\s+([\w/.-]+)`)

	// ls -l /path (followed by expected mode)
	reLsL = regexp.MustCompile(
		`(?i)ls\s+-[la]+\s+([\w/.-]+)`)

	// test -e /path or [ -f /path ] or [ -d /path ]
	reFileExists = regexp.MustCompile(
		`(?i)(?:test\s+-[efd]\b|if\s*\[\s*-[efd])\s+['""]?([\w/.-]+)['""]?`)

	// grep pattern /etc/path (for file-contains checks)
	reFileContains = regexp.MustCompile(
		`(?i)grep\s+(?:-[a-zA-Z]+\s+)?"?([^"\s]+)"?\s+(/etc/[\w/.-]+|/var/[\w/.-]+|/usr/[\w/.-]+)`)

	// ── Windows patterns ──────────────────────────────────────────────────────

	// Registry: Get-ItemProperty or reg query
	reWinRegistry = regexp.MustCompile(
		`(?i)(?:Get-ItemProperty\s+['""]?(HKLM|HKCU|HKCR|HKU)[:\\]([^'""\s]+)['""]?\s+[-–]\s*Name\s+['""]?(\w+)['""]?|` +
			`reg\s+query\s+"?(HKLM|HKCU)[\\]([^"]+)"?\s+/v\s+(\S+))`)
	// Simpler registry path: just a HKLM\path\value pattern
	reWinRegPath = regexp.MustCompile(
		`(?i)(HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU)[\\:]([\\A-Za-z0-9 _.()-]+)`)

	// Audit policy: auditpol /get /subcategory
	reWinAuditPol = regexp.MustCompile(
		`(?i)auditpol\s+/get\s+/subcategory:"?([^"]+)"?`)

	// Windows features: Get-WindowsOptionalFeature or Get-WindowsFeature
	reWinFeature = regexp.MustCompile(
		`(?i)(?:Get-WindowsOptionalFeature|Get-WindowsFeature)\s+(?:-Online\s+)?-FeatureName\s+['""]?(\S+)['""]?`)

	// Windows services: Get-Service or sc query
	reWinService = regexp.MustCompile(
		`(?i)(?:Get-Service\s+['""]?(\S+)['""]?|sc\s+query\s+['""]?(\S+)['""]?)`)

	// ── macOS patterns ────────────────────────────────────────────────────────

	// defaults read domain key
	reMacDefaults = regexp.MustCompile(
		`(?i)/usr/bin/defaults\s+read\s+([\w./]+)\s+(\w+)`)
	// /usr/bin/profiles
	reMacProfiles = regexp.MustCompile(
		`(?i)/usr/bin/profiles\s+(?:-P|-show|show|list)`)
	// Profile identifier
	reMacProfileID = regexp.MustCompile(
		`(?i)PayloadIdentifier|PayloadType|ProfileIdentifier\s*[=:]\s*['""]?([\w.]+)['""]?`)

	// ── Kubernetes patterns ───────────────────────────────────────────────────

	// kubectl get/describe
	reKubectl = regexp.MustCompile(
		`(?i)kubectl\s+(get|describe|exec|logs)\s+([\w-]+(?:\s+[\w-]+)*)`)

	// FixText patterns for argv extraction
	reFixSystemctl = regexp.MustCompile(
		`(?i)systemctl\s+(enable|disable|start|stop|restart|enable\s+--now|mask)\s+([\w.@-]+)`)
	reFixDnf = regexp.MustCompile(
		`(?i)dnf\s+(install|remove)\s+([\w.+:-]+)`)
	reFixSysctl = regexp.MustCompile(
		`(?i)sysctl\s+-w\s+([\w.]+)=(\S+)`)
	reFixGrubUpdate = regexp.MustCompile(
		`(?i)grub2-mkconfig`)
	reFixSELinux = regexp.MustCompile(
		`(?i)setenforce\s+1`)
	reFixFIPS = regexp.MustCompile(
		`(?i)fips-mode-setup\s+--enable`)
)

// ── Public API ────────────────────────────────────────────────────────────────

// ClassifyRule converts one parsed STIGRule into a CheckSpec.
// Platform is detected from rule.StigFile so the right classifier chain runs.
// Metadata (Title, Severity, CCIs) is intentionally NOT stored in the spec —
// it lives in the CSV database and is resolved at runtime via GetSTIGTitle etc.
func ClassifyRule(rule STIGRule) CheckSpec {
	return ClassifyRuleForPlatform(rule, DetectPlatform(rule.StigFile))
}

// ClassifyRuleForPlatform classifies a rule using the appropriate chain for
// the given platform.  Callers can supply the platform explicitly when the
// StigFile name is not sufficient to determine it.
func ClassifyRuleForPlatform(rule STIGRule, platform Platform) CheckSpec {
	checkText := rule.CheckText
	fixText := rule.FixText

	switch platform {
	case PlatformWindows:
		return classifyWindows(rule.ID, checkText, fixText)
	case PlatformMacOS:
		return classifyMacOS(rule.ID, checkText, fixText)
	case PlatformKubernetes:
		return classifyKubernetes(rule.ID, checkText, fixText)
	default:
		return classifyLinux(rule.ID, checkText, fixText)
	}
}

// classifyLinux runs the Linux/UNIX classifier chain (RHEL, Ubuntu, Oracle Linux).
func classifyLinux(ruleID, checkText, fixText string) CheckSpec {
	if spec, ok := trySSHConfig(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := trySysctl(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryPackage(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryServiceActive(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryServiceEnabled(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryModuleDisabled(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryAuditRule(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryGrubArg(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryPAMConfig(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryMountOption(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryFileMode(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryFileContains(ruleID, checkText, fixText); ok {
		return spec
	}
	return CheckSpec{RuleID: ruleID, CheckType: CheckManual}
}

// classifyWindows runs the Windows classifier chain.
func classifyWindows(ruleID, checkText, fixText string) CheckSpec {
	if spec, ok := tryWinRegistry(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryWinAuditPolicy(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryWinFeature(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryWinService(ruleID, checkText, fixText); ok {
		return spec
	}
	// Windows can also have file-based checks for config files
	if spec, ok := tryFileContains(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryFileExists(ruleID, checkText, fixText); ok {
		return spec
	}
	return CheckSpec{RuleID: ruleID, CheckType: CheckManual}
}

// classifyMacOS runs the macOS classifier chain.
func classifyMacOS(ruleID, checkText, fixText string) CheckSpec {
	if spec, ok := tryMacDefaults(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryMacProfiles(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryFileContains(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryFileExists(ruleID, checkText, fixText); ok {
		return spec
	}
	return CheckSpec{RuleID: ruleID, CheckType: CheckManual}
}

// classifyKubernetes runs the Kubernetes classifier chain.
func classifyKubernetes(ruleID, checkText, fixText string) CheckSpec {
	if spec, ok := tryKubectl(ruleID, checkText, fixText); ok {
		return spec
	}
	if spec, ok := tryFileContains(ruleID, checkText, fixText); ok {
		return spec
	}
	return CheckSpec{RuleID: ruleID, CheckType: CheckManual}
}

// GenerateCheckTableGo downloads/parses the given STIG (already parsed into
// rules), classifies each rule, then writes a Go source file at outPath
// containing a []CheckSpec var named varName in package pkgName.
//
// Use stigFamily to name the variable, e.g. "rhel09" → var rhel09STIG = []CheckSpec{...}
func GenerateCheckTableGo(rules []STIGRule, stigFamily, pkgName, varName, outPath string) error {
	// Classify all rules.
	specs := make([]CheckSpec, 0, len(rules))
	for _, r := range rules {
		specs = append(specs, ClassifyRule(r))
	}

	// Sort by RuleID for deterministic output (makes git diffs readable).
	sort.Slice(specs, func(i, j int) bool {
		return specs[i].RuleID < specs[j].RuleID
	})

	// Render Go source.
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()

	data := checkTableTemplateData{
		Package:    pkgName,
		VarName:    varName,
		STIGFamily: stigFamily,
		RuleCount:  len(specs),
		Generated:  time.Now().UTC().Format(time.RFC3339),
		Specs:      specs,
	}
	return checkTableTpl.Execute(f, data)
}

// ── Classifiers ───────────────────────────────────────────────────────────────

func trySSHConfig(ruleID, checkText, fixText string) (CheckSpec, bool) {
	var param string

	// Pattern 1: grep ParameterName /etc/ssh/sshd_config
	if m := reSSHParam.FindStringSubmatch(checkText); m != nil {
		param = m[1]
	} else if m := reSSHdT.FindStringSubmatch(checkText); m != nil {
		param = m[2]
	}

	if param == "" {
		return CheckSpec{}, false
	}
	param = canonicalSSHParam(param)
	expected := inferSSHExpected(param, checkText)

	var fix *FixSpec
	if expected != "" {
		fix = &FixSpec{
			Argv: [][]string{
				{"asaf-confedit", "/etc/ssh/sshd_config", param, expected},
				{"systemctl", "restart", "sshd"},
			},
		}
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckSSHConfig,
		Target:    param,
		Expected:  expected,
		Fix:       fix,
	}, true
}

func trySysctl(ruleID, checkText, fixText string) (CheckSpec, bool) {
	var key string
	if m := reSysctl.FindStringSubmatch(checkText); m != nil {
		key = strings.TrimRight(m[1], " =")
	} else if m := reSysctlA.FindStringSubmatch(checkText); m != nil {
		key = m[1]
	}
	if key == "" {
		return CheckSpec{}, false
	}

	expected := inferSysctlExpected(key, checkText)
	var fix *FixSpec
	if expected != "" {
		if m := reFixSysctl.FindStringSubmatch(fixText); m != nil {
			fix = &FixSpec{
				Argv: [][]string{
					{"sysctl", "-w", m[1] + "=" + m[2]},
				},
			}
		} else {
			fix = &FixSpec{
				Argv: [][]string{
					{"sysctl", "-w", key + "=" + expected},
				},
			}
		}
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckSysctl,
		Target:    key,
		Expected:  expected,
		Fix:       fix,
	}, true
}

func tryPackage(ruleID, checkText, fixText string) (CheckSpec, bool) {
	var pkg string
	if m := rePackage.FindStringSubmatch(checkText); m != nil {
		pkg = m[1]
	} else if m := rePackageDnf.FindStringSubmatch(checkText); m != nil {
		pkg = m[1]
	}
	if pkg == "" {
		return CheckSpec{}, false
	}

	var fix *FixSpec
	if m := reFixDnf.FindStringSubmatch(fixText); m != nil {
		if strings.EqualFold(m[1], "install") {
			fix = &FixSpec{
				Argv: [][]string{{"dnf", "install", "-y", m[2]}},
			}
		} else {
			fix = &FixSpec{
				Argv: [][]string{{"dnf", "remove", "-y", m[2]}},
			}
		}
	} else {
		fix = &FixSpec{
			Argv: [][]string{{"dnf", "install", "-y", pkg}},
		}
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckPackage,
		Target:    pkg,
		Expected:  "",
		Fix:       fix,
	}, true
}

func tryServiceActive(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reServiceActive.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	svc := strings.TrimSuffix(m[1], ".service")
	fix := inferServiceFix(svc, fixText, "enable --now")
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckServiceActive,
		Target:    svc,
		Expected:  "",
		Fix:       fix,
	}, true
}

func tryServiceEnabled(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reServiceEnabled.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	svc := strings.TrimSuffix(m[1], ".service")
	fix := inferServiceFix(svc, fixText, "enable")
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckServiceEnabled,
		Target:    svc,
		Expected:  "",
		Fix:       fix,
	}, true
}

func tryModuleDisabled(ruleID, checkText, fixText string) (CheckSpec, bool) {
	var module string
	if m := reModuleDisabled.FindStringSubmatch(checkText); m != nil {
		module = m[1]
	} else if m := reLsmod.FindStringSubmatch(checkText); m != nil {
		// only if the context is clearly a "disabled" check
		if strings.Contains(strings.ToLower(checkText), "disable") ||
			strings.Contains(strings.ToLower(checkText), "blacklist") ||
			strings.Contains(strings.ToLower(checkText), "install /bin/true") {
			module = m[1]
		}
	}
	if module == "" {
		return CheckSpec{}, false
	}
	confFile := fmt.Sprintf("/etc/modprobe.d/disable-%s.conf", module)
	fix := &FixSpec{
		Argv: [][]string{
			{"bash", "-c",
				fmt.Sprintf("echo 'install %s /bin/true' > %s && echo 'blacklist %s' >> %s",
					module, confFile, module, confFile)},
		},
		Reboot: true,
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckModuleDisabled,
		Target:    module,
		Expected:  "",
		Fix:       fix,
	}, true
}

func tryAuditRule(ruleID, checkText, fixText string) (CheckSpec, bool) {
	if !reAuditctl.MatchString(checkText) {
		return CheckSpec{}, false
	}
	// Extract the audit rule pattern being looked for
	target := ""
	if m := reAuditRule.FindStringSubmatch(checkText); m != nil {
		target = m[1]
	}
	if target == "" {
		// Fallback: extract a recognizable audit keyword from the rule text
		target = inferAuditTarget(checkText, ruleID)
	}
	if target == "" {
		return CheckSpec{}, false
	}

	var fix *FixSpec
	auditRule := inferAuditFix(target, fixText)
	if auditRule != "" {
		fix = &FixSpec{
			Argv: [][]string{
				{"bash", "-c", fmt.Sprintf("echo '%s' >> /etc/audit/rules.d/audit.rules", auditRule)},
				{"augenrules", "--load"},
			},
		}
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckAuditRule,
		Target:    target,
		Expected:  "",
		Fix:       fix,
	}, true
}

func tryGrubArg(ruleID, checkText, fixText string) (CheckSpec, bool) {
	if !reProcCmdline.MatchString(checkText) {
		return CheckSpec{}, false
	}
	var arg, expected string
	if m := reCmdlineArg.FindStringSubmatch(checkText); m != nil {
		kv := strings.SplitN(m[1], "=", 2)
		arg = kv[0]
		if len(kv) == 2 {
			expected = kv[1]
		}
	}
	if arg == "" {
		return CheckSpec{}, false
	}

	var fix *FixSpec
	if reFixGrubUpdate.MatchString(fixText) {
		kv := arg
		if expected != "" {
			kv = arg + "=" + expected
		}
		fix = &FixSpec{
			Argv: [][]string{
				{"grubby", "--update-kernel=ALL", "--args=" + kv},
			},
			Reboot: true,
		}
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckGrubArg,
		Target:    arg,
		Expected:  expected,
		Fix:       fix,
	}, true
}

func tryPAMConfig(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := rePAMConfig.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	module := m[1]
	pamFile := m[2]
	if !strings.HasPrefix(pamFile, "/etc/pam.d/") {
		return CheckSpec{}, false
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckPAMConfig,
		Target:    pamFile,
		Expected:  module,
	}, true
}

func tryMountOption(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reMountPoint.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	mountPoint := m[1]
	option := inferMountOption(mountPoint, checkText)
	if option == "" {
		return CheckSpec{}, false
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckMountOption,
		Target:    mountPoint,
		Expected:  option,
	}, true
}

func tryFileMode(ruleID, checkText, fixText string) (CheckSpec, bool) {
	var target string
	if m := reFileStat.FindStringSubmatch(checkText); m != nil {
		target = m[1]
	} else if m := reLsL.FindStringSubmatch(checkText); m != nil {
		target = m[1]
	}
	if target == "" || !strings.HasPrefix(target, "/") {
		return CheckSpec{}, false
	}
	expected := inferExpectedMode(target, checkText, fixText)
	if expected == "" {
		return CheckSpec{}, false
	}

	var fix *FixSpec
	octal := expected
	if len(octal) == 4 {
		octal = octal[1:] // strip leading zero for chmod
	}
	fix = &FixSpec{
		Argv: [][]string{
			{"chmod", octal, target},
		},
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckFileMode,
		Target:    target,
		Expected:  expected,
		Fix:       fix,
	}, true
}

func tryFileContains(ruleID, checkText, fixText string) (CheckSpec, bool) {
	// Use file-contains for well-known config files with specific grep patterns.
	// Skip SSH/PAM (handled by dedicated classifiers above).
	m := reFileContains.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	needle := m[1]
	target := m[2]

	// Avoid capturing binary-like or too-short needles
	if len(needle) < 2 || strings.HasPrefix(needle, "-") {
		return CheckSpec{}, false
	}
	// Avoid re-capturing SSH config (already handled)
	if strings.HasSuffix(target, "sshd_config") {
		return CheckSpec{}, false
	}
	// Avoid re-capturing PAM
	if strings.Contains(target, "/pam.d/") {
		return CheckSpec{}, false
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckFileContains,
		Target:    target,
		Expected:  needle,
	}, true
}

// ── Windows classifiers ───────────────────────────────────────────────────────

// reWinRegProse matches the DISA Windows STIG structured-prose registry check format:
//   Registry Hive: HKEY_LOCAL_MACHINE
//   Registry Path: \SOFTWARE\Policies\Microsoft\FVE\
//   Value Name: UseAdvancedStartup
//   Value: 0x00000001 (1)
var reWinRegProse = regexp.MustCompile(
	`(?i)Registry\s+Hive:\s*(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_USERS|HKU)\s+` +
		`Registry\s+Path:\s*([^\n]+?)\s+Value\s+Name:\s*([^\n]+?)\s+` +
		`(?:Type:[^\n]+\s+)?Value:\s*([^\n]+)`)

func tryWinRegistry(ruleID, checkText, fixText string) (CheckSpec, bool) {
	// Priority 1: DISA structured prose format (most common in real Windows STIGs)
	//   Registry Hive: HKLM
	//   Registry Path: \SOFTWARE\...
	//   Value Name: FooBar
	//   Value: 0x00000001 (1)
	if m := reWinRegProse.FindStringSubmatch(checkText); m != nil {
		hive := normalizeHive(strings.TrimSpace(m[1]))
		path := strings.Trim(strings.TrimSpace(m[2]), `\`)
		val := strings.TrimSpace(m[3])
		expected := strings.TrimSpace(m[4])
		// Clean up "0x00000001 (1)" → "1"
		if hex := regexp.MustCompile(`0x[0-9a-fA-F]+\s+\((\d+)\)`).FindStringSubmatch(expected); len(hex) > 1 {
			expected = hex[1]
		}
		target := hive + `\` + path + `\` + val
		return CheckSpec{
			RuleID:    ruleID,
			CheckType: CheckRegistryValue,
			Target:    target,
			Expected:  expected,
		}, true
	}

	// Priority 2: reg query "HKLM\path" /v ValueName (command-line style)
	reRegQuery := regexp.MustCompile(
		`(?i)reg\s+query\s+"?(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)[\\:]([^"'\s]+)"?\s+/v\s+"?(\S+?)"?(?:\s|$)`)
	if m := reRegQuery.FindStringSubmatch(checkText); m != nil {
		hive := normalizeHive(m[1])
		key := strings.TrimRight(m[2], "\\")
		val := m[3]
		target := hive + "\\" + key + "\\" + val
		expected := inferRegExpected(target, checkText, fixText)
		return CheckSpec{
			RuleID:    ruleID,
			CheckType: CheckRegistryValue,
			Target:    target,
			Expected:  expected,
		}, true
	}

	// Priority 3: Get-ItemProperty "HKLM:\path" -Name ValueName
	reGetItem := regexp.MustCompile(
		`(?i)Get-ItemProperty\s+-Path\s+"?(HKLM|HKCU)[:\\]([^"']+)"?\s+(?:-Name\s+"?(\w+)"?)`)
	if m := reGetItem.FindStringSubmatch(checkText); m != nil {
		hive := normalizeHive(m[1])
		key := strings.TrimRight(strings.ReplaceAll(m[2], "/", "\\"), "\\")
		val := m[3]
		target := hive + "\\" + key + "\\" + val
		expected := inferRegExpected(target, checkText, fixText)
		return CheckSpec{
			RuleID:    ruleID,
			CheckType: CheckRegistryValue,
			Target:    target,
			Expected:  expected,
		}, true
	}
	return CheckSpec{}, false
}

func tryWinAuditPolicy(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reWinAuditPol.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	subcategory := strings.TrimSpace(m[1])
	expected := inferAuditPolExpected(checkText)
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckWinAuditPolicy,
		Target:    subcategory,
		Expected:  expected,
	}, true
}

func tryWinFeature(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reWinFeature.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	feature := strings.TrimSpace(m[1])
	// Determine if the check is asserting enabled or disabled
	lower := strings.ToLower(checkText)
	expected := "disabled"
	if strings.Contains(lower, "must be installed") || strings.Contains(lower, "is installed") ||
		strings.Contains(lower, "enabled") && !strings.Contains(lower, "not enabled") {
		expected = "enabled"
	}
	var fix *FixSpec
	if expected == "disabled" {
		fix = &FixSpec{
			Argv: [][]string{
				{"powershell", "-NonInteractive", "-Command",
					fmt.Sprintf("Disable-WindowsOptionalFeature -Online -FeatureName %s -NoRestart", feature)},
			},
			Reboot: true,
		}
	} else {
		fix = &FixSpec{
			Argv: [][]string{
				{"powershell", "-NonInteractive", "-Command",
					fmt.Sprintf("Enable-WindowsOptionalFeature -Online -FeatureName %s -NoRestart", feature)},
			},
			Reboot: true,
		}
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckWinFeature,
		Target:    feature,
		Expected:  expected,
		Fix:       fix,
	}, true
}

func tryWinService(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reWinService.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	svc := m[1]
	if svc == "" {
		svc = m[2]
	}
	if svc == "" {
		return CheckSpec{}, false
	}
	lower := strings.ToLower(checkText)
	expected := "disabled"
	if strings.Contains(lower, "must be running") || strings.Contains(lower, "is running") {
		expected = "running"
	} else if strings.Contains(lower, "must be stopped") {
		expected = "stopped"
	}
	var fix *FixSpec
	switch expected {
	case "disabled":
		fix = &FixSpec{Argv: [][]string{{"sc", "config", svc, "start=", "disabled"}}}
	case "running":
		fix = &FixSpec{Argv: [][]string{{"sc", "start", svc}}}
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckWinService,
		Target:    svc,
		Expected:  expected,
		Fix:       fix,
	}, true
}

// tryFileExists is shared across platforms.
func tryFileExists(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reFileExists.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	path := m[1]
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "C:\\") &&
		!strings.HasPrefix(path, "%") {
		return CheckSpec{}, false
	}
	lower := strings.ToLower(checkText)
	expected := ""
	if strings.Contains(lower, "must not exist") || strings.Contains(lower, "should not exist") {
		expected = "absent"
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckFileExists,
		Target:    path,
		Expected:  expected,
	}, true
}

// ── macOS classifiers ─────────────────────────────────────────────────────────

func tryMacDefaults(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reMacDefaults.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	domain := m[1]
	key := m[2]
	target := domain + "|" + key
	expected := inferMacDefaultsExpected(key, checkText)
	var fix *FixSpec
	if expected != "" {
		fix = &FixSpec{
			Argv: [][]string{
				{"/usr/bin/defaults", "write", domain, key, expected},
			},
		}
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckMacDefaults,
		Target:    target,
		Expected:  expected,
		Fix:       fix,
	}, true
}

func tryMacProfiles(ruleID, checkText, fixText string) (CheckSpec, bool) {
	if !reMacProfiles.MatchString(checkText) {
		return CheckSpec{}, false
	}
	// Extract profile identifier from check text
	profileID := ""
	if m := reMacProfileID.FindStringSubmatch(checkText); m != nil {
		profileID = m[1]
	}
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckMacProfiles,
		Target:    profileID,
		Expected:  "",
	}, true
}

// ── Kubernetes classifiers ────────────────────────────────────────────────────

func tryKubectl(ruleID, checkText, fixText string) (CheckSpec, bool) {
	m := reKubectl.FindStringSubmatch(checkText)
	if m == nil {
		return CheckSpec{}, false
	}
	// Build the kubectl subcommand string: "get pods --all-namespaces"
	target := strings.TrimSpace(m[1] + " " + m[2])
	// Try to extract what the check is looking for
	expected := inferKubectlExpected(target, checkText)
	return CheckSpec{
		RuleID:    ruleID,
		CheckType: CheckKubectl,
		Target:    target,
		Expected:  expected,
	}, true
}

// ── Inference helpers ─────────────────────────────────────────────────────────

// canonicalSSHParam normalises capitalisation from check-text variations.
func canonicalSSHParam(s string) string {
	// DISA check text uses lowercase grep; SSH param names are CamelCase.
	table := map[string]string{
		"permitrootlogin":            "PermitRootLogin",
		"permitemptypasswords":       "PermitEmptyPasswords",
		"permituserenvironment":      "PermitUserEnvironment",
		"x11forwarding":              "X11Forwarding",
		"usepam":                     "UsePAM",
		"protocol":                   "Protocol",
		"banner":                     "Banner",
		"clientaliveinterval":        "ClientAliveInterval",
		"clientalivecountmax":        "ClientAliveCountMax",
		"logingracetime":             "LoginGraceTime",
		"maxauthtries":               "MaxAuthTries",
		"maxsessions":                "MaxSessions",
		"hostbasedauthentication":    "HostbasedAuthentication",
		"ignoreuserknownhosts":       "IgnoreUserKnownHosts",
		"kerberosauthentication":      "KerberosAuthentication",
		"gssapiauthentication":        "GSSAPIAuthentication",
		"strictmodes":                "StrictModes",
		"compression":                "Compression",
		"macs":                       "MACs",
		"ciphers":                    "Ciphers",
		"kexalgorithms":              "KexAlgorithms",
		"printlastlog":               "PrintLastLog",
		"rekeylimit":                 "RekeyLimit",
		"logintimeout":               "LoginGraceTime",
		"allowtcpforwarding":         "AllowTcpForwarding",
		"permittty":                  "PermitTTY",
		"printmotd":                  "PrintMotd",
		"subsystem":                  "Subsystem",
		"acceptenv":                  "AcceptEnv",
		"syslogfacility":             "SyslogFacility",
		"loglevel":                   "LogLevel",
		"addressfamily":              "AddressFamily",
		"challengeresponseauthentication": "ChallengeResponseAuthentication",
		"passwordauthentication":     "PasswordAuthentication",
		"pubkeyauthentication":       "PubkeyAuthentication",
	}
	if v, ok := table[strings.ToLower(s)]; ok {
		return v
	}
	// PascalCase pass-through if we don't know it
	return s
}

// inferSSHExpected extracts the required value for an SSH parameter from the
// check text context.  E.g. "PermitRootLogin no" → "no".
func inferSSHExpected(param, checkText string) string {
	// Look for "param value" or "param = value" in context
	re := regexp.MustCompile(
		`(?i)\b` + regexp.QuoteMeta(strings.ToLower(param)) + `\s*(?:=\s*)?(\S+)`)
	if m := re.FindStringSubmatch(strings.ToLower(checkText)); m != nil {
		v := m[1]
		// Strip quotes
		v = strings.Trim(v, `"'`)
		// Reject if it looks like a shell test operator or sentence punctuation
		if v == "is" || v == "must" || v == "should" || v == "not" || v == "be" ||
			v == "the" || v == "set" || v == "to" || v == "configured" {
			return ""
		}
		return v
	}
	// Fallback table for high-frequency params
	table := map[string]string{
		"PermitRootLogin":         "no",
		"PermitEmptyPasswords":    "no",
		"X11Forwarding":           "no",
		"IgnoreUserKnownHosts":    "yes",
		"HostbasedAuthentication": "no",
		"KerberosAuthentication":  "no",
		"GSSAPIAuthentication":    "no",
		"StrictModes":             "yes",
		"Compression":             "no",
		"PermitUserEnvironment":   "no",
		"PrintLastLog":            "yes",
		"UsePAM":                  "yes",
		"AllowTcpForwarding":      "no",
		"PasswordAuthentication":  "no",
		"PubkeyAuthentication":    "yes",
		"LoginGraceTime":          "30",
		"MaxAuthTries":            "4",
		"MaxSessions":             "10",
		"ClientAliveInterval":     "600",
		"ClientAliveCountMax":     "0",
		"Protocol":                "2",
		"LogLevel":                "VERBOSE",
		"SyslogFacility":          "AUTH",
		"Banner":                  "/etc/issue",
		"AddressFamily":           "inet",
		"ChallengeResponseAuthentication": "no",
	}
	if v, ok := table[param]; ok {
		return v
	}
	return ""
}

// inferSysctlExpected infers the required value for a sysctl key.
func inferSysctlExpected(key, checkText string) string {
	// Context: most network hardening params expect 0 or 1
	zeros := []string{
		"send_redirects", "accept_redirects", "secure_redirects",
		"accept_source_route", "accept_ra", "ip_forward",
	}
	ones := []string{
		"log_martians", "rp_filter", "tcp_syncookies",
		"icmp_echo_ignore_broadcasts", "icmp_ignore_bogus_error_responses",
		"dmesg_restrict", "kptr_restrict",
	}
	for _, z := range zeros {
		if strings.Contains(key, z) {
			return "0"
		}
	}
	for _, o := range ones {
		if strings.Contains(key, o) {
			return "1"
		}
	}
	// kernel.randomize_va_space
	if strings.Contains(key, "randomize_va_space") {
		return "2"
	}
	// Try to extract from check text: "= 0" or "= 1" near the key
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(key) + `\s*=\s*(\d+)`)
	if m := re.FindStringSubmatch(checkText); m != nil {
		return m[1]
	}
	return ""
}

func inferServiceFix(svc, fixText, action string) *FixSpec {
	// Prefer explicit systemctl command in fixText
	if m := reFixSystemctl.FindStringSubmatch(fixText); m != nil {
		args := strings.Fields("systemctl " + m[1] + " " + m[2])
		return &FixSpec{Argv: [][]string{args}}
	}
	// Generate reasonable default
	parts := append([]string{"systemctl"}, strings.Fields(action)...)
	parts = append(parts, svc)
	return &FixSpec{Argv: [][]string{parts}}
}

func inferAuditTarget(checkText, ruleID string) string {
	// Heuristic: extract the first file path or syscall name from checkText.
	reFile := regexp.MustCompile(`-w\s+([\w/.-]+)`)
	if m := reFile.FindStringSubmatch(checkText); m != nil {
		return m[1]
	}
	reSyscall := regexp.MustCompile(`-S\s+(\w+)`)
	if m := reSyscall.FindStringSubmatch(checkText); m != nil {
		return m[1]
	}
	return ""
}

func inferAuditFix(target, fixText string) string {
	// Prefer an -a or -w rule from fixText
	re := regexp.MustCompile(`(?m)^(-[aw]\s+\S+.*)$`)
	if m := re.FindStringSubmatch(fixText); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func inferMountOption(mountPoint, checkText string) string {
	options := []string{"nodev", "nosuid", "noexec", "ro"}
	lower := strings.ToLower(checkText)
	for _, o := range options {
		if strings.Contains(lower, o) {
			return o
		}
	}
	return ""
}

func inferExpectedMode(target, checkText, fixText string) string {
	// Look for chmod NNNN or mode NNNN in fixText first
	reFix := regexp.MustCompile(`(?i)chmod\s+0?(\d{3,4})\s+` + regexp.QuoteMeta(target))
	if m := reFix.FindStringSubmatch(fixText); m != nil {
		return padMode(m[1])
	}
	// Fallback: well-known paths
	modeTable := map[string]string{
		"/etc/passwd":           "0644",
		"/etc/shadow":           "0000",
		"/etc/group":            "0644",
		"/etc/gshadow":          "0000",
		"/etc/ssh/sshd_config":  "0600",
		"/etc/crontab":          "0600",
		"/etc/cron.d":           "0700",
		"/etc/cron.hourly":      "0700",
		"/etc/cron.daily":       "0700",
		"/etc/cron.weekly":      "0700",
		"/etc/cron.monthly":     "0700",
		"/boot/grub2/grub.cfg":  "0600",
	}
	if v, ok := modeTable[target]; ok {
		return v
	}
	// Extract from check text: "N N N permissions" or "(N N N)"
	re := regexp.MustCompile(`\b0(\d{3})\b`)
	if m := re.FindStringSubmatch(checkText); m != nil {
		return "0" + m[1]
	}
	return ""
}

func padMode(s string) string {
	if len(s) == 3 {
		return "0" + s
	}
	return s
}

func normalizeHive(s string) string {
	switch strings.ToUpper(s) {
	case "HKEY_LOCAL_MACHINE", "HKLM":
		return "HKLM"
	case "HKEY_CURRENT_USER", "HKCU":
		return "HKCU"
	case "HKEY_CLASSES_ROOT", "HKCR":
		return "HKCR"
	case "HKU", "HKEY_USERS":
		return "HKU"
	}
	return s
}

func inferRegExpected(target, checkText, fixText string) string {
	// Look for "= 1", "= 0", dword:00000001 patterns in checkText/fixText
	reDword := regexp.MustCompile(`(?i)(?:=\s*|dword:0{6}|value\s+(?:is|must be|should be)\s+)(\d+)`)
	for _, text := range []string{checkText, fixText} {
		if m := reDword.FindStringSubmatch(text); m != nil {
			return m[1]
		}
	}
	// Enabled/disabled patterns
	lower := strings.ToLower(checkText)
	if strings.Contains(lower, "must be enabled") || strings.Contains(lower, "value of 1") {
		return "1"
	}
	if strings.Contains(lower, "must be disabled") || strings.Contains(lower, "value of 0") {
		return "0"
	}
	return ""
}

func inferAuditPolExpected(checkText string) string {
	lower := strings.ToLower(checkText)
	switch {
	case strings.Contains(lower, "success and failure"):
		return "Success and Failure"
	case strings.Contains(lower, "success"):
		return "Success"
	case strings.Contains(lower, "failure"):
		return "Failure"
	case strings.Contains(lower, "no auditing"):
		return "No Auditing"
	}
	return "Success and Failure" // STIG default
}

func inferMacDefaultsExpected(key, checkText string) string {
	lower := strings.ToLower(checkText)
	// Boolean fields
	if strings.Contains(lower, "must be enabled") || strings.Contains(lower, "set to 1") ||
		strings.Contains(lower, "set to true") {
		return "1"
	}
	if strings.Contains(lower, "must be disabled") || strings.Contains(lower, "set to 0") ||
		strings.Contains(lower, "set to false") {
		return "0"
	}
	// Numeric value extraction
	re := regexp.MustCompile(`(?i)set to (\d+)`)
	if m := re.FindStringSubmatch(checkText); m != nil {
		return m[1]
	}
	return ""
}

func inferKubectlExpected(target, checkText string) string {
	// Look for quoted strings that represent required values
	re := regexp.MustCompile(`"([^"]{3,50})"`)
	matches := re.FindAllStringSubmatch(checkText, -1)
	for _, m := range matches {
		v := m[1]
		// Skip obvious non-value strings
		if strings.Contains(v, " ") && len(strings.Fields(v)) > 4 {
			continue
		}
		return v
	}
	return ""
}

// ── Go source emitter ─────────────────────────────────────────────────────────

type checkTableTemplateData struct {
	Package    string
	VarName    string
	STIGFamily string
	RuleCount  int
	Generated  string
	Specs      []CheckSpec
}

var checkTableTpl = template.Must(template.New("checkTable").Funcs(template.FuncMap{
	"goStr": func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return `"` + s + `"`
	},
	"goArgv": func(argv [][]string) string {
		if len(argv) == 0 {
			return "nil"
		}
		var parts []string
		for _, args := range argv {
			var innerParts []string
			for _, a := range args {
				a = strings.ReplaceAll(a, `\`, `\\`)
				a = strings.ReplaceAll(a, `"`, `\"`)
				innerParts = append(innerParts, `"`+a+`"`)
			}
			parts = append(parts, "{"+strings.Join(innerParts, ", ")+"}")
		}
		return "[][]string{" + strings.Join(parts, ", ") + "}"
	},
}).Parse(`// Code generated by stig-updater --gen-go on {{ .Generated }}.
// Source: DISA {{ .STIGFamily }} XCCDF benchmark — {{ .RuleCount }} rules.
// DO NOT EDIT MANUALLY. Re-generate with:
//   go run ./cmd/stig-updater --mode online --filter {{ .STIGFamily }} --gen-go
package {{ .Package }}

// {{ .VarName }} contains all CheckSpec rows derived from the DISA {{ .STIGFamily }}
// XCCDF benchmark.  Each row's metadata (Title, Severity, CCI refs) is resolved
// at runtime from the embedded STIG_CCI_Map.csv — it is not duplicated here.
var {{ .VarName }} = []CheckSpec{
{{- range .Specs }}
	{
		RuleID:    {{ goStr .RuleID }},
		CheckType: {{ printf "%q" .CheckType }},
		Target:    {{ goStr .Target }},
		Expected:  {{ goStr .Expected }},
{{- if .Fix }}
		Fix: &FixSpec{
			Argv:   {{ goArgv .Fix.Argv }},
			Reboot: {{ .Fix.Reboot }},
		},
{{- else }}
		Fix: nil,
{{- end }}
	},
{{- end }}
}
`))
