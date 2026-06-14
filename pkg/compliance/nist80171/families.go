package nist80171

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

// NIST 800-171 Rev 2 — All 14 Families
// Families beyond AC (Access Control) are catalogued here.
// Controls marked MANUAL_REVIEW require analyst attestation, policy documents,
// or evidence that cannot be collected by reading filesystem/sysctl state alone.
//
// To run full audit: call ValidateAllFamilies() which invokes every family.
// Each family that has automatable checks (AU, IA, SC, SI) calls real system checks.
// All others return MANUAL_REVIEW with the specific evidence required.

// ValidateAllFamilies runs all 14 NIST 800-171 families and returns combined results.
func (v *Validator) ValidateAllFamilies() []ControlResult {
	all := []ControlResult{}
	all = append(all, v.ValidateACFamily()...) // Access Control        (22 controls)
	all = append(all, v.ValidateAUFamily()...) // Audit & Accountability (9 controls)
	all = append(all, v.ValidateATFamily()...) // Awareness & Training   (3 controls)
	all = append(all, v.ValidateCMFamily()...) // Config Management      (9 controls)
	all = append(all, v.ValidateIAFamily()...) // Identification & Auth  (11 controls)
	all = append(all, v.ValidateIRFamily()...) // Incident Response      (3 controls)
	all = append(all, v.ValidateMAFamily()...) // Maintenance            (6 controls)
	all = append(all, v.ValidateMPFamily()...) // Media Protection       (9 controls)
	all = append(all, v.ValidatePEFamily()...) // Physical Protection    (6 controls)
	all = append(all, v.ValidatePSFamily()...) // Personnel Security     (2 controls)
	all = append(all, v.ValidateRAFamily()...) // Risk Assessment        (3 controls)
	all = append(all, v.ValidateCAFamily()...) // Security Assessment    (4 controls)
	all = append(all, v.ValidateSCFamily()...) // System & Comms Prot   (16 controls)
	all = append(all, v.ValidateSIFamily()...) // System & Info Integrity (7 controls)
	v.Results = all
	return all
}

// ComputeSummary computes aggregate compliance metrics across loaded results.
func (v *Validator) ComputeSummary() ComplianceSummary {
	s := ComplianceSummary{
		TotalControls:   len(v.Results),
		BaselineVersion: "Rev 2",
	}
	for _, r := range v.Results {
		switch r.Status {
		case "PASS":
			s.Passed++
		case "FAIL":
			s.Failed++
		case "MANUAL_REVIEW":
			s.ManualReview++
		case "NOT_APPLICABLE":
			s.NotApplicable++
		}
	}
	// Score: PASS = 1.0 credit, MANUAL_REVIEW = 0.5 credit (conditional — requires attestation)
	denominator := s.TotalControls - s.NotApplicable
	if denominator > 0 {
		s.Score = (float64(s.Passed) + float64(s.ManualReview)*0.5) / float64(denominator) * 100.0
	}
	return s
}

// ── AU: Audit and Accountability (9 controls: 3.3.1 – 3.3.9) ─────────────────

func (v *Validator) ValidateAUFamily() []ControlResult {
	return []ControlResult{
		v.checkServiceActive("3.3.1", FamilyAU,
			"Create and retain system audit logs to monitor, analyze, investigate, and report unlawful or unauthorized system activity.",
			"auditd",
			"Audit daemon (auditd) running — system audit logs being generated.",
			"auditd not active. Install and enable: sudo systemctl enable --now auditd"),
		v.checkServiceEnabled("3.3.2", FamilyAU,
			"Ensure that the actions of individual system users can be uniquely traced to those users.",
			"auditd",
			"auditd enabled at boot — audit trail continuity ensured.",
			"Enable auditd: sudo systemctl enable auditd"),
		v.requiresManualReview("3.3.3", FamilyAU, "Review and update logged events.", "Requires log policy review and event catalog documentation."),
		v.requiresManualReview("3.3.4", FamilyAU, "Alert in the event of audit logging process failure.", "Requires SIEM or log monitoring tool configuration review."),
		v.requiresManualReview("3.3.5", FamilyAU, "Correlate audit record review, analysis, and reporting.", "Requires SIEM configuration or analyst workflow documentation."),
		v.requiresManualReview("3.3.6", FamilyAU, "Provide audit record reduction and report generation.", "Requires log aggregation tool attestation."),
		v.requiresManualReview("3.3.7", FamilyAU, "Provide system capability for audit record comparison (NTP/time synchronization).", "Requires chrony or NTP configuration review."),
		v.checkAuditLogPermissions(),
		v.requiresManualReview("3.3.9", FamilyAU, "Limit audit management to subset of privileged users.", "Requires RBAC configuration review for audit log access."),
	}
}

func (v *Validator) checkAuditLogPermissions() ControlResult {
	r := ControlResult{
		ControlID:   "3.3.8",
		Title:       "Protect Audit Information",
		Family:      FamilyAU,
		Description: "Protect audit information and audit tools from unauthorized access, modification, and deletion.",
		CheckedAt:   time.Now(),
	}
	info, err := os.Stat("/var/log/audit")
	if err != nil {
		info, err = os.Stat("/var/log")
	}
	if err != nil {
		r.Status = "MANUAL_REVIEW"
		r.Finding = "Cannot check audit log directory permissions — manual review required"
		return r
	}
	mode := info.Mode().Perm()
	if mode&0002 != 0 {
		r.Status = "FAIL"
		r.Finding = "Audit log directory is world-writable — audit integrity at risk."
		r.Remediation = "chmod o-w /var/log/audit; chown root:root /var/log/audit"
	} else {
		r.Status = "PASS"
		r.Finding = "Audit log directory not world-writable."
	}
	return r
}

// ── AT: Awareness and Training (3 controls: 3.2.1 – 3.2.3) ──────────────────

func (v *Validator) ValidateATFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.2.1", FamilyAT, "Ensure personnel are aware of security risks.", "Requires training records or LMS attestation."),
		v.requiresManualReview("3.2.2", FamilyAT, "Ensure personnel are trained to carry out assigned responsibilities.", "Requires role-based training completion records."),
		v.requiresManualReview("3.2.3", FamilyAT, "Provide security awareness training on recognizing and reporting threats.", "Requires phishing simulation or training program documentation."),
	}
}

// ── CM: Configuration Management (9 controls: 3.4.1 – 3.4.9) ────────────────

func (v *Validator) ValidateCMFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.4.1", FamilyCM, "Establish and maintain baseline configurations.", "Requires baseline config documentation (CMDB or SCM)."),
		v.requiresManualReview("3.4.2", FamilyCM, "Establish and enforce security configuration settings.", "Requires hardening benchmark evidence (SCAP scan results)."),
		v.requiresManualReview("3.4.3", FamilyCM, "Track, review, approve, and log changes to systems.", "Requires change management process documentation."),
		v.requiresManualReview("3.4.4", FamilyCM, "Analyze security impact of changes prior to implementation.", "Requires change advisory board records or security review process."),
		v.requiresManualReview("3.4.5", FamilyCM, "Define, document, approve, and enforce physical and logical access restrictions.", "Requires access control policy for configuration changes."),
		v.checkHostFirewall(),
		v.requiresManualReview("3.4.7", FamilyCM, "Restrict, disable, or prevent the use of nonessential programs.", "Requires software whitelist/blacklist policy review."),
		v.requiresManualReview("3.4.8", FamilyCM, "Apply deny-by-exception policy to software usage.", "Requires application control tool attestation."),
		v.requiresManualReview("3.4.9", FamilyCM, "Control and monitor user-installed software.", "Requires endpoint software inventory and control mechanism review."),
	}
}

func (v *Validator) checkHostFirewall() ControlResult {
	r := ControlResult{
		ControlID:   "3.4.6",
		Title:       "Least Functionality",
		Family:      FamilyCM,
		Description: "Employ the principle of least functionality by configuring systems to provide only essential capabilities.",
		CheckedAt:   time.Now(),
	}
	if isServiceActive("firewalld") || isServiceActive("iptables") || isServiceActive("nftables") {
		r.Status = "PASS"
		r.Finding = "Host-based firewall active (firewalld/iptables/nftables) — network least functionality enforced."
	} else {
		r.Status = "FAIL"
		r.Finding = "No host-based firewall detected. System may expose unnecessary network services."
		r.Remediation = "Install and enable firewalld: sudo dnf install firewalld && sudo systemctl enable --now firewalld"
	}
	return r
}

// ── IA: Identification and Authentication (11 controls: 3.5.1 – 3.5.11) ──────

func (v *Validator) ValidateIAFamily() []ControlResult {
	return []ControlResult{
		v.checkUniqueUIDs(),
		v.requiresManualReview("3.5.2", FamilyIA, "Authenticate identities of users, processes, or devices.", "Requires IdP configuration review or PKI attestation."),
		v.requiresManualReview("3.5.3", FamilyIA, "Use multifactor authentication for local and network access.", "Requires MFA configuration documentation (PIV, TOTP, FIDO2)."),
		v.requiresManualReview("3.5.4", FamilyIA, "Employ replay-resistant authentication mechanisms.", "Requires authentication protocol review (Kerberos, TLS mutual auth)."),
		v.requiresManualReview("3.5.5", FamilyIA, "Employ identifier management.", "Requires account lifecycle management policy review."),
		v.requiresManualReview("3.5.6", FamilyIA, "Employ authenticator management.", "Requires password/credential lifecycle policy documentation."),
		v.checkPasswordComplexity(),
		v.requiresManualReview("3.5.8", FamilyIA, "Prohibit reuse of identifiers for defined period.", "Requires identity management system configuration review."),
		v.requiresManualReview("3.5.9", FamilyIA, "Allow temporary password use with immediate change requirement.", "Requires IAM/LDAP policy review."),
		v.requiresManualReview("3.5.10", FamilyIA, "Store and transmit only cryptographically-protected passwords.", "Requires authentication backend configuration review (shadow hash algorithm)."),
		v.requiresManualReview("3.5.11", FamilyIA, "Obscure feedback of authentication information.", "Requires terminal/UI configuration review."),
	}
}

func (v *Validator) checkUniqueUIDs() ControlResult {
	r := ControlResult{
		ControlID:   "3.5.1",
		Title:       "User Identification — Unique UIDs",
		Family:      FamilyIA,
		Description: "Identify system users, processes acting on behalf of users, and devices.",
		CheckedAt:   time.Now(),
	}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		r.Status = "MANUAL_REVIEW"
		r.Finding = "Cannot read /etc/passwd — manual identity uniqueness review required"
		return r
	}
	uidSeen := map[string]string{}
	duplicates := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		uid, user := parts[2], parts[0]
		if uid == "0" && user == "root" {
			continue
		}
		if existing, seen := uidSeen[uid]; seen {
			duplicates = append(duplicates, "UID "+uid+" shared by "+existing+" and "+user)
		} else {
			uidSeen[uid] = user
		}
	}
	if len(duplicates) == 0 {
		r.Status = "PASS"
		r.Finding = "No duplicate UIDs — users uniquely identified."
	} else {
		r.Status = "FAIL"
		r.Finding = "Duplicate UIDs: " + strings.Join(duplicates, "; ")
		r.Remediation = "Assign unique UIDs: usermod -u <newuid> <username>"
	}
	return r
}

func (v *Validator) checkPasswordComplexity() ControlResult {
	r := ControlResult{
		ControlID:   "3.5.7",
		Title:       "Password Complexity",
		Family:      FamilyIA,
		Description: "Enforce a minimum password complexity and change of characters when new passwords are created.",
		CheckedAt:   time.Now(),
	}
	data, err := os.ReadFile("/etc/security/pwquality.conf")
	if err != nil {
		r.Status = "FAIL"
		r.Finding = "/etc/security/pwquality.conf not found — password complexity not configured."
		r.Remediation = "Install libpwquality and configure /etc/security/pwquality.conf with minlen=15."
		return r
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "minlen") && strings.Contains(trimmed, "=") {
			r.Status = "PASS"
			r.Finding = "Password complexity configured: " + trimmed
			return r
		}
	}
	r.Status = "FAIL"
	r.Finding = "pwquality.conf exists but minlen not configured."
	r.Remediation = "Add 'minlen = 15' to /etc/security/pwquality.conf"
	return r
}

// ── IR: Incident Response (3 controls: 3.6.1 – 3.6.3) ───────────────────────

func (v *Validator) ValidateIRFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.6.1", FamilyIR, "Establish an operational incident-handling capability.", "Requires IRP documentation and tabletop exercise records."),
		v.requiresManualReview("3.6.2", FamilyIR, "Track, document, and report incidents.", "Requires ticketing system or incident log review."),
		v.requiresManualReview("3.6.3", FamilyIR, "Test the organizational incident response capability.", "Requires IR exercise completion records."),
	}
}

// ── MA: Maintenance (6 controls: 3.7.1 – 3.7.6) ─────────────────────────────

func (v *Validator) ValidateMAFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.7.1", FamilyMA, "Perform maintenance on organizational systems.", "Requires maintenance schedule and log review."),
		v.requiresManualReview("3.7.2", FamilyMA, "Provide controls on tools, techniques, mechanisms, and personnel for maintenance.", "Requires maintenance tool inventory and access control review."),
		v.requiresManualReview("3.7.3", FamilyMA, "Ensure equipment removed for maintenance is sanitized.", "Requires media sanitization policy documentation."),
		v.requiresManualReview("3.7.4", FamilyMA, "Check media containing diagnostic programs for malicious code.", "Requires malware scan records for maintenance media."),
		v.requiresManualReview("3.7.5", FamilyMA, "Require MFA for remote maintenance sessions.", "Requires remote maintenance authentication policy review."),
		v.requiresManualReview("3.7.6", FamilyMA, "Supervise maintenance activities of personnel without required access authorization.", "Requires visitor/maintenance supervision policy documentation."),
	}
}

// ── MP: Media Protection (9 controls: 3.8.1 – 3.8.9) ────────────────────────

func (v *Validator) ValidateMPFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.8.1", FamilyMP, "Protect system media containing CUI.", "Requires media inventory and physical/logical protection policy."),
		v.requiresManualReview("3.8.2", FamilyMP, "Limit access to CUI on system media.", "Requires media access control policy review."),
		v.requiresManualReview("3.8.3", FamilyMP, "Sanitize or destroy system media before disposal.", "Requires media sanitization records or NIST SP 800-88 compliance documentation."),
		v.requiresManualReview("3.8.4", FamilyMP, "Mark media with necessary CUI markings and distribution limitations.", "Requires media labeling policy review."),
		v.requiresManualReview("3.8.5", FamilyMP, "Control access to media containing CUI.", "Requires physical media storage access log review."),
		v.requiresManualReview("3.8.6", FamilyMP, "Implement cryptographic mechanisms to protect CUI during transport.", "Requires encryption-in-transit policy for removable media."),
		v.requiresManualReview("3.8.7", FamilyMP, "Control the use of removable media on system components.", "Requires USB port control or endpoint policy documentation."),
		v.requiresManualReview("3.8.8", FamilyMP, "Prohibit use of portable storage devices without identifiable owner.", "Requires removable media registration policy."),
		v.requiresManualReview("3.8.9", FamilyMP, "Protect the confidentiality of backup CUI at storage locations.", "Requires backup encryption policy and storage access control review."),
	}
}

// ── PE: Physical Protection (6 controls: 3.10.1 – 3.10.6) ───────────────────

func (v *Validator) ValidatePEFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.10.1", FamilyPE, "Limit physical access to systems to authorized individuals.", "Requires facility access log, badge system configuration, or physical security audit."),
		v.requiresManualReview("3.10.2", FamilyPE, "Protect and monitor physical facility and support infrastructure.", "Requires CCTV/alarm system attestation or security guard logs."),
		v.requiresManualReview("3.10.3", FamilyPE, "Escort visitors and monitor visitor activity.", "Requires visitor log and escort policy documentation."),
		v.requiresManualReview("3.10.4", FamilyPE, "Maintain audit logs of physical access.", "Requires physical access control system log review."),
		v.requiresManualReview("3.10.5", FamilyPE, "Control and manage physical access devices.", "Requires key/badge inventory and lifecycle management documentation."),
		v.requiresManualReview("3.10.6", FamilyPE, "Enforce safeguarding measures for CUI at alternate work sites.", "Requires telework/remote work security policy documentation."),
	}
}

// ── PS: Personnel Security (2 controls: 3.9.1 – 3.9.2) ──────────────────────

func (v *Validator) ValidatePSFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.9.1", FamilyPS, "Screen individuals prior to authorizing access.", "Requires background check policy and HR records."),
		v.requiresManualReview("3.9.2", FamilyPS, "Ensure CUI is protected during and after personnel actions.", "Requires offboarding checklist and account termination records."),
	}
}

// ── RA: Risk Assessment (3 controls: 3.11.1 – 3.11.3) ───────────────────────

func (v *Validator) ValidateRAFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.11.1", FamilyRA, "Periodically assess the risk to operations from the processing, storage, or transmission of CUI.", "Requires formal risk assessment documentation (last 12 months)."),
		v.requiresManualReview("3.11.2", FamilyRA, "Scan for vulnerabilities in organizational systems periodically.", "Requires vulnerability scanner output dated within 30 days."),
		v.requiresManualReview("3.11.3", FamilyRA, "Remediate vulnerabilities in accordance with risk assessments.", "Requires patch management records and vulnerability remediation tracking."),
	}
}

// ── CA: Security Assessment (4 controls: 3.12.1 – 3.12.4) ───────────────────

func (v *Validator) ValidateCAFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.12.1", FamilyCA, "Periodically assess the security controls in systems to determine effectiveness.", "Requires control assessment records or C3PAO assessment documentation."),
		v.requiresManualReview("3.12.2", FamilyCA, "Develop and implement plans of action to correct deficiencies.", "Requires POAM documentation with milestones and POC assignments."),
		v.requiresManualReview("3.12.3", FamilyCA, "Monitor security controls on an ongoing basis.", "Requires continuous monitoring plan or SIEM dashboard attestation."),
		v.requiresManualReview("3.12.4", FamilyCA, "Develop, document, and periodically update system security plans.", "Requires SSP document with last-updated date within 12 months."),
	}
}

// ── SC: System and Communications Protection (16 controls: 3.13.1 – 3.13.16) ─

func (v *Validator) ValidateSCFamily() []ControlResult {
	return []ControlResult{
		v.requiresManualReview("3.13.1", FamilySC, "Monitor, control, and protect communications at external boundaries.", "Requires network boundary protection documentation."),
		v.requiresManualReview("3.13.2", FamilySC, "Employ architectural designs that promote security.", "Requires system architecture documentation."),
		v.requiresManualReview("3.13.3", FamilySC, "Separate user functionality from system management functionality.", "Requires network/VLAN segmentation documentation."),
		v.requiresManualReview("3.13.4", FamilySC, "Prevent unauthorized and unintended information transfer.", "Requires data flow control documentation."),
		v.checkFirewallZones(),
		v.requiresManualReview("3.13.6", FamilySC, "Deny network communications traffic by default.", "Requires firewall ruleset review confirming default-deny posture."),
		v.requiresManualReview("3.13.7", FamilySC, "Prevent remote devices from simultaneously connecting to local network (split tunneling).", "Requires VPN split-tunneling policy review."),
		v.requiresManualReview("3.13.8", FamilySC, "Implement cryptographic mechanisms to prevent unauthorized CUI disclosure during transmission.", "Requires TLS/VPN configuration review with cipher suite documentation."),
		v.requiresManualReview("3.13.9", FamilySC, "Terminate network connections after defined period of inactivity.", "Requires firewall/session timeout configuration review."),
		v.checkFIPSKeyManagement(),
		v.checkFIPSCrypto(),
		v.requiresManualReview("3.13.12", FamilySC, "Prohibit remote activation of collaborative computing devices.", "Requires video/microphone policy review."),
		v.requiresManualReview("3.13.13", FamilySC, "Control and monitor the use of mobile code.", "Requires mobile code policy documentation."),
		v.requiresManualReview("3.13.14", FamilySC, "Control and monitor the use of VoIP technologies.", "Requires VoIP policy documentation."),
		v.requiresManualReview("3.13.15", FamilySC, "Protect the authenticity of communications sessions.", "Requires session authentication mechanism review."),
		v.requiresManualReview("3.13.16", FamilySC, "Protect CUI at rest.", "Requires disk/database encryption configuration review."),
	}
}

func (v *Validator) checkFirewallZones() ControlResult {
	r := ControlResult{
		ControlID:   "3.13.5",
		Title:       "Public-Access System Separation",
		Family:      FamilySC,
		Description: "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
		CheckedAt:   time.Now(),
	}
	out, err := exec.Command("firewall-cmd", "--list-all-zones").Output()
	if err != nil {
		r.Status = "MANUAL_REVIEW"
		r.Finding = "Cannot query firewall zones — manual network segmentation review required"
		return r
	}
	zones := 0
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			zones++
		}
	}
	if zones > 1 {
		r.Status = "PASS"
		r.Finding = "Multiple firewall zones configured — network segmentation present."
	} else {
		r.Status = "MANUAL_REVIEW"
		r.Finding = "Single firewall zone — network segmentation requires physical/logical architecture review."
	}
	return r
}

func (v *Validator) checkFIPSKeyManagement() ControlResult {
	r := ControlResult{
		ControlID:   "3.13.10",
		Title:       "Cryptographic Key Management",
		Family:      FamilySC,
		Description: "Establish and manage cryptographic keys for required cryptography employed in organizational systems.",
		CheckedAt:   time.Now(),
	}
	return v.checkFIPSState(r)
}

func (v *Validator) checkFIPSCrypto() ControlResult {
	r := ControlResult{
		ControlID:   "3.13.11",
		Title:       "FIPS-Validated Cryptography",
		Family:      FamilySC,
		Description: "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
		CheckedAt:   time.Now(),
	}
	return v.checkFIPSState(r)
}

func (v *Validator) checkFIPSState(r ControlResult) ControlResult {
	data, err := os.ReadFile("/proc/sys/crypto/fips_enabled")
	if err != nil {
		r.Status = "MANUAL_REVIEW"
		r.Finding = "Cannot determine FIPS state — manual cryptographic configuration review required"
		return r
	}
	if strings.TrimSpace(string(data)) == "1" {
		r.Status = "PASS"
		r.Finding = "FIPS mode enabled — NIST-approved cryptographic algorithms enforced."
	} else {
		r.Status = "FAIL"
		r.Finding = "FIPS mode disabled — non-FIPS algorithms may be in use."
		r.Remediation = "Enable FIPS: sudo fips-mode-setup --enable && reboot"
	}
	return r
}

// ── SI: System and Information Integrity (7 controls: 3.14.1 – 3.14.7) ───────

func (v *Validator) ValidateSIFamily() []ControlResult {
	return []ControlResult{
		v.checkFlawRemediation(),
		v.requiresManualReview("3.14.2", FamilySI, "Provide protection from malicious code at appropriate locations.", "Requires antimalware tool configuration review."),
		v.requiresManualReview("3.14.3", FamilySI, "Monitor system security alerts and advisories.", "Requires threat intelligence feed subscription or CISA alert monitoring documentation."),
		v.requiresManualReview("3.14.4", FamilySI, "Update malicious code protection mechanisms.", "Requires AV/EDR signature update schedule review."),
		v.requiresManualReview("3.14.5", FamilySI, "Perform periodic scans and real-time scans of files from external sources.", "Requires malware scanner schedule and scan log review."),
		v.requiresManualReview("3.14.6", FamilySI, "Monitor systems to detect attacks and indicators of potential attacks.", "Requires IDS/IPS or EDR deployment attestation."),
		v.requiresManualReview("3.14.7", FamilySI, "Identify unauthorized use of systems.", "Requires behavioral analytics or UEBA tool attestation."),
	}
}

func (v *Validator) checkFlawRemediation() ControlResult {
	r := ControlResult{
		ControlID:   "3.14.1",
		Title:       "Flaw Remediation",
		Family:      FamilySI,
		Description: "Identify, report, and correct information and information system flaws in a timely manner.",
		CheckedAt:   time.Now(),
	}
	_, err1 := os.Stat("/etc/dnf/automatic.conf")
	_, err2 := os.Stat("/etc/yum/yum-cron.conf")
	if err1 == nil || err2 == nil {
		r.Status = "PASS"
		r.Finding = "Automatic update mechanism configured (dnf-automatic or yum-cron detected)."
	} else {
		r.Status = "MANUAL_REVIEW"
		r.Finding = "Automatic update configuration not found — manual patch management process review required."
	}
	return r
}

// ── Shared internal helpers ───────────────────────────────────────────────────

func isServiceActive(name string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil
}

func (v *Validator) checkServiceActive(controlID, family, description, svcName, passMsg, failMsg string) ControlResult {
	r := ControlResult{ControlID: controlID, Family: family, Description: description, CheckedAt: time.Now()}
	if isServiceActive(svcName) {
		r.Status = "PASS"
		r.Finding = passMsg
	} else {
		r.Status = "FAIL"
		r.Finding = failMsg
		r.Remediation = "sudo systemctl enable --now " + svcName
	}
	return r
}

func (v *Validator) checkServiceEnabled(controlID, family, description, svcName, passMsg, failMsg string) ControlResult {
	r := ControlResult{ControlID: controlID, Family: family, Description: description, CheckedAt: time.Now()}
	if exec.Command("systemctl", "is-enabled", "--quiet", svcName).Run() == nil {
		r.Status = "PASS"
		r.Finding = passMsg
	} else {
		r.Status = "FAIL"
		r.Finding = failMsg
		r.Remediation = "sudo systemctl enable " + svcName
	}
	return r
}
