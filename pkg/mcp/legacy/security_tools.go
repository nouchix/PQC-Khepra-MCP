// package legacy — Security Domain Tool Definitions
//
// This file extends pkg/mcp/tools.go with all comprehensive security domain tools,
// creating the world's first Natural Language security operations platform.
//
// Every tool is mapped to existing pkg/ implementations:
//
//	pkg/ir         → Incident Response tools
//	pkg/arsenal    → Firewall, secret scanning, pentest tools
//	pkg/sonar      → Network discovery/OSINT
//	pkg/forensics  → Evidence collection (Imhotep's Eye)
//	pkg/drbc       → Disaster Recovery / Business Continuity
//	pkg/ert        → Evidence Recording Token / threat analysis
//	pkg/phantom    → Stealth network operations
//	pkg/fingerprint → Behavioral/device fingerprinting
//	pkg/dag        → Tamper-evident audit chain
//	pkg/adinkra    → PQC signing for all evidence
//
// Natural Language Examples → Tool Chains:
//
//	"Is my network compromised?"
//	→ khepra_hunt_threats + khepra_get_ids_alerts + khepra_analyze_iocs
//
//	"Someone is attacking us right now"
//	→ khepra_declare_incident + khepra_collect_forensics + khepra_contain_threat + khepra_block_threat_actor
//
//	"Show me everything suspicious in the last 24 hours"
//	→ khepra_get_security_timeline + khepra_search_logs + khepra_correlate_events
//
//	"Run a full pentest on our dev environment"
//	→ khepra_discover_endpoints + khepra_enumerate_services + khepra_check_vulnerabilities + khepra_run_pentest
package legacy

// SecurityDomainTools returns all security operation tools beyond the base Khepra compliance tools.
// These extend KhepraTools() to create a comprehensive zero-day-resistant security platform.
func SecurityDomainTools() []Tool {
	return []Tool{

		// ═══════════════════════════════════════════════════════════════════════
		// THREAT HUNTING
		// "Find what the attacker didn't want you to find"
		// ═══════════════════════════════════════════════════════════════════════

		{
			Name: "khepra_hunt_threats",
			Description: "AI-powered threat hunt across all telemetry sources. " +
				"Correlates process behavior, network flows, file changes, and authentication events " +
				"to surface hidden adversary activity using MITRE ATT&CK TTPs. " +
				"Anchored in the DAG for tamper-evident hunt provenance. " +
				"Natural language: 'Hunt for lateral movement', 'Find ransomware precursors', 'Is APT29 in my network?'",
			InputSchema: schemaObj(props{
				"query":                strProp("Natural language threat hunt query or MITRE ATT&CK technique ID (e.g. T1059.001)"),
				"scope":                enumProp("Hunt scope", "all", "network", "endpoints", "identity", "cloud"),
				"lookback_hours":       intProp("Hours of telemetry to analyze (default: 24)", 24),
				"confidence_threshold": numProp("Minimum confidence score 0.0-1.0 to surface findings (default: 0.6)", 0.6),
			}, []string{"query"}),
		},

		{
			Name: "khepra_analyze_iocs",
			Description: "Enrich, correlate, and score Indicators of Compromise (IOCs). " +
				"Cross-references against CISA KEV, MITRE ATT&CK, NVD, and the Khepra Dark Crypto Moat. " +
				"Returns threat actor attribution, associated TTPs, and recommended response actions. " +
				"Natural language: 'Is this IP malicious?', 'What malware uses this hash?'",
			InputSchema: schemaObj(props{
				"indicators": arrProp("IOCs to analyze: IPs, domains, hashes, emails, CVEs, URLs"),
				"enrich":     boolProp("Perform full enrichment via threat intel feeds (default: true)", true),
				"correlate":  boolProp("Correlate across your own telemetry for local hits (default: true)", true),
			}, []string{"indicators"}),
		},

		{
			Name: "khepra_search_logs",
			Description: "Natural language log search across all security telemetry. " +
				"Translates your question into optimized queries across Supabase, DAG chain, " +
				"process events, network flows, and auth logs. Returns ranked results with context. " +
				"Natural language: 'What happened at 3am last night?', 'Show me all admin logins from outside the US'",
			InputSchema: schemaObj(props{
				"query":       strProp("Natural language question about your logs and security events"),
				"sources":     arrProp("Log sources to search: process, network, auth, file, siem, dag, all (default: all)"),
				"time_from":   strProp("ISO8601 start time (default: 24h ago)"),
				"time_to":     strProp("ISO8601 end time (default: now)"),
				"max_results": intProp("Maximum results to return (default: 100)", 100),
			}, []string{"query"}),
		},

		{
			Name: "khepra_correlate_events",
			Description: "Timeline correlation engine — reconstructs attack sequences from disparate events. " +
				"Uses SouHimBou AI to identify causal chains, dwell time, and blast radius. " +
				"Output is a NIST 800-61 compatible incident timeline with PQC attestation. " +
				"Natural language: 'Reconstruct what the attacker did', 'Show me the attack chain'",
			InputSchema: schemaObj(props{
				"entity_ids":  arrProp("Entity IDs (IPs, hostnames, user IDs) to correlate around"),
				"time_window": strProp("ISO8601 time range (e.g. '2026-02-27T00:00:00Z/2026-02-27T06:00:00Z')"),
				"include_dag": boolProp("Include DAG audit chain in correlation (default: true)", true),
			}, []string{"entity_ids"}),
		},

		// ═══════════════════════════════════════════════════════════════════════
		// PENETRATION TESTING
		// "Attack yourself before the adversary does"
		// ═══════════════════════════════════════════════════════════════════════

		{
			Name: "khepra_run_pentest",
			Description: "Automated penetration test using the Sonar + Arsenal toolkit. " +
				"Performs reconnaissance, service enumeration, vulnerability assessment, and exploitation simulation. " +
				"CRITICAL: Requires explicit scope authorization. All activity logged to DAG chain. " +
				"Natural language: 'Pentest our dev environment', 'Check if we're vulnerable to Log4Shell'",
			InputSchema: schemaObj(props{
				"target":      strProp("Target IP, CIDR, hostname, or cloud resource (MUST be authorized scope)"),
				"scope_token": strProp("Authorization token confirming scope (required for safety)"),
				"intensity":   enumProp("Test intensity", "recon", "standard", "full"),
				"techniques":  arrProp("Specific MITRE ATT&CK techniques to simulate (e.g. ['T1190', 'T1595'])"),
				"exclude":     arrProp("IPs/ranges to exclude from testing"),
			}, []string{"target", "scope_token"}),
		},

		{
			Name: "khepra_enumerate_services",
			Description: "Deep service/version fingerprinting of discovered endpoints. " +
				"Identifies running services, OS, software versions, and configuration weaknesses. " +
				"Maps findings to known CVEs via the ERT vulnerability database. " +
				"Natural language: 'What services are exposed on our servers?', 'Find outdated software'",
			InputSchema: schemaObj(props{
				"targets":  arrProp("IPs or hostnames to enumerate"),
				"ports":    strProp("Port range (e.g. '1-65535', 'top-1000', 'web') - default: top-1000"),
				"depth":    enumProp("Enumeration depth", "fast", "standard", "thorough"),
				"map_cves": boolProp("Map discovered services to CVEs (default: true)", true),
			}, []string{"targets"}),
		},

		{
			Name: "khepra_check_vulnerabilities",
			Description: "CVE/vulnerability assessment against your asset inventory. " +
				"Correlates discovered services with CISA KEV, NVD, and zero-day intelligence. " +
				"Prioritizes by EPSS score and active exploitation status. " +
				"Natural language: 'Are we vulnerable to anything critical?', 'What CVEs affect us?'",
			InputSchema: schemaObj(props{
				"scope":          enumProp("Assessment scope", "all", "critical_assets", "internet_facing", "specific"),
				"asset_ids":      arrProp("Specific asset IDs (when scope=specific)"),
				"min_severity":   enumProp("Minimum severity filter", "CRITICAL", "HIGH", "MEDIUM", "LOW"),
				"epss_threshold": numProp("Minimum EPSS exploit probability (0.0-1.0, default: 0.1)", 0.1),
			}, []string{"scope"}),
		},

		// ═══════════════════════════════════════════════════════════════════════
		// INCIDENT RESPONSE (pkg/ir)
		// "When it happens — and it will — respond in seconds not hours"
		// ═══════════════════════════════════════════════════════════════════════

		{
			Name: "khepra_declare_incident",
			Description: "Open a NIST 800-61 compliant security incident. Automatically: " +
				"(1) Creates incident record with timeline, (2) Starts forensic evidence collection, " +
				"(3) Notifies team, (4) Anchors incident declaration in DAG chain with PQC signature. " +
				"Natural language: 'We have an incident', 'Someone is in our network', 'Ransomware detected'",
			InputSchema: schemaObj(props{
				"description":  strProp("What happened — describe in natural language"),
				"severity":     enumProp("Incident severity", "CRITICAL", "HIGH", "MEDIUM", "LOW"),
				"iocs":         arrProp("Known IOCs: IPs, hashes, domains, file paths (optional — AI will find more)"),
				"auto_contain": boolProp("Automatically initiate containment (default: false — requires explicit approval)", false),
			}, []string{"description", "severity"}),
		},

		{
			Name: "khepra_collect_forensics",
			Description: "Imhotep's Eye — comprehensive digital forensics collection. " +
				"Captures process list, network connections, file changes, memory artifacts, " +
				"auth events, and registry state. Evidence hashed with SHA-256 + Dilithium-3 signature. " +
				"Chain of custody maintained in DAG. Admissible-grade evidence package. " +
				"Natural language: 'Collect evidence from the compromised server', 'Preserve the attack artifacts'",
			InputSchema: schemaObj(props{
				"target_id":   strProp("Endpoint or asset ID to collect forensics from"),
				"incident_id": strProp("Associated incident ID for evidence chain-of-custody"),
				"collections": arrProp("Evidence types: process, network, files, memory, auth, registry, all"),
				"preserve":    boolProp("Create immutable evidence package (cannot be modified after creation)", true),
			}, []string{"target_id"}),
		},

		{
			Name: "khepra_contain_threat",
			Description: "Execute threat containment actions. Options: network isolation, " +
				"account disable, process termination, firewall block, or full quarantine. " +
				"Every containment action logged to DAG for audit trail. Reversible within 24 hours. " +
				"Natural language: 'Isolate the compromised server', 'Block this IP immediately', 'Disable this account'",
			InputSchema: schemaObj(props{
				"target_id":     strProp("Asset, IP, user account, or process to contain"),
				"action":        enumProp("Containment action", "isolate_network", "disable_account", "kill_process", "block_ip", "quarantine_file"),
				"incident_id":   strProp("Associated incident ID"),
				"justification": strProp("Reason for containment (required for audit trail)"),
			}, []string{"target_id", "action", "justification"}),
		},

		{
			Name: "khepra_eradicate_threat",
			Description: "Execute threat eradication after containment is confirmed. " +
				"Removes malware artifacts, malicious persistence mechanisms, backdoor accounts, " +
				"and C2 infrastructure references. Generates remediation evidence package. " +
				"Natural language: 'Clean up the malware', 'Remove the backdoor', 'Purge the attacker's foothold'",
			InputSchema: schemaObj(props{
				"incident_id":  strProp("Incident ID for eradication scope"),
				"targets":      arrProp("Specific artifacts to eradicate (files, registry keys, accounts, services)"),
				"verify_clean": boolProp("Run verification scan after eradication (default: true)", true),
			}, []string{"incident_id"}),
		},

		{
			Name: "khepra_post_incident_report",
			Description: "Generate a NIST 800-61 compliant post-incident report with: " +
				"executive summary, technical timeline, root cause analysis, lessons learned, " +
				"remediation status, and DAG-anchored evidence citations. " +
				"Report is signed with Dilithium-3 — suitable for regulatory submission. " +
				"Natural language: 'Write the incident report', 'Create a post-mortem'",
			InputSchema: schemaObj(props{
				"incident_id": strProp("Incident ID to generate report for"),
				"format":      enumProp("Report format", "json", "pdf", "markdown", "eMASS"),
				"audience":    enumProp("Target audience (affects detail level)", "technical", "management", "regulatory", "c3pao"),
			}, []string{"incident_id"}),
		},

		// ═══════════════════════════════════════════════════════════════════════
		// IDS / IPS — Intrusion Detection & Prevention
		// "See everything, stop everything"
		// ═══════════════════════════════════════════════════════════════════════

		{
			Name: "khepra_get_ids_alerts",
			Description: "Retrieve active IDS/IPS alerts with AI triage. " +
				"SouHimBou ML scores each alert for false-positive probability and attack confidence. " +
				"Alerts correlated against threat intel for context. " +
				"Natural language: 'Show me active threats', 'What alerted in the last hour?', 'Any critical alerts?'",
			InputSchema: schemaObj(props{
				"severity_min":  enumProp("Minimum alert severity", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
				"status":        enumProp("Alert status filter", "active", "investigating", "resolved", "all"),
				"lookback_mins": intProp("Minutes of alerts to retrieve (default: 60)", 60),
				"ml_score_min":  numProp("Minimum SouHimBou anomaly score (0.0-1.0, default: 0.0)", 0.0),
			}, []string{}),
		},

		{
			Name: "khepra_create_ips_rule",
			Description: "Create an IPS/firewall blocking rule. Supports IP block, geo-block, " +
				"rate-limit, protocol block, and behavioral pattern matching. " +
				"Rules deployed to pkg/arsenal firewall engine + Cloudflare WAF if configured. " +
				"Natural language: 'Block Russia and China', 'Rate-limit port 22', 'Block this attack pattern'",
			InputSchema: schemaObj(props{
				"rule_type": enumProp("Rule type", "block_ip", "block_cidr", "block_country", "rate_limit", "block_pattern", "block_protocol"),
				"value":     strProp("Value to match: IP, CIDR, country code (ISO 3166), regex pattern, or protocol"),
				"direction": enumProp("Traffic direction", "inbound", "outbound", "both"),
				"duration":  strProp("Rule duration: 'permanent', '1h', '24h', '7d' (default: permanent)"),
				"reason":    strProp("Reason for the rule — logged to DAG audit chain"),
			}, []string{"rule_type", "value", "reason"}),
		},

		{
			Name: "khepra_analyze_traffic",
			Description: "Behavioral traffic baseline analysis. Identifies anomalous patterns: " +
				"data exfiltration, C2 beaconing, port scans, unusual geolocations, protocol abuse. " +
				"Powered by SouHimBou ML against your established baseline. " +
				"Natural language: 'Is there unusual traffic?', 'Are we being exfiltrated?', 'Find beaconing'",
			InputSchema: schemaObj(props{
				"lookback_hours": intProp("Hours of traffic to analyze (default: 1)", 1),
				"sensitivity":    enumProp("Anomaly detection sensitivity", "low", "medium", "high", "paranoid"),
				"focus":          enumProp("Analysis focus area", "all", "exfiltration", "c2", "scanning", "lateral"),
			}, []string{}),
		},

		// ═══════════════════════════════════════════════════════════════════════
		// SIEM / SOAR — Security Information, Event Management & Orchestration
		// "Detect. Decide. Act. Automatically."
		// ═══════════════════════════════════════════════════════════════════════

		{
			Name: "khepra_get_security_timeline",
			Description: "Cross-source security event timeline. Reconstructs what happened, " +
				"when it happened, and in what order — across all telemetry sources. " +
				"Supabase-backed for persistence. DAG-anchored for integrity. " +
				"Natural language: 'Timeline of the breach', 'Show me everything from last night'",
			InputSchema: schemaObj(props{
				"entity_id": strProp("Focus entity: hostname, IP, user ID, incident ID (optional — returns global timeline)"),
				"time_from": strProp("ISO8601 start time (default: 24h ago)"),
				"time_to":   strProp("ISO8601 end time (default: now)"),
				"sources":   arrProp("Sources to include: auth, network, process, file, dag, compliance, anomaly"),
				"limit":     intProp("Max events (default: 500)", 500),
			}, []string{}),
		},

		{
			Name: "khepra_run_playbook",
			Description: "Execute a SOAR playbook — automated response sequence. " +
				"Built-in playbooks: ransomware_response, data_breach, account_takeover, " +
				"ddos_mitigation, insider_threat, zero_day_response, compliance_violation. " +
				"Custom playbooks defined in YAML. All actions logged to DAG. " +
				"Natural language: 'Run the ransomware playbook', 'Respond to this phishing attack'",
			InputSchema: schemaObj(props{
				"playbook_id": strProp("Playbook ID or name: ransomware_response, data_breach, account_takeover, ddos_mitigation, zero_day_response"),
				"incident_id": strProp("Incident to execute playbook against"),
				"params":      objProp("Playbook-specific parameters"),
				"dry_run":     boolProp("Simulate playbook without executing actions (default: false)", false),
			}, []string{"playbook_id", "incident_id"}),
		},

		{
			Name: "khepra_create_alert_rule",
			Description: "Create a detection rule. Supports: threshold, pattern match, " +
				"ML-based anomaly, compliance violation, and composite (multi-signal) rules. " +
				"Rules tested against historical data before activation. " +
				"Natural language: 'Alert me when anyone logs in from a new country', 'Detect impossible travel'",
			InputSchema: schemaObj(props{
				"name":        strProp("Rule name"),
				"description": strProp("What this rule detects (natural language OK — AI will formalize it)"),
				"rule_type":   enumProp("Detection method", "threshold", "pattern", "ml_anomaly", "compliance", "composite"),
				"severity":    enumProp("Alert severity when triggered", "CRITICAL", "HIGH", "MEDIUM", "LOW"),
				"actions":     arrProp("Auto-actions on trigger: notify_email, notify_slack, create_ticket, run_playbook, block_ip"),
			}, []string{"name", "description", "rule_type", "severity"}),
		},

		{
			Name: "khepra_notify_team",
			Description: "Send security alert notification to team channels. " +
				"Supports: email, Slack, PagerDuty, webhook. Message includes " +
				"AI-generated summary, recommended actions, and DAG node ID for evidence tracing. " +
				"Natural language: 'Alert the team about this incident', 'Page the on-call engineer'",
			InputSchema: schemaObj(props{
				"message":     strProp("Notification message (natural language — AI will format for each channel)"),
				"channels":    arrProp("Channels: email, slack, pagerduty, webhook, sms"),
				"severity":    enumProp("Alert urgency", "CRITICAL", "HIGH", "MEDIUM", "LOW"),
				"incident_id": strProp("Associated incident ID (attaches evidence link)"),
				"recipients":  arrProp("Specific recipients (optional — defaults to on-call rotation)"),
			}, []string{"message", "severity"}),
		},

		// ═══════════════════════════════════════════════════════════════════════
		// AI-ENABLED POLYMORPHIC FIREWALL
		// "A firewall that learns, adapts, and never needs updating"
		// ═══════════════════════════════════════════════════════════════════════

		{
			Name: "khepra_update_firewall_rule",
			Description: "Dynamic firewall rule management via the Khepra Polymorphic API Engine. " +
				"Rules automatically rotate signatures to evade fingerprinting. " +
				"Supports Cloudflare WAF integration for edge-level enforcement. " +
				"Natural language: 'Open port 443 for our new app', 'Close all unused ports', 'Block brute force'",
			InputSchema: schemaObj(props{
				"action":      enumProp("Rule action", "allow", "block", "rate_limit", "challenge", "log_only"),
				"target":      strProp("Target: IP, CIDR, port, protocol, country, or URL pattern"),
				"direction":   enumProp("Traffic direction", "inbound", "outbound", "both"),
				"priority":    intProp("Rule priority (lower = higher priority, default: 100)", 100),
				"polymorphic": boolProp("Enable signature rotation to evade firewall fingerprinting (default: true)", true),
				"deploy_edge": boolProp("Also deploy to Cloudflare WAF (default: true if configured)", true),
			}, []string{"action", "target"}),
		},

		{
			Name: "khepra_block_threat_actor",
			Description: "Automated threat actor blocking. Takes an IOC, identifies the threat actor " +
				"group, and blocks ALL known infrastructure associated with that actor. " +
				"Uses threat intel feeds + behavioral analysis. PQC-signed block list shared " +
				"across your org's endpoints in real-time via Supabase Realtime. " +
				"Natural language: 'Block APT29', 'Block the group attacking us', 'Block all Conti infrastructure'",
			InputSchema: schemaObj(props{
				"ioc":        strProp("Starting IOC: IP, domain, hash, threat actor name, or campaign name"),
				"confidence": numProp("Minimum attribution confidence to act on (0.0-1.0, default: 0.7)", 0.7),
				"scope":      enumProp("Block scope", "this_ioc_only", "actor_infrastructure", "full_campaign"),
				"duration":   strProp("Block duration: permanent, '1h', '24h', '7d' (default: '24h')"),
			}, []string{"ioc"}),
		},

		{
			Name: "khepra_get_traffic_analysis",
			Description: "Real-time traffic behavioral baseline and anomaly report. " +
				"Shows: top talkers, unusual ports, geo distribution, protocol breakdown, " +
				"TLS inspection summary, DNS query anomalies, and SouHimBou risk scores. " +
				"Natural language: 'Traffic report', 'Who is talking to what?', 'Anomalies in last hour?'",
			InputSchema: schemaObj(props{
				"window_mins": intProp("Analysis window in minutes (default: 60)", 60),
				"include_ml":  boolProp("Include SouHimBou ML risk scoring (default: true)", true),
				"top_n":       intProp("Number of top talkers to include (default: 20)", 20),
			}, []string{}),
		},

		// ═══════════════════════════════════════════════════════════════════════
		// DISASTER RECOVERY / BUSINESS CONTINUITY (pkg/drbc)
		// "When everything breaks — recover in minutes"
		// ═══════════════════════════════════════════════════════════════════════

		{
			Name: "khepra_create_backup",
			Description: "Create an encrypted, PQC-sealed system backup using the Genesis engine. " +
				"Backup is AES-256 encrypted with HMAC-SHA512 integrity. " +
				"Stored with Dilithium-3 attestation for tamper detection. " +
				"Natural language: 'Backup everything before the maintenance window', 'Save current state'",
			InputSchema: schemaObj(props{
				"scope":       enumProp("Backup scope", "full", "config_only", "data_only", "critical"),
				"label":       strProp("Backup label/description (optional)"),
				"offsite":     boolProp("Replicate to offsite storage (Supabase Storage)", true),
				"encrypt_key": strProp("Encryption key identifier from KMS (optional — uses master seed if omitted)"),
			}, []string{"scope"}),
		},

		{
			Name: "khepra_test_recovery",
			Description: "Validate disaster recovery procedures without impacting production. " +
				"Tests: backup integrity, restore time, data consistency, and failover procedures. " +
				"Generates RTO/RPO compliance report with DAG attestation. " +
				"Natural language: 'Test our DR plan', 'Can we actually recover from a ransomware attack?'",
			InputSchema: schemaObj(props{
				"backup_id":   strProp("Backup to test recovery from (omit for latest)"),
				"test_type":   enumProp("Recovery test type", "integrity_check", "restore_simulation", "failover_test", "full_dr_drill"),
				"environment": enumProp("Test environment", "isolated_sandbox", "staging", "production_readonly"),
			}, []string{"test_type"}),
		},

		{
			Name: "khepra_get_rto_rpo",
			Description: "Calculate and report current RTO (Recovery Time Objective) and RPO (Recovery Point Objective). " +
				"Assesses backup age, restore speed from last test, dependencies, and SPOF risk. " +
				"CMMC/NIST 800-171 SR.L2-3.14.7 compliant report. " +
				"Natural language: 'What's our recovery time?', 'How much data would we lose in an attack?'",
			InputSchema: schemaObj(props{
				"system_id": strProp("Specific system/service to assess (optional — reports all if omitted)"),
				"format":    enumProp("Output format", "summary", "detailed", "executive"),
			}, []string{}),
		},

		{
			Name: "khepra_initiate_failover",
			Description: "Execute failover to backup infrastructure. " +
				"Follows pre-defined DR runbook: validates backup, fails over services, " +
				"updates DNS, notifies team, and documents in DAG chain. " +
				"CRITICAL: Irreversible in short term — requires explicit confirmation token. " +
				"Natural language: 'Switch to backup systems', 'Initiate DR failover'",
			InputSchema: schemaObj(props{
				"service_id":    strProp("Service or system to fail over"),
				"confirm_token": strProp("Explicit confirmation token (prevents accidental execution)"),
				"runbook_id":    strProp("DR runbook to execute (optional — uses default runbook if omitted)"),
			}, []string{"service_id", "confirm_token"}),
		},

		// ═══════════════════════════════════════════════════════════════════════
		// DATA ANALYTICS, VISUALIZATION & REPORTING
		// "Know your posture, tell your story, prove your readiness"
		// ═══════════════════════════════════════════════════════════════════════

		{
			Name: "khepra_get_risk_dashboard",
			Description: "Real-time executive risk dashboard. Returns: overall risk score, " +
				"threat level, active incidents, compliance gaps, asset vulnerabilities, " +
				"trend analysis (7/30/90 days), and top remediation priorities. " +
				"Natural language: 'What's our security posture?', 'How are we doing?', 'Risk summary'",
			InputSchema: schemaObj(props{
				"org_id":  strProp("Organization ID (optional for single-org deployments)"),
				"period":  enumProp("Trend analysis period", "7d", "30d", "90d", "1y"),
				"include": arrProp("Include sections: risk_score, threats, compliance, vulnerabilities, trends, recommendations"),
			}, []string{}),
		},

		{
			Name: "khepra_generate_report",
			Description: "Generate automated security report. Types: executive brief, " +
				"technical deep-dive, compliance status, incident summary, vulnerability assessment, " +
				"threat hunt results, or monthly security review. " +
				"PQC-signed PDF/JSON output suitable for board presentation or regulatory submission. " +
				"Natural language: 'Generate monthly security report', 'Create board presentation'",
			InputSchema: schemaObj(props{
				"report_type": enumProp("Report type", "executive_brief", "technical", "compliance", "incident", "vulnerability", "threat_hunt", "monthly_review"),
				"period_from": strProp("Report period start (ISO8601, default: 30 days ago)"),
				"period_to":   strProp("Report period end (ISO8601, default: now)"),
				"format":      enumProp("Output format", "pdf", "json", "markdown", "html", "eMASS"),
				"include_dag": boolProp("Include DAG proof chain (default: true for compliance reports)", true),
			}, []string{"report_type"}),
		},

		{
			Name: "khepra_export_executive_brief",
			Description: "Generate a C-suite security brief: one-page summary of security posture, " +
				"top 3 risks, compliance status, incident count, and recommended board actions. " +
				"Designed for non-technical audience. No jargon. Actionable. " +
				"Natural language: 'Create the board security slide', 'What do I tell the CEO?'",
			InputSchema: schemaObj(props{
				"org_id":  strProp("Organization ID"),
				"context": strProp("Additional context for the AI writer (e.g. 'upcoming CMMC assessment in 30 days')"),
				"format":  enumProp("Output format", "json", "pdf", "markdown"),
			}, []string{}),
		},

		{
			Name: "khepra_calculate_risk_score",
			Description: "Quantitative cyber risk score using FAIR methodology. " +
				"Combines: threat frequency, vulnerability severity, asset value, " +
				"control effectiveness, and compliance gaps. " +
				"Returns: risk in dollars ($), probability distribution, and top risk drivers. " +
				"Natural language: 'What's our financial exposure?', 'Quantify our risk'",
			InputSchema: schemaObj(props{
				"org_id":       strProp("Organization ID"),
				"asset_class":  enumProp("Asset class to assess", "all", "critical_data", "infrastructure", "identity", "applications"),
				"threat_model": enumProp("Threat model", "generic_adversary", "nation_state", "ransomware", "insider", "supply_chain"),
			}, []string{}),
		},
	}
}

// AllKhepraTools returns ALL Khepra tools: compliance + security operations.
// This is the complete tool set exposed by the Khepra MCP server.
func AllKhepraTools() []Tool {
	return append(KhepraTools(), SecurityDomainTools()...)
}

// ─── Schema helper functions ──────────────────────────────────────────────────

type props = map[string]interface{}

func schemaObj(properties props, required []string) map[string]interface{} {
	return map[string]interface{}{
		"type":       "object",
		"properties": properties,
		"required":   required,
	}
}

func strProp(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "description": desc}
}

func intProp(desc string, defaultVal int) map[string]interface{} {
	return map[string]interface{}{"type": "integer", "description": desc, "default": defaultVal}
}

func numProp(desc string, defaultVal float64) map[string]interface{} {
	return map[string]interface{}{"type": "number", "description": desc, "default": defaultVal}
}

func boolProp(desc string, defaultVal bool) map[string]interface{} {
	return map[string]interface{}{"type": "boolean", "description": desc, "default": defaultVal}
}

func arrProp(desc string) map[string]interface{} {
	return map[string]interface{}{
		"type":        "array",
		"items":       map[string]interface{}{"type": "string"},
		"description": desc,
	}
}

func objProp(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "object", "description": desc}
}

func enumProp(desc string, values ...string) map[string]interface{} {
	return map[string]interface{}{
		"type":        "string",
		"description": desc,
		"enum":        values,
	}
}
