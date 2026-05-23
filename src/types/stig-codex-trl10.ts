/**
 * Type definitions for STIG-Codex TRL10 system
 * Separated for better TypeScript performance
 */

// Core Configuration Types
export interface STIGConfigurationBaseline {
  id: string;
  organization_id: string;
  asset_id: string;
  stig_rule_id: string;
  configuration_hash: string;
  configuration_data: any;
  snapshot_type: 'baseline' | 'current' | 'violation' | 'remediated';
  compliance_status: 'compliant' | 'non_compliant' | 'pending' | 'exception';
  risk_score: number;
  validated_by?: string;
  captured_at: string;
  created_at: string;
}

export interface STIGDriftEvent {
  id: string;
  organization_id: string;
  asset_id: string;
  stig_rule_id: string;
  drift_type: 'configuration_change' | 'unauthorized_access' | 'policy_violation' | 'security_bypass';
  severity: 'critical' | 'high' | 'medium' | 'low';
  previous_state: any;
  current_state: any;
  detection_method: 'hash_mismatch' | 'real_time_monitoring' | 'scheduled_scan' | 'event_triggered';
  auto_remediated: boolean;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
  remediation_action?: string;
  detected_at: string;
  created_at: string;
}

export interface STIGMonitoringAgent {
  id: string;
  organization_id: string;
  agent_name: string;
  agent_type: string;
  deployment_mode: string;
  target_platforms: string[];
  supported_stigs: string[];
  operational_mode: string;
  configuration: any;
  status: string;
  last_heartbeat: string;
  performance_metrics: any;
  deployed_at?: string;
  created_at: string;
}

// Registry Types
export interface STIGTrustedConfiguration {
  id: string;
  organization_id?: string;
  stig_id: string;
  platform: string;
  configuration_name: string;
  configuration_data: any;
  cryptographic_hash: string;
  digital_signature?: string;
  trust_level: number;
  source_type: string;
  validation_status: string;
  compliance_frameworks: string[];
  usage_count: number;
  success_rate: number;
  risk_assessment: any;
  metadata: any;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface AIVerificationResult {
  id: string;
  configuration_id: string;
  verification_status: 'verified' | 'failed' | 'pending';
  confidence_score: number;
  ai_model: string;
  verification_criteria: string[];
  security_analysis: any;
  compatibility_assessment: any;
  risk_evaluation: any;
  recommendations: string[];
  verified_at: string;
}

// Threat Intelligence Types
export interface ThreatIndicator {
  id: string;
  type: 'ip_address' | 'domain' | 'file_hash' | 'url' | 'cve' | 'mitre_technique';
  value: string;
  threat_level: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence_score: number;
  source: string;
  context: any;
  first_seen: string;
  last_seen: string;
  expires_at?: string;
}

export interface STIGThreatCorrelation {
  id: string;
  organization_id: string;
  stig_rule_id: string;
  threat_source: string;
  threat_indicator: string;
  indicator_type: string;
  risk_elevation: 'critical' | 'high' | 'medium' | 'low' | 'info';
  correlation_confidence: number;
  threat_context: any;
  recommended_actions: string[];
  correlated_at: string;
  created_at: string;
}

export interface STIGRemediationAction {
  id: string;
  organization_id: string;
  violation_id: string;
  action_type: 'automated' | 'manual' | 'approval_required';
  remediation_script: string;
  execution_method: 'powershell' | 'bash' | 'ansible' | 'group_policy' | 'api_call';
  target_assets: string[];
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  actions_taken: string[];
  execution_log: any;
  rollback_available: boolean;
  rollback_script?: string;
  executed_by?: string;
  executed_at?: string;
  created_at: string;
}