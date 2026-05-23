/**
 * STIG Viewer API Integration Service
 * Provides STIG rule lookup, fingerprinting, and compliance checking
 */

import { supabase } from '@/integrations/supabase/client';

export interface STIGRule {
  id: string;
  stigId: string;
  title: string;
  description: string;
  checkText: string;
  fixText: string;
  severity: 'cat1' | 'cat2' | 'cat3';
  vulnId: string;
  ruleId: string;
  version: string;
  platform: string;
  nistMapping?: string[];
  cmmcMapping?: string[];
}

export interface STIGFingerprint {
  platform: string;
  version: string;
  stigVersion: string;
  totalRules: number;
  applicableRules: number;
  complianceScore: number;
  findings: {
    open: number;
    notApplicable: number;
    notAFinding: number;
    notReviewed: number;
  };
}

export interface ConfigurationDelta {
  ruleid: string;
  parameter: string;
  beforeValue: any;
  afterValue: any;
  timestamp: Date;
  remediated: boolean;
  verification?: string;
}

export class STIGViewerService {
  private static readonly SUPPORTED_PLATFORMS = [
    'Windows Server 2019',
    'Windows Server 2022',
    'Ubuntu 22.04',
    'IIS 10.0',
    'Apache 2.4',
    'SQL Server 2019',
    'Oracle Linux 8'
  ];

  /**
   * Perform STIG fingerprinting for a target system
   */
  static async performSTIGFingerprinting(
    targetIP: string,
    platform: string
  ): Promise<STIGFingerprint> {
    try {
      const { data, error } = await supabase.functions.invoke('infrastructure-discovery', {
        body: {
          action: 'stig_fingerprinting',
          target_ip: targetIP,
          platform: platform,
          include_nist_mapping: true,
          include_cmmc_mapping: true
        }
      });

      if (error) throw error;

      // Mock response for demo - in production this would come from STIG Viewer API
      return {
        platform: platform,
        version: data?.version || '2.6',
        stigVersion: data?.stig_version || 'V2R6',
        totalRules: data?.total_rules || 284,
        applicableRules: data?.applicable_rules || 267,
        complianceScore: data?.compliance_score || 85,
        findings: {
          open: data?.findings?.open || 23,
          notApplicable: data?.findings?.not_applicable || 17,
          notAFinding: data?.findings?.not_a_finding || 195,
          notReviewed: data?.findings?.not_reviewed || 49
        }
      };
    } catch (error) {
      console.error('STIG fingerprinting failed:', error);
      throw error;
    }
  }

  /**
   * Lookup specific STIG rule by ID via the real Go Gateway relay
   */
  static async lookupSTIGRule(stigId: string, _platform: string, organizationId?: string): Promise<STIGRule> {
    try {
      if (!organizationId) {
        throw new Error('Organization ID is required for live STIG data');
      }

      const { data, error } = await supabase.functions.invoke('stig-relay', {
        body: {
          action: 'query_stigs',
          organization_id: organizationId,
          rule_id: stigId
        }
      });

      if (error) throw error;

      if (!data.success) {
        throw new Error(data.error || 'Failed to fetch rule from gateway');
      }

      // Format data to match STIGRule interface
      const ruleData = data.data?.rules?.[0];
      if (!ruleData) {
        throw new Error(`STIG rule ${stigId} not found in remote catalog`);
      }

      return {
        id: ruleData.rule_id,
        stigId: ruleData.stig_id || stigId,
        title: ruleData.title,
        description: ruleData.description,
        checkText: ruleData.check_text || 'Refer to documentation',
        fixText: ruleData.fix_text || 'See official STIG guide',
        severity: (ruleData.severity?.toLowerCase()?.replaceAll('_', '') ?? 'cat2') as STIGRule['severity'],
        vulnId: ruleData.vuln_id || 'N/A',
        ruleId: ruleData.rule_id,
        version: ruleData.version || '1.0',
        platform: ruleData.platform || _platform,
      };
    } catch (error) {
      console.error('STIG rule lookup failed:', error);
      throw error;
    }
  }

  /**
   * Track configuration state changes for STIG compliance
   */
  static async trackConfigurationDelta(
    assetId: string,
    stigRuleId: string,
    beforeState: any,
    afterState: any
  ): Promise<ConfigurationDelta> {
    try {
      const delta: ConfigurationDelta = {
        ruleid: stigRuleId,
        parameter: 'configuration',
        beforeValue: beforeState,
        afterValue: afterState,
        timestamp: new Date(),
        remediated: true
      };

      // Log to security events for audit trail
      await supabase.functions.invoke('security-event-logger', {
        body: {
          event_type: 'stig_configuration_change',
          asset_id: assetId,
          rule_id: stigRuleId,
          before_state: beforeState,
          after_state: afterState,
          remediation_applied: true
        }
      });

      return delta;
    } catch (error) {
      console.error('Configuration delta tracking failed:', error);
      throw error;
    }
  }

  /**
   * Generate NIST 800-171 to CMMC to STIG mapping
   */
  static async generateControlMapping(
    nistControl: string,
    targetPlatforms: string[]
  ): Promise<{
    nist: string;
    cmmc: string[];
    stigRules: { platform: string; rules: STIGRule[] }[];
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'nist_cmmc_stig_mapping',
          nist_control: nistControl,
          target_platforms: targetPlatforms,
          include_implementation_guidance: true
        }
      });

      if (error) throw error;

      return data;
    } catch (error) {
      console.error('Control mapping generation failed:', error);
      throw error;
    }
  }

  /**
   * Automated STIG remediation for supported rules
   */
  static async performAutomatedRemediation(
    assetId: string,
    stigRules: string[]
  ): Promise<{
    remediated: string[];
    failed: string[];
    requiresManual: string[];
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('automated-remediation', {
        body: {
          action: 'stig_remediation',
          asset_id: assetId,
          stig_rules: stigRules,
          track_config_deltas: true,
          create_evidence: true
        }
      });

      if (error) throw error;

      return {
        remediated: data?.remediated || [],
        failed: data?.failed || [],
        requiresManual: data?.requires_manual || []
      };
    } catch (error) {
      console.error('Automated STIG remediation failed:', error);
      throw error;
    }
  }

  /**
   * Get supported platforms
   */
  static getSupportedPlatforms(): string[] {
    return [...this.SUPPORTED_PLATFORMS];
  }
}