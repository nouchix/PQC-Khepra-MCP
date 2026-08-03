/**
 * STIG Viewer API Integration Service
 * Provides STIG rule lookup, fingerprinting, and compliance checking
 */

import { supabase } from '@/integrations/supabase/client';
import { isSaasMode } from '@/lib/supabase';

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

  private static cachedStigs: any[] | null = null;

  /**
   * Helper to map platform names to STIGViewer slugs
   */
  private static getSlugForPlatform(platform: string): string {
    const p = platform.toLowerCase();
    if (p.includes('windows server 2022')) return 'microsoft_windows_server_2022';
    if (p.includes('windows server 2019')) return 'microsoft_windows_server_2019';
    if (p.includes('ubuntu 22.04')) return 'canonical_ubuntu_22.04_lts';
    if (p.includes('oracle linux 8')) return 'oracle_linux_8';
    if (p.includes('red hat enterprise linux 9') || p.includes('rhel 9')) return 'red_hat_enterprise_linux_9';
    if (p.includes('red hat enterprise linux 10') || p.includes('rhel 10')) return 'red_hat_enterprise_linux_10';
    return platform.toLowerCase().replace(/\s+/g, '_');
  }

  /**
   * Dynamically fetch and resolve the slug for a given platform name by crawling the catalog.
   */
  private static async resolveSlugDynamically(platform: string, headers: Record<string, string>): Promise<string> {
    try {
      if (!this.cachedStigs) {
        const response = await fetch('/api/v1/stig/viewer/stigs', {
          method: 'GET',
          headers,
        });
        if (response.ok) {
          const res = await response.json();
          this.cachedStigs = res.stigs || res || [];
        }
      }

      if (this.cachedStigs && this.cachedStigs.length > 0) {
        const platformLower = platform.toLowerCase();
        
        // Try exact match or containment match
        let bestMatch = this.cachedStigs.find((s: any) => {
          const id = (s.stigId || s.benchmarkId || '').toLowerCase();
          const title = (s.title || '').toLowerCase();
          return id === platformLower || title.includes(platformLower) || platformLower.includes(title);
        });

        // Try fuzzy word overlap match if no exact containment
        if (!bestMatch) {
          const platformWords = platformLower.split(/[\s_-]+/);
          bestMatch = this.cachedStigs.find((s: any) => {
            const title = (s.title || '').toLowerCase();
            const id = (s.stigId || s.benchmarkId || '').toLowerCase();
            return platformWords.every(word => title.includes(word) || id.includes(word));
          });
        }

        if (bestMatch) {
          return bestMatch.stigId || bestMatch.benchmarkId;
        }
      }
    } catch (e) {
      console.warn('Dynamic STIG catalog crawl failed, using fallback parser:', e);
    }

    return this.getSlugForPlatform(platform);
  }

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
   * Lookup specific STIG rule by ID via local gateway (sovereign) or cloud relay (SaaS)
   */
  static async lookupSTIGRule(stigId: string, _platform: string, organizationId?: string): Promise<STIGRule> {
    try {
      // 1. Sovereign Mode: Bypass Supabase and query the local Go Gateway directly
      if (!isSaasMode()) {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };
        const token = localStorage.getItem('asaf_license_key');
        if (token) {
          headers['Authorization'] = token;
        }

        // Dynamically resolve slug using catalog crawl
        const slug = await this.resolveSlugDynamically(_platform, headers);

        // Query the local proxy route that directs to STIG Viewer API
        const response = await fetch(`/api/v1/stig/viewer/stigs/${slug}/controls?limit=100&search=${stigId}`, {
          method: 'GET',
          headers,
        });

        if (!response.ok) {
          throw new Error(`Local gateway returned HTTP ${response.status}`);
        }

        const res = await response.json();
        // Match the requested rule ID or group ID
        const ruleData = res.findings?.find((f: any) => f.ruleId === stigId || f.groupId === stigId) || res.findings?.[0];
        
        if (!ruleData) {
          throw new Error(`STIG rule ${stigId} not found in local catalog`);
        }

        return {
          id: ruleData.ruleId,
          stigId: ruleData.groupId || stigId,
          title: ruleData.title || ruleData.ruleTitle,
          description: ruleData.description || ruleData.vulnDiscussion,
          checkText: ruleData.checkContent || 'Refer to documentation',
          fixText: ruleData.fixText || 'See official STIG guide',
          severity: (ruleData.severity?.toLowerCase()?.replaceAll('_', '') ?? 'cat2') as STIGRule['severity'],
          vulnId: ruleData.ruleId || 'N/A',
          ruleId: ruleData.ruleId,
          version: ruleData.ruleVersion || '1.0',
          platform: _platform,
        };
      }

      // 2. SaaS/Cloud Mode Fallback: Use Supabase stig-relay function
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