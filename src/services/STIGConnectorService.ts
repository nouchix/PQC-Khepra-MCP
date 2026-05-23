/**
 * STIG-Connector Service
 * Comprehensive asset discovery and STIG classification system
 */

import { supabase } from '@/integrations/supabase/client';

export interface DiscoveredAsset {
  id: string;
  organization_id: string;
  discovery_job_id?: string;
  asset_identifier: string;
  asset_type: string;
  platform?: string;
  operating_system?: string;
  version?: string;
  hostname?: string;
  ip_addresses?: string[];
  mac_addresses?: string[];
  discovered_services: any[];
  system_info: any;
  applicable_stigs: string[];
  stig_version_mapping: any;
  discovery_method: string;
  last_discovered: string;
  first_discovered: string;
  is_active: boolean;
  risk_score: number;
  compliance_status: any;
  metadata: any;
}

export interface DiscoveryJob {
  id: string;
  organization_id: string;
  job_name: string;
  discovery_type: string;
  target_specification: any;
  credential_ids: string[];
  discovery_config: any;
  schedule_config?: any;
  status: string;
  last_run_at?: string;
  next_run_at?: string;
  created_at: string;
  updated_at: string;
}

export interface DiscoveryCredential {
  id: string;
  organization_id: string;
  credential_name: string;
  credential_type: string;
  target_systems: any;
  metadata: any;
  created_at: string;
  is_active: boolean;
}

export interface DiscoveryExecution {
  id: string;
  discovery_job_id: string;
  organization_id: string;
  execution_status: string;
  started_at: string;
  completed_at?: string;
  assets_discovered: number;
  assets_updated: number;
  errors_count: number;
  execution_log: any;
  performance_metrics: any;
}

export interface STIGApplicabilityRule {
  id: string;
  stig_id: string;
  stig_title: string;
  stig_version: string;
  platform_patterns: any;
  version_patterns: any;
  service_requirements: any;
  exclusion_rules: any;
  priority: number;
}

export class STIGConnectorService {
  
  /**
   * Start enhanced TRL 10 asset discovery process
   */
  static async startDiscovery(
    organizationId: string, 
    discoveryConfig: {
      type: 'nmap_scan' | 'comprehensive_scan' | 'stealth_scan' | 'vulnerability_scan';
      targets: string[];
      credential_ids?: string[];
      scan_options?: {
        ports?: string;
        timing?: string;
        scripts?: string[];
        os_detection?: boolean;
        service_detection?: boolean;
        aggressive?: boolean;
        stealth?: boolean;
      };
      nmap_options?: string;
    }
  ): Promise<{ 
    job_id: string; 
    execution_id: string; 
    assets_discovered: number;
    threat_intelligence_matches: number;
    sbom_components: number;
    security_score: number;
    compliance_summary: any;
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('enhanced-asset-discovery', {
        body: {
          action: 'start_discovery',
          organization_id: organizationId,
          discovery_config: discoveryConfig
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Enhanced discovery start failed:', error);
      throw error;
    }
  }

  /**
   * Get discovery job status
   */
  static async getDiscoveryStatus(jobId: string): Promise<{
    status: string;
    assets_discovered: number;
    started_at: string;
    completed_at?: string;
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-asset-discovery', {
        body: {
          action: 'get_status',
          discovery_job_id: jobId
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Get discovery status failed:', error);
      throw error;
    }
  }

  /**
   * Stop running discovery
   */
  static async stopDiscovery(jobId: string): Promise<{ success: boolean }> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-asset-discovery', {
        body: {
          action: 'stop_discovery',
          discovery_job_id: jobId
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Stop discovery failed:', error);
      throw error;
    }
  }

  /**
   * Get discovered assets
   */
  static async getDiscoveredAssets(
    organizationId: string, 
    jobId?: string
  ): Promise<{ assets: DiscoveredAsset[]; total_count: number }> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-asset-discovery', {
        body: {
          action: 'get_results',
          organization_id: organizationId,
          discovery_job_id: jobId
        }
      });

      if (error) throw error;
      
      // Transform the data to match our interface types
      const transformedAssets = (data.assets || []).map((asset: any) => ({
        ...asset,
        ip_addresses: Array.isArray(asset.ip_addresses) ? 
          asset.ip_addresses.map((ip: any) => String(ip)) : [],
        mac_addresses: Array.isArray(asset.mac_addresses) ? 
          asset.mac_addresses.map((mac: any) => String(mac)) : [],
        discovered_services: Array.isArray(asset.discovered_services) ? 
          asset.discovered_services : [],
        applicable_stigs: Array.isArray(asset.applicable_stigs) ? 
          asset.applicable_stigs : []
      }));

      return {
        assets: transformedAssets,
        total_count: data.total_count || 0
      };
    } catch (error) {
      console.error('Get discovered assets failed:', error);
      throw error;
    }
  }

  /**
   * Create discovery job
   */
  static async createDiscoveryJob(
    organizationId: string,
    jobData: Omit<DiscoveryJob, 'id' | 'organization_id' | 'created_at' | 'updated_at'>
  ): Promise<DiscoveryJob> {
    try {
      const { data, error } = await supabase
        .from('discovery_jobs')
        .insert({
          organization_id: organizationId,
          ...jobData
        })
        .select()
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Create discovery job failed:', error);
      throw error;
    }
  }

  /**
   * Get discovery jobs
   */
  static async getDiscoveryJobs(organizationId: string): Promise<DiscoveryJob[]> {
    try {
      const { data, error } = await supabase
        .from('discovery_jobs')
        .select('*')
        .eq('organization_id', organizationId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('Get discovery jobs failed:', error);
      throw error;
    }
  }

  /**
   * Create discovery credential
   */
  static async createCredential(
    organizationId: string,
    credentialData: {
      credential_name: string;
      credential_type: 'ssh_key' | 'username_password' | 'api_token' | 'certificate';
      target_systems: string[];
      credentials: any; // Will be encrypted
      metadata?: any;
    }
  ): Promise<DiscoveryCredential> {
    try {
      // In production, credentials would be encrypted before storage
      const { data, error } = await supabase
        .from('discovery_credentials')
        .insert({
          organization_id: organizationId,
          credential_name: credentialData.credential_name,
          credential_type: credentialData.credential_type,
          target_systems: credentialData.target_systems,
          encrypted_credentials: credentialData.credentials, // Should be encrypted
          metadata: credentialData.metadata || {}
        })
        .select()
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Create credential failed:', error);
      throw error;
    }
  }

  /**
   * Get discovery credentials (sanitized)
   */
  static async getCredentials(organizationId: string): Promise<DiscoveryCredential[]> {
    try {
      const { data, error } = await supabase
        .from('discovery_credentials')
        .select('id, organization_id, credential_name, credential_type, target_systems, metadata, created_at, is_active')
        .eq('organization_id', organizationId)
        .eq('is_active', true)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('Get credentials failed:', error);
      throw error;
    }
  }

  /**
   * Get discovery executions
   */
  static async getDiscoveryExecutions(
    organizationId: string,
    jobId?: string
  ): Promise<DiscoveryExecution[]> {
    try {
      let query = supabase
        .from('discovery_executions')
        .select('*')
        .eq('organization_id', organizationId)
        .order('started_at', { ascending: false });

      if (jobId) {
        query = query.eq('discovery_job_id', jobId);
      }

      const { data, error } = await query;

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('Get discovery executions failed:', error);
      throw error;
    }
  }

  /**
   * Get STIG applicability rules
   */
  static async getSTIGApplicabilityRules(): Promise<STIGApplicabilityRule[]> {
    try {
      const { data, error } = await supabase
        .from('stig_applicability_rules')
        .select('*')
        .order('priority', { ascending: true });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('Get STIG rules failed:', error);
      throw error;
    }
  }

  /**
   * Get asset statistics
   */
  static async getAssetStatistics(organizationId: string): Promise<{
    total_assets: number;
    by_type: Record<string, number>;
    by_platform: Record<string, number>;
    risk_distribution: Record<string, number>;
    compliance_overview: {
      total_stigs: number;
      assets_scanned: number;
      compliance_percentage: number;
    };
  }> {
    try {
      const { data: assets, error } = await supabase
        .from('discovered_assets')
        .select('asset_type, platform, risk_score, applicable_stigs, compliance_status')
        .eq('organization_id', organizationId)
        .eq('is_active', true);

      if (error) throw error;

      const stats = {
        total_assets: assets?.length || 0,
        by_type: {},
        by_platform: {},
        risk_distribution: { low: 0, medium: 0, high: 0, critical: 0 },
        compliance_overview: {
          total_stigs: 0,
          assets_scanned: 0,
          compliance_percentage: 0
        }
      };

      if (assets) {
        // Calculate statistics
        for (const asset of assets) {
          // Count by type
          stats.by_type[asset.asset_type] = (stats.by_type[asset.asset_type] || 0) + 1;
          
          // Count by platform
          if (asset.platform) {
            stats.by_platform[asset.platform] = (stats.by_platform[asset.platform] || 0) + 1;
          }

          // Risk distribution
          const riskLevel = asset.risk_score >= 80 ? 'critical' :
                           asset.risk_score >= 60 ? 'high' :
                           asset.risk_score >= 40 ? 'medium' : 'low';
          stats.risk_distribution[riskLevel]++;

          // Compliance stats
          stats.compliance_overview.total_stigs += asset.applicable_stigs?.length || 0;
          
          // Safely check compliance_status
          if (asset.compliance_status && 
              typeof asset.compliance_status === 'object' && 
              asset.compliance_status !== null) {
            const complianceStatus = asset.compliance_status as any;
            if (complianceStatus.last_scan) {
              stats.compliance_overview.assets_scanned++;
            }
          }
        }

        // Calculate compliance percentage
        if (stats.compliance_overview.total_stigs > 0) {
          const totalCompliant = assets.reduce((sum, asset) => {
            if (asset.compliance_status && 
                typeof asset.compliance_status === 'object' && 
                asset.compliance_status !== null) {
              const complianceStatus = asset.compliance_status as any;
              return sum + (Number(complianceStatus.compliant) || 0);
            }
            return sum;
          }, 0);
          stats.compliance_overview.compliance_percentage = 
            Math.round((totalCompliant / stats.compliance_overview.total_stigs) * 100);
        }
      }

      return stats;
    } catch (error) {
      console.error('Get asset statistics failed:', error);
      throw error;
    }
  }

  /**
   * Delete discovered asset
   */
  static async deleteAsset(assetId: string): Promise<void> {
    try {
      const { error } = await supabase
        .from('discovered_assets')
        .delete()
        .eq('id', assetId);

      if (error) throw error;
    } catch (error) {
      console.error('Delete asset failed:', error);
      throw error;
    }
  }

  /**
   * Update asset metadata
   */
  static async updateAsset(
    assetId: string, 
    updates: Partial<Omit<DiscoveredAsset, 'id' | 'organization_id'>>
  ): Promise<DiscoveredAsset> {
    try {
      const { data, error } = await supabase
        .from('discovered_assets')
        .update(updates)
        .eq('id', assetId)
        .select()
        .single();

      if (error) throw error;
      
      // Type cast the returned data to match our interface
      return {
        ...data,
        ip_addresses: Array.isArray(data.ip_addresses) ? 
          data.ip_addresses.map(ip => String(ip)) : [],
        mac_addresses: Array.isArray(data.mac_addresses) ? 
          data.mac_addresses.map(mac => String(mac)) : [],
        discovered_services: Array.isArray(data.discovered_services) ? 
          data.discovered_services : [],
        applicable_stigs: Array.isArray(data.applicable_stigs) ? 
          data.applicable_stigs : []
      } as DiscoveredAsset;
    } catch (error) {
      console.error('Update asset failed:', error);
      throw error;
    }
  }
}