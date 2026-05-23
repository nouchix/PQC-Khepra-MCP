/**
 * Core STIG Engine - Simplified for better performance
 */

import { supabase } from '@/integrations/supabase/client';
import type { 
  STIGConfigurationBaseline, 
  STIGDriftEvent, 
  STIGMonitoringAgent,
  STIGRemediationAction
} from '@/types/stig-codex-trl10';

export class STIGEngine {
  static async initializeConfigurationMonitoring(
    organizationId: string, 
    assets: string[], 
    stigRules: string[]
  ) {
    const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
      body: {
        action: 'initialize_monitoring',
        organization_id: organizationId,
        assets,
        stig_rules: stigRules
      }
    });

    if (error) throw error;
    return data;
  }

  static async captureConfigurationBaseline(
    organizationId: string,
    assetId: string,
    stigRules: string[]
  ): Promise<STIGConfigurationBaseline[]> {
    const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
      body: {
        action: 'capture_baseline',
        organization_id: organizationId,
        asset_id: assetId,
        stig_rules: stigRules
      }
    });

    if (error) throw error;
    return data.baselines;
  }

  static async detectConfigurationDrift(
    organizationId: string,
    assetId?: string
  ): Promise<STIGDriftEvent[]> {
    const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
      body: {
        action: 'detect_drift',
        organization_id: organizationId,
        asset_id: assetId
      }
    });

    if (error) throw error;
    return data.drift_events;
  }

  static async getMonitoringAgents(organizationId: string): Promise<STIGMonitoringAgent[]> {
    const { data, error } = await supabase
      .from('stig_monitoring_agents')
      .select('*')
      .eq('organization_id', organizationId);

    if (error) throw error;
    return data;
  }

  static async calculateComplianceScore(organizationId: string, scope?: any) {
    const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
      body: {
        action: 'calculate_compliance',
        organization_id: organizationId,
        scope
      }
    });

    if (error) throw error;
    return data;
  }
}