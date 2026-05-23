/**
 * Core STIG Registry - Simplified for better performance
 */

import { supabase } from '@/integrations/supabase/client';
import type { STIGTrustedConfiguration, AIVerificationResult } from '@/types/stig-codex-trl10';

export class STIGRegistry {
  static async searchConfigurations(criteria: any) {
    const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
      body: {
        action: 'search_configurations',
        criteria
      }
    });

    if (error) throw error;
    return data;
  }

  static async getTrustedConfigurations(
    stigId: string, 
    platform: string
  ): Promise<STIGTrustedConfiguration[]> {
    const { data, error } = await supabase
      .from('stig_trusted_registry')
      .select('*')
      .eq('stig_id', stigId)
      .eq('platform', platform)
      .eq('validation_status', 'verified');

    if (error) throw error;
    return data;
  }

  static async verifyConfigurationWithAI(
    configId: string, 
    environment: any
  ): Promise<AIVerificationResult> {
    const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
      body: {
        action: 'verify_with_ai',
        configuration_id: configId,
        environment
      }
    });

    if (error) throw error;
    return data.verification;
  }

  static async addTrustedConfiguration(
    organizationId: string, 
    config: any
  ): Promise<STIGTrustedConfiguration> {
    const { data, error } = await supabase
      .from('stig_trusted_registry')
      .insert({
        organization_id: organizationId,
        ...config
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }
}