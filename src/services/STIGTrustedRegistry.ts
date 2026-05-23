/**
 * STIG Trusted Registry Service
 * Centralized repository of DISA-approved STIG configurations and AI verification
 * Implements trusted registry concept from CimTrak competitive analysis
 */

import { supabase } from '@/integrations/supabase/client';

export interface TrustedSTIGConfiguration {
  id: string;
  stig_id: string;
  rule_id: string;
  platform: string;
  platform_type: string;
  version: string;
  configuration_template: any;
  verification_script: string;
  remediation_actions: any[];
  disa_approved: boolean;
  vendor_certified: boolean;
  vendor_specific_notes?: string;
  implementation_guidance?: string;
  confidence_score: number;
  risk_assessment: {
    implementation_risk: 'low' | 'medium' | 'high';
    operational_impact: 'minimal' | 'moderate' | 'significant';
    rollback_complexity: 'simple' | 'complex' | 'critical';
  };
  ai_verified: boolean;
  trust_score: number;
  usage_statistics: {
    successful_implementations: number;
    failed_implementations: number;
    average_implementation_time_minutes: number;
  };
  validation_rules?: any[];
}

export interface STIGImplementationPattern {
  id: string;
  pattern_name: string;
  vendor: string;
  product_family: string;
  applicable_stigs: string[];
  implementation_steps: Array<{
    step_order: number;
    description: string;
    command: string;
    validation_command?: string;
    rollback_command?: string;
    estimated_time_minutes: number;
  }>;
  prerequisites: string[];
  post_implementation_validation: string[];
  known_issues: string[];
  community_verified: boolean;
}

export interface AIVerificationResult {
  id: string;
  configuration_id: string;
  verification_status: 'verified' | 'failed' | 'warning' | 'pending';
  confidence_score: number;
  verification_details: {
    security_analysis: any;
    compliance_check: any;
    impact_assessment: any;
    recommendation: string;
  };
  recommendations: string[];
  verified_at: string;
  verified_by_ai_model: string;
}

export class STIGTrustedRegistry {

  /**
   * Get DISA-approved STIG configuration templates
   */
  static async getTrustedConfigurations(
    stigId: string,
    platform: string,
    version?: string
  ): Promise<TrustedSTIGConfiguration[]> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'get_trusted_configurations',
          stig_id: stigId,
          platform: platform,
          version: version,
          filters: {
            disa_approved: true,
            ai_verified: true,
            min_trust_score: 0.8
          }
        }
      });

      if (error) throw error;
      return data.configurations || [];
    } catch (error) {
      console.error('Failed to get trusted configurations:', error);
      throw error;
    }
  }

  /**
   * Verify STIG configuration using AI analysis
   */
  static async verifyConfigurationWithAI(
    configurationId: string,
    targetEnvironment: {
      platform: string;
      version: string;
      existing_configurations: any;
      security_requirements: string[];
    }
  ): Promise<AIVerificationResult> {
    try {
      const { data, error } = await supabase.functions.invoke('ai-compliance-analyzer', {
        body: {
          action: 'verify_stig_configuration',
          configuration_id: configurationId,
          target_environment: targetEnvironment,
          verification_scope: {
            security_impact: true,
            compliance_validation: true,
            operational_impact: true,
            compatibility_check: true
          }
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('AI verification failed:', error);
      throw error;
    }
  }

  /**
   * Get vendor-specific STIG implementation patterns
   */
  static async getImplementationPatterns(
    vendor: string,
    productFamily: string,
    stigCategories?: string[]
  ): Promise<STIGImplementationPattern[]> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'get_implementation_patterns',
          vendor: vendor,
          product_family: productFamily,
          stig_categories: stigCategories || [],
          include_community_patterns: true
        }
      });

      if (error) throw error;
      return data.patterns || [];
    } catch (error) {
      console.error('Failed to get implementation patterns:', error);
      throw error;
    }
  }

  /**
   * Submit new STIG configuration for registry inclusion
   */
  static async submitConfigurationForApproval(
    organizationId: string,
    configuration: {
      stig_id: string;
      platform: string;
      configuration_data: any;
      implementation_notes: string;
      testing_results: any;
      environment_details: any;
    }
  ): Promise<{
    submission_id: string;
    status: 'submitted' | 'under_review' | 'approved' | 'rejected';
    ai_pre_verification: AIVerificationResult;
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'submit_configuration',
          organization_id: organizationId,
          configuration: configuration,
          request_ai_verification: true
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Configuration submission failed:', error);
      throw error;
    }
  }

  /**
   * Search STIG configurations by criteria
   */
  static async searchConfigurations(searchCriteria: {
    stig_ids?: string[];
    platforms?: string[];
    keywords?: string[];
    trust_score_min?: number;
    disa_approved_only?: boolean;
    recently_updated?: boolean;
  }): Promise<{
    configurations: TrustedSTIGConfiguration[];
    total_results: number;
    search_metadata: {
      search_time_ms: number;
      filters_applied: string[];
      suggestions: string[];
    };
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'search_configurations',
          search_criteria: searchCriteria,
          include_metadata: true
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Configuration search failed:', error);
      throw error;
    }
  }

  /**
   * Get STIG configuration recommendations based on environment
   */
  static async getConfigurationRecommendations(
    organizationId: string,
    environmentProfile: {
      platforms: string[];
      security_requirements: string[];
      compliance_frameworks: string[];
      risk_tolerance: 'low' | 'medium' | 'high';
      automation_preference: 'manual' | 'semi_automated' | 'fully_automated';
    }
  ): Promise<{
    recommendations: Array<{
      stig_id: string;
      priority: number;
      rationale: string;
      implementation_effort: string;
      automation_available: boolean;
      configuration: TrustedSTIGConfiguration;
    }>;
    implementation_roadmap: Array<{
      phase: number;
      stig_implementations: string[];
      estimated_duration_days: number;
      dependencies: string[];
    }>;
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('ai-compliance-analyzer', {
        body: {
          action: 'generate_stig_recommendations',
          organization_id: organizationId,
          environment_profile: environmentProfile,
          include_roadmap: true
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to get recommendations:', error);
      throw error;
    }
  }

  /**
   * Validate configuration integrity and authenticity
   */
  static async validateConfigurationIntegrity(
    configurationId: string,
    validationOptions: {
      check_digital_signature: boolean;
      verify_disa_source: boolean;
      validate_hash: boolean;
      check_version_compatibility: boolean;
    }
  ): Promise<{
    is_valid: boolean;
    validation_results: {
      signature_valid: boolean;
      source_verified: boolean;
      hash_matches: boolean;
      version_compatible: boolean;
    };
    trust_indicators: {
      disa_certified: boolean;
      community_endorsed: boolean;
      enterprise_tested: boolean;
      ai_validated: boolean;
    };
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'validate_integrity',
          configuration_id: configurationId,
          validation_options: validationOptions
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Integrity validation failed:', error);
      throw error;
    }
  }

  /**
   * Get configuration usage analytics and success rates
   */
  static async getConfigurationAnalytics(
    configurationId: string,
    timeRange: {
      start_date: string;
      end_date: string;
    }
  ): Promise<{
    usage_stats: {
      total_implementations: number;
      successful_implementations: number;
      failed_implementations: number;
      success_rate: number;
    };
    performance_metrics: {
      average_implementation_time_minutes: number;
      median_implementation_time_minutes: number;
      fastest_implementation_minutes: number;
      slowest_implementation_minutes: number;
    };
    feedback_summary: {
      average_rating: number;
      total_reviews: number;
      common_issues: string[];
      improvement_suggestions: string[];
    };
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'get_configuration_analytics',
          configuration_id: configurationId,
          time_range: timeRange
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Failed to get configuration analytics:', error);
      throw error;
    }
  }
}