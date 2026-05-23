/**
 * STIG Intelligence Engine
 * Threat intelligence integration and zero-day correlation for STIG rules
 * Advanced AI-powered STIG analysis and adaptation system
 */

import { supabase } from '@/integrations/supabase/client';

export interface STIGThreatCorrelation {
  id: string;
  stig_rule_id: string;
  threat_id: string;
  threat_indicator: string;
  threat_type: string;
  threat_source: 'cve' | 'cisa_alert' | 'disa_advisory' | 'vendor_bulletin' | 'zero_day';
  correlation_strength: number;
  correlation_confidence: number;
  risk_elevation: 'none' | 'low' | 'medium' | 'high' | 'critical';
  recommended_actions: string[];
  mitigation_recommendations: string[];
  correlation_details: string;
  temporal_urgency: 'immediate' | 'within_24h' | 'within_week' | 'normal_cycle';
  affected_platforms: string[];
  mitigation_available: boolean;
  automated_response_triggered: boolean;
  correlated_stig_rules: string[];
}

export interface STIGRuleUpdate {
  id: string;
  original_stig_rule_id: string;
  update_type: 'security_enhancement' | 'vulnerability_patch' | 'configuration_change' | 'new_requirement';
  update_source: 'disa_release' | 'vendor_advisory' | 'threat_intelligence' | 'ai_recommendation';
  updated_configuration: any;
  implementation_guidance: string;
  backwards_compatible: boolean;
  testing_required: boolean;
  rollout_priority: number;
  effective_date: string;
}

export interface IntelligenceFeed {
  feed_id: string;
  feed_name: string;
  source_type: 'disa' | 'nist' | 'cisa' | 'vendor' | 'community' | 'commercial';
  last_updated: string;
  active: boolean;
  reliability_score: number;
  stig_relevance_score: number;
}

export interface AISTIGAnalysis {
  id: string;
  analysis_id: string;
  stig_rule_id: string;
  analysis_type: 'vulnerability_correlation' | 'configuration_optimization' | 'risk_assessment' | 'implementation_guidance' | 'predictive' | 'optimization';
  confidence_score: number;
  findings: {
    security_gaps: string[];
    optimization_opportunities: string[];
    implementation_risks: string[];
    compliance_implications: string[];
  };
  recommendations: string[];
  estimated_impact?: string;
  generated_at: string;
  model_version: string;
}

export class STIGIntelligenceEngine {

  /**
   * Correlate threats with STIG rules using AI analysis
   */
  static async correlateThreatIntelligence(
    organizationId: string,
    threatSources: string[] = ['cve', 'cisa_alert', 'disa_advisory']
  ): Promise<STIGThreatCorrelation[]> {
    try {
      const { data, error } = await supabase.functions.invoke('threat-intelligence-lookup', {
        body: {
          action: 'correlate_stig_threats',
          organization_id: organizationId,
          threat_sources: threatSources,
          correlation_options: {
            include_zero_day: true,
            risk_threshold: 'medium',
            temporal_window_days: 30,
            ai_enhanced_matching: true
          }
        }
      });

      if (error) throw error;
      return data.correlations || [];
    } catch (error) {
      console.error('Threat correlation failed:', error);
      throw error;
    }
  }

  /**
   * Monitor DISA STIG releases and generate update recommendations
   */
  static async monitorSTIGUpdates(
    organizationId: string,
    monitoredSTIGs: string[]
  ): Promise<{
    available_updates: STIGRuleUpdate[];
    critical_updates: STIGRuleUpdate[];
    update_summary: {
      total_updates: number;
      security_critical: number;
      configuration_changes: number;
      new_requirements: number;
    };
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('stix-taxii-sync', {
        body: {
          action: 'check_stig_updates',
          organization_id: organizationId,
          monitored_stigs: monitoredSTIGs,
          update_filters: {
            include_draft_releases: false,
            priority_threshold: 'medium',
            compatibility_check: true
          }
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('STIG update monitoring failed:', error);
      throw error;
    }
  }

  /**
   * AI-powered STIG rule optimization analysis
   */
  static async analyzeSTIGOptimization(
    assetId: string,
    stigRuleIds: string[],
    analysisScope: {
      security_analysis: boolean;
      performance_impact: boolean;
      compliance_gaps: boolean;
      implementation_optimization: boolean;
    }
  ): Promise<AISTIGAnalysis[]> {
    try {
      const { data, error } = await supabase.functions.invoke('ai-compliance-analyzer', {
        body: {
          action: 'analyze_stig_optimization',
          asset_id: assetId,
          stig_rules: stigRuleIds,
          analysis_scope: analysisScope,
          ai_options: {
            model: 'gpt-4-turbo',
            include_risk_scoring: true,
            generate_recommendations: true,
            cross_reference_threats: true
          }
        }
      });

      if (error) throw error;
      return data.analyses || [];
    } catch (error) {
      console.error('STIG optimization analysis failed:', error);
      throw error;
    }
  }

  /**
   * Integrate external threat intelligence feeds
   */
  static async configureIntelligenceFeeds(
    organizationId: string,
    feedConfigurations: Array<{
      feed_type: string;
      api_credentials: any;
      update_frequency: 'real_time' | 'hourly' | 'daily' | 'weekly';
      filtering_rules: string[];
      priority_scoring: any;
    }>
  ): Promise<{
    configured_feeds: IntelligenceFeed[];
    integration_status: {
      successful: number;
      failed: number;
      warnings: string[];
    };
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('threat-intelligence-lookup', {
        body: {
          action: 'configure_feeds',
          organization_id: organizationId,
          feed_configurations: feedConfigurations
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Intelligence feed configuration failed:', error);
      throw error;
    }
  }

  /**
   * Generate predictive STIG compliance recommendations
   */
  static async generatePredictiveRecommendations(
    organizationId: string,
    predictionScope: {
      time_horizon_days: number;
      risk_scenarios: string[];
      asset_categories: string[];
      compliance_frameworks: string[];
    }
  ): Promise<{
    predictions: Array<{
      scenario: string;
      probability: number;
      impact_assessment: any;
      recommended_preparations: string[];
      stig_rules_affected: string[];
      timeline: any;
    }>;
    proactive_actions: Array<{
      action: string;
      urgency: 'low' | 'medium' | 'high';
      effort_required: string;
      risk_mitigation_value: number;
    }>;
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('ai-compliance-analyzer', {
        body: {
          action: 'generate_predictive_recommendations',
          organization_id: organizationId,
          prediction_scope: predictionScope,
          ai_models: {
            primary: 'gpt-4-turbo',
            threat_analysis: 'claude-3-opus',
            risk_scoring: 'custom-risk-model'
          }
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Predictive recommendations failed:', error);
      throw error;
    }
  }

  /**
   * Zero-day vulnerability to STIG rule mapping
   */
  static async mapZeroDayToSTIGs(
    vulnerabilityData: {
      cve_id?: string;
      vulnerability_description: string;
      affected_products: string[];
      attack_vectors: string[];
      severity_score: number;
    }
  ): Promise<{
    applicable_stig_rules: Array<{
      stig_id: string;
      rule_id: string;
      relevance_score: number;
      mitigation_effectiveness: number;
      implementation_urgency: 'immediate' | 'high' | 'medium' | 'low';
    }>;
    gap_analysis: {
      covered_attack_vectors: string[];
      uncovered_attack_vectors: string[];
      additional_controls_needed: string[];
    };
    emergency_mitigations: Array<{
      action: string;
      effectiveness: number;
      implementation_time: string;
    }>;
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('ai-compliance-analyzer', {
        body: {
          action: 'map_zeroday_to_stigs',
          vulnerability_data: vulnerabilityData,
          mapping_options: {
            include_emergency_mitigations: true,
            cross_reference_existing_controls: true,
            generate_gap_analysis: true
          }
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Zero-day to STIG mapping failed:', error);
      throw error;
    }
  }

  /**
   * Continuous STIG adaptation engine
   */
  static async enableAdaptiveSTIGManagement(
    organizationId: string,
    adaptationConfig: {
      auto_update_threshold: number;
      human_approval_required: boolean;
      rollback_policy: 'automatic' | 'manual' | 'time_based';
      learning_enabled: boolean;
      feedback_integration: boolean;
    }
  ): Promise<{
    adaptation_engine_status: 'active' | 'inactive' | 'pending';
    learning_models_deployed: string[];
    monitoring_capabilities: string[];
    feedback_loops_configured: number;
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('ai-compliance-analyzer', {
        body: {
          action: 'enable_adaptive_management',
          organization_id: organizationId,
          adaptation_config: adaptationConfig
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Adaptive STIG management enablement failed:', error);
      throw error;
    }
  }

  /**
   * Generate STIG intelligence dashboard data
   */
  static async getIntelligenceDashboard(
    organizationId: string,
    timeRange: {
      start_date: string;
      end_date: string;
    }
  ): Promise<{
    threat_landscape: {
      active_threats: number;
      new_vulnerabilities: number;
      stig_correlations: number;
      risk_trend: 'increasing' | 'stable' | 'decreasing';
    };
    stig_updates: {
      available_updates: number;
      critical_updates: number;
      applied_updates: number;
      pending_reviews: number;
    };
    ai_insights: {
      optimization_opportunities: number;
      predictive_alerts: number;
      automation_suggestions: number;
      confidence_score: number;
    };
    feed_health: {
      active_feeds: number;
      failed_feeds: number;
      last_sync_times: Record<string, string>;
      data_quality_score: number;
    };
  }> {
    try {
      const { data, error } = await supabase.functions.invoke('threat-intelligence-lookup', {
        body: {
          action: 'get_intelligence_dashboard',
          organization_id: organizationId,
          time_range: timeRange
        }
      });

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('Intelligence dashboard data retrieval failed:', error);
      throw error;
    }
  }
}