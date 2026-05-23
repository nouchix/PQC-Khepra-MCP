/**
 * Enhanced STIG-Codex Hook
 * Comprehensive STIG-first compliance automation with real-time monitoring
 * Integrates all STIG-Codex engine capabilities
 */

import { useState, useEffect, useCallback } from 'react';
import { useToast } from '@/hooks/use-toast';
import { STIGCodexEngine, STIGConfigurationSnapshot, STIGDriftEvent, STIGAgent } from '@/services/STIGCodexEngine';
import { STIGTrustedRegistry, TrustedSTIGConfiguration, AIVerificationResult } from '@/services/STIGTrustedRegistry';
import { STIGIntelligenceEngine, STIGThreatCorrelation, AISTIGAnalysis } from '@/services/STIGIntelligenceEngine';

export interface STIGCodexState {
  // Configuration monitoring
  baselines: STIGConfigurationSnapshot[];
  driftEvents: STIGDriftEvent[];
  agents: STIGAgent[];
  
  // Trusted registry
  trustedConfigurations: TrustedSTIGConfiguration[];
  aiVerifications: AIVerificationResult[];
  
  // Intelligence
  threatCorrelations: STIGThreatCorrelation[];
  aiAnalyses: AISTIGAnalysis[];
  
  // Compliance scoring
  complianceScore: number;
  complianceBreakdown: any;
  riskAnalysis: any;
  
  // System status
  loading: boolean;
  error: string | null;
  lastUpdated: string | null;
}

export interface STIGCodexOperations {
  // Core engine operations
  initializeMonitoring: (assets: string[], stigRules: string[]) => Promise<void>;
  captureBaseline: (assetId: string, stigRules: string[]) => Promise<void>;
  detectDrift: (assetId: string) => Promise<void>;
  deployAgents: (config: any) => Promise<void>;
  setOperationalMode: (agentId: string, mode: string, config?: any) => Promise<void>;
  executeRemediation: (violationId: string, options?: any) => Promise<void>;
  
  // Registry operations
  getTrustedConfigurations: (stigId: string, platform: string) => Promise<void>;
  verifyWithAI: (configId: string, environment: any) => Promise<void>;
  searchConfigurations: (criteria: any) => Promise<void>;
  
  // Intelligence operations
  correlateThreatIntel: (threatSources?: string[]) => Promise<void>;
  analyzeOptimization: (assetId: string, stigRules: string[]) => Promise<void>;
  generatePredictiveRecommendations: (scope: any) => Promise<void>;
  
  // Utility operations
  calculateCompliance: (scope?: any) => Promise<void>;
  refreshAllData: () => Promise<void>;
}

export const useSTIGCodex = (organizationId: string): STIGCodexState & STIGCodexOperations => {
  const [state, setState] = useState<STIGCodexState>({
    baselines: [],
    driftEvents: [],
    agents: [],
    trustedConfigurations: [],
    aiVerifications: [],
    threatCorrelations: [],
    aiAnalyses: [],
    complianceScore: 0,
    complianceBreakdown: null,
    riskAnalysis: null,
    loading: false,
    error: null,
    lastUpdated: null
  });

  const { toast } = useToast();

  // Update state helper
  const updateState = useCallback((updates: Partial<STIGCodexState>) => {
    setState(prev => ({
      ...prev,
      ...updates,
      lastUpdated: new Date().toISOString()
    }));
  }, []);

  // Error handler
  const handleError = useCallback((error: any, operation: string) => {
    const errorMessage = error?.message || `${operation} failed`;
    console.error(`STIG-Codex ${operation}:`, error);
    updateState({ error: errorMessage, loading: false });
    toast({
      title: "STIG-Codex Error",
      description: errorMessage,
      variant: "destructive"
    });
  }, [updateState, toast]);

  // Success handler
  const handleSuccess = useCallback((message: string) => {
    toast({
      title: "STIG-Codex Success",
      description: message,
    });
  }, [toast]);

  // Core Engine Operations
  const initializeMonitoring = useCallback(async (assets: string[], stigRules: string[]) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexEngine.initializeConfigurationMonitoring(organizationId, assets, stigRules);
      handleSuccess(`Monitoring initialized: ${result.baselines_created} baselines, ${result.monitoring_agents_deployed} agents`);
      updateState({ loading: false });
      // Refresh agent data
      // Note: In a full implementation, we'd fetch updated agent data here
    } catch (error) {
      handleError(error, 'monitoring initialization');
    }
  }, [organizationId, updateState, handleError, handleSuccess]);

  const captureBaseline = useCallback(async (assetId: string, stigRules: string[]) => {
    try {
      updateState({ loading: true, error: null });
      const snapshots = await STIGCodexEngine.captureConfigurationBaseline(assetId, stigRules);
      updateState({ 
        baselines: [...state.baselines, ...snapshots],
        loading: false 
      });
      handleSuccess(`Captured ${snapshots.length} configuration baselines`);
    } catch (error) {
      handleError(error, 'baseline capture');
    }
  }, [state.baselines, updateState, handleError, handleSuccess]);

  const detectDrift = useCallback(async (assetId: string) => {
    try {
      updateState({ loading: true, error: null });
      const driftEvents = await STIGCodexEngine.detectConfigurationDrift(assetId, true);
      updateState({ 
        driftEvents: [...state.driftEvents, ...driftEvents],
        loading: false 
      });
      if (driftEvents.length > 0) {
        const criticalEvents = driftEvents.filter(e => e.severity === 'critical').length;
        handleSuccess(`Detected ${driftEvents.length} drift events (${criticalEvents} critical)`);
      }
    } catch (error) {
      handleError(error, 'drift detection');
    }
  }, [state.driftEvents, updateState, handleError, handleSuccess]);

  const deployAgents = useCallback(async (config: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexEngine.deploySTIGAgents(organizationId, config);
      updateState({ 
        agents: result.agents_deployed,
        loading: false 
      });
      handleSuccess(`Deployed ${result.deployment_summary.successful_deployments} STIG agents`);
    } catch (error) {
      handleError(error, 'agent deployment');
    }
  }, [organizationId, updateState, handleError, handleSuccess]);

  const setOperationalMode = useCallback(async (agentId: string, mode: string, config?: any) => {
    try {
      updateState({ loading: true, error: null });
      await STIGCodexEngine.setOperationalMode(agentId, mode as any, config);
      // Update agent in state
      const updatedAgents = state.agents.map(agent => 
        agent.id === agentId ? { ...agent, operational_mode: mode as any } : agent
      );
      updateState({ 
        agents: updatedAgents,
        loading: false 
      });
      handleSuccess(`Agent operational mode set to ${mode}`);
    } catch (error) {
      handleError(error, 'operational mode change');
    }
  }, [state.agents, updateState, handleError, handleSuccess]);

  const executeRemediation = useCallback(async (violationId: string, options?: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexEngine.executeAutomatedRemediation(violationId, options || {
        remediation_type: 'immediate',
        rollback_enabled: true,
        verification_required: true,
        impact_assessment: true
      });
      updateState({ loading: false });
      handleSuccess(`Remediation ${result.status}: ${result.actions_taken.length} actions taken`);
    } catch (error) {
      handleError(error, 'automated remediation');
    }
  }, [updateState, handleError, handleSuccess]);

  // Registry Operations
  const getTrustedConfigurations = useCallback(async (stigId: string, platform: string) => {
    try {
      updateState({ loading: true, error: null });
      const configurations = await STIGTrustedRegistry.getTrustedConfigurations(stigId, platform);
      updateState({ 
        trustedConfigurations: configurations,
        loading: false 
      });
    } catch (error) {
      handleError(error, 'trusted configuration retrieval');
    }
  }, [updateState, handleError]);

  const verifyWithAI = useCallback(async (configId: string, environment: any) => {
    try {
      updateState({ loading: true, error: null });
      const verification = await STIGTrustedRegistry.verifyConfigurationWithAI(configId, environment);
      updateState({ 
        aiVerifications: [...state.aiVerifications, verification],
        loading: false 
      });
      handleSuccess(`AI verification complete: ${verification.verification_status} (${Math.round(verification.confidence_score * 100)}% confidence)`);
    } catch (error) {
      handleError(error, 'AI verification');
    }
  }, [state.aiVerifications, updateState, handleError, handleSuccess]);

  const searchConfigurations = useCallback(async (criteria: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGTrustedRegistry.searchConfigurations(criteria);
      updateState({ 
        trustedConfigurations: result.configurations,
        loading: false 
      });
      handleSuccess(`Found ${result.total_results} matching configurations`);
    } catch (error) {
      handleError(error, 'configuration search');
    }
  }, [updateState, handleError, handleSuccess]);

  // Intelligence Operations
  const correlateThreatIntel = useCallback(async (threatSources?: string[]) => {
    try {
      updateState({ loading: true, error: null });
      const correlations = await STIGIntelligenceEngine.correlateThreatIntelligence(organizationId, threatSources);
      updateState({ 
        threatCorrelations: correlations,
        loading: false 
      });
      const criticalCorrelations = correlations.filter(c => c.risk_elevation === 'critical').length;
      if (criticalCorrelations > 0) {
        handleSuccess(`Threat correlation complete: ${criticalCorrelations} critical threats identified`);
      }
    } catch (error) {
      handleError(error, 'threat correlation');
    }
  }, [organizationId, updateState, handleError, handleSuccess]);

  const analyzeOptimization = useCallback(async (assetId: string, stigRules: string[]) => {
    try {
      updateState({ loading: true, error: null });
      const analyses = await STIGIntelligenceEngine.analyzeSTIGOptimization(assetId, stigRules, {
        security_analysis: true,
        performance_impact: true,
        compliance_gaps: true,
        implementation_optimization: true
      });
      updateState({ 
        aiAnalyses: [...state.aiAnalyses, ...analyses],
        loading: false 
      });
      handleSuccess(`AI optimization analysis complete: ${analyses.length} recommendations generated`);
    } catch (error) {
      handleError(error, 'optimization analysis');
    }
  }, [state.aiAnalyses, updateState, handleError, handleSuccess]);

  const generatePredictiveRecommendations = useCallback(async (scope: any) => {
    try {
      updateState({ loading: true, error: null });
      await STIGIntelligenceEngine.generatePredictiveRecommendations(organizationId, scope);
      updateState({ loading: false });
      handleSuccess('Predictive recommendations generated successfully');
    } catch (error) {
      handleError(error, 'predictive recommendations');
    }
  }, [organizationId, updateState, handleError, handleSuccess]);

  // Utility Operations
  const calculateCompliance = useCallback(async (scope?: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexEngine.calculateComplianceScore(organizationId, scope);
      updateState({ 
        complianceScore: result.overall_score,
        complianceBreakdown: result.compliance_breakdown,
        riskAnalysis: result.risk_analysis,
        loading: false 
      });
    } catch (error) {
      handleError(error, 'compliance calculation');
    }
  }, [organizationId, updateState, handleError]);

  const refreshAllData = useCallback(async () => {
    try {
      updateState({ loading: true, error: null });
      await Promise.all([
        calculateCompliance(),
        correlateThreatIntel()
      ]);
      updateState({ loading: false });
      handleSuccess('All STIG-Codex data refreshed');
    } catch (error) {
      handleError(error, 'data refresh');
    }
  }, [calculateCompliance, correlateThreatIntel, updateState, handleError, handleSuccess]);

  // Initialize on mount
  useEffect(() => {
    if (organizationId) {
      refreshAllData();
    }
  }, [organizationId, refreshAllData]);

  return {
    ...state,
    initializeMonitoring,
    captureBaseline,
    detectDrift,
    deployAgents,
    setOperationalMode,
    executeRemediation,
    getTrustedConfigurations,
    verifyWithAI,
    searchConfigurations,
    correlateThreatIntel,
    analyzeOptimization,
    generatePredictiveRecommendations,
    calculateCompliance,
    refreshAllData
  };
};