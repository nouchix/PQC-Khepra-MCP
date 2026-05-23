/**
 * Codex Agent Swarm Hook
 * React hook for managing AI agent swarm operations
 */

import { useState, useEffect, useCallback } from 'react';
import { useToast } from '@/hooks/use-toast';
import { STIGCodexOrchestrator, CodexAgent, SwarmTask } from '@/services/STIGCodexOrchestrator';
import { ChatGPTCodexIntegration, PolymorphicAPI } from '@/services/ChatGPTCodexIntegration';
import { PolymorphicSchemaEngine, AdaptiveSchema } from '@/services/PolymorphicSchemaEngine';

export interface CodexSwarmState {
  agents: CodexAgent[];
  polymorphicAPIs: PolymorphicAPI[];
  adaptiveSchemas: AdaptiveSchema[];
  activeTasks: SwarmTask[];
  swarmPerformance: any;
  competitiveAnalysis: any;
  loading: boolean;
  error: string | null;
}

export interface CodexSwarmOperations {
  initializeSwarm: (config: any) => Promise<void>;
  orchestrateTask: (taskDefinition: any) => Promise<void>;
  evolveAPI: (systemAnalysis: any) => Promise<void>;
  generateConnector: (systemAnalysis: any) => Promise<void>;
  analyzeCompetitive: (scenario: any) => Promise<void>;
  exportChatGPTInstructions: () => Promise<void>;
  getSwarmPerformance: () => Promise<void>;
  refreshData: () => Promise<void>;
}

export const useCodexSwarm = (organizationId: string): CodexSwarmState & CodexSwarmOperations => {
  const [state, setState] = useState<CodexSwarmState>({
    agents: [],
    polymorphicAPIs: [],
    adaptiveSchemas: [],
    activeTasks: [],
    swarmPerformance: null,
    competitiveAnalysis: null,
    loading: false,
    error: null
  });

  const { toast } = useToast();

  const updateState = useCallback((updates: Partial<CodexSwarmState>) => {
    setState(prev => ({ ...prev, ...updates }));
  }, []);

  const handleError = useCallback((error: any, operation: string) => {
    const errorMessage = error?.message || `${operation} failed`;
    console.error(`Codex Swarm ${operation}:`, error);
    updateState({ error: errorMessage, loading: false });
    toast({
      title: "Codex Swarm Error",
      description: errorMessage,
      variant: "destructive"
    });
  }, [updateState, toast]);

  const handleSuccess = useCallback((message: string) => {
    toast({
      title: "Codex Swarm Success",
      description: message,
    });
  }, [toast]);

  // Initialize AI Agent Swarm
  const initializeSwarm = useCallback(async (config: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexOrchestrator.initializeSwarm(organizationId, {
        agent_types: [
          { type: 'discovery', count: 2, ai_model: 'gpt-5', specialized_knowledge: ['network_scanning', 'asset_discovery'] },
          { type: 'analysis', count: 2, ai_model: 'claude-opus-4-1', specialized_knowledge: ['schema_analysis', 'pattern_recognition'] },
          { type: 'compliance', count: 1, ai_model: 'o3', specialized_knowledge: ['stig_validation', 'cmmc_mapping'] },
          { type: 'connector', count: 2, ai_model: 'gpt-4.1', specialized_knowledge: ['api_generation', 'integration_patterns'] }
        ],
        coordination_strategy: 'hybrid',
        learning_enabled: true,
        auto_scaling: true,
        ...config
      });
      
      updateState({ 
        agents: result.agents_deployed,
        loading: false 
      });
      handleSuccess(`Swarm initialized: ${result.agents_deployed.length} agents deployed`);
    } catch (error) {
      handleError(error, 'swarm initialization');
    }
  }, [organizationId, updateState, handleError, handleSuccess]);

  // Orchestrate Multi-Agent Task
  const orchestrateTask = useCallback(async (taskDefinition: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexOrchestrator.orchestrateTask({
        task_type: 'integration_discovery',
        complexity: 'expert',
        requirements: {
          data_sources: ['enterprise_systems'],
          compliance_frameworks: ['STIG', 'CMMC'],
          integration_targets: ['palantir_alternative'],
          performance_constraints: { response_time: '<2s', throughput: '>1000rps' }
        },
        execution_preferences: {
          speed_priority: 'balanced',
          agent_selection: 'automatic',
          human_oversight: false
        },
        ...taskDefinition
      });

      updateState({ 
        activeTasks: [...state.activeTasks, { 
          id: result.task_id,
          task_type: 'integration_discovery',
          priority: 'high',
          assigned_agents: result.assigned_agents.map(a => a.id),
          status: 'in_progress',
          input_data: taskDefinition,
          execution_strategy: 'parallel',
          created_at: new Date().toISOString()
        } as SwarmTask],
        loading: false 
      });
      handleSuccess(`Task orchestrated: ${result.assigned_agents.length} agents assigned`);
    } catch (error) {
      handleError(error, 'task orchestration');
    }
  }, [state.activeTasks, updateState, handleError, handleSuccess]);

  // Evolve Polymorphic API
  const evolveAPI = useCallback(async (systemAnalysis: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexOrchestrator.evolveIntegrationAPI({
        discovered_systems: [
          {
            system_name: 'Enterprise System 1',
            api_endpoints: ['/api/v1/data', '/api/v1/users'],
            data_schemas: { users: { id: 'string', name: 'string' } },
            authentication: { type: 'oauth2' },
            compliance_posture: { stig_score: 85 }
          }
        ],
        usage_patterns: { peak_hours: '9-17', avg_requests: 1000 },
        performance_metrics: { avg_response_time: 150, error_rate: 0.02 },
        ...systemAnalysis
      });

      updateState({ 
        polymorphicAPIs: [...state.polymorphicAPIs, ...result.evolved_apis.map(api => ({
          id: `api-${Date.now()}`,
          api_name: api.api_name,
          version: '1.0.0',
          endpoints: [],
          authentication: {},
          rate_limits: {},
          auto_evolution_enabled: true,
          learning_metadata: {
            usage_patterns: {},
            performance_optimizations: {},
            error_patterns: {}
          }
        }))],
        loading: false 
      });
      handleSuccess(`API evolution complete: ${result.evolved_apis.length} APIs generated`);
    } catch (error) {
      handleError(error, 'API evolution');
    }
  }, [state.polymorphicAPIs, updateState, handleError, handleSuccess]);

  // Generate Intelligent Connector
  const generateConnector = useCallback(async (systemAnalysis: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await ChatGPTCodexIntegration.generateIntelligentConnector({
        system_name: 'Target System',
        discovered_endpoints: ['/api/data'],
        data_patterns: { structure: 'json' },
        security_posture: { auth_required: true },
        compliance_gaps: ['missing_stig_controls'],
        ...systemAnalysis
      });

      updateState({ loading: false });
      handleSuccess(`Connector generated with ${result.stig_validations.length} STIG validations`);
    } catch (error) {
      handleError(error, 'connector generation');
    }
  }, [updateState, handleError, handleSuccess]);

  // Competitive Analysis
  const analyzeCompetitive = useCallback(async (scenario: any) => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexOrchestrator.analyzeCompetitiveAdvantage({
        enterprise_systems: ['SAP', 'Salesforce', 'AWS'],
        data_volume: 'enterprise',
        compliance_requirements: ['STIG', 'CMMC', 'SOX'],
        performance_requirements: { latency: '<100ms', throughput: '>10000rps' },
        ...scenario
      });

      updateState({ 
        competitiveAnalysis: result,
        loading: false 
      });
      handleSuccess(`Competitive analysis complete: ${result.palantir_comparison.cost_advantage}% cost advantage identified`);
    } catch (error) {
      handleError(error, 'competitive analysis');
    }
  }, [updateState, handleError, handleSuccess]);

  // Export ChatGPT Instructions
  const exportChatGPTInstructions = useCallback(async () => {
    try {
      updateState({ loading: true, error: null });
      const result = await ChatGPTCodexIntegration.exportChatGPTInstructions({
        generated_apis: state.polymorphicAPIs,
        integration_patterns: [],
        performance_optimizations: [],
        compliance_validations: []
      });

      // Create downloadable file
      const instructionsBlob = new Blob([result.developer_guide], { type: 'text/markdown' });
      const url = URL.createObjectURL(instructionsBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'chatgpt_codex_instructions.md';
      a.click();
      URL.revokeObjectURL(url);

      updateState({ loading: false });
      handleSuccess(`ChatGPT instructions exported: ${result.chatgpt_prompts.length} prompts generated`);
    } catch (error) {
      handleError(error, 'ChatGPT export');
    }
  }, [state.polymorphicAPIs, updateState, handleError, handleSuccess]);

  // Get Swarm Performance
  const getSwarmPerformance = useCallback(async () => {
    try {
      updateState({ loading: true, error: null });
      const result = await STIGCodexOrchestrator.getSwarmPerformance(organizationId);
      
      updateState({ 
        swarmPerformance: result,
        loading: false 
      });
    } catch (error) {
      handleError(error, 'performance monitoring');
    }
  }, [organizationId, updateState, handleError]);

  // Refresh All Data
  const refreshData = useCallback(async () => {
    try {
      updateState({ loading: true, error: null });
      await Promise.all([
        getSwarmPerformance()
      ]);
      updateState({ loading: false });
      handleSuccess('Swarm data refreshed');
    } catch (error) {
      handleError(error, 'data refresh');
    }
  }, [getSwarmPerformance, updateState, handleError, handleSuccess]);

  // Initialize on mount
  useEffect(() => {
    if (organizationId) {
      refreshData();
    }
  }, [organizationId, refreshData]);

  return {
    ...state,
    initializeSwarm,
    orchestrateTask,
    evolveAPI,
    generateConnector,
    analyzeCompetitive,
    exportChatGPTInstructions,
    getSwarmPerformance,
    refreshData
  };
};