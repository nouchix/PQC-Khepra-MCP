import { useState, useEffect } from 'react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from '@/hooks/useOrganization';

export interface EnterpriseAgent {
  id: string;
  organization_id: string;
  agent_name: string;
  agent_type: string;
  trust_level: number;
  status: string;
  specialization: string;
  capabilities: any[];
  permissions: Record<string, any>;
  performance_metrics: Record<string, any>;
  learning_data: Record<string, any>;
  created_at: string;
  updated_at: string;
  last_active?: string;
  deployment_status: string;
  created_by?: string;
  role_id?: string;
}

export interface AgentAction {
  id: string;
  agent_id: string;
  action_type: string;
  action_context: string;
  success: boolean;
  execution_time_ms?: number;
  risk_score?: number;
  created_at: string;
}

export interface AgentPerformanceData {
  metrics: any[];
  successRate: number;
  actionsLast24h: number;
  totalActions: number;
}

export const useEnterpriseAgents = () => {
  const [agents, setAgents] = useState<EnterpriseAgent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();
  const { currentOrganization } = useOrganization();

  // Load agents for current organization
  const loadAgents = async () => {
    if (!currentOrganization?.id) return;

    setLoading(true);
    try {
      const { data, error } = await supabase
        .from('ai_agents')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setAgents((data || []) as EnterpriseAgent[]);
    } catch (err: any) {
      setError(err.message);
      toast({
        title: "Error loading agents",
        description: err.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  // Create new agent
  const createAgent = async (agentData: Partial<EnterpriseAgent>) => {
    if (!currentOrganization?.id) return null;

    try {
      const response = await supabase.functions.invoke('ai-agent-manager', {
        body: {
          action: 'create',
          agentData: {
            ...agentData,
            organizationId: currentOrganization.id
          }
        }
      });

      if (response.error) throw new Error(response.error.message);

      const newAgent = response.data.agent;
      setAgents(prev => [newAgent, ...prev]);
      
      toast({
        title: "Agent created successfully",
        description: `${newAgent.agent_name} is ready for training`
      });

      return newAgent;
    } catch (err: any) {
      toast({
        title: "Failed to create agent",
        description: err.message,
        variant: "destructive"
      });
      return null;
    }
  };

  // Update agent
  const updateAgent = async (agentId: string, updates: Partial<EnterpriseAgent>) => {
    try {
      const response = await supabase.functions.invoke('ai-agent-manager', {
        body: {
          action: 'update',
          agentId,
          agentData: {
            ...updates,
            organizationId: currentOrganization?.id
          }
        }
      });

      if (response.error) throw new Error(response.error.message);

      const updatedAgent = response.data.agent;
      setAgents(prev => prev.map(agent => 
        agent.id === agentId ? updatedAgent : agent
      ));

      toast({
        title: "Agent updated successfully",
        description: `${updatedAgent.agent_name} configuration updated`
      });

      return updatedAgent;
    } catch (err: any) {
      toast({
        title: "Failed to update agent",
        description: err.message,
        variant: "destructive"
      });
      return null;
    }
  };

  // Execute agent action
  const executeAgentAction = async (agentId: string, actionData: any) => {
    try {
      const response = await supabase.functions.invoke('ai-agent-manager', {
        body: {
          action: 'execute',
          agentId,
          actionData: {
            ...actionData,
            organizationId: currentOrganization?.id
          }
        }
      });

      if (response.error) throw new Error(response.error.message);

      toast({
        title: "Agent action executed",
        description: "Action completed successfully"
      });

      return response.data.result;
    } catch (err: any) {
      toast({
        title: "Agent action failed",
        description: err.message,
        variant: "destructive"
      });
      throw err;
    }
  };

  // Get agent performance data
  const getAgentPerformance = async (agentId: string): Promise<AgentPerformanceData | null> => {
    try {
      const response = await supabase.functions.invoke('ai-agent-manager', {
        body: {
          action: 'get_performance',
          agentId
        }
      });

      if (response.error) throw new Error(response.error.message);
      return response.data;
    } catch (err: any) {
      toast({
        title: "Failed to load performance data",
        description: err.message,
        variant: "destructive"
      });
      return null;
    }
  };

  // Get agent actions history
  const getAgentActions = async (agentId: string): Promise<AgentAction[]> => {
    try {
      const { data, error } = await supabase
        .from('agent_actions')
        .select('*')
        .eq('agent_id', agentId)
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      return data || [];
    } catch (err: any) {
      toast({
        title: "Failed to load agent actions",
        description: err.message,
        variant: "destructive"
      });
      return [];
    }
  };

  // Promote agent trust level
  const promoteAgent = async (agentId: string) => {
    const agent = agents.find(a => a.id === agentId);
    if (!agent) return;

    const newTrustLevel = Math.min(100, agent.trust_level + 25);
    let newStatus = agent.status;

    if (newTrustLevel >= 25 && newTrustLevel < 50) {
      newStatus = 'training';
    } else if (newTrustLevel >= 50) {
      newStatus = 'active';
    }

    return await updateAgent(agentId, {
      trust_level: newTrustLevel,
      status: newStatus
    });
  };

  // Deploy agent to production
  const deployAgent = async (agentId: string) => {
    return await updateAgent(agentId, {
      deployment_status: 'production',
      status: 'active'
    });
  };

  // Suspend agent
  const suspendAgent = async (agentId: string, reason: string) => {
    return await updateAgent(agentId, {
      status: 'suspended',
      learning_data: { suspension_reason: reason }
    });
  };

  useEffect(() => {
    loadAgents();
  }, [currentOrganization?.id]);

  return {
    agents,
    loading,
    error,
    createAgent,
    updateAgent,
    executeAgentAction,
    getAgentPerformance,
    getAgentActions,
    promoteAgent,
    deployAgent,
    suspendAgent,
    refreshAgents: loadAgents
  };
};