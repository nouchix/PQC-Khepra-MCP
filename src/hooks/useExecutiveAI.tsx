import { useState } from 'react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

export interface ExecutiveAIRequest {
  action: 'threat-analysis' | 'cmmc-planning' | 'team-performance' | 'security-report';
  context?: any;
}

export interface ExecutiveAIResponse {
  response: string;
  action: string;
  timestamp: string;
}

export const useExecutiveAI = () => {
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const callExecutiveAI = async (request: ExecutiveAIRequest): Promise<string | null> => {
    setLoading(true);
    
    try {
      toast({
        title: "AI Analysis in Progress",
        description: "Generating executive insights...",
      });

      const { data: { user } } = await supabase.auth.getUser();
      
      const response = await supabase.functions.invoke('executive-ai-agent', {
        body: {
          ...request,
          userId: user?.id,
          context: { 
            ...request.context, 
            timestamp: new Date().toISOString() 
          }
        }
      });

      if (response.error) {
        throw new Error(response.error.message);
      }

      const result: ExecutiveAIResponse = response.data;

      toast({
        title: "AI Analysis Complete",
        description: "Executive insights have been generated",
        variant: "default"
      });

      return result.response;
    } catch (error) {
      console.error('Executive AI Error:', error);
      toast({
        title: "AI Analysis Failed",
        description: "Please try again later",
        variant: "destructive"
      });
      return null;
    } finally {
      setLoading(false);
    }
  };

  const getThreatAnalysis = () => callExecutiveAI({ action: 'threat-analysis' });
  const getCMMCPlanning = () => callExecutiveAI({ action: 'cmmc-planning' });
  const getTeamPerformance = () => callExecutiveAI({ action: 'team-performance' });
  const getSecurityReport = () => callExecutiveAI({ action: 'security-report' });

  return {
    loading,
    callExecutiveAI,
    getThreatAnalysis,
    getCMMCPlanning,
    getTeamPerformance,
    getSecurityReport
  };
};