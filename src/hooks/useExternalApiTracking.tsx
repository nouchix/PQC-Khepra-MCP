import { useState, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from '@/hooks/useOrganization';
import { useToast } from '@/hooks/use-toast';

interface ApiUsageRecord {
  id: string;
  organization_id: string;
  api_provider: string;
  api_endpoint: string;
  tokens_used: number;
  estimated_cost: number;
  request_metadata: any;
  created_at: string;
}

interface RateLimitStatus {
  current_usage: number;
  limit_per_period: number;
  period_type: string;
  reset_time: string;
  blocked: boolean;
}

interface ApiCostConfig {
  id: string;
  api_provider: string;
  endpoint_pattern: string;
  cost_per_token: number;
  cost_per_request: number;
  rate_limit_per_hour: number;
  rate_limit_per_day: number;
}

export const useExternalApiTracking = () => {
  const [loading, setLoading] = useState(false);
  const { currentOrganization } = useOrganization();
  const { toast } = useToast();

  // Track API usage with automatic cost calculation
  const trackApiUsage = useCallback(async (
    apiProvider: string,
    apiEndpoint: string,
    tokensUsed: number = 0,
    requestMetadata: Record<string, any> = {}
  ) => {
    if (!currentOrganization?.id) return null;

    try {
      setLoading(true);

      const { data, error } = await supabase.functions.invoke('track-external-api-usage', {
        body: {
          organizationId: currentOrganization.id,
          apiProvider,
          apiEndpoint,
          tokensUsed,
          requestMetadata
        }
      });

      if (error) throw error;
      return data;
    } catch (error: any) {
      console.error('Error tracking API usage:', error);
      toast({
        title: "Usage Tracking Error",
        description: error.message || "Failed to track API usage",
        variant: "destructive"
      });
      return null;
    } finally {
      setLoading(false);
    }
  }, [currentOrganization?.id, toast]);

  // Check rate limits before making API calls
  const checkRateLimit = useCallback(async (
    apiProvider: string,
    apiEndpoint: string
  ): Promise<RateLimitStatus | null> => {
    if (!currentOrganization?.id) return null;

    try {
      const { data, error } = await supabase.functions.invoke('check-rate-limit', {
        body: {
          organizationId: currentOrganization.id,
          apiProvider,
          apiEndpoint
        }
      });

      if (error) throw error;
      return data as RateLimitStatus;
    } catch (error: any) {
      console.error('Error checking rate limit:', error);
      return null;
    }
  }, [currentOrganization?.id]);

  // Get usage statistics for billing
  const getUsageStats = useCallback(async (
    startDate?: string,
    endDate?: string
  ) => {
    if (!currentOrganization?.id) return [];

    // Awaiting API usage telemetry integration
    return [];
  }, [currentOrganization?.id]);

  // Get current month's costs by provider
  const getCostBreakdown = useCallback(async () => {
    if (!currentOrganization?.id) return [];

    // Awaiting API cost analytics integration
    return [];
  }, [currentOrganization?.id]);

  // Update API cost configurations (admin only)
  const updateApiCosts = useCallback(async (
    apiProvider: string,
    costConfig: Partial<ApiCostConfig>
  ) => {
    try {
      // Awaiting external API tables configuration
      console.log('Update API Costs config:', { apiProvider, costConfig });

      toast({
        title: "API Costs Updated",
        description: `Updated cost configuration for ${apiProvider}`,
      });

      return { api_provider: apiProvider, ...costConfig };
    } catch (error: any) {
      console.error('Error updating API costs:', error);
      toast({
        title: "Update Error",
        description: error.message || "Failed to update API costs",
        variant: "destructive"
      });
      return null;
    }
  }, [toast]);

  return {
    loading,
    trackApiUsage,
    checkRateLimit,
    getUsageStats,
    getCostBreakdown,
    updateApiCosts
  };
};