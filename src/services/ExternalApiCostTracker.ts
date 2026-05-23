import { supabase } from '@/integrations/supabase/client';
import { rateLimitingService } from './RateLimitingService';

interface ApiCall {
  organizationId: string;
  apiProvider: string;
  endpoint: string;
  tokensUsed?: number;
  requestMetadata?: Record<string, any>;
}

interface CostCalculation {
  estimatedCost: number;
  tokensUsed: number;
  rateLimitStatus: any;
}

export class ExternalApiCostTracker {
  private static instance: ExternalApiCostTracker;

  static getInstance(): ExternalApiCostTracker {
    if (!ExternalApiCostTracker.instance) {
      ExternalApiCostTracker.instance = new ExternalApiCostTracker();
    }
    return ExternalApiCostTracker.instance;
  }

  // Track API call before execution
  async preCallCheck(apiCall: ApiCall): Promise<{ allowed: boolean; reason?: string }> {
    const rateLimit = await rateLimitingService.checkRateLimit(
      apiCall.organizationId,
      apiCall.apiProvider,
      apiCall.endpoint,
      apiCall.tokensUsed || 0
    );

    if (!rateLimit.allowed) {
      await rateLimitingService.recordRateLimitHit(
        apiCall.organizationId,
        apiCall.apiProvider,
        apiCall.endpoint,
        'request_limit'
      );

      return {
        allowed: false,
        reason: rateLimit.reason || 'Rate limit exceeded'
      };
    }

    return { allowed: true };
  }

  // Track API call after execution
  async trackApiCall(apiCall: ApiCall): Promise<CostCalculation> {
    try {
      // Use edge function for tracking until tables are available
      const { error } = await supabase.functions.invoke('track-external-api-usage', {
        body: {
          organizationId: apiCall.organizationId,
          apiProvider: apiCall.apiProvider,
          apiEndpoint: apiCall.endpoint,
          tokensUsed: apiCall.tokensUsed || 0,
          requestMetadata: apiCall.requestMetadata || {}
        }
      });

      if (error) {
        console.error('Error tracking API usage:', error);
      }

      // Calculate estimated cost with default rates
      const tokensUsed = apiCall.tokensUsed || 0;
      const defaultRates = {
        openai: { requestCost: 0.002, tokenCost: 0.00002 },
        grok: { requestCost: 0.001, tokenCost: 0.00001 },
        shodan: { requestCost: 0.1, tokenCost: 0 },
        virustotal: { requestCost: 0.05, tokenCost: 0 }
      };

      const rates = defaultRates[apiCall.apiProvider as keyof typeof defaultRates] ||
        { requestCost: 0.001, tokenCost: 0.00001 };
      const estimatedCost = rates.requestCost + (tokensUsed * rates.tokenCost);

      return {
        estimatedCost,
        tokensUsed,
        rateLimitStatus: await rateLimitingService.checkRateLimit(
          apiCall.organizationId,
          apiCall.apiProvider,
          apiCall.endpoint
        )
      };

    } catch (error) {
      console.error('Error in trackApiCall:', error);
      return {
        estimatedCost: 0,
        tokensUsed: apiCall.tokensUsed || 0,
        rateLimitStatus: { allowed: true }
      };
    }
  }

  // Update usage-based billing record
  private async updateUsageBilling(organizationId: string, cost: number) {
    // Awaiting billing tables initialization
  }

  // Check if cost alerts should be triggered
  private async checkCostAlerts(organizationId: string, apiProvider: string, newCost: number) {
    // Awaiting cost alert monitoring configuration
  }

  // Create cost alert
  private async createCostAlert(
    organizationId: string,
    apiProvider: string,
    alertType: string,
    currentCost: number,
    thresholdAmount: number
  ) {
    // Awaiting cost alert tables mapping
  }

  // Get cost analytics for an organization
  async getCostAnalytics(organizationId: string, days: number = 30) {
    return {
      totalCost: 0,
      dailyAverage: 0,
      topProvider: 'none',
      trends: []
    };
  }
}

export const apiCostTracker = ExternalApiCostTracker.getInstance();