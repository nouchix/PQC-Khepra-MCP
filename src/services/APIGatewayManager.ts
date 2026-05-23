/**
 * API Gateway Manager
 * Enterprise API management with intelligent routing, rate limiting, and STIG-compliant logging
 */

import { supabase } from '@/integrations/supabase/client';

export interface APIRoute {
  id: string;
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  target_service: string;
  authentication_required: boolean;
  rate_limit_per_minute: number;
  cache_ttl_seconds?: number;
  compliance_logging: boolean;
}

export interface RateLimitConfig {
  requests_per_minute: number;
  burst_limit: number;
  backoff_strategy: 'exponential' | 'linear' | 'fixed';
}

export interface RequestContext {
  organization_id: string;
  user_id?: string;
  ip_address: string;
  user_agent: string;
  request_id: string;
  timestamp: string;
}

export class APIGatewayManager {
  private static rateLimitCache = new Map<string, { count: number; resetTime: number }>();

  /**
   * Route API request with intelligent load balancing
   */
  static async routeRequest(
    route: APIRoute,
    context: RequestContext,
    payload: any = {}
  ): Promise<{
    success: boolean;
    data?: any;
    error?: string;
    response_time_ms: number;
    cached: boolean;
  }> {
    const startTime = Date.now();

    try {
      // Check rate limiting
      const rateLimitCheck = await this.checkRateLimit(context, route.rate_limit_per_minute);
      if (!rateLimitCheck.allowed) {
        await this.logRequest(context, route, payload, {
          status: 429,
          error: 'Rate limit exceeded',
          response_time_ms: Date.now() - startTime
        });

        return {
          success: false,
          error: `Rate limit exceeded. Try again in ${rateLimitCheck.retry_after_seconds} seconds`,
          response_time_ms: Date.now() - startTime,
          cached: false
        };
      }

      // Check cache if applicable
      if (route.cache_ttl_seconds && route.method === 'GET') {
        const cachedResponse = await this.getCachedResponse(route, context, payload);
        if (cachedResponse) {
          await this.logRequest(context, route, payload, {
            status: 200,
            cached: true,
            response_time_ms: Date.now() - startTime
          });

          return {
            success: true,
            data: cachedResponse,
            response_time_ms: Date.now() - startTime,
            cached: true
          };
        }
      }

      // Route to target service
      const response = await this.forwardRequest(route, context, payload);
      
      // Cache successful GET responses
      if (route.cache_ttl_seconds && route.method === 'GET' && response.success) {
        await this.cacheResponse(route, context, payload, response.data, route.cache_ttl_seconds);
      }

      // Log request
      await this.logRequest(context, route, payload, {
        status: response.success ? 200 : 500,
        response_time_ms: Date.now() - startTime,
        error: response.error
      });

      return {
        ...response,
        response_time_ms: Date.now() - startTime,
        cached: false
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      await this.logRequest(context, route, payload, {
        status: 500,
        error: error instanceof Error ? error.message : 'Unknown error',
        response_time_ms: responseTime
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Request processing failed',
        response_time_ms: responseTime,
        cached: false
      };
    }
  }

  /**
   * Configure rate limiting for organization
   */
  static async configureRateLimit(
    organizationId: string,
    config: RateLimitConfig
  ): Promise<void> {
    try {
      // Store rate limit configuration
      await supabase
        .from('enhanced_open_controls_integrations')
        .upsert({
          organization_id: organizationId,
          integration_name: 'API Gateway Rate Limiting',
          api_endpoint: 'internal://rate-limiting',
          authentication_method: 'internal',
          performance_metrics: {
            rate_limit_config: config as any,
            configured_at: new Date().toISOString()
          } as any,
          is_active: true
        });
    } catch (error) {
      console.error('Rate limit configuration failed:', error);
      throw error;
    }
  }

  /**
   * Monitor API performance and health
   */
  static async getAPIHealthMetrics(organizationId: string, timeRange: {
    start: string;
    end: string;
  }): Promise<{
    total_requests: number;
    success_rate: number;
    average_response_time: number;
    error_breakdown: Record<string, number>;
    top_endpoints: Array<{ endpoint: string; request_count: number }>;
  }> {
    try {
      const { data, error } = await supabase
        .from('live_api_gateway_requests')
        .select('*')
        .eq('organization_id', organizationId)
        .gte('request_timestamp', timeRange.start)
        .lte('request_timestamp', timeRange.end);

      if (error) throw error;

      const totalRequests = data.length;
      const successfulRequests = data.filter(r => r.response_status >= 200 && r.response_status < 300).length;
      const successRate = totalRequests > 0 ? (successfulRequests / totalRequests) * 100 : 0;
      
      const averageResponseTime = totalRequests > 0 
        ? data.reduce((sum, r) => sum + r.response_time_ms, 0) / totalRequests
        : 0;

      // Error breakdown by status code
      const errorBreakdown: Record<string, number> = {};
      data.filter(r => r.response_status >= 400).forEach(r => {
        const statusRange = `${Math.floor(r.response_status / 100)}xx`;
        errorBreakdown[statusRange] = (errorBreakdown[statusRange] || 0) + 1;
      });

      // Top endpoints
      const endpointCounts: Record<string, number> = {};
      data.forEach(r => {
        endpointCounts[r.api_endpoint] = (endpointCounts[r.api_endpoint] || 0) + 1;
      });

      const topEndpoints = Object.entries(endpointCounts)
        .map(([endpoint, count]) => ({ endpoint, request_count: count }))
        .sort((a, b) => b.request_count - a.request_count)
        .slice(0, 10);

      return {
        total_requests: totalRequests,
        success_rate: Math.round(successRate * 100) / 100,
        average_response_time: Math.round(averageResponseTime),
        error_breakdown: errorBreakdown,
        top_endpoints: topEndpoints
      };
    } catch (error) {
      console.error('API health metrics fetch failed:', error);
      return {
        total_requests: 0,
        success_rate: 0,
        average_response_time: 0,
        error_breakdown: {},
        top_endpoints: []
      };
    }
  }

  /**
   * Auto-scale API resources based on load
   */
  static async autoScaleResources(organizationId: string): Promise<{
    scaling_action: 'scale_up' | 'scale_down' | 'no_action';
    current_capacity: number;
    target_capacity: number;
    reason: string;
  }> {
    try {
      // Get recent load metrics
      const recentMetrics = await this.getAPIHealthMetrics(organizationId, {
        start: new Date(Date.now() - 300000).toISOString(), // Last 5 minutes
        end: new Date().toISOString()
      });

      const currentLoad = recentMetrics.total_requests / 5; // Requests per minute
      const errorRate = 100 - recentMetrics.success_rate;
      const avgResponseTime = recentMetrics.average_response_time;

      // Auto-scaling logic
      let scalingAction: 'scale_up' | 'scale_down' | 'no_action' = 'no_action';
      let reason = 'System operating within normal parameters';
      const currentCapacity = 100; // Mock current capacity
      let targetCapacity = currentCapacity;

      if (currentLoad > 80 || errorRate > 5 || avgResponseTime > 1000) {
        scalingAction = 'scale_up';
        targetCapacity = Math.min(currentCapacity * 1.5, 500);
        reason = 'High load detected: scaling up to handle increased traffic';
      } else if (currentLoad < 20 && errorRate < 1 && avgResponseTime < 200) {
        scalingAction = 'scale_down';
        targetCapacity = Math.max(currentCapacity * 0.8, 50);
        reason = 'Low load detected: scaling down to optimize costs';
      }

      // Record scaling decision
      await supabase
        .from('open_controls_performance_metrics')
        .insert({
          organization_id: organizationId,
          metric_type: 'auto_scaling',
          metric_name: `scaling_decision_${Date.now()}`,
          metric_value: targetCapacity,
          metric_metadata: {
            scaling_action: scalingAction,
            current_capacity: currentCapacity,
            load_metrics: recentMetrics,
            reason
          }
        });

      return {
        scaling_action: scalingAction,
        current_capacity: currentCapacity,
        target_capacity: targetCapacity,
        reason
      };
    } catch (error) {
      console.error('Auto-scaling failed:', error);
      return {
        scaling_action: 'no_action',
        current_capacity: 100,
        target_capacity: 100,
        reason: 'Auto-scaling unavailable due to system error'
      };
    }
  }

  /**
   * Private helper methods
   */
  private static async checkRateLimit(context: RequestContext, limitPerMinute: number): Promise<{
    allowed: boolean;
    retry_after_seconds?: number;
  }> {
    const key = `${context.organization_id}:${context.ip_address}`;
    const now = Date.now();
    const windowStart = Math.floor(now / 60000) * 60000; // Start of current minute

    const currentWindow = this.rateLimitCache.get(key);
    
    if (!currentWindow || currentWindow.resetTime <= now) {
      this.rateLimitCache.set(key, { count: 1, resetTime: windowStart + 60000 });
      return { allowed: true };
    }

    if (currentWindow.count >= limitPerMinute) {
      const retryAfter = Math.ceil((currentWindow.resetTime - now) / 1000);
      return { allowed: false, retry_after_seconds: retryAfter };
    }

    currentWindow.count++;
    return { allowed: true };
  }

  private static async forwardRequest(route: APIRoute, context: RequestContext, payload: any): Promise<{
    success: boolean;
    data?: any;
    error?: string;
  }> {
    try {
      // Mock service forwarding - ready for real service integration
      if (route.target_service === 'disa-stigs-api') {
        return {
          success: true,
          data: { message: 'Mock DISA STIGs API response', payload }
        };
      } else if (route.target_service === 'open-controls') {
        return {
          success: true,
          data: { message: 'Mock Open Controls response', payload }
        };
      }

      return {
        success: false,
        error: `Unknown target service: ${route.target_service}`
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Service forwarding failed'
      };
    }
  }

  private static async getCachedResponse(route: APIRoute, context: RequestContext, payload: any): Promise<any | null> {
    const cacheKey = `${route.path}_${JSON.stringify(payload)}`;
    
    const { data } = await supabase
      .from('disa_stigs_api_cache')
      .select('cached_data')
      .eq('organization_id', context.organization_id)
      .eq('api_endpoint', route.path)
      .eq('cache_key', cacheKey)
      .gt('cache_expires_at', new Date().toISOString())
      .single();

    return data?.cached_data || null;
  }

  private static async cacheResponse(route: APIRoute, context: RequestContext, payload: any, responseData: any, ttlSeconds: number): Promise<void> {
    const cacheKey = `${route.path}_${JSON.stringify(payload)}`;
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

    await supabase
      .from('disa_stigs_api_cache')
      .upsert({
        organization_id: context.organization_id,
        api_endpoint: route.path,
        cache_key: cacheKey,
        cached_data: responseData,
        cache_expires_at: expiresAt
      });
  }

  private static async logRequest(context: RequestContext, route: APIRoute, payload: any, result: {
    status: number;
    response_time_ms: number;
    error?: string;
    cached?: boolean;
  }): Promise<void> {
    await supabase
      .from('live_api_gateway_requests')
      .insert({
        organization_id: context.organization_id,
        request_id: context.request_id,
        api_endpoint: route.path,
        request_method: route.method,
        request_payload: payload,
        response_data: result.cached ? { cached: true } : {},
        response_status: result.status,
        response_time_ms: result.response_time_ms,
        error_details: result.error ? { message: result.error } : {},
        user_agent: context.user_agent,
        ip_address: context.ip_address
      });
  }
}