/**
 * AWS Cost Explorer Connector
 * ═══════════════════════════
 *
 * Real cost data from AWS Cost Explorer API via Supabase Edge Function relay.
 *
 * The browser does NOT call AWS APIs directly — all requests route through
 * a Supabase Edge Function that uses AWS SDK v3 with STS-assumed role credentials.
 *
 * Capabilities:
 *   - Monthly/daily cost breakdown by service
 *   - Cost forecast (GetCostForecast)
 *   - Cost by tag (e.g., environment, team)
 *   - Savings recommendations
 *
 * AWS API: ce.getCostAndUsage() / ce.getCostForecast()
 * Documentation: https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/
 */

import { supabase } from '@/integrations/supabase/client';
import { IntegrationKeyService } from './IntegrationKeyService';
import { apiCostTracker } from '../ExternalApiCostTracker';

// ─── Response Types ────────────────────────────────────────────────────────────

export interface CostBreakdown {
    service: string;
    amount: number;
    currency: string;
    percentage_of_total: number;
}

export interface CostAnalysisResult {
    total_cost: number;
    currency: string;
    period_start: string;
    period_end: string;
    breakdown_by_service: CostBreakdown[];
    top_services: CostBreakdown[];
    daily_average: number;
    month_over_month_change: number | null;
    data_available: boolean;
    data_source: 'aws_cost_explorer' | 'supabase_cached' | 'not_configured' | 'error';
    error_message?: string;
}

export interface CostForecastResult {
    forecasted_total: number;
    currency: string;
    forecast_start: string;
    forecast_end: string;
    confidence_level: number;
    data_available: boolean;
    data_source: 'aws_cost_explorer' | 'not_configured';
    error_message?: string;
}

// ─── Connector Implementation ──────────────────────────────────────────────────

export class AWSCostExplorerConnector {
    private static readonly PROVIDER = 'aws' as const;
    private static readonly RELAY_FUNCTION = 'aws-cost-relay';

    /**
     * Get cost analysis for a given period.
     * Replaces INT-004: Math.random() * 50000 + 10000 for total_cost.
     */
    static async getCostAnalysis(
        organizationId: string,
        options?: {
            /** Start date (YYYY-MM-DD). Default: first day of current month */
            startDate?: string;
            /** End date (YYYY-MM-DD). Default: today */
            endDate?: string;
            /** Granularity: DAILY or MONTHLY. Default: MONTHLY */
            granularity?: 'DAILY' | 'MONTHLY';
            /** Group by dimension. Default: SERVICE */
            groupBy?: 'SERVICE' | 'LINKED_ACCOUNT' | 'REGION' | 'USAGE_TYPE';
        }
    ): Promise<CostAnalysisResult> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential) {
            // Check for cached cost data
            return this.getCachedCostData(organizationId);
        }

        const preCheck = await apiCostTracker.preCallCheck({
            organizationId,
            apiProvider: 'aws',
            endpoint: 'ce/getCostAndUsage',
        });

        if (!preCheck.allowed) {
            return {
                total_cost: 0,
                currency: 'USD',
                period_start: '',
                period_end: '',
                breakdown_by_service: [],
                top_services: [],
                daily_average: 0,
                month_over_month_change: null,
                data_available: false,
                data_source: 'error',
                error_message: preCheck.reason,
            };
        }

        try {
            // Calculate default date range (current month)
            const now = new Date();
            const startDate = options?.startDate ||
                `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
            const endDate = options?.endDate ||
                `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;

            // Call through Supabase Edge Function relay
            // The Edge Function uses AWS SDK v3 with STS credentials
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'get_cost_and_usage',
                        organization_id: organizationId,
                        params: {
                            time_period: { start: startDate, end: endDate },
                            granularity: options?.granularity || 'MONTHLY',
                            group_by: [{
                                type: 'DIMENSION',
                                key: options?.groupBy || 'SERVICE',
                            }],
                            metrics: ['UnblendedCost', 'UsageQuantity'],
                        },
                    },
                }
            );

            if (error) throw error;

            // Parse AWS Cost Explorer response
            const costResult = this.parseAWSCostResponse(data, startDate, endDate);

            // Cache the result
            await this.persistCostData(organizationId, costResult);

            // Track API usage
            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'aws',
                endpoint: 'ce/getCostAndUsage',
                requestMetadata: {
                    total_cost: costResult.total_cost,
                    services_count: costResult.breakdown_by_service.length,
                },
            });

            return costResult;
        } catch (error) {
            console.error('[AWSCostExplorerConnector] Cost analysis failed:', error);
            // Fall back to cached data
            return this.getCachedCostData(organizationId);
        }
    }

    /**
     * Get cost forecast for the remainder of the billing period.
     */
    static async getCostForecast(
        organizationId: string,
        forecastDays: number = 30
    ): Promise<CostForecastResult> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential) {
            return {
                forecasted_total: 0,
                currency: 'USD',
                forecast_start: '',
                forecast_end: '',
                confidence_level: 0,
                data_available: false,
                data_source: 'not_configured',
                error_message: 'AWS credentials not configured.',
            };
        }

        try {
            const now = new Date();
            const forecastEnd = new Date(now.getTime() + forecastDays * 24 * 60 * 60 * 1000);

            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'get_cost_forecast',
                        organization_id: organizationId,
                        params: {
                            time_period: {
                                start: now.toISOString().split('T')[0],
                                end: forecastEnd.toISOString().split('T')[0],
                            },
                            metric: 'UNBLENDED_COST',
                            granularity: 'MONTHLY',
                        },
                    },
                }
            );

            if (error) throw error;

            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'aws',
                endpoint: 'ce/getCostForecast',
                requestMetadata: { forecast_days: forecastDays },
            });

            return {
                forecasted_total: data?.total?.amount || 0,
                currency: data?.total?.unit || 'USD',
                forecast_start: now.toISOString().split('T')[0],
                forecast_end: forecastEnd.toISOString().split('T')[0],
                confidence_level: data?.confidence_level || 0,
                data_available: true,
                data_source: 'aws_cost_explorer',
            };
        } catch (error) {
            console.error('[AWSCostExplorerConnector] Forecast failed:', error);
            return {
                forecasted_total: 0,
                currency: 'USD',
                forecast_start: '',
                forecast_end: '',
                confidence_level: 0,
                data_available: false,
                data_source: 'not_configured',
                error_message: error instanceof Error ? error.message : 'Forecast error',
            };
        }
    }

    // ─── Private Helpers ───────────────────────────────────────────────────────

    private static parseAWSCostResponse(
        data: any,
        startDate: string,
        endDate: string
    ): CostAnalysisResult {
        const results = data?.results_by_time || [];
        const breakdown: CostBreakdown[] = [];
        let totalCost = 0;

        for (const period of results) {
            for (const group of (period.groups || [])) {
                const serviceName = group.keys?.[0] || 'Unknown';
                const amount = Number.parseFloat(group.metrics?.UnblendedCost?.amount || '0');
                totalCost += amount;

                const existing = breakdown.find(b => b.service === serviceName);
                if (existing) {
                    existing.amount += amount;
                } else {
                    breakdown.push({
                        service: serviceName,
                        amount,
                        currency: group.metrics?.UnblendedCost?.unit || 'USD',
                        percentage_of_total: 0, // Calculated below
                    });
                }
            }
        }

        // Calculate percentages and sort
        for (const item of breakdown) {
            item.percentage_of_total = totalCost > 0
                ? Math.round((item.amount / totalCost) * 10000) / 100
                : 0;
        }
        breakdown.sort((a, b) => b.amount - a.amount);

        // Calculate daily average
        const startMs = new Date(startDate).getTime();
        const endMs = new Date(endDate).getTime();
        const days = Math.max(1, (endMs - startMs) / (24 * 60 * 60 * 1000));

        return {
            total_cost: Math.round(totalCost * 100) / 100,
            currency: 'USD',
            period_start: startDate,
            period_end: endDate,
            breakdown_by_service: breakdown,
            top_services: breakdown.slice(0, 5),
            daily_average: Math.round((totalCost / days) * 100) / 100,
            month_over_month_change: null, // Requires previous period data
            data_available: true,
            data_source: 'aws_cost_explorer',
        };
    }

    private static async getCachedCostData(
        organizationId: string
    ): Promise<CostAnalysisResult> {
        try {
            const { data, error } = await supabase
                .from('open_controls_performance_metrics')
                .select('metric_metadata')
                .eq('organization_id', organizationId)
                .eq('metric_type', 'aws_cost_analysis')
                .order('created_at', { ascending: false })
                .limit(1)
                .maybeSingle();

            if (error) throw error;
            const cached = data?.metric_metadata as unknown as CostAnalysisResult | null;

            if (cached) {
                return { ...cached, data_source: 'supabase_cached' };
            }
        } catch (error) {
            console.error('[AWSCostExplorerConnector] Cache retrieval failed:', error);
        }

        return {
            total_cost: 0,
            currency: 'USD',
            period_start: '',
            period_end: '',
            breakdown_by_service: [],
            top_services: [],
            daily_average: 0,
            month_over_month_change: null,
            data_available: false,
            data_source: 'not_configured',
            error_message: 'AWS Cost Explorer not configured. Add AWS credentials in Settings > Integrations.',
        };
    }

    private static async persistCostData(
        organizationId: string,
        costData: CostAnalysisResult
    ): Promise<void> {
        try {
            await supabase
                .from('open_controls_performance_metrics')
                .insert({
                    organization_id: organizationId,
                    metric_type: 'aws_cost_analysis',
                    metric_name: `aws_cost_${Date.now()}`,
                    metric_value: costData.total_cost,
                    metric_metadata: costData as any,
                });
        } catch (error) {
            console.error('[AWSCostExplorerConnector] Persistence failed:', error);
        }
    }
}
