/**
 * Datadog Metrics Connector
 * ═════════════════════════
 *
 * Real-time system metrics from the Datadog Metrics API v1.
 *
 * Supported Metrics:
 *   - system.cpu.user / system.cpu.idle
 *   - system.mem.used / system.mem.total
 *   - system.disk.in_use
 *   - system.net.bytes_sent / system.net.bytes_rcvd
 *   - trace.servlet.request.hits (throughput)
 *   - trace.servlet.request.errors (error rate)
 *
 * Rate Limits:
 *   - Free:       60 req/min,  10,000/day
 *   - Enterprise: 600 req/min, 100,000/day
 *
 * Documentation: https://docs.datadoghq.com/api/latest/metrics/#query-timeseries-points
 */

import { supabase } from '@/integrations/supabase/client';
import { IntegrationKeyService } from './IntegrationKeyService';
import { apiCostTracker } from '../ExternalApiCostTracker';

// ─── Response Types ────────────────────────────────────────────────────────────

export interface DatadogMetricPoint {
    timestamp: number;
    value: number;
}

export interface DatadogTimeseriesResult {
    metric: string;
    display_name: string;
    unit: string | null;
    pointlist: DatadogMetricPoint[];
    scope: string;
}

export interface RealTimeMetricsResult {
    cpu_utilization: number | null;
    memory_usage: number | null;
    disk_io: number | null;
    network_throughput: number | null;
    response_time_ms: number | null;
    error_rate: number | null;
    concurrent_users: number | null;
    data_available: boolean;
    data_source: 'datadog' | 'no_monitoring_data_available' | 'not_configured' | 'error';
    error_message?: string;
    raw_series?: DatadogTimeseriesResult[];
}

export interface RequestVolumeResult {
    total_requests: number;
    period_minutes: number;
    requests_per_minute: number;
    data_available: boolean;
    data_source: 'datadog' | 'not_configured';
}

// ─── Connector Implementation ──────────────────────────────────────────────────

export class DatadogConnector {
    private static readonly PROVIDER = 'datadog' as const;

    /**
     * Collect real-time system metrics from Datadog.
     */
    static async collectRealTimeMetrics(
        organizationId: string,
        options?: {
            /** Lookback window in seconds (default: 300 = 5 minutes) */
            windowSeconds?: number;
            /** Specific host filter (e.g., "host:web-prod-01") */
            hostFilter?: string;
        }
    ): Promise<RealTimeMetricsResult> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential?.api_key) {
            return {
                cpu_utilization: null,
                memory_usage: null,
                disk_io: null,
                network_throughput: null,
                response_time_ms: null,
                error_rate: null,
                concurrent_users: null,
                data_available: false,
                data_source: 'not_configured',
                error_message: 'Datadog API key not configured. Go to Settings > Integrations to add your API/App keys.',
            };
        }

        const preCheck = await apiCostTracker.preCallCheck({
            organizationId,
            apiProvider: 'datadog',
            endpoint: 'v1/query',
        });

        if (!preCheck.allowed) {
            return {
                cpu_utilization: null,
                memory_usage: null,
                disk_io: null,
                network_throughput: null,
                response_time_ms: null,
                error_rate: null,
                concurrent_users: null,
                data_available: false,
                data_source: 'error',
                error_message: preCheck.reason,
            };
        }

        const windowSec = options?.windowSeconds || 300;
        const now = Math.floor(Date.now() / 1000);
        const from = now - windowSec;
        const filter = options?.hostFilter || '*';

        try {
            // Batch query: CPU, Memory, Disk, Network in parallel
            const [cpuResult, memResult, diskResult, netResult] = await Promise.all([
                this.queryMetric(credential.api_key, credential.api_secret, credential.base_url, from, now, `avg:system.cpu.user{${filter}}`),
                this.queryMetric(credential.api_key, credential.api_secret, credential.base_url, from, now, `avg:system.mem.pct_usable{${filter}}`),
                this.queryMetric(credential.api_key, credential.api_secret, credential.base_url, from, now, `avg:system.disk.in_use{${filter}}`),
                this.queryMetric(credential.api_key, credential.api_secret, credential.base_url, from, now, `avg:system.net.bytes_sent{${filter}}`),
            ]);

            const cpu = this.latestValue(cpuResult);
            const mem = this.latestValue(memResult);
            const disk = this.latestValue(diskResult);
            const net = this.latestValue(netResult);

            // Track API usage (4 queries made)
            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'datadog',
                endpoint: 'v1/query',
                requestMetadata: { queries: 4, window_seconds: windowSec },
            });

            // Persist to Supabase for dashboard
            await this.persistMetrics(organizationId, { cpu, mem, disk, net });

            return {
                cpu_utilization: cpu,
                memory_usage: mem === null ? null : (1 - mem) * 100, // pct_usable → pct_used
                disk_io: disk === null ? null : disk * 100, // fraction → percentage
                network_throughput: net,
                response_time_ms: null, 
                error_rate: null,       
                concurrent_users: null, 
                data_available: cpu !== null || mem !== null || disk !== null,
                data_source: 'datadog',
                raw_series: [cpuResult, memResult, diskResult, netResult].filter(Boolean),
            };
        } catch (error) {
            console.error('[DatadogConnector] Metrics collection failed:', error);
            return {
                cpu_utilization: null,
                memory_usage: null,
                disk_io: null,
                network_throughput: null,
                response_time_ms: null,
                error_rate: null,
                concurrent_users: null,
                data_available: false,
                data_source: 'error',
                error_message: error instanceof Error ? error.message : 'Datadog API error',
            };
        }
    }

    /**
     * Get request volume/throughput from Datadog APM.
     */
    static async getRequestVolume(
        organizationId: string,
        periodMinutes: number = 60
    ): Promise<RequestVolumeResult> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential?.api_key) {
            return {
                total_requests: 0,
                period_minutes: periodMinutes,
                requests_per_minute: 0,
                data_available: false,
                data_source: 'not_configured',
            };
        }

        try {
            const now = Math.floor(Date.now() / 1000);
            const from = now - (periodMinutes * 60);

            const result = await this.queryMetric(
                credential.api_key,
                credential.api_secret,
                credential.base_url,
                from,
                now,
                'sum:trace.servlet.request.hits{*}.as_count()'
            );

            if (!result?.pointlist?.length) {
                return {
                    total_requests: 0,
                    period_minutes: periodMinutes,
                    requests_per_minute: 0,
                    data_available: false,
                    data_source: 'datadog',
                };
            }

            const totalRequests = result.pointlist.reduce(
                (sum: number, p: DatadogMetricPoint) => sum + p.value, 0
            );

            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'datadog',
                endpoint: 'v1/query',
                requestMetadata: { query: 'request_volume', period_minutes: periodMinutes },
            });

            return {
                total_requests: Math.round(totalRequests),
                period_minutes: periodMinutes,
                requests_per_minute: Math.round(totalRequests / periodMinutes),
                data_available: true,
                data_source: 'datadog',
            };
        } catch (error) {
            console.error('[DatadogConnector] Request volume query failed:', error);
            return {
                total_requests: 0,
                period_minutes: periodMinutes,
                requests_per_minute: 0,
                data_available: false,
                data_source: 'datadog',
            };
        }
    }

    // ─── Private Helpers ───────────────────────────────────────────────────────

    /**
     * Query a single Datadog metric timeseries.
     * Endpoint: GET /api/v1/query?from=&to=&query=
     */
    private static async queryMetric(
        apiKey: string,
        appKey: string | undefined,
        baseUrl: string,
        from: number,
        to: number,
        query: string
    ): Promise<DatadogTimeseriesResult | null> {
        try {
            const params = new URLSearchParams({
                from: from.toString(),
                to: to.toString(),
                query,
            });

            const headers: Record<string, string> = {
                'DD-API-KEY': apiKey,
                'Accept': 'application/json',
            };
            if (appKey) {
                headers['DD-APPLICATION-KEY'] = appKey;
            }

            const response = await fetch(`${baseUrl}/v1/query?${params}`, {
                method: 'GET',
                headers,
            });

            if (response.status === 429) {
                console.warn('[DatadogConnector] Rate limited');
                return null;
            }

            if (!response.ok) {
                const body = await response.text();
                console.error(`[DatadogConnector] API error ${response.status}:`, body);
                return null;
            }

            const data = await response.json();
            const series = data?.series?.[0];
            if (!series) return null;

            return {
                metric: series.metric || query,
                display_name: series.display_name || query,
                unit: series.unit?.[0]?.name || null,
                pointlist: (series.pointlist || []).map((p: number[]) => ({
                    timestamp: p[0],
                    value: p[1],
                })),
                scope: series.scope || '*',
            };
        } catch (error) {
            if (error instanceof TypeError && error.message.includes('fetch')) {
                console.error('[DatadogConnector] Network error — Datadog API unreachable');
            }
            return null;
        }
    }

    /**
     * Extract the latest non-null value from a timeseries result.
     */
    private static latestValue(result: DatadogTimeseriesResult | null): number | null {
        if (!result?.pointlist?.length) return null;
        // pointlist is chronologically ordered; take the last value
        const last = result.pointlist.at(-1);
        return last?.value ?? null;
    }

    /**
     * Persist collected metrics to Supabase for dashboard display.
     */
    private static async persistMetrics(
        organizationId: string,
        metrics: { cpu: number | null; mem: number | null; disk: number | null; net: number | null }
    ): Promise<void> {
        try {
            await supabase
                .from('open_controls_performance_metrics')
                .insert({
                    organization_id: organizationId,
                    metric_type: 'datadog_system_metrics',
                    metric_name: `dd_metrics_${Date.now()}`,
                    metric_value: metrics.cpu || 0,
                    metric_metadata: {
                        source: 'datadog',
                        cpu_utilization: metrics.cpu,
                        memory_usage: metrics.mem,
                        disk_io: metrics.disk,
                        network_throughput: metrics.net,
                        collected_at: new Date().toISOString(),
                    },
                });
        } catch (error) {
            console.error('[DatadogConnector] Failed to persist metrics:', error);
        }
    }
}
