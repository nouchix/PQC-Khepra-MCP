/**
 * STIGViewer Connector — Frontend Service
 * ════════════════════════════════════════
 *
 * Uses STIGViewer API for compliance scoring and STIG catalog enrichment.
 *
 * Architecture (per STIGVIEWER_STRATEGY_MITOCHONDRIA.md):
 *
 *   Browser → Supabase Edge Function (relay) → Gateway (Zone 2)
 *     → mTLS → stig_connector (Zone 1 DMZ) → STIGViewer API (Zone 0)
 *
 * The browser NEVER calls the STIGViewer API directly.
 * All requests route through the DMZ connector via the mitochondrial API server.
 *
 * API Token Storage:
 *   - Stored encrypted in `enhanced_open_controls_integrations` table
 *   - Retrieved by the DMZ stig_connector via Vault (Go side)
 *   - Frontend only sees sanitized, validated results
 */

import { supabase } from '@/integrations/supabase/client';
import { IntegrationKeyService } from './IntegrationKeyService';
import { apiCostTracker } from '../ExternalApiCostTracker';

// ─── Response Types ────────────────────────────────────────────────────────────

export interface STIGViewerRule {
    rule_id: string;
    title: string;
    severity: 'CAT_I' | 'CAT_II' | 'CAT_III';
    complexity?: 'LOW' | 'MEDIUM' | 'HIGH';
    owner_roles: string[];
    description: string;
    controls: string[];
    atomic_requirements?: Array<{
        id: string;
        description: string;
        testable: boolean;
        automatable: boolean;
    }>;
    role_mappings?: Array<{
        role: string;
        responsibility: string;
    }>;
}

export interface STIGCatalogResult {
    stigs: Array<{
        stig_id: string;
        title: string;
        version: string;
        release: string;
        rule_count: number;
        benchmark_date: string;
    }>;
    total_count: number;
    data_source: 'stigviewer_api' | 'supabase_cache' | 'not_configured';
    fetched_at: string;
    error_message?: string;
}

export interface ComplianceScoreResult {
    overall_score: number | null;
    cat_i_findings: number;
    cat_ii_findings: number;
    cat_iii_findings: number;
    total_checks: number;
    passed_checks: number;
    failed_checks: number;
    not_applicable: number;
    data_available: boolean;
    data_source: 'stigviewer_computed' | 'supabase_computed' | 'not_configured';
    error_message?: string;
    breakdown_by_stig?: Array<{
        stig_id: string;
        score: number;
        total: number;
        passed: number;
    }>;
}

export interface STIGQueryOptions {
    stig_id?: string;
    rule_id?: string;
    severity?: 'CAT_I' | 'CAT_II' | 'CAT_III';
    keyword?: string;
    limit?: number;
    offset?: number;
}

// ─── Connector Implementation ──────────────────────────────────────────────────

export class STIGViewerConnector {
    private static readonly PROVIDER = 'stigviewer' as const;
    private static readonly RELAY_FUNCTION = 'stig-relay';

    /**
     * Query STIG rules via the DMZ connector.
     *
     * Flow: Browser → Supabase Edge Function → Gateway → DMZ → STIGViewer API
     *
     * The Edge Function acts as the relay between the browser and the
     * Go gateway running in Zone 2, which then calls the DMZ stig_connector
     * in Zone 1 via mTLS.
     */
    static async querySTIGs(
        organizationId: string,
        options?: STIGQueryOptions
    ): Promise<{
        rules: STIGViewerRule[];
        total_count: number;
        cache_hit: boolean;
        source: string;
    }> {
        // 1. Verify integration is configured
        const isConfigured = await this.isConfigured(organizationId);
        if (!isConfigured) {
            return {
                rules: [],
                total_count: 0,
                cache_hit: false,
                source: 'not_configured',
            };
        }

        // 2. Rate limit pre-check
        const preCheck = await apiCostTracker.preCallCheck({
            organizationId,
            apiProvider: 'stigviewer',
            endpoint: 'api/stigs',
        });

        if (!preCheck.allowed) {
            return {
                rules: [],
                total_count: 0,
                cache_hit: false,
                source: 'rate_limited',
            };
        }

        try {
            // 3. Call through Supabase Edge Function relay
            //    The Edge Function forwards to the Go gateway (Zone 2)
            //    which forwards to stig_connector (Zone 1 DMZ) via mTLS
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'query_stigs',
                        organization_id: organizationId,
                        filter: {
                            stig_id: options?.stig_id,
                            rule_id: options?.rule_id,
                            severity: options?.severity,
                            keyword: options?.keyword,
                            limit: Math.min(options?.limit || 50, 200),
                            offset: options?.offset || 0,
                        },
                    },
                }
            );

            if (error) throw error;

            // 4. Track API usage
            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'stigviewer',
                endpoint: 'api/stigs',
                requestMetadata: {
                    rules_returned: data?.rules?.length || 0,
                    cache_hit: data?.cache_hit || false,
                },
            });

            return {
                rules: data?.rules || [],
                total_count: data?.total_count || 0,
                cache_hit: data?.cache_hit || false,
                source: data?.source || 'stigviewer_api',
            };
        } catch (error) {
            console.error('[STIGViewerConnector] Query failed:', error);
            return {
                rules: [],
                total_count: 0,
                cache_hit: false,
                source: 'error',
            };
        }
    }

    /**
     * Fetch the STIG catalog (list of available STIGs).
     */
    static async fetchCatalog(
        organizationId: string
    ): Promise<STIGCatalogResult> {
        const isConfigured = await this.isConfigured(organizationId);
        if (!isConfigured) {
            // Fall back to Supabase-cached catalog if available
            return this.getCachedCatalog(organizationId);
        }

        try {
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'get_catalog',
                        organization_id: organizationId,
                    },
                }
            );

            if (error) throw error;

            // Persist catalog to Supabase for offline availability
            if (data?.stigs?.length > 0) {
                await this.persistCatalog(organizationId, data.stigs);
            }

            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'stigviewer',
                endpoint: 'api/catalog',
                requestMetadata: { stigs_returned: data?.stigs?.length || 0 },
            });

            return {
                stigs: data?.stigs || [],
                total_count: data?.total_count || 0,
                data_source: 'stigviewer_api',
                fetched_at: new Date().toISOString(),
            };
        } catch (error) {
            console.error('[STIGViewerConnector] Catalog fetch failed:', error);
            // Fall back to cached catalog
            return this.getCachedCatalog(organizationId);
        }
    }

    /**
     * Compute compliance score from actual STIG assessment results.
     *
     * When STIGViewer API is available, enriches scoring with decomposed
     * rule complexity and role mapping data.
     */
    static async computeComplianceScore(
        organizationId: string
    ): Promise<ComplianceScoreResult> {
        try {
            // 1. Get actual STIG assessment results from Supabase
            const { data: assessments, error: assessError } = await supabase
                .from('stig_assessment_results')
                .select('*')
                .eq('organization_id', organizationId)
                .order('assessed_at', { ascending: false })
                .limit(1000);

            if (assessError) throw assessError;

            if (!assessments || assessments.length === 0) {
                return {
                    overall_score: null,
                    cat_i_findings: 0,
                    cat_ii_findings: 0,
                    cat_iii_findings: 0,
                    total_checks: 0,
                    passed_checks: 0,
                    failed_checks: 0,
                    not_applicable: 0,
                    data_available: false,
                    data_source: 'not_configured',
                    error_message: 'No STIG assessment results found. Run a compliance scan first.',
                };
            }

            // 2. Aggregate results
            const {
                catI, catII, catIII, passed, failed, notApplicable, stigBreakdown
            } = this.aggregateAssessments(assessments);

            const totalChecks = passed + failed + notApplicable;
            const applicableChecks = passed + failed;

            // 3. Calculate weighted compliance score
            // CAT_I failures are weighted 10x, CAT_II 3x, CAT_III 1x
            const maxPenalty = applicableChecks > 0 ? applicableChecks * 10 : 1;
            const actualPenalty = (catI * 10) + (catII * 3) + (catIII * 1);
            const overallScore = applicableChecks > 0
                ? Math.max(0, Math.round((1 - actualPenalty / maxPenalty) * 100))
                : null;

            return {
                overall_score: overallScore,
                cat_i_findings: catI,
                cat_ii_findings: catII,
                cat_iii_findings: catIII,
                total_checks: totalChecks,
                passed_checks: passed,
                failed_checks: failed,
                not_applicable: notApplicable,
                data_available: true,
                data_source: 'supabase_computed',
                breakdown_by_stig: Array.from(stigBreakdown.entries()).map(([stigId, stats]) => ({
                    stig_id: stigId,
                    score: stats.total > 0 ? Math.round((stats.passed / stats.total) * 100) : 0,
                    total: stats.total,
                    passed: stats.passed,
                })),
            };
        } catch (error) {
            console.error('[STIGViewerConnector] Compliance score computation failed:', error);
            return {
                overall_score: null,
                cat_i_findings: 0,
                cat_ii_findings: 0,
                cat_iii_findings: 0,
                total_checks: 0,
                passed_checks: 0,
                failed_checks: 0,
                not_applicable: 0,
                data_available: false,
                data_source: 'not_configured',
                error_message: error instanceof Error ? error.message : 'Unknown error',
            };
        }
    }

    /**
     * Get connector health status (circuit breaker state, cache stats).
     */
    static async getHealthStatus(organizationId: string): Promise<{
        configured: boolean;
        circuit_state: string;
        connector_zone: string;
    }> {
        const isConfigured = await this.isConfigured(organizationId);
        if (!isConfigured) {
            return {
                configured: false,
                circuit_state: 'not_configured',
                connector_zone: 'n/a',
            };
        }

        try {
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'health',
                        organization_id: organizationId,
                    },
                }
            );

            if (error) throw error;

            return {
                configured: true,
                circuit_state: data?.circuit_state || 'unknown',
                connector_zone: 'dmz',
            };
        } catch {
            return {
                configured: true,
                circuit_state: 'unreachable',
                connector_zone: 'dmz',
            };
        }
    }

    // ─── Private Helpers ───────────────────────────────────────────────────────

    /**
     * Check if the STIGViewer integration is configured for an organization.
     * The API token is stored in Supabase (encrypted), retrieved by the Go
     * DMZ connector via Vault — never by the frontend.
     */
    private static async isConfigured(organizationId: string): Promise<boolean> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            'stigviewer' as any  // Provider type to be added
        );
        return credential?.is_active ?? false;
    }

    /**
     * Get cached STIG catalog from Supabase when API is unavailable.
     */
    private static async getCachedCatalog(
        organizationId: string
    ): Promise<STIGCatalogResult> {
        try {
            const { data, error } = await supabase
                .from('open_controls_performance_metrics')
                .select('metric_metadata')
                .eq('organization_id', organizationId)
                .eq('metric_type', 'stig_catalog_cache')
                .order('created_at', { ascending: false })
                .limit(1)
                .maybeSingle();

            if (error) throw error;

            const metadata = data?.metric_metadata as Record<string, any> | null;
            if (metadata?.stigs) {
                return {
                    stigs: metadata.stigs,
                    total_count: metadata.stigs.length,
                    data_source: 'supabase_cache',
                    fetched_at: metadata.cached_at || new Date().toISOString(),
                };
            }

            return {
                stigs: [],
                total_count: 0,
                data_source: 'not_configured',
                fetched_at: new Date().toISOString(),
                error_message: 'STIGViewer API not configured and no cached catalog available.',
            };
        } catch (error) {
            console.error('[STIGViewerConnector] Cached catalog retrieval failed:', error);
            return {
                stigs: [],
                total_count: 0,
                data_source: 'not_configured',
                fetched_at: new Date().toISOString(),
                error_message: 'Failed to retrieve cached catalog.',
            };
        }
    }

    /**
     * Persist catalog to Supabase for offline/cache availability.
     */
    private static async persistCatalog(
        organizationId: string,
        stigs: STIGCatalogResult['stigs']
    ): Promise<void> {
        try {
            await supabase
                .from('open_controls_performance_metrics')
                .insert({
                    organization_id: organizationId,
                    metric_type: 'stig_catalog_cache',
                    metric_name: `stig_catalog_${Date.now()}`,
                    metric_value: stigs.length,
                    metric_metadata: {
                        source: 'stigviewer_api',
                        stigs,
                        cached_at: new Date().toISOString(),
                    },
                });
        } catch (error) {
            console.error('[STIGViewerConnector] Catalog persistence failed:', error);
        }
    }

    /**
     * Aggregates assessment results into categories and stats.
     */
    private static aggregateAssessments(assessments: any[]) {
        let catI = 0, catII = 0, catIII = 0;
        let passed = 0, failed = 0, notApplicable = 0;
        const stigBreakdown = new Map<string, { total: number; passed: number }>();

        for (const result of assessments) {
            const status = result.status as string;
            const severity = result.severity as string;
            const stigId = result.stig_id as string;

            if (status === 'pass' || status === 'passed') {
                passed++;
            } else if (status === 'not_applicable' || status === 'na') {
                notApplicable++;
            } else {
                failed++;
                if (severity === 'CAT_I' || severity === 'high') catI++;
                else if (severity === 'CAT_II' || severity === 'medium') catII++;
                else if (severity === 'CAT_III' || severity === 'low') catIII++;
            }

            if (stigId) {
                const existing = stigBreakdown.get(stigId) || { total: 0, passed: 0 };
                existing.total++;
                if (status === 'pass' || status === 'passed') existing.passed++;
                stigBreakdown.set(stigId, existing);
            }
        }

        return { catI, catII, catIII, passed, failed, notApplicable, stigBreakdown };
    }
}
