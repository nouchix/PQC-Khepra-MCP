/**
 * Microsoft Defender Threat Intelligence Connector
 * ═══════════════════════════════════════════════════
 *
 * Replaces INT-012 (mock DISA auth) and INT-021 (hardcoded predictive insights)
 * with real threat intelligence from Microsoft Defender TI (MDTI) via Microsoft Graph API.
 *
 * Capabilities:
 *   - Threat indicators (IoCs) — IP, domain, URL, file hash reputation
 *   - Vulnerability articles — CVE enrichment with Microsoft analysis
 *   - Threat articles — APT group profiles, campaigns, and techniques
 *   - WHOIS/passive DNS enrichment — domain intelligence
 *
 * Authentication: OAuth 2.0 Client Credentials (Microsoft Entra ID)
 *   - Tenant ID, Client ID, Client Secret stored in IntegrationKeyService
 *   - Token automatically refreshed via Supabase Edge Function
 *
 * API: Microsoft Graph Security API v1.0 + Threat Intelligence beta
 * Documentation: https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview
 */

import { supabase } from '@/integrations/supabase/client';
import { IntegrationKeyService } from './IntegrationKeyService';
import { apiCostTracker } from '../ExternalApiCostTracker';

// ─── Response Types ────────────────────────────────────────────────────────────

export interface ThreatIndicator {
    id: string;
    indicator_type: 'ip' | 'domain' | 'url' | 'file_hash' | 'email';
    value: string;
    severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
    confidence: number;  // 0-100
    source: string;
    first_seen: string;
    last_seen: string;
    tags: string[];
    description: string;
    kill_chain_phases?: string[];
    threat_type?: string;
}

export interface VulnerabilityArticle {
    cve_id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    cvss_score: number;
    description: string;
    published_date: string;
    last_modified_date: string;
    exploited_in_wild: boolean;
    has_patch: boolean;
    affected_products: string[];
    mitigations: string[];
    references: string[];
}

export interface ThreatArticle {
    id: string;
    title: string;
    description: string;
    first_published: string;
    last_updated: string;
    tags: string[];
    threat_actors: string[];
    techniques: Array<{
        technique_id: string; // MITRE ATT&CK ID
        name: string;
        tactic: string;
    }>;
    indicators_count: number;
}

export interface ThreatIntelligenceResult {
    indicators: ThreatIndicator[];
    total_indicators: number;
    data_available: boolean;
    data_source: 'microsoft_defender_ti' | 'not_configured' | 'error';
    error_message?: string;
}

export interface CVEEnrichmentResult {
    article: VulnerabilityArticle | null;
    data_available: boolean;
    data_source: 'microsoft_defender_ti' | 'not_configured' | 'error';
    error_message?: string;
}

// ─── Connector Implementation ──────────────────────────────────────────────────

export class MicrosoftDefenderTIConnector {
    private static readonly PROVIDER = 'microsoft' as const;
    private static readonly RELAY_FUNCTION = 'msft-ti-relay';

    /**
     * Query threat indicators from Microsoft Defender TI.
     * Replaces INT-021: hardcoded 2 predictive insights.
     */
    static async queryThreatIndicators(
        organizationId: string,
        options?: {
            /** Filter by indicator type */
            type?: 'ip' | 'domain' | 'url' | 'file_hash';
            /** Minimum severity */
            minSeverity?: 'low' | 'medium' | 'high' | 'critical';
            /** Specific values to look up */
            values?: string[];
            /** Max results */
            limit?: number;
        }
    ): Promise<ThreatIntelligenceResult> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential) {
            return {
                indicators: [],
                total_indicators: 0,
                data_available: false,
                data_source: 'not_configured',
                error_message: 'Microsoft Defender TI not configured. Add Microsoft Graph API credentials in Settings > Integrations.',
            };
        }

        const preCheck = await apiCostTracker.preCallCheck({
            organizationId,
            apiProvider: 'microsoft',
            endpoint: 'security/threatIntelligence',
        });

        if (!preCheck.allowed) {
            return {
                indicators: [],
                total_indicators: 0,
                data_available: false,
                data_source: 'error',
                error_message: preCheck.reason,
            };
        }

        try {
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'query_indicators',
                        organization_id: organizationId,
                        params: {
                            type: options?.type,
                            min_severity: options?.minSeverity,
                            values: options?.values?.slice(0, 50), // Cap batch size
                            limit: Math.min(options?.limit || 25, 100),
                        },
                    },
                }
            );

            if (error) throw error;

            const indicators: ThreatIndicator[] = (data?.indicators || []).map(
                (raw: any) => this.parseThreatIndicator(raw)
            );

            // Track API usage
            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'microsoft',
                endpoint: 'security/threatIntelligence',
                requestMetadata: {
                    indicators_returned: indicators.length,
                    query_type: options?.type || 'all',
                },
            });

            // Persist for dashboard
            await this.persistIndicators(organizationId, indicators);

            return {
                indicators,
                total_indicators: data?.total_count || indicators.length,
                data_available: indicators.length > 0,
                data_source: 'microsoft_defender_ti',
            };
        } catch (error) {
            console.error('[MicrosoftDefenderTI] Indicator query failed:', error);
            return {
                indicators: [],
                total_indicators: 0,
                data_available: false,
                data_source: 'error',
                error_message: error instanceof Error ? error.message : 'MDTI API error',
            };
        }
    }

    /**
     * Enrich a CVE with Microsoft Defender TI analysis.
     * Provides exploit-in-the-wild data, patch availability, and mitigations.
     */
    static async enrichCVE(
        organizationId: string,
        cveId: string
    ): Promise<CVEEnrichmentResult> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential) {
            return {
                article: null,
                data_available: false,
                data_source: 'not_configured',
                error_message: 'Microsoft Defender TI not configured.',
            };
        }

        // Validate CVE ID format (CVE-YYYY-NNNNN)
        if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
            return {
                article: null,
                data_available: false,
                data_source: 'error',
                error_message: `Invalid CVE ID format: ${cveId}`,
            };
        }

        try {
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'enrich_cve',
                        organization_id: organizationId,
                        params: { cve_id: cveId },
                    },
                }
            );

            if (error) throw error;

            if (!data?.article) {
                return {
                    article: null,
                    data_available: false,
                    data_source: 'microsoft_defender_ti',
                    error_message: `No MDTI data found for ${cveId}`,
                };
            }

            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'microsoft',
                endpoint: 'security/vulnerabilities',
                requestMetadata: { cve_id: cveId },
            });

            return {
                article: this.parseVulnerabilityArticle(data.article),
                data_available: true,
                data_source: 'microsoft_defender_ti',
            };
        } catch (error) {
            console.error('[MicrosoftDefenderTI] CVE enrichment failed:', error);
            return {
                article: null,
                data_available: false,
                data_source: 'error',
                error_message: error instanceof Error ? error.message : 'CVE enrichment error',
            };
        }
    }

    /**
     * Get threat articles (APT profiles, campaign analysis).
     */
    static async getThreatArticles(
        organizationId: string,
        options?: {
            keyword?: string;
            threat_actor?: string;
            limit?: number;
        }
    ): Promise<{
        articles: ThreatArticle[];
        total_count: number;
        data_available: boolean;
        data_source: string;
        error_message?: string;
    }> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential) {
            return {
                articles: [],
                total_count: 0,
                data_available: false,
                data_source: 'not_configured',
                error_message: 'Microsoft Defender TI not configured.',
            };
        }

        try {
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'get_articles',
                        organization_id: organizationId,
                        params: {
                            keyword: options?.keyword,
                            threat_actor: options?.threat_actor,
                            limit: Math.min(options?.limit || 10, 50),
                        },
                    },
                }
            );

            if (error) throw error;

            const articles: ThreatArticle[] = (data?.articles || []).map(
                (raw: any) => this.parseThreatArticle(raw)
            );

            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'microsoft',
                endpoint: 'security/threatIntelligence/articles',
                requestMetadata: { articles_returned: articles.length },
            });

            return {
                articles,
                total_count: data?.total_count || articles.length,
                data_available: articles.length > 0,
                data_source: 'microsoft_defender_ti',
            };
        } catch (error) {
            console.error('[MicrosoftDefenderTI] Article query failed:', error);
            return {
                articles: [],
                total_count: 0,
                data_available: false,
                data_source: 'error',
                error_message: error instanceof Error ? error.message : 'Article query error',
            };
        }
    }

    // ─── Private Helpers ───────────────────────────────────────────────────────

    private static parseThreatIndicator(raw: any): ThreatIndicator {
        return {
            id: raw.id || '',
            indicator_type: raw.pattern_type || raw.indicator_type || 'ip',
            value: raw.pattern || raw.value || '',
            severity: raw.severity || 'informational',
            confidence: raw.confidence || 0,
            source: raw.source || 'Microsoft Defender TI',
            first_seen: raw.first_seen_date_time || raw.first_seen || new Date().toISOString(),
            last_seen: raw.last_seen_date_time || raw.last_seen || new Date().toISOString(),
            tags: raw.tags || [],
            description: raw.description || '',
            kill_chain_phases: raw.kill_chain_phases || [],
            threat_type: raw.threat_type || undefined,
        };
    }

    private static parseVulnerabilityArticle(raw: any): VulnerabilityArticle {
        return {
            cve_id: raw.id || raw.cve_id || '',
            title: raw.title || raw.name || '',
            severity: raw.severity || 'medium',
            cvss_score: raw.cvss_score || raw.cvssV3?.baseScore || 0,
            description: raw.description || '',
            published_date: raw.published_date_time || raw.published_date || '',
            last_modified_date: raw.last_modified_date_time || raw.last_modified_date || '',
            exploited_in_wild: raw.exploited_in_wild || raw.hasExploit || false,
            has_patch: raw.has_patch || raw.hasFix || false,
            affected_products: raw.affected_products || raw.components?.map((c: any) => c.name) || [],
            mitigations: raw.mitigations || [],
            references: raw.references || [],
        };
    }

    private static parseThreatArticle(raw: any): ThreatArticle {
        return {
            id: raw.id || '',
            title: raw.title || '',
            description: raw.description || '',
            first_published: raw.created_date_time || raw.first_published || '',
            last_updated: raw.last_updated_date_time || raw.last_updated || '',
            tags: raw.tags || [],
            threat_actors: raw.actors?.map((a: any) => a.name || a) || [],
            techniques: (raw.indicators_related || raw.techniques || []).map((t: any) => ({
                technique_id: t.id || t.technique_id || '',
                name: t.name || '',
                tactic: t.tactic || '',
            })),
            indicators_count: raw.indicators_count || 0,
        };
    }

    private static async persistIndicators(
        organizationId: string,
        indicators: ThreatIndicator[]
    ): Promise<void> {
        try {
            const severityBreakdown = {
                critical: indicators.filter(i => i.severity === 'critical').length,
                high: indicators.filter(i => i.severity === 'high').length,
                medium: indicators.filter(i => i.severity === 'medium').length,
                low: indicators.filter(i => i.severity === 'low').length,
                informational: indicators.filter(i => i.severity === 'informational').length,
            };

            await supabase
                .from('open_controls_performance_metrics')
                .insert({
                    organization_id: organizationId,
                    metric_type: 'mdti_threat_indicators',
                    metric_name: `mdti_indicators_${Date.now()}`,
                    metric_value: indicators.length,
                    metric_metadata: {
                        source: 'microsoft_defender_ti',
                        total_indicators: indicators.length,
                        severity_breakdown: severityBreakdown,
                        ingested_at: new Date().toISOString(),
                    } as any,
                });
        } catch (error) {
            console.error('[MicrosoftDefenderTI] Persistence failed:', error);
        }
    }
}
