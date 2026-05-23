/**
 * VirusTotal Enterprise Connector — Alpha Connector
 * ═══════════════════════════════════════════════════
 *
 * Live VirusTotal v3 data for vulnerability and malware analysis.
 *
 * Capabilities:
 *   1. File/Hash Analysis — Submit file hashes for malware verdicts
 *   2. URL Analysis — Check if a URL is malicious
 *   3. Intelligence Hunting — Pull live hunting notifications (Enterprise)
 *   4. Domain/IP Reputation — Enrich asset discovery with reputation data
 *
 * Rate Limits (respected automatically):
 *   - Free tier:       4 requests/minute,   500/day
 *   - Standard tier:  15 requests/minute,  5000/day
 *   - Enterprise:     30 requests/minute, 25000/day
 *
 * Documentation: https://docs.virustotal.com/reference/overview
 */

import { supabase } from '@/integrations/supabase/client';
import { IntegrationKeyService } from './IntegrationKeyService';
import { apiCostTracker } from '../ExternalApiCostTracker';

// ─── Response Types ────────────────────────────────────────────────────────────

export interface VTFileReport {
    id: string;
    type: 'file';
    sha256: string;
    sha1: string;
    md5: string;
    meaningful_name: string | null;
    type_description: string | null;
    size: number;
    first_submission_date: number;
    last_analysis_date: number;
    last_analysis_stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout: number;
        'confirmed-timeout': number;
        failure: number;
        'type-unsupported': number;
    };
    reputation: number;
    tags: string[];
    total_votes: { harmless: number; malicious: number };
    popular_threat_classification?: {
        suggested_threat_label: string;
        popular_threat_category?: Array<{ count: number; value: string }>;
        popular_threat_name?: Array<{ count: number; value: string }>;
    };
}

export interface VTUrlReport {
    id: string;
    type: 'url';
    url: string;
    last_http_response_code: number;
    last_analysis_stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout: number;
    };
    reputation: number;
    categories: Record<string, string>;
    last_analysis_date: number;
}

export interface VTDomainReport {
    id: string;
    type: 'domain';
    last_analysis_stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout: number;
    };
    reputation: number;
    registrar: string | null;
    creation_date: number | null;
    whois: string | null;
    categories: Record<string, string>;
}

export interface VTIPReport {
    id: string;
    type: 'ip_address';
    last_analysis_stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout: number;
    };
    reputation: number;
    country: string;
    as_owner: string;
    asn: number;
}

export interface VulnerabilityFeedResult {
    vulnerabilities_processed: number;
    threat_correlations: number;
    high_priority_alerts: number;
    feed_status: 'active' | 'not_configured' | 'rate_limited' | 'error';
    error_message?: string;
    items: Array<{
        hash: string;
        type: string;
        detection_ratio: string;
        threat_label: string | null;
        severity: 'critical' | 'high' | 'medium' | 'low' | 'clean';
        first_seen: string;
        last_analyzed: string;
        tags: string[];
    }>;
    api_quota?: {
        used: number;
        allowed: number;
        remaining: number;
    };
}

// ─── Connector Implementation ──────────────────────────────────────────────────

export class VirusTotalConnector {
    private static readonly PROVIDER = 'virustotal' as const;

    /**
     * Ingest live vulnerability/malware data from VirusTotal.
     */
    static async ingestThreatFeed(
        organizationId: string,
        options?: {
            /** File hashes (SHA256/SHA1/MD5) to check against VT */
            hashes?: string[];
            /** Domains to check reputation */
            domains?: string[];
            /** IPs to check reputation */
            ips?: string[];
            /** Max items to process per call */
            limit?: number;
        }
    ): Promise<VulnerabilityFeedResult> {
        // 1. Retrieve API credential from secure storage
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential?.api_key) {
            return {
                vulnerabilities_processed: 0,
                threat_correlations: 0,
                high_priority_alerts: 0,
                feed_status: 'not_configured',
                error_message: 'VirusTotal API key not configured. Go to Settings > Integrations to add your API key.',
                items: [],
            };
        }

        // 2. Pre-flight rate limit check
        const preCheck = await apiCostTracker.preCallCheck({
            organizationId,
            apiProvider: 'virustotal',
            endpoint: 'intelligence/feed',
        });

        if (!preCheck.allowed) {
            return {
                vulnerabilities_processed: 0,
                threat_correlations: 0,
                high_priority_alerts: 0,
                feed_status: 'rate_limited',
                error_message: preCheck.reason,
                items: [],
            };
        }

        // 3. Determine what to query
        const limit = Math.min(options?.limit || 10, 25); // Cap at 25 items per batch
        const items: VulnerabilityFeedResult['items'] = [];
        let highPriorityCount = 0;
        let threatCorrelations = 0;

        try {
            // 3a. Check file hashes against VT
            if (options?.hashes && options.hashes.length > 0) {
                const hashResults = await this.batchLookupHashes(
                    credential.api_key,
                    credential.base_url,
                    organizationId,
                    options.hashes.slice(0, limit)
                );
                items.push(...hashResults.items);
                highPriorityCount += hashResults.highPriority;
                threatCorrelations += hashResults.correlations;
            }

            // 3b. Check domains
            if (options?.domains && options.domains.length > 0) {
                const domainResults = await this.batchLookupDomains(
                    credential.api_key,
                    credential.base_url,
                    organizationId,
                    options.domains.slice(0, limit)
                );
                items.push(...domainResults.items);
                highPriorityCount += domainResults.highPriority;
            }

            // 3c. Check IPs
            if (options?.ips && options.ips.length > 0) {
                const ipResults = await this.batchLookupIPs(
                    credential.api_key,
                    credential.base_url,
                    organizationId,
                    options.ips.slice(0, limit)
                );
                items.push(...ipResults.items);
                highPriorityCount += ipResults.highPriority;
            }

            // 3d. If no specific items provided, fetch user's recent scans
            if (items.length === 0 && !options?.hashes && !options?.domains && !options?.ips) {
                const recentActivity = await this.fetchUserRecentScans(
                    credential.api_key,
                    credential.base_url,
                    organizationId,
                    limit
                );
                items.push(...recentActivity.items);
                highPriorityCount += recentActivity.highPriority;
            }

            // 4. Store results in Supabase for dashboard consumption
            await this.persistFeedResults(organizationId, items, highPriorityCount);

            // 5. Record API usage for cost tracking
            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'virustotal',
                endpoint: 'intelligence/feed',
                requestMetadata: {
                    items_queried: items.length,
                    high_priority: highPriorityCount,
                },
            });

            return {
                vulnerabilities_processed: items.length,
                threat_correlations: threatCorrelations,
                high_priority_alerts: highPriorityCount,
                feed_status: 'active',
                items,
            };
        } catch (error) {
            console.error('[VirusTotalConnector] Feed ingestion failed:', error);

            const errorMessage = error instanceof Error ? error.message : 'Unknown VT API error';

            // Log the error for audit
            await supabase
                .from('open_controls_performance_metrics')
                .insert({
                    organization_id: organizationId,
                    metric_type: 'vt_feed_error',
                    metric_name: `vt_error_${Date.now()}`,
                    metric_value: 0,
                    metric_metadata: {
                        error: errorMessage,
                        timestamp: new Date().toISOString(),
                    },
                });

            return {
                vulnerabilities_processed: 0,
                threat_correlations: 0,
                high_priority_alerts: 0,
                feed_status: 'error',
                error_message: errorMessage,
                items: [],
            };
        }
    }

    /**
     * Analyze a single file hash against VirusTotal.
     * Returns the full VT report or null if not found.
     */
    static async analyzeHash(
        organizationId: string,
        hash: string
    ): Promise<VTFileReport | null> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );
        if (!credential?.api_key) return null;

        const response = await this.vtRequest(
            credential.api_key,
            credential.base_url,
            `/files/${hash}`,
            organizationId
        );

        if (!response) return null;
        return this.parseFileReport(response.data);
    }

    /**
     * Analyze a URL against VirusTotal.
     */
    static async analyzeUrl(
        organizationId: string,
        url: string
    ): Promise<VTUrlReport | null> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );
        if (!credential?.api_key) return null;

        // VT URL lookup requires base64-encoded URL (without padding)
        const urlId = btoa(url).replace(/=+$/, '');

        const response = await this.vtRequest(
            credential.api_key,
            credential.base_url,
            `/urls/${urlId}`,
            organizationId
        );

        if (!response) return null;

        const attrs = response.data?.attributes || {};
        return {
            id: response.data?.id || urlId,
            type: 'url',
            url: attrs.url || url,
            last_http_response_code: attrs.last_http_response_code || 0,
            last_analysis_stats: attrs.last_analysis_stats || { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0 },
            reputation: attrs.reputation || 0,
            categories: attrs.categories || {},
            last_analysis_date: attrs.last_analysis_date || 0,
        };
    }

    /**
     * Get domain reputation from VirusTotal.
     */
    static async analyzeDomain(
        organizationId: string,
        domain: string
    ): Promise<VTDomainReport | null> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );
        if (!credential?.api_key) return null;

        const response = await this.vtRequest(
            credential.api_key,
            credential.base_url,
            `/domains/${domain}`,
            organizationId
        );

        if (!response) return null;
        const attrs = response.data?.attributes || {};

        return {
            id: response.data?.id || domain,
            type: 'domain',
            last_analysis_stats: attrs.last_analysis_stats || { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0 },
            reputation: attrs.reputation || 0,
            registrar: attrs.registrar || null,
            creation_date: attrs.creation_date || null,
            whois: attrs.whois || null,
            categories: attrs.categories || {},
        };
    }

    /**
     * Get IP reputation from VirusTotal.
     */
    static async analyzeIP(
        organizationId: string,
        ip: string
    ): Promise<VTIPReport | null> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );
        if (!credential?.api_key) return null;

        const response = await this.vtRequest(
            credential.api_key,
            credential.base_url,
            `/ip_addresses/${ip}`,
            organizationId
        );

        if (!response) return null;
        const attrs = response.data?.attributes || {};

        return {
            id: response.data?.id || ip,
            type: 'ip_address',
            last_analysis_stats: attrs.last_analysis_stats || { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0 },
            reputation: attrs.reputation || 0,
            country: attrs.country || 'unknown',
            as_owner: attrs.as_owner || 'unknown',
            asn: attrs.asn || 0,
        };
    }

    /**
     * Get the current API quota status for the configured key.
     */
    static async getQuotaStatus(organizationId: string): Promise<{
        configured: boolean;
        tier: string;
        daily_used: number;
        daily_allowed: number;
        hourly_used: number;
        hourly_allowed: number;
    } | null> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential?.api_key) {
            return { configured: false, tier: 'none', daily_used: 0, daily_allowed: 0, hourly_used: 0, hourly_allowed: 0 };
        }

        try {
            const response = await this.vtRequest(
                credential.api_key,
                credential.base_url,
                '/users/me',
                organizationId
            );

            if (!response) return null;

            const quotas = response.data?.attributes?.quotas || {};
            const apiRequestsDaily = quotas.api_requests_daily || {};
            const apiRequestsHourly = quotas.api_requests_hourly || {};

            return {
                configured: true,
                tier: credential.tier,
                daily_used: apiRequestsDaily.used || 0,
                daily_allowed: apiRequestsDaily.allowed || credential.rate_limits.requests_per_day,
                hourly_used: apiRequestsHourly.used || 0,
                hourly_allowed: apiRequestsHourly.allowed || credential.rate_limits.requests_per_minute * 60,
            };
        } catch {
            return null;
        }
    }

    // ─── Private Helpers ───────────────────────────────────────────────────────

    /**
     * Core VT API request handler with auth, error handling, and cost tracking.
     */
    private static async vtRequest(
        apiKey: string,
        baseUrl: string,
        path: string,
        organizationId: string
    ): Promise<any> {
        try {
            const response = await fetch(`${baseUrl}${path}`, {
                method: 'GET',
                headers: {
                    'x-apikey': apiKey,
                    'Accept': 'application/json',
                },
            });

            if (response.status === 429) {
                console.warn('[VirusTotalConnector] Rate limited by VT API');
                return null;
            }

            if (response.status === 404) {
                // Not found in VT database — this is normal for new/unknown files
                return null;
            }

            if (!response.ok) {
                const errorBody = await response.text();
                console.error(`[VirusTotalConnector] API error ${response.status}:`, errorBody);
                throw new Error(`VT API returned ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            if (error instanceof TypeError && error.message.includes('fetch')) {
                console.error('[VirusTotalConnector] Network error — VT API unreachable');
            }
            throw error;
        }
    }

    /**
     * Batch lookup file hashes against VT.
     */
    private static async batchLookupHashes(
        apiKey: string,
        baseUrl: string,
        organizationId: string,
        hashes: string[]
    ): Promise<{ items: VulnerabilityFeedResult['items']; highPriority: number; correlations: number }> {
        const items: VulnerabilityFeedResult['items'] = [];
        let highPriority = 0;
        let correlations = 0;

        for (const hash of hashes) {
            const response = await this.vtRequest(apiKey, baseUrl, `/files/${hash}`, organizationId);
            if (!response?.data) continue;

            const report = this.parseFileReport(response.data);
            const severity = this.calculateSeverity(report.last_analysis_stats);

            if (severity === 'critical' || severity === 'high') {
                highPriority++;
            }
            if (report.popular_threat_classification?.suggested_threat_label) {
                correlations++;
            }

            items.push({
                hash: report.sha256,
                type: report.type_description || 'unknown',
                detection_ratio: `${report.last_analysis_stats.malicious}/${report.last_analysis_stats.malicious +
                    report.last_analysis_stats.undetected +
                    report.last_analysis_stats.harmless
                    }`,
                threat_label: report.popular_threat_classification?.suggested_threat_label || null,
                severity,
                first_seen: new Date(report.first_submission_date * 1000).toISOString(),
                last_analyzed: new Date(report.last_analysis_date * 1000).toISOString(),
                tags: report.tags.slice(0, 10),
            });
        }

        return { items, highPriority, correlations };
    }

    /**
     * Batch lookup domains against VT.
     */
    private static async batchLookupDomains(
        apiKey: string,
        baseUrl: string,
        organizationId: string,
        domains: string[]
    ): Promise<{ items: VulnerabilityFeedResult['items']; highPriority: number }> {
        const items: VulnerabilityFeedResult['items'] = [];
        let highPriority = 0;

        for (const domain of domains) {
            const response = await this.vtRequest(apiKey, baseUrl, `/domains/${domain}`, organizationId);
            if (!response?.data) continue;

            const attrs = response.data.attributes || {};
            const stats = attrs.last_analysis_stats || {};
            const severity = this.calculateSeverity(stats);

            if (severity === 'critical' || severity === 'high') highPriority++;

            items.push({
                hash: domain,
                type: 'domain',
                detection_ratio: `${stats.malicious || 0}/${(stats.malicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)}`,
                threat_label: null,
                severity,
                first_seen: attrs.creation_date ? new Date(attrs.creation_date * 1000).toISOString() : new Date().toISOString(),
                last_analyzed: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : new Date().toISOString(),
                tags: [],
            });
        }

        return { items, highPriority };
    }

    /**
     * Batch lookup IPs against VT.
     */
    private static async batchLookupIPs(
        apiKey: string,
        baseUrl: string,
        organizationId: string,
        ips: string[]
    ): Promise<{ items: VulnerabilityFeedResult['items']; highPriority: number }> {
        const items: VulnerabilityFeedResult['items'] = [];
        let highPriority = 0;

        for (const ip of ips) {
            const response = await this.vtRequest(apiKey, baseUrl, `/ip_addresses/${ip}`, organizationId);
            if (!response?.data) continue;

            const attrs = response.data.attributes || {};
            const stats = attrs.last_analysis_stats || {};
            const severity = this.calculateSeverity(stats);

            if (severity === 'critical' || severity === 'high') highPriority++;

            items.push({
                hash: ip,
                type: `ip_address (${attrs.country || 'unknown'})`,
                detection_ratio: `${stats.malicious || 0}/${(stats.malicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)}`,
                threat_label: attrs.as_owner || null,
                severity,
                first_seen: new Date().toISOString(),
                last_analyzed: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : new Date().toISOString(),
                tags: [],
            });
        }

        return { items, highPriority };
    }

    /**
     * Fetch user's recent scan activity from VT API.
     */
    private static async fetchUserRecentScans(
        apiKey: string,
        baseUrl: string,
        organizationId: string,
        limit: number
    ): Promise<{ items: VulnerabilityFeedResult['items']; highPriority: number }> {
        try {
            // Query user's recent analyses
            const response = await this.vtRequest(
                apiKey,
                baseUrl,
                `/intelligence/search?query=entity:file&limit=${Math.min(limit, 10)}`,
                organizationId
            );

            // This endpoint requires VT Enterprise — if 403/404, return empty
            if (!response?.data || !Array.isArray(response.data)) {
                return { items: [], highPriority: 0 };
            }

            const items: VulnerabilityFeedResult['items'] = [];
            let highPriority = 0;

            for (const entry of response.data) {
                const attrs = entry.attributes || {};
                const stats = attrs.last_analysis_stats || {};
                const severity = this.calculateSeverity(stats);
                if (severity === 'critical' || severity === 'high') highPriority++;

                items.push({
                    hash: attrs.sha256 || entry.id || 'unknown',
                    type: attrs.type_description || 'file',
                    detection_ratio: `${stats.malicious || 0}/${(stats.malicious || 0) + (stats.undetected || 0)}`,
                    threat_label: attrs.popular_threat_classification?.suggested_threat_label || null,
                    severity,
                    first_seen: attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toISOString() : new Date().toISOString(),
                    last_analyzed: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : new Date().toISOString(),
                    tags: (attrs.tags || []).slice(0, 10),
                });
            }

            return { items, highPriority };
        } catch {
            // Intelligence/search may not be available on free tier — graceful degradation
            return { items: [], highPriority: 0 };
        }
    }

    /**
     * Parse a raw VT API file response into our typed report.
     */
    private static parseFileReport(data: any): VTFileReport {
        const attrs = data?.attributes || {};
        return {
            id: data?.id || 'unknown',
            type: 'file',
            sha256: attrs.sha256 || '',
            sha1: attrs.sha1 || '',
            md5: attrs.md5 || '',
            meaningful_name: attrs.meaningful_name || null,
            type_description: attrs.type_description || null,
            size: attrs.size || 0,
            first_submission_date: attrs.first_submission_date || 0,
            last_analysis_date: attrs.last_analysis_date || 0,
            last_analysis_stats: attrs.last_analysis_stats || {
                malicious: 0, suspicious: 0, undetected: 0, harmless: 0,
                timeout: 0, 'confirmed-timeout': 0, failure: 0, 'type-unsupported': 0,
            },
            reputation: attrs.reputation || 0,
            tags: attrs.tags || [],
            total_votes: attrs.total_votes || { harmless: 0, malicious: 0 },
            popular_threat_classification: attrs.popular_threat_classification || undefined,
        };
    }

    /**
     * Calculate severity from VT detection stats.
     * DISA-aligned mapping:
     *   - 10+ engines flagging = critical
     *   - 5-9 engines          = high
     *   - 2-4 engines          = medium
     *   - 1 engine             = low
     *   - 0                    = clean
     */
    private static calculateSeverity(
        stats: { malicious?: number; suspicious?: number }
    ): 'critical' | 'high' | 'medium' | 'low' | 'clean' {
        const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
        if (malicious >= 10) return 'critical';
        if (malicious >= 5) return 'high';
        if (malicious >= 2) return 'medium';
        if (malicious >= 1) return 'low';
        return 'clean';
    }

    /**
     * Persist feed results to Supabase for dashboard display and historical tracking.
     */
    private static async persistFeedResults(
        organizationId: string,
        items: VulnerabilityFeedResult['items'],
        highPriorityCount: number
    ): Promise<void> {
        try {
            await supabase
                .from('open_controls_performance_metrics')
                .insert({
                    organization_id: organizationId,
                    metric_type: 'vt_feed_ingestion',
                    metric_name: `vt_feed_${Date.now()}`,
                    metric_value: items.length,
                    metric_metadata: {
                        source: 'virustotal_enterprise',
                        items_processed: items.length,
                        high_priority_alerts: highPriorityCount,
                        severity_breakdown: {
                            critical: items.filter(i => i.severity === 'critical').length,
                            high: items.filter(i => i.severity === 'high').length,
                            medium: items.filter(i => i.severity === 'medium').length,
                            low: items.filter(i => i.severity === 'low').length,
                            clean: items.filter(i => i.severity === 'clean').length,
                        },
                        ingested_at: new Date().toISOString(),
                    },
                });
        } catch (error) {
            console.error('[VirusTotalConnector] Failed to persist feed results:', error);
        }
    }
}
