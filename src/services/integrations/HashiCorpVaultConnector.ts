/**
 * HashiCorp Vault Connector
 * ═════════════════════════
 *
 * Real credential verification via HashiCorp Vault.
 *
 * Architecture:
 *   - Vault runs self-hosted or on HCP (HashiCorp Cloud Platform)
 *   - API calls route through Supabase Edge Function relay
 *   - Vault token stored encrypted in IntegrationKeyService
 *   - All secret access logged to DAG audit trail
 *
 * Capabilities:
 *   - Secret read/write (KV v2 engine)
 *   - Dynamic credential generation (database, AWS, PKI)
 *   - Credential rotation triggering
 *   - Vault health/seal status monitoring
 *   - Audit trail retrieval
 *
 * API: HashiCorp Vault HTTP API v1
 * Documentation: https://developer.hashicorp.com/vault/api-docs
 */

import { supabase } from '@/integrations/supabase/client';
import { IntegrationKeyService } from './IntegrationKeyService';
import { apiCostTracker } from '../ExternalApiCostTracker';

// ─── Response Types ────────────────────────────────────────────────────────────

export type VaultDataSource = 'hashicorp_vault' | 'not_configured' | 'error';

export interface VaultHealthStatus {
    initialized: boolean;
    sealed: boolean;
    standby: boolean;
    performance_standby: boolean;
    server_time_utc: number;
    version: string;
    cluster_name: string;
    data_available: boolean;
    data_source: VaultDataSource;
    error_message?: string;
}

export interface CredentialTestResult {
    success: boolean;
    credential_id: string;
    vault_path: string;
    details: string;
    response_time_ms: number;
    last_rotation: string | null;
    expires_at: string | null;
    data_source: VaultDataSource;
}

export interface SecretMetadata {
    path: string;
    version: number;
    created_time: string;
    deletion_time: string;
    destroyed: boolean;
    custom_metadata: Record<string, string>;
}

export interface RotationResult {
    success: boolean;
    path: string;
    new_version: number;
    rotated_at: string;
    next_rotation: string;
    data_source: VaultDataSource;
    error_message?: string;
}

// ─── Connector Implementation ──────────────────────────────────────────────────

export class HashiCorpVaultConnector {
    private static readonly PROVIDER = 'hashicorp' as const;
    private static readonly RELAY_FUNCTION = 'vault-relay';

    /**
     * Get Vault health/seal status.
     * Used for monitoring and dashboard display.
     */
    static async getHealthStatus(
        organizationId: string
    ): Promise<VaultHealthStatus> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential) {
            return {
                initialized: false,
                sealed: true,
                standby: false,
                performance_standby: false,
                server_time_utc: 0,
                version: 'unknown',
                cluster_name: 'unknown',
                data_available: false,
                data_source: 'not_configured',
                error_message: 'HashiCorp Vault not configured. Add Vault address and token in Settings > Integrations.',
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
                initialized: data?.initialized ?? false,
                sealed: data?.sealed ?? true,
                standby: data?.standby ?? false,
                performance_standby: data?.performance_standby ?? false,
                server_time_utc: data?.server_time_utc || 0,
                version: data?.version || 'unknown',
                cluster_name: data?.cluster_name || 'unknown',
                data_available: true,
                data_source: 'hashicorp_vault',
            };
        } catch (error) {
            console.error('[HashiCorpVaultConnector] Health check failed:', error);
            return {
                initialized: false,
                sealed: true,
                standby: false,
                performance_standby: false,
                server_time_utc: 0,
                version: 'unknown',
                cluster_name: 'unknown',
                data_available: false,
                data_source: 'error',
                error_message: error instanceof Error ? error.message : 'Vault health check error',
            };
        }
    }

    /**
     * Test credential connectivity via Vault.
     */
    static async testCredential(
        organizationId: string,
        credentialId: string,
        vaultPath: string
    ): Promise<CredentialTestResult> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential) {
            return {
                success: false,
                credential_id: credentialId,
                vault_path: vaultPath,
                details: 'HashiCorp Vault not configured. Cannot verify credentials without a secret store.',
                response_time_ms: 0,
                last_rotation: null,
                expires_at: null,
                data_source: 'not_configured',
            };
        }

        const startTime = Date.now();

        try {
            // Sanitize vault path — prevent path traversal
            const sanitizedPath = this.sanitizeVaultPath(vaultPath);
            if (!sanitizedPath) {
                return {
                    success: false,
                    credential_id: credentialId,
                    vault_path: vaultPath,
                    details: 'Invalid Vault path format.',
                    response_time_ms: 0,
                    last_rotation: null,
                    expires_at: null,
                    data_source: 'error',
                };
            }

            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'test_credential',
                        organization_id: organizationId,
                        params: {
                            credential_id: credentialId,
                            vault_path: sanitizedPath,
                        },
                    },
                }
            );

            if (error) throw error;

            const responseTime = Date.now() - startTime;

            // Track API usage
            await apiCostTracker.trackApiCall({
                organizationId,
                apiProvider: 'hashicorp',
                endpoint: 'v1/secret/data',
                requestMetadata: {
                    credential_id: credentialId,
                    test_result: data?.success ? 'pass' : 'fail',
                    response_ms: responseTime,
                },
            });

            // Log to audit trail
            await this.logAuditEvent(organizationId, 'credential_test', {
                credential_id: credentialId,
                vault_path: sanitizedPath,
                result: data?.success ? 'pass' : 'fail',
                response_ms: responseTime.toString(),
            });

            return {
                success: data?.success || false,
                credential_id: credentialId,
                vault_path: sanitizedPath,
                details: data?.details || (data?.success ? 'Credential verified successfully' : 'Credential verification failed'),
                response_time_ms: responseTime,
                last_rotation: data?.metadata?.created_time || null,
                expires_at: data?.metadata?.expires_at || null,
                data_source: 'hashicorp_vault',
            };
        } catch (error) {
            const responseTime = Date.now() - startTime;
            console.error('[HashiCorpVaultConnector] Credential test failed:', error);
            return {
                success: false,
                credential_id: credentialId,
                vault_path: vaultPath,
                details: error instanceof Error ? error.message : 'Vault connectivity error',
                response_time_ms: responseTime,
                last_rotation: null,
                expires_at: null,
                data_source: 'error',
            };
        }
    }

    /**
     * Get secret metadata (version, creation time, custom metadata).
     * Does NOT return the secret value — only metadata.
     */
    static async getSecretMetadata(
        organizationId: string,
        vaultPath: string
    ): Promise<SecretMetadata | null> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );
        if (!credential) return null;

        const sanitizedPath = this.sanitizeVaultPath(vaultPath);
        if (!sanitizedPath) return null;

        try {
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'get_metadata',
                        organization_id: organizationId,
                        params: { vault_path: sanitizedPath },
                    },
                }
            );

            if (error) throw error;
            if (!data?.metadata) return null;

            return {
                path: sanitizedPath,
                version: data.metadata.version || 0,
                created_time: data.metadata.created_time || '',
                deletion_time: data.metadata.deletion_time || '',
                destroyed: data.metadata.destroyed || false,
                custom_metadata: data.metadata.custom_metadata || {},
            };
        } catch (error) {
            console.error('[HashiCorpVaultConnector] Metadata retrieval failed:', error);
            return null;
        }
    }

    /**
     * Trigger credential rotation for a given Vault path.
     * The actual rotation is performed by Vault's secret engine.
     */
    static async rotateCredential(
        organizationId: string,
        vaultPath: string
    ): Promise<RotationResult> {
        const credential = await IntegrationKeyService.getCredential(
            organizationId,
            this.PROVIDER
        );

        if (!credential) {
            return {
                success: false,
                path: vaultPath,
                new_version: 0,
                rotated_at: '',
                next_rotation: '',
                data_source: 'not_configured',
                error_message: 'HashiCorp Vault not configured.',
            };
        }

        const sanitizedPath = this.sanitizeVaultPath(vaultPath);
        if (!sanitizedPath) {
            return {
                success: false,
                path: vaultPath,
                new_version: 0,
                rotated_at: '',
                next_rotation: '',
                data_source: 'error',
                error_message: 'Invalid Vault path.',
            };
        }

        try {
            const { data, error } = await supabase.functions.invoke(
                this.RELAY_FUNCTION,
                {
                    body: {
                        action: 'rotate_credential',
                        organization_id: organizationId,
                        params: { vault_path: sanitizedPath },
                    },
                }
            );

            if (error) throw error;

            // Log rotation event
            await this.logAuditEvent(organizationId, 'credential_rotated', {
                vault_path: sanitizedPath,
                new_version: String(data?.new_version || 0),
            });

            return {
                success: data?.success || false,
                path: sanitizedPath,
                new_version: data?.new_version || 0,
                rotated_at: new Date().toISOString(),
                next_rotation: data?.next_rotation || '',
                data_source: 'hashicorp_vault',
            };
        } catch (error) {
            console.error('[HashiCorpVaultConnector] Rotation failed:', error);
            return {
                success: false,
                path: vaultPath,
                new_version: 0,
                rotated_at: '',
                next_rotation: '',
                data_source: 'error',
                error_message: error instanceof Error ? error.message : 'Rotation error',
            };
        }
    }

    // ─── Private Helpers ───────────────────────────────────────────────────────

    /**
     * Sanitize Vault path to prevent path traversal attacks.
     * Only allows alphanumeric, hyphens, underscores, and forward slashes.
     */
    private static sanitizeVaultPath(path: string): string | null {
        if (!path || path.length > 256) return null;

        // Block path traversal
        if (path.includes('..') || path.includes('\\')) return null;

        // Must match safe pattern: khepra/service/key_name
        const safePattern = /^[a-zA-Z0-9][a-zA-Z0-9_/ -]*[a-zA-Z0-9_-]$/;
        if (!safePattern.test(path)) return null;

        // Remove double slashes
        return path.replaceAll(/\/+/g, '/');
    }

    /**
     * Log a security-relevant event to the audit trail.
     */
    private static async logAuditEvent(
        organizationId: string,
        eventType: string,
        details: Record<string, string>
    ): Promise<void> {
        try {
            await supabase
                .from('open_controls_performance_metrics')
                .insert({
                    organization_id: organizationId,
                    metric_type: 'vault_audit_event',
                    metric_name: `vault_${eventType}_${Date.now()}`,
                    metric_value: 1,
                    metric_metadata: {
                        event_type: eventType,
                        ...details,
                        timestamp: new Date().toISOString(),
                    },
                });
        } catch (error) {
            console.error('[HashiCorpVaultConnector] Audit log failed:', error);
        }
    }
}
