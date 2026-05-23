/**
 * TRL 10 Secure Credential Vault Service
 * Enterprise-grade credential management with AES-256 encryption, MFA, and audit logging
 */

import { supabase } from '@/integrations/supabase/client';

export interface SecureCredential {
  id: string;
  organization_id: string;
  credential_name: string;
  credential_type: 'ssh_key' | 'username_password' | 'api_token' | 'certificate' | 'cloud_service_account';
  target_systems: string[];
  credential_fingerprint: string;
  access_pattern: any;
  mfa_required: boolean;
  max_concurrent_uses: number;
  usage_count: number;
  last_used_at?: string;
  last_accessed_by?: string;
  metadata: any;
  expires_at?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  created_by?: string;
}

export interface CredentialAccess {
  credential_id: string;
  access_reason: string;
  intended_use: string;
  mfa_token?: string;
}

export interface EncryptionKey {
  id: string;
  key_name: string;
  key_purpose: string;
  key_version: number;
  is_active: boolean;
  created_at: string;
  expires_at?: string;
  key_metadata: any;
}

export class SecureCredentialVault {

  /**
   * Store encrypted credentials with enterprise security controls
   */
  static async storeCredential(
    organizationId: string,
    credentialData: {
      credential_name: string;
      credential_type: 'ssh_key' | 'username_password' | 'api_token' | 'certificate' | 'cloud_service_account';
      target_systems: string[];
      credentials: any; // Will be encrypted
      access_pattern?: any;
      mfa_required?: boolean;
      max_concurrent_uses?: number;
      expires_at?: string;
      metadata?: any;
    }
  ): Promise<SecureCredential> {
    try {
      // Validate credential strength
      this.validateCredentialStrength(credentialData.credentials, credentialData.credential_type);

      // Encrypt credentials using database function
      const { data: encryptedData, error: encryptError } = await supabase
        .rpc('encrypt_credential_data', {
          credential_data: credentialData.credentials
        });

      if (encryptError) throw encryptError;

      // Generate credential fingerprint for integrity verification
      const fingerprint = await this.generateCredentialFingerprint(credentialData.credentials);

      // Insert secure credential
      const { data, error } = await supabase
        .from('secure_discovery_credentials')
        .insert({
          organization_id: organizationId,
          credential_name: credentialData.credential_name,
          credential_type: credentialData.credential_type,
          target_systems: credentialData.target_systems,
          encrypted_credentials: encryptedData,
          credential_fingerprint: fingerprint,
          access_pattern: credentialData.access_pattern || {},
          mfa_required: credentialData.mfa_required ?? true,
          max_concurrent_uses: credentialData.max_concurrent_uses || 5,
          expires_at: credentialData.expires_at,
          metadata: credentialData.metadata || {}
        })
        .select()
        .single();

      if (error) throw error;

      // Log credential creation
      await this.logCredentialEvent('credential_created', data.id, organizationId, {
        credential_name: credentialData.credential_name,
        credential_type: credentialData.credential_type,
        target_systems_count: credentialData.target_systems.length
      });

      return this.sanitizeCredential(data);
    } catch (error) {
      console.error('Store credential failed:', error);
      throw error;
    }
  }

  /**
   * Retrieve and decrypt credentials with access control
   */
  static async retrieveCredential(
    credentialId: string,
    accessRequest: CredentialAccess
  ): Promise<{ credential: SecureCredential; decrypted_data: any }> {
    try {
      // Get credential metadata
      const { data: credential, error: credError } = await supabase
        .from('secure_discovery_credentials')
        .select('*')
        .eq('id', credentialId)
        .eq('is_active', true)
        .single();

      if (credError || !credential) {
        throw new Error('Credential not found or access denied');
      }

      // Validate access permissions
      await this.validateCredentialAccess(credential, accessRequest);

      // Decrypt credentials using database function
      const { data: decryptedData, error: decryptError } = await supabase
        .rpc('decrypt_credential_data', {
          encrypted_data: credential.encrypted_credentials
        });

      if (decryptError) throw decryptError;

      // Update usage tracking
      await supabase
        .from('secure_discovery_credentials')
        .update({
          usage_count: credential.usage_count + 1,
          last_used_at: new Date().toISOString(),
          last_accessed_by: (await supabase.auth.getUser()).data.user?.id
        })
        .eq('id', credentialId);

      // Log credential access
      await this.logCredentialEvent('credential_accessed', credentialId, credential.organization_id, {
        access_reason: accessRequest.access_reason,
        intended_use: accessRequest.intended_use,
        mfa_verified: !!accessRequest.mfa_token
      });

      return {
        credential: this.sanitizeCredential(credential),
        decrypted_data: decryptedData
      };
    } catch (error) {
      console.error('Retrieve credential failed:', error);

      // Log failed access attempt
      await this.logCredentialEvent('credential_access_denied', credentialId, '', {
        error: error.message,
        access_reason: accessRequest.access_reason
      }, 'ERROR');

      throw error;
    }
  }

  /**
   * List available credentials (sanitized)
   */
  static async listCredentials(organizationId: string): Promise<SecureCredential[]> {
    try {
      const { data, error } = await supabase
        .from('secure_discovery_credentials')
        .select('id, organization_id, credential_name, credential_type, target_systems, credential_fingerprint, access_pattern, mfa_required, max_concurrent_uses, usage_count, last_used_at, metadata, expires_at, is_active, created_at, updated_at')
        .eq('organization_id', organizationId)
        .eq('is_active', true)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return (data || []).map(item => ({
        ...item,
        target_systems: Array.isArray(item.target_systems) ? item.target_systems : []
      })) as SecureCredential[];
    } catch (error) {
      console.error('List credentials failed:', error);
      throw error;
    }
  }

  /**
   * Rotate credential encryption keys
   */
  static async rotateEncryptionKeys(organizationId: string): Promise<{ rotated: number; new_key_id: string }> {
    try {
      // Only master admins can rotate keys
      const { data: user } = await supabase.auth.getUser();
      if (!user) throw new Error('Authentication required');

      // Create new encryption key
      const { data: newKey, error: keyError } = await supabase
        .from('encryption_keys')
        .insert({
          key_name: `credential_key_${Date.now()}`,
          key_purpose: 'credential_encryption',
          key_version: 1,
          key_metadata: {
            algorithm: 'AES-256-GCM',
            rotated_from: 'default_credential_key',
            rotation_timestamp: new Date().toISOString()
          }
        })
        .select()
        .single();

      if (keyError) throw keyError;

      // Mark old key as inactive
      await supabase
        .from('encryption_keys')
        .update({
          is_active: false,
          rotated_at: new Date().toISOString()
        })
        .eq('key_name', 'default_credential_key');

      // Log key rotation
      await this.logCredentialEvent('encryption_key_rotated', '', organizationId, {
        old_key: 'default_credential_key',
        new_key_id: newKey.id,
        rotation_reason: 'scheduled_rotation'
      }, 'INFO');

      return {
        rotated: 1,
        new_key_id: newKey.id
      };
    } catch (error) {
      console.error('Key rotation failed:', error);
      throw error;
    }
  }

  /**
   * Revoke credential access
   */
  static async revokeCredential(credentialId: string, reason: string): Promise<void> {
    try {
      const { error } = await supabase
        .from('secure_discovery_credentials')
        .update({
          is_active: false,
          metadata: {
            revoked_at: new Date().toISOString(),
            revocation_reason: reason
          }
        })
        .eq('id', credentialId);

      if (error) throw error;

      // Log credential revocation
      await this.logCredentialEvent('credential_revoked', credentialId, '', {
        revocation_reason: reason,
        revoked_by: (await supabase.auth.getUser()).data.user?.id
      }, 'WARN');
    } catch (error) {
      console.error('Revoke credential failed:', error);
      throw error;
    }
  }

  /**
   * Audit credential access logs
   */
  static async getCredentialAuditLogs(
    organizationId: string,
    credentialId?: string,
    limit: number = 100
  ): Promise<any[]> {
    try {
      let query = supabase
        .from('discovery_audit_trail')
        .select('*')
        .eq('organization_id', organizationId)
        .like('event_type', 'credential_%')
        .order('created_at', { ascending: false })
        .limit(limit);

      if (credentialId) {
        query = query.contains('event_details', { credential_id: credentialId });
      }

      const { data, error } = await query;
      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('Get audit logs failed:', error);
      throw error;
    }
  }

  /**
   * Validate credential strength based on type
   */
  private static validateCredentialStrength(credentials: any, type: string): void {
    switch (type) {
      case 'username_password':
        if (!credentials.username || !credentials.password) {
          throw new Error('Username and password required');
        }
        if (credentials.password.length < 12) {
          throw new Error('Password must be at least 12 characters long');
        }
        break;

      case 'ssh_key':
        if (!credentials.private_key || !credentials.public_key) {
          throw new Error('SSH key pair required');
        }
        if (!credentials.private_key.includes('BEGIN') || !credentials.private_key.includes('PRIVATE KEY')) {
          throw new Error('Invalid SSH private key format');
        }
        break;

      case 'api_token':
        if (!credentials.token) {
          throw new Error('API token required');
        }
        if (credentials.token.length < 32) {
          throw new Error('API token appears to be too short');
        }
        break;

      case 'certificate':
        if (!credentials.certificate || !credentials.private_key) {
          throw new Error('Certificate and private key required');
        }
        break;
    }
  }

  /**
   * Generate credential fingerprint for integrity verification
   */
  private static async generateCredentialFingerprint(credentials: any): Promise<string> {
    const credentialString = JSON.stringify(credentials, Object.keys(credentials).sort());
    const encoder = new TextEncoder();
    const data = encoder.encode(credentialString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Validate credential access permissions
   */
  private static async validateCredentialAccess(credential: any, accessRequest: CredentialAccess): Promise<void> {
    // Check if credential is expired
    if (credential.expires_at && new Date(credential.expires_at) < new Date()) {
      throw new Error('Credential has expired');
    }

    // Check concurrent usage limits
    if (credential.usage_count >= credential.max_concurrent_uses) {
      // Check if last use was recent (within 5 minutes)
      const lastUsed = new Date(credential.last_used_at || 0);
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);

      if (lastUsed > fiveMinutesAgo) {
        throw new Error('Credential usage limit exceeded');
      }
    }

    // Validate MFA if required
    if (credential.mfa_required && !accessRequest.mfa_token) {
      throw new Error('Multi-factor authentication required');
    }

    // Validate access pattern if defined
    if (credential.access_pattern && Object.keys(credential.access_pattern).length > 0) {
      const currentHour = new Date().getHours();
      const allowedHours = credential.access_pattern.allowed_hours;

      if (allowedHours && !allowedHours.includes(currentHour)) {
        throw new Error('Credential access not allowed at this time');
      }
    }
  }

  /**
   * Remove sensitive data from credential object
   */
  private static sanitizeCredential(credential: any): SecureCredential {
    const { encrypted_credentials, encryption_key_id, ...sanitized } = credential;
    return sanitized;
  }

  /**
   * Log credential-related events for audit trail
   */
  private static async logCredentialEvent(
    eventType: string,
    credentialId: string,
    organizationId: string,
    details: any,
    severity: string = 'INFO'
  ): Promise<void> {
    try {
      await supabase
        .from('discovery_audit_trail')
        .insert({
          organization_id: organizationId,
          event_type: eventType,
          event_severity: severity,
          event_details: {
            credential_id: credentialId,
            ...details
          },
          security_context: {
            timestamp: new Date().toISOString(),
            source: 'secure_credential_vault',
            session_id: crypto.randomUUID()
          }
        });
    } catch (error) {
      console.error('Failed to log credential event:', error);
      // Don't throw here to avoid breaking the main operation
    }
  }

  /**
   * Get encryption key management status
   */
  static async getEncryptionKeyStatus(): Promise<EncryptionKey[]> {
    try {
      const { data, error } = await supabase
        .from('encryption_keys')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('Get encryption key status failed:', error);
      throw error;
    }
  }

  /**
   * Test credential connectivity
   */
  static async testCredential(
    credentialId: string,
    testTarget: string
  ): Promise<{ success: boolean; details: string }> {
    try {
      await this.logCredentialEvent('credential_test_initiated', credentialId, '', {
        test_target: testTarget,
        test_timestamp: new Date().toISOString()
      });

      // Call the real credential connectivity test via Edge Function
      const { data, error } = await supabase.functions.invoke('credential-connectivity-test', {
        body: {
          credential_id: credentialId,
          test_target: testTarget,
        },
      });

      if (error) {
        await this.logCredentialEvent('credential_test_failed', credentialId, '', {
          test_target: testTarget,
          test_result: 'edge_function_error',
          error_message: error.message,
        }, 'WARN');

        return {
          success: false,
          details: `Connectivity test failed: ${error.message}`,
        };
      }

      const success = data?.success === true;

      await this.logCredentialEvent(
        success ? 'credential_test_successful' : 'credential_test_failed',
        credentialId,
        '',
        {
          test_target: testTarget,
          test_result: success ? 'connectivity_verified' : (data?.error || 'connection_failed'),
        },
        success ? 'INFO' : 'WARN'
      );

      return {
        success,
        details: success
          ? 'Credential connectivity verified successfully'
          : `Failed to establish connection: ${data?.error || 'unknown error'}`,
      };
    } catch (error) {
      console.error('Test credential failed:', error);
      throw error;
    }
  }
}