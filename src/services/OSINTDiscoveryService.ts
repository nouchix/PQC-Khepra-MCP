/**
 * OSINT Discovery Service
 * Integrates with real OSINT tools for network and threat intelligence discovery
 */

export interface OSINTTarget {
  type: 'domain' | 'ip' | 'cidr' | 'organization';
  value: string;
}

export interface OSINTAsset {
  id: string;
  type: string;
  hostname: string;
  ipAddress: string;
  port?: number;
  service?: string;
  version?: string;
  os?: string;
  vulnerabilities?: string[];
  location?: {
    country?: string;
    city?: string;
  };
  organization?: string;
  discovered: string;
  source: string;
}

export interface OSINTDiscoveryResult {
  assets: OSINTAsset[];
  totalFound: number;
  sources: string[];
  scanDuration: number;
  timestamp: string;
}

export class OSINTDiscoveryService {
  /**
   * Trigger server-side OSINT discovery
   */
  static async discoverAssets(
    organizationId: string,
    targets: OSINTTarget[],
    clientDiscoveries?: any
  ): Promise<OSINTDiscoveryResult> {
    const startTime = Date.now();

    try {
      console.log('Starting OSINT discovery for targets:', targets);

      // Call the edge function that handles real OSINT tool integration
      const { data, error } = await supabase.functions.invoke('environment-discovery', {
        body: {
          organizationId,
          targets,
          clientDiscoveries,
        },
      });

      if (error) {
        console.error('OSINT discovery error:', error);
        throw error;
      }

      const scanDuration = Date.now() - startTime;

      return {
        assets: data.discoveries || [],
        totalFound: data.totalDiscoveries || 0,
        sources: data.sources || ['shodan'],
        scanDuration,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      console.error('Failed to perform OSINT discovery:', error);
      return {
        assets: [],
        totalFound: 0,
        sources: [],
        scanDuration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Extract potential targets from client-side discoveries
   */
  static extractTargetsFromDiscoveries(discoveries: any): OSINTTarget[] {
    const targets: OSINTTarget[] = [];

    // Extract from network discovery
    if (discoveries.network?.metadata?.domain) {
      targets.push({
        type: 'domain',
        value: discoveries.network.metadata.domain,
      });
    }

    if (discoveries.network?.metadata?.organization) {
      targets.push({
        type: 'organization',
        value: discoveries.network.metadata.organization,
      });
    }

    // Extract from cloud discovery
    if (discoveries.cloud?.provider) {
      // Add cloud provider specific targets
      // This could be expanded to include specific cloud resources
      targets.push({
        type: 'organization',
        value: `cloud.provider:${discoveries.cloud.provider}`,
      });
    }

    return targets;
  }

  /**
   * Validate if OSINT tools are configured
   */
  static async validateConfiguration(): Promise<{
    configured: boolean;
    availableTools: string[];
    missingTools: string[];
  }> {
    // This would check if API keys are configured
    // For now, we'll return a basic response
    return {
      configured: true,
      availableTools: ['shodan'],
      missingTools: [],
    };
  }
}

// Import supabase client
import { supabase } from '@/integrations/supabase/client';
