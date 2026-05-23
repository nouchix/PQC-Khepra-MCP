/**
 * Environment Auto-Discovery Orchestrator
 * Coordinates cloud, network, and platform detection
 */

import { supabase } from '@/integrations/supabase/client';
import { CloudProviderDetector } from './CloudProviderDetector';
import { NetworkDiscoveryService } from './NetworkDiscoveryService';

export interface PlatformDetectionResult {
  operatingSystem: string;
  browser: string;
  containerRuntime?: string;
  cicdPlatform?: string;
  metadata: Record<string, any>;
}

export interface DiscoveryResults {
  cloud: {
    provider: string;
    confidence: number;
    region?: string;
    metadata: Record<string, any>;
  };
  network: {
    hasCorporateProxy: boolean;
    isActiveDomain: boolean;
    detectedServices: string[];
    confidence: number;
  };
  platform: PlatformDetectionResult;
  overallConfidence: number;
}

export class EnvironmentAutoDiscovery {
  private organizationId: string;

  constructor(organizationId: string) {
    this.organizationId = organizationId;
  }

  /**
   * Run complete environment discovery
   */
  async discover(): Promise<DiscoveryResults> {
    console.log('Starting environment auto-discovery...');

    // Run all detections in parallel for speed
    const [cloudResult, networkResult, platformResult] = await Promise.all([
      CloudProviderDetector.detectCloudProvider(),
      NetworkDiscoveryService.discoverNetwork(),
      this.detectPlatform(),
    ]);

    const results: DiscoveryResults = {
      cloud: {
        provider: cloudResult.provider,
        confidence: cloudResult.confidence,
        region: cloudResult.region,
        metadata: cloudResult.metadata,
      },
      network: {
        hasCorporateProxy: networkResult.hasCorporateProxy,
        isActiveDomain: networkResult.isActiveDomain,
        detectedServices: networkResult.detectedServices,
        confidence: networkResult.confidence,
      },
      platform: platformResult,
      overallConfidence: this.calculateOverallConfidence(
        cloudResult.confidence,
        networkResult.confidence
      ),
    };

    // Store discoveries in database
    await this.storeDiscoveries(results);

    // Trigger server-side deep discovery
    await this.triggerServerSideDiscovery(results);

    return results;
  }

  /**
   * Detect platform information from browser
   */
  private async detectPlatform(): Promise<PlatformDetectionResult> {
    const ua = navigator.userAgent;
    const platform = navigator.platform;

    const metadata: Record<string, any> = {
      userAgent: ua,
      platform: platform,
      languages: navigator.languages,
      hardwareConcurrency: navigator.hardwareConcurrency,
    };

    // Detect OS
    let os = 'unknown';
    if (ua.includes('Windows')) os = 'windows';
    else if (ua.includes('Mac')) os = 'macos';
    else if (ua.includes('Linux')) os = 'linux';
    else if (ua.includes('Android')) os = 'android';
    else if (ua.includes('iOS')) os = 'ios';

    // Detect browser
    let browser = 'unknown';
    if (ua.includes('Chrome')) browser = 'chrome';
    else if (ua.includes('Firefox')) browser = 'firefox';
    else if (ua.includes('Safari')) browser = 'safari';
    else if (ua.includes('Edge')) browser = 'edge';

    // Check for container runtime indicators
    let containerRuntime: string | undefined;
    if (ua.includes('Docker')) containerRuntime = 'docker';
    else if (ua.includes('Kubernetes')) containerRuntime = 'kubernetes';

    // Check for CI/CD platform indicators
    let cicdPlatform: string | undefined;
    if (ua.includes('GitHub')) cicdPlatform = 'github';
    else if (ua.includes('GitLab')) cicdPlatform = 'gitlab';
    else if (ua.includes('Jenkins')) cicdPlatform = 'jenkins';

    return {
      operatingSystem: os,
      browser,
      containerRuntime,
      cicdPlatform,
      metadata,
    };
  }

  /**
   * Store discovery results in database
   */
  private async storeDiscoveries(results: DiscoveryResults): Promise<void> {
    const discoveries = [];

    // Cloud discovery
    if (results.cloud.confidence > 30) {
      discoveries.push({
        organization_id: this.organizationId,
        discovery_type: 'cloud',
        provider: results.cloud.provider,
        confidence_score: results.cloud.confidence,
        detected_metadata: results.cloud.metadata,
        auto_configured: false,
      });
    }

    // Network discovery
    if (results.network.confidence > 20) {
      discoveries.push({
        organization_id: this.organizationId,
        discovery_type: 'network',
        provider: results.network.isActiveDomain ? 'on-prem' : 'unknown',
        confidence_score: results.network.confidence,
        detected_metadata: {
          hasCorporateProxy: results.network.hasCorporateProxy,
          isActiveDomain: results.network.isActiveDomain,
          detectedServices: results.network.detectedServices,
        },
        auto_configured: false,
      });
    }

    // Platform discovery
    discoveries.push({
      organization_id: this.organizationId,
      discovery_type: 'platform',
      provider: results.platform.operatingSystem || 'unknown',
      confidence_score: 90, // High confidence for client-side platform detection
      detected_metadata: results.platform,
      auto_configured: false,
    });

    // CI/CD discovery
    if (results.platform.cicdPlatform) {
      discoveries.push({
        organization_id: this.organizationId,
        discovery_type: 'ci_cd',
        provider: results.platform.cicdPlatform,
        confidence_score: 80,
        detected_metadata: { platform: results.platform.cicdPlatform },
        auto_configured: false,
      });
    }

    // Insert all discoveries
    if (discoveries.length > 0) {
      const { error } = await supabase
        .from('environment_discoveries')
        .insert(discoveries);

      if (error) {
        console.error('Failed to store discoveries:', error);
      } else {
        console.log(`Stored ${discoveries.length} discoveries`);
      }
    }
  }

  /**
   * Trigger server-side deep discovery
   */
  private async triggerServerSideDiscovery(
    clientResults: DiscoveryResults
  ): Promise<void> {
    try {
      const { data, error } = await supabase.functions.invoke(
        'environment-discovery',
        {
          body: {
            organizationId: this.organizationId,
            clientDiscoveries: clientResults,
          },
        }
      );

      if (error) {
        console.error('Server-side discovery failed:', error);
      } else {
        console.log('Server-side discovery completed:', data);
      }
    } catch (error) {
      console.error('Failed to trigger server-side discovery:', error);
    }
  }

  /**
   * Calculate overall confidence score
   */
  private calculateOverallConfidence(
    cloudConfidence: number,
    networkConfidence: number
  ): number {
    // Weighted average: cloud detection is more important
    return Math.round(cloudConfidence * 0.6 + networkConfidence * 0.4);
  }

  /**
   * Get stored discoveries for organization
   */
  static async getDiscoveries(organizationId: string) {
    const { data, error } = await supabase
      .from('environment_discoveries')
      .select('*')
      .eq('organization_id', organizationId)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Failed to fetch discoveries:', error);
      return [];
    }

    return data || [];
  }
}
