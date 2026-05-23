/**
 * Network Infrastructure Discovery Service
 * Safe, non-invasive network reconnaissance
 */

export interface NetworkDiscoveryResult {
  hasCorporateProxy: boolean;
  isActiveDomain: boolean;
  detectedServices: string[];
  networkMetadata: Record<string, any>;
  confidence: number;
}

export class NetworkDiscoveryService {
  /**
   * Perform safe network discovery
   */
  static async discoverNetwork(): Promise<NetworkDiscoveryResult> {
    const results = await Promise.allSettled([
      this.detectCorporateProxy(),
      this.detectActiveDomain(),
      this.detectCommonServices(),
    ]);

    const proxyResult = results[0].status === 'fulfilled' ? results[0].value : { detected: false, metadata: {} };
    const domainResult = results[1].status === 'fulfilled' ? results[1].value : { detected: false, metadata: {} };
    const servicesResult = results[2].status === 'fulfilled' ? results[2].value : { services: [], metadata: {} };

    return {
      hasCorporateProxy: proxyResult.detected || false,
      isActiveDomain: domainResult.detected || false,
      detectedServices: servicesResult.services || [],
      networkMetadata: {
        proxy: proxyResult,
        domain: domainResult,
        services: servicesResult,
      },
      confidence: this.calculateConfidence(
        proxyResult,
        domainResult,
        servicesResult
      ),
    };
  }

  /**
   * Detect corporate proxy configuration
   */
  private static async detectCorporateProxy(): Promise<{
    detected: boolean;
    metadata: Record<string, any>;
  }> {
    const metadata: Record<string, any> = {};
    let detected = false;

    // Check for proxy in connection info (limited browser API)
    try {
      // Check if requests go through proxy (timing-based heuristic)
      const timing = performance.getEntriesByType('navigation')[0] as any;
      if (timing) {
        const proxyLatency = timing.connectEnd - timing.connectStart;
        if (proxyLatency > 100) {
          // Suspicious latency might indicate proxy
          metadata.suspiciousLatency = proxyLatency;
          detected = true;
        }
      }
    } catch (e) {
      // Performance API not available
    }

    return { detected, metadata };
  }

  /**
   * Detect Active Directory domain membership
   */
  private static async detectActiveDomain(): Promise<{
    detected: boolean;
    metadata: Record<string, any>;
  }> {
    const metadata: Record<string, any> = {};
    let detected = false;

    // Check for domain-joined indicators
    const hostname = globalThis.location.hostname;
    
    // Corporate domain patterns
    const corporateDomainPatterns = [
      /\.local$/,
      /\.corp$/,
      /\.internal$/,
      /\.(mil|gov)$/,
    ];

    for (const pattern of corporateDomainPatterns) {
      if (pattern.test(hostname)) {
        detected = true;
        metadata.domainPattern = pattern.source;
        break;
      }
    }

    return { detected, metadata };
  }

  /**
   * Detect common internal services
   */
  private static async detectCommonServices(): Promise<{
    services: string[];
    metadata: Record<string, any>;
  }> {
    const services: string[] = [];
    const metadata: Record<string, any> = {};

    // Check user agent for enterprise management tools
    const ua = navigator.userAgent;
    
    if (ua.includes('ManageEngine')) {
      services.push('manageengine');
    }
    if (ua.includes('SCCM') || ua.includes('ConfigMgr')) {
      services.push('sccm');
    }

    // Check for common enterprise software indicators
    try {
      // Check if running in a managed environment
      const isManaged =
        'managed' in navigator ||
        'enterprise' in navigator ||
        (navigator as any).webdriver;
      
      if (isManaged) {
        services.push('managed-device');
        metadata.managedDevice = true;
      }
    } catch (e) {
      // Not a managed device
    }

    return { services, metadata };
  }

  /**
   * Calculate overall confidence score
   */
  private static calculateConfidence(
    proxyResult: any,
    domainResult: any,
    servicesResult: any
  ): number {
    let confidence = 0;

    if (proxyResult?.detected) confidence += 30;
    if (domainResult?.detected) confidence += 40;
    if (servicesResult?.services?.length > 0) confidence += 30;

    return Math.min(confidence, 100);
  }
}
