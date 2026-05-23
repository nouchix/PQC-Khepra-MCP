/**
 * Cloud Provider Auto-Detection Service
 * Detects AWS, Azure, GCP, and other cloud environments
 */

export interface CloudDetectionResult {
  provider: 'aws' | 'azure' | 'gcp' | 'on-prem' | 'unknown';
  confidence: number; // 0-100
  region?: string;
  metadata: Record<string, any>;
  detectionMethod: string;
}

export class CloudProviderDetector {
  /**
   * Detect cloud provider from browser environment
   */
  static async detectCloudProvider(): Promise<CloudDetectionResult> {
    const results = await Promise.allSettled([
      this.detectAWS(),
      this.detectAzure(),
      this.detectGCP(),
    ]);

    // Return the highest confidence detection
    const detections = results
      .filter((r) => r.status === 'fulfilled')
      .map((r: any) => r.value)
      .filter((d) => d.confidence > 0)
      .sort((a, b) => b.confidence - a.confidence);

    return detections[0] || {
      provider: 'unknown',
      confidence: 0,
      metadata: {},
      detectionMethod: 'none',
    };
  }

  /**
   * AWS Detection via environment variables and metadata endpoints
   */
  private static async detectAWS(): Promise<CloudDetectionResult> {
    const metadata: Record<string, any> = {};
    let confidence = 0;

    // Check for AWS-specific environment indicators
    const awsIndicators = [
      'AWS_REGION',
      'AWS_DEFAULT_REGION',
      'AWS_EXECUTION_ENV',
      'AWS_LAMBDA_FUNCTION_NAME',
    ];

    // Browser-based detection (limited)
    const hostname = globalThis.location.hostname;
    if (
      hostname.includes('amazonaws.com') ||
      hostname.includes('aws.amazon.com')
    ) {
      confidence += 40;
      metadata.detectedFrom = 'hostname';
    }

    // Check localStorage for AWS SDK configurations
    try {
      const awsConfig = localStorage.getItem('aws-amplify-config');
      if (awsConfig) {
        confidence += 30;
        metadata.hasAmplifyConfig = true;
      }
    } catch (e) {
      // localStorage not accessible
    }

    // Check for AWS CloudShell indicators
    if (navigator.userAgent.includes('CloudShell')) {
      confidence += 50;
      metadata.environment = 'cloudshell';
    }

    return {
      provider: confidence > 30 ? 'aws' : 'unknown',
      confidence,
      metadata,
      detectionMethod: 'browser-inspection',
    };
  }

  /**
   * Azure Detection
   */
  private static async detectAzure(): Promise<CloudDetectionResult> {
    const metadata: Record<string, any> = {};
    let confidence = 0;

    const hostname = globalThis.location.hostname;
    if (
      hostname.includes('azure.com') ||
      hostname.includes('azurewebsites.net') ||
      hostname.includes('windows.net')
    ) {
      confidence += 40;
      metadata.detectedFrom = 'hostname';
    }

    // Check for Azure-specific indicators
    try {
      const azureConfig = localStorage.getItem('azure-auth-config');
      if (azureConfig) {
        confidence += 30;
        metadata.hasAzureAuth = true;
      }
    } catch (e) {
      // localStorage not accessible
    }

    return {
      provider: confidence > 30 ? 'azure' : 'unknown',
      confidence,
      metadata,
      detectionMethod: 'browser-inspection',
    };
  }

  /**
   * GCP Detection
   */
  private static async detectGCP(): Promise<CloudDetectionResult> {
    const metadata: Record<string, any> = {};
    let confidence = 0;

    const hostname = globalThis.location.hostname;
    if (
      hostname.includes('googleapis.com') ||
      hostname.includes('googleusercontent.com') ||
      hostname.includes('google.com')
    ) {
      confidence += 40;
      metadata.detectedFrom = 'hostname';
    }

    // Check for GCP-specific indicators
    try {
      const gcpConfig = localStorage.getItem('gcp-project-id');
      if (gcpConfig) {
        confidence += 30;
        metadata.hasGCPConfig = true;
      }
    } catch (e) {
      // localStorage not accessible
    }

    return {
      provider: confidence > 30 ? 'gcp' : 'unknown',
      confidence,
      metadata,
      detectionMethod: 'browser-inspection',
    };
  }

  /**
   * Detect cloud region from various sources
   */
  static detectRegion(provider: string): string | undefined {
    // This would typically come from backend detection
    // For now, return undefined to indicate server-side detection needed
    return undefined;
  }
}
