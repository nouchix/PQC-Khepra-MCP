/**
 * Container STIG Scanner Service
 * Integrates with container registries to perform automated STIG compliance scanning
 * Supports Docker, Kubernetes, and OCI-compliant container images
 */

export interface ContainerImage {
  registry: string;
  repository: string;
  tag: string;
  digest?: string;
  platform?: string;
}

export interface ContainerScanResult {
  image: ContainerImage;
  stigFindings: STIGFinding[];
  vulnerabilities: CVEVulnerability[];
  complianceScore: number;
  scanTimestamp: string;
  runtimeChecks?: RuntimeSecurityCheck[];
}

export interface STIGFinding {
  ruleId: string;
  severity: 'CAT_I' | 'CAT_II' | 'CAT_III';
  status: 'OPEN' | 'NOT_APPLICABLE' | 'COMPLIANT';
  layer?: string;
  remediation?: string;
}

export interface CVEVulnerability {
  cveId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  package: string;
  fixedVersion?: string;
  stigMapping?: string[];
}

export interface RuntimeSecurityCheck {
  checkType: 'privilege' | 'network' | 'filesystem' | 'capabilities';
  status: 'PASS' | 'FAIL' | 'WARNING';
  details: string;
  stigReference?: string;
}

export class ContainerSTIGScanner {
  private readonly baseUrl: string = 'https://xjknkjbrjgljuovaazeu.supabase.co/functions/v1';


  /**
   * Scan a container image for STIG compliance
   */
  async scanImage(
    image: ContainerImage,
    organizationId: string,
    options?: {
      includeVulnerabilities?: boolean;
      includeRuntimeChecks?: boolean;
      scanDepth?: 'quick' | 'standard' | 'deep';
    }
  ): Promise<ContainerScanResult> {
    const response = await fetch(`${this.baseUrl}/container-stig-scanner`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        image,
        organizationId,
        options: {
          includeVulnerabilities: options?.includeVulnerabilities ?? true,
          includeRuntimeChecks: options?.includeRuntimeChecks ?? false,
          scanDepth: options?.scanDepth ?? 'standard',
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`Container scan failed: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Scan all images in a Kubernetes cluster
   */
  async scanKubernetesCluster(
    clusterId: string,
    organizationId: string,
    namespaces?: string[]
  ): Promise<ContainerScanResult[]> {
    const response = await fetch(`${this.baseUrl}/container-stig-scanner`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        scanType: 'kubernetes',
        clusterId,
        organizationId,
        namespaces,
      }),
    });

    if (!response.ok) {
      throw new Error(`Kubernetes scan failed: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Generate remediation Dockerfile for STIG findings
   */
  async generateRemediationDockerfile(
    scanResult: ContainerScanResult
  ): Promise<string> {
    const response = await fetch(`${this.baseUrl}/container-stig-scanner`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        action: 'generate_dockerfile',
        scanResult,
      }),
    });

    if (!response.ok) {
      throw new Error(`Dockerfile generation failed: ${response.statusText}`);
    }

    const result = await response.json();
    return result.dockerfile;
  }

  /**
   * Validate a golden image against STIG requirements
   */
  async validateGoldenImage(
    image: ContainerImage,
    organizationId: string,
    stigProfile: string
  ): Promise<{
    compliant: boolean;
    findings: STIGFinding[];
    certification: string;
  }> {
    const response = await fetch(`${this.baseUrl}/container-stig-scanner`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        action: 'validate_golden_image',
        image,
        organizationId,
        stigProfile,
      }),
    });

    if (!response.ok) {
      throw new Error(`Golden image validation failed: ${response.statusText}`);
    }

    return response.json();
  }
}
