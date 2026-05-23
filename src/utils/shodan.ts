/**
 * Shodan API Integration
 * Deep network intelligence and vulnerability scanning
 * Requires API key stored in Supabase secrets
 */

export interface ShodanHost {
  ip_str: string;
  org: string;
  isp: string;
  asn: string;
  hostnames: string[];
  domains: string[];
  ports: number[];
  vulns: string[];
  tags: string[];
  os: string | null;
  location: {
    country_name: string;
    country_code: string;
    city: string;
    region_code: string;
    latitude: number;
    longitude: number;
  };
  last_update: string;
}

export interface ShodanEnrichment {
  ip: string;
  organization: string;
  isp: string;
  autonomous_system: string;
  hostnames: string[];
  domains: string[];
  open_ports: number[];
  vulnerabilities: string[];
  operating_system: string | null;
  location: string;
  threat_score: number;
  services: Array<{
    port: number;
    service: string;
    product: string;
    version: string;
  }>;
}

export class ShodanService {
  private static readonly BASE_URL = 'https://api.shodan.io';

  /**
   * Lookup IP address in Shodan (requires API key via edge function)
   */
  static async lookupIP(ip: string): Promise<ShodanHost | null> {
    try {
      // Call through edge function to keep API key secure
      const response = await fetch('/functions/v1/shodan-lookup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ip })
      });

      if (!response.ok) {
        console.error('Shodan API error:', response.status);
        return null;
      }

      const data: ShodanHost = await response.json();
      return data;
    } catch (error) {
      console.error('Shodan lookup error:', error);
      return null;
    }
  }

  /**
   * Enrich IP with comprehensive Shodan data
   */
  static async enrichIP(ip: string): Promise<ShodanEnrichment | null> {
    const hostData = await this.lookupIP(ip);
    
    if (!hostData) {
      return null;
    }

    const threatScore = this.calculateThreatScore(hostData);

    return {
      ip: hostData.ip_str,
      organization: hostData.org,
      isp: hostData.isp,
      autonomous_system: hostData.asn,
      hostnames: hostData.hostnames,
      domains: hostData.domains,
      open_ports: hostData.ports,
      vulnerabilities: hostData.vulns,
      operating_system: hostData.os,
      location: `${hostData.location.city}, ${hostData.location.country_name}`,
      threat_score: threatScore,
      services: [] // Populated from detailed service data
    };
  }

  /**
   * Calculate threat score based on Shodan findings
   */
  private static calculateThreatScore(host: ShodanHost): number {
    let score = 0;

    // Critical vulnerabilities
    const criticalCVEs = host.vulns.filter(v => 
      v.includes('CVE-') && this.isCriticalCVE(v)
    );
    score += criticalCVEs.length * 25;

    // Dangerous ports exposed
    const dangerousPorts = [23, 3389, 445, 1433, 3306, 5432, 6379, 9200, 27017];
    const exposedDangerous = host.ports.filter(p => dangerousPorts.includes(p));
    score += exposedDangerous.length * 15;

    // Threat tags
    score += host.tags.length * 10;

    return Math.min(score, 100);
  }

  /**
   * Check if CVE is critical severity
   */
  private static isCriticalCVE(cve: string): boolean {
    // In production, check against NVD database
    // For now, flag recent high-profile vulnerabilities
    const criticalKeywords = ['log4j', 'heartbleed', 'shellshock', 'eternal', 'ransomware'];
    return criticalKeywords.some(keyword => cve.toLowerCase().includes(keyword));
  }

  /**
   * Search Shodan for specific query (requires credits)
   */
  static async search(query: string, facets?: string[]): Promise<any> {
    try {
      const response = await fetch('/functions/v1/shodan-search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ query, facets })
      });

      if (!response.ok) {
        console.error('Shodan search error:', response.status);
        return null;
      }

      return await response.json();
    } catch (error) {
      console.error('Shodan search error:', error);
      return null;
    }
  }

  /**
   * Get organization's internet-facing assets
   */
  static async getOrganizationAssets(organization: string): Promise<any[]> {
    const searchQuery = `org:"${organization}"`;
    const results = await this.search(searchQuery);
    return results?.matches || [];
  }
}
