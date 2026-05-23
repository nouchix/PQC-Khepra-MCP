/**
 * InternetDB API Integration
 * Fast IP lookups for open ports, vulnerabilities, and threat intelligence
 * API Docs: https://internetdb.shodan.io/
 */

export interface InternetDBHost {
  cpes: string[];
  hostnames: string[];
  ip: string;
  ports: number[];
  tags: string[];
  vulns: string[];
}

export interface InternetDBEnrichment {
  ip: string;
  open_ports: number[];
  vulnerabilities: string[];
  cpe_identifiers: string[];
  hostnames: string[];
  threat_tags: string[];
  risk_score: number;
  last_seen?: string;
}

export class InternetDBService {
  private static readonly BASE_URL = 'https://internetdb.shodan.io';

  /**
   * Lookup IP address in InternetDB for threat intelligence
   */
  static async lookupIP(ip: string): Promise<InternetDBHost | null> {
    try {
      const response = await fetch(`${this.BASE_URL}/${ip}`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        if (response.status === 404) {
          // IP not found in database - clean IP
          return null;
        }
        throw new Error(`InternetDB API error: ${response.status}`);
      }

      const data: InternetDBHost = await response.json();
      return data;
    } catch (error) {
      console.error('InternetDB lookup error:', error);
      return null;
    }
  }

  /**
   * Enrich IP data with threat intelligence
   */
  static async enrichIP(ip: string): Promise<InternetDBEnrichment | null> {
    const hostData = await this.lookupIP(ip);
    
    if (!hostData) {
      return {
        ip,
        open_ports: [],
        vulnerabilities: [],
        cpe_identifiers: [],
        hostnames: [],
        threat_tags: [],
        risk_score: 0
      };
    }

    // Calculate risk score based on findings
    const riskScore = this.calculateRiskScore(hostData);

    return {
      ip: hostData.ip,
      open_ports: hostData.ports,
      vulnerabilities: hostData.vulns,
      cpe_identifiers: hostData.cpes,
      hostnames: hostData.hostnames,
      threat_tags: hostData.tags,
      risk_score: riskScore,
      last_seen: new Date().toISOString()
    };
  }

  /**
   * Calculate risk score based on InternetDB findings
   */
  private static calculateRiskScore(host: InternetDBHost): number {
    let score = 0;

    // Base risk from open ports
    score += host.ports.length * 2;

    // High risk ports
    const highRiskPorts = [23, 3389, 445, 1433, 3306, 5432, 27017];
    const hasHighRiskPort = host.ports.some(p => highRiskPorts.includes(p));
    if (hasHighRiskPort) score += 20;

    // Vulnerabilities significantly increase risk
    score += host.vulns.length * 15;

    // Threat tags (malware, botnet, etc.)
    score += host.tags.length * 10;

    // Normalize to 0-100
    return Math.min(score, 100);
  }

  /**
   * Batch lookup multiple IPs
   */
  static async batchLookup(ips: string[]): Promise<Map<string, InternetDBEnrichment | null>> {
    const results = new Map<string, InternetDBEnrichment | null>();
    
    // Process in parallel with rate limiting
    const batchSize = 10;
    for (let i = 0; i < ips.length; i += batchSize) {
      const batch = ips.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(ip => this.enrichIP(ip))
      );
      
      batch.forEach((ip, index) => {
        results.set(ip, batchResults[index]);
      });

      // Rate limiting - wait 1 second between batches
      if (i + batchSize < ips.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    return results;
  }

  /**
   * Check if IP has known vulnerabilities
   */
  static async hasVulnerabilities(ip: string): Promise<boolean> {
    const data = await this.lookupIP(ip);
    return data ? data.vulns.length > 0 : false;
  }

  /**
   * Get vulnerability details for IP
   */
  static async getVulnerabilities(ip: string): Promise<string[]> {
    const data = await this.lookupIP(ip);
    return data?.vulns || [];
  }
}
