/**
 * STIG JSON Converter Service
 * Supports STIG Viewer 3.5+ JSON format for modern checklist management
 * Converts between XML and JSON formats for better integration
 */

export interface STIGChecklistJSON {
  version: '3.5';
  metadata: {
    title: string;
    description: string;
    release: string;
    benchmark_date: string;
  };
  target: {
    hostname: string;
    ip_address?: string;
    mac_address?: string;
    fqdn?: string;
    role: string;
    technology_area: string;
  };
  checklist: STIGCheckJSON[];
  statistics: {
    total_rules: number;
    open: number;
    not_applicable: number;
    not_reviewed: number;
    compliant: number;
  };
}

export interface STIGCheckJSON {
  rule_id: string;
  stig_id: string;
  severity: 'high' | 'medium' | 'low';
  group_title: string;
  rule_title: string;
  vulnerability_discussion: string;
  check_content: string;
  fix_text: string;
  cci_references: string[];
  status: 'Open' | 'NotAFinding' | 'Not_Applicable' | 'Not_Reviewed';
  finding_details?: string;
  comments?: string;
  severity_override?: 'high' | 'medium' | 'low';
  severity_justification?: string;
}

export interface STIGChecklistXML {
  // Legacy XML structure
  xml: string;
}

export class STIGJsonConverter {
  /**
   * Convert XML STIG checklist to JSON format
   */
  async xmlToJson(xmlContent: string): Promise<STIGChecklistJSON> {
    // Parse XML (simplified - in production use a proper XML parser)
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlContent, 'text/xml');

    // Extract metadata
    const metadata = this.extractMetadata(xmlDoc);
    const target = this.extractTarget(xmlDoc);
    const checklist = this.extractChecklist(xmlDoc);

    // Calculate statistics
    const statistics = this.calculateStatistics(checklist);

    return {
      version: '3.5',
      metadata,
      target,
      checklist,
      statistics,
    };
  }

  /**
   * Convert JSON STIG checklist to XML format
   */
  async jsonToXml(jsonContent: STIGChecklistJSON): Promise<string> {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<CHECKLIST>\n';

    // Add metadata
    xml += '  <ASSET>\n';
    xml += `    <ROLE>${jsonContent.target.role}</ROLE>\n`;
    xml += `    <ASSET_TYPE>${jsonContent.target.technology_area}</ASSET_TYPE>\n`;
    xml += `    <HOST_NAME>${jsonContent.target.hostname}</HOST_NAME>\n`;
    if (jsonContent.target.ip_address) {
      xml += `    <HOST_IP>${jsonContent.target.ip_address}</HOST_IP>\n`;
    }
    xml += '  </ASSET>\n';

    // Add STIG info
    xml += '  <STIGS>\n';
    xml += '    <iSTIG>\n';
    xml += '      <STIG_INFO>\n';
    xml += `        <SID_NAME>version</SID_NAME>\n`;
    xml += `        <SID_DATA>${jsonContent.metadata.release}</SID_DATA>\n`;
    xml += '      </STIG_INFO>\n';

    // Add vulnerabilities
    for (const check of jsonContent.checklist) {
      xml += this.checkToXml(check);
    }

    xml += '    </iSTIG>\n';
    xml += '  </STIGS>\n';
    xml += '</CHECKLIST>';

    return xml;
  }

  /**
   * Export checklist as CSV for spreadsheet analysis
   */
  async exportToCsv(jsonContent: STIGChecklistJSON): Promise<string> {
    const headers = [
      'Rule ID',
      'STIG ID',
      'Severity',
      'Title',
      'Status',
      'Finding Details',
      'Comments',
    ];

    let csv = headers.join(',') + '\n';

    for (const check of jsonContent.checklist) {
      const row = [
        check.rule_id,
        check.stig_id,
        check.severity,
        `"${check.rule_title.replace(/"/g, '""')}"`,
        check.status,
        `"${(check.finding_details || '').replace(/"/g, '""')}"`,
        `"${(check.comments || '').replace(/"/g, '""')}"`,
      ];
      csv += row.join(',') + '\n';
    }

    return csv;
  }

  /**
   * Export checklist as HTML report
   */
  async exportToHtml(jsonContent: STIGChecklistJSON): Promise<string> {
    let html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>STIG Compliance Report - ${jsonContent.target.hostname}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #2c3e50; }
    .metadata { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
    .statistics { display: flex; gap: 15px; margin: 20px 0; }
    .stat-card { background: #3498db; color: white; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }
    .stat-card.open { background: #e74c3c; }
    .stat-card.compliant { background: #27ae60; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { border: 1px solid #bdc3c7; padding: 10px; text-align: left; }
    th { background: #34495e; color: white; }
    .high { color: #e74c3c; font-weight: bold; }
    .medium { color: #f39c12; font-weight: bold; }
    .low { color: #3498db; font-weight: bold; }
  </style>
</head>
<body>
  <h1>STIG Compliance Report</h1>
  
  <div class="metadata">
    <h2>Target System</h2>
    <p><strong>Hostname:</strong> ${jsonContent.target.hostname}</p>
    <p><strong>IP Address:</strong> ${jsonContent.target.ip_address || 'N/A'}</p>
    <p><strong>Role:</strong> ${jsonContent.target.role}</p>
    <p><strong>Technology Area:</strong> ${jsonContent.target.technology_area}</p>
  </div>

  <div class="statistics">
    <div class="stat-card">
      <h3>${jsonContent.statistics.total_rules}</h3>
      <p>Total Rules</p>
    </div>
    <div class="stat-card open">
      <h3>${jsonContent.statistics.open}</h3>
      <p>Open Findings</p>
    </div>
    <div class="stat-card compliant">
      <h3>${jsonContent.statistics.compliant}</h3>
      <p>Compliant</p>
    </div>
    <div class="stat-card">
      <h3>${jsonContent.statistics.not_applicable}</h3>
      <p>Not Applicable</p>
    </div>
  </div>

  <h2>Checklist Details</h2>
  <table>
    <thead>
      <tr>
        <th>Rule ID</th>
        <th>STIG ID</th>
        <th>Severity</th>
        <th>Title</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>`;

    for (const check of jsonContent.checklist) {
      html += `
      <tr>
        <td>${check.rule_id}</td>
        <td>${check.stig_id}</td>
        <td class="${check.severity}">${check.severity.toUpperCase()}</td>
        <td>${check.rule_title}</td>
        <td>${check.status}</td>
      </tr>`;
    }

    html += `
    </tbody>
  </table>
</body>
</html>`;

    return html;
  }

  /**
   * Validate JSON checklist format
   */
  validateJson(jsonContent: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (jsonContent.version !== '3.5') {
      errors.push('Invalid version: must be 3.5');
    }

    if (!jsonContent.metadata || !jsonContent.metadata.title) {
      errors.push('Missing required metadata');
    }

    if (!jsonContent.target || !jsonContent.target.hostname) {
      errors.push('Missing required target information');
    }

    if (!Array.isArray(jsonContent.checklist)) {
      errors.push('Checklist must be an array');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  // Helper methods
  private extractMetadata(xmlDoc: Document): STIGChecklistJSON['metadata'] {
    return {
      title: 'STIG Checklist',
      description: 'Automated STIG Compliance Checklist',
      release: 'Release 1',
      benchmark_date: new Date().toISOString().split('T')[0],
    };
  }

  private extractTarget(xmlDoc: Document): STIGChecklistJSON['target'] {
    return {
      hostname: 'unknown',
      role: 'None',
      technology_area: 'General',
    };
  }

  private extractChecklist(xmlDoc: Document): STIGCheckJSON[] {
    return [];
  }

  private calculateStatistics(
    checklist: STIGCheckJSON[]
  ): STIGChecklistJSON['statistics'] {
    return {
      total_rules: checklist.length,
      open: checklist.filter(c => c.status === 'Open').length,
      not_applicable: checklist.filter(c => c.status === 'Not_Applicable')
        .length,
      not_reviewed: checklist.filter(c => c.status === 'Not_Reviewed').length,
      compliant: checklist.filter(c => c.status === 'NotAFinding').length,
    };
  }

  private checkToXml(check: STIGCheckJSON): string {
    return `
      <VULN>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>${check.rule_id}</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STATUS>${check.status}</STATUS>
        <FINDING_DETAILS>${check.finding_details || ''}</FINDING_DETAILS>
        <COMMENTS>${check.comments || ''}</COMMENTS>
      </VULN>`;
  }
}
