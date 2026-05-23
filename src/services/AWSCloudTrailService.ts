/**
 * AWS CloudTrail Service for KHEPRA Protocol
 * Handles audit event logging to AWS CloudTrail Data Store
 */

export interface CloudTrailConfig {
  channelArn: string;
  externalId: string;
  region: string;
  accountId: string;
}

export interface AuditEventPayload {
  eventSource: string;
  eventName: string;
  userIdentity: {
    type: string;
    principalId: string;
    arn?: string;
    accountId: string;
    userName?: string;
  };
  awsRegion: string;
  sourceIPAddress?: string;
  userAgent?: string;
  resources?: Array<{
    accountId: string;
    type: string;
    ARN: string;
  }>;
  eventType: 'AwsApiCall' | 'AwsServiceEvent' | 'AwsConsoleAction';
  managementEvent: boolean;
  additionalEventData?: Record<string, any>;
  serviceEventDetails?: Record<string, any>;
}

export class AWSCloudTrailService {
  private config: CloudTrailConfig;

  constructor(config: CloudTrailConfig) {
    this.config = config;
  }

  /**
   * Send an audit event to AWS CloudTrail
   * Note: This is a client-side implementation. In production, 
   * this should be handled by a backend service with proper AWS SDK integration.
   */
  async sendAuditEvent(payload: AuditEventPayload): Promise<void> {
    const event = {
      eventVersion: '1.08',
      ...payload,
      eventTime: new Date().toISOString(),
      recipientAccountId: this.config.accountId,
      eventId: this.generateEventId(),
    };

    console.log('Audit event prepared for CloudTrail:', {
      channelArn: this.config.channelArn,
      externalId: this.config.externalId,
      event
    });

    // In a real implementation, this would call:
    // await cloudTrailDataClient.putAuditEvents({
    //   channelArn: this.config.channelArn,
    //   externalId: this.config.externalId,
    //   auditEvents: [event]
    // });

    // For now, log to console and send to backend via API
    try {
      await this.sendToBackend(event);
    } catch (error) {
      console.error('Failed to send audit event:', error);
      throw error;
    }
  }

  /**
   * Send KHEPRA Protocol security events
   */
  async logSecurityEvent(eventName: string, details: Record<string, any>): Promise<void> {
    await this.sendAuditEvent({
      eventSource: 'khepra-protocol.ai',
      eventName,
      userIdentity: {
        type: 'IAMUser',
        principalId: 'KHEPRA-PROTOCOL-AGENT',
        accountId: this.config.accountId,
        userName: 'khepra-agent'
      },
      awsRegion: this.config.region,
      sourceIPAddress: await this.getClientIP(),
      userAgent: 'KHEPRA-Protocol/1.0',
      resources: [{
        accountId: this.config.accountId,
        type: 'AWS::CloudTrail::Channel',
        ARN: this.config.channelArn
      }],
      eventType: 'AwsServiceEvent',
      managementEvent: false,
      serviceEventDetails: details
    });
  }

  /**
   * Log agent orchestration events
   */
  async logAgentEvent(agentId: string, action: string, details: Record<string, any>): Promise<void> {
    await this.logSecurityEvent('AgentOrchestrationEvent', {
      agentId,
      action,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  /**
   * Log compliance validation events
   */
  async logComplianceEvent(framework: string, controlId: string, status: 'PASS' | 'FAIL' | 'WARNING', details: Record<string, any>): Promise<void> {
    await this.logSecurityEvent('ComplianceValidationEvent', {
      framework,
      controlId,
      status,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  /**
   * Log threat detection events
   */
  async logThreatEvent(threatType: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', details: Record<string, any>): Promise<void> {
    await this.logSecurityEvent('ThreatDetectionEvent', {
      threatType,
      severity,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  private generateEventId(): string {
    return `khepra-${Date.now()}-${crypto.randomUUID().replace(/-/g, '').substr(0, 9)}`;
  }

  private async getClientIP(): Promise<string> {
    try {
      // In a real app, you might use a service to get the actual IP
      return '127.0.0.1';
    } catch {
      return '127.0.0.1';
    }
  }

  private async sendToBackend(event: any): Promise<void> {
    // This would typically send to your Supabase Edge Function
    // which would then use the AWS SDK to call cloudtrail-data:PutAuditEvents
    const response = await fetch('/api/audit-events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        channelArn: this.config.channelArn,
        externalId: this.config.externalId,
        event
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
  }

  /**
   * Test the CloudTrail connection
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.logSecurityEvent('ConnectionTest', {
        timestamp: new Date().toISOString(),
        source: 'khepra-protocol-ui'
      });
      return true;
    } catch (error) {
      console.error('CloudTrail connection test failed:', error);
      return false;
    }
  }
}

// Default configuration based on the provided CloudTrail setup
export const defaultCloudTrailConfig: CloudTrailConfig = {
  channelArn: 'arn:aws:cloudtrail:us-east-1:445971788114:channel/de77d6a3-e98c-46f3-abbd-8925101cb20f',
  externalId: 'souhimbou-ai',
  region: 'us-east-1',
  accountId: '445971788114'
};

// Singleton instance for easy access
export const cloudTrailService = new AWSCloudTrailService(defaultCloudTrailConfig);