/**
 * Continuous Compliance Monitor Service
 * Implements 30-minute enforcement cycles with real-time alerting
 * Supports policy-as-code and automated drift detection
 */

import { supabase } from '@/integrations/supabase/client';

export interface MonitoringPolicy {
  id: string;
  name: string;
  enforcementInterval: number; // minutes
  stigRules: string[];
  autoRemediate: boolean;
  alertThreshold: 'immediate' | 'after_retry' | 'daily_digest';
  notificationChannels: string[];
}

export interface ComplianceCheckResult {
  assetId: string;
  checkTimestamp: string;
  driftDetected: boolean;
  findings: DriftFinding[];
  remediationAttempted: boolean;
  remediationSuccess?: boolean;
}

export interface DriftFinding {
  stigRuleId: string;
  expectedState: any;
  actualState: any;
  severity: 'CAT_I' | 'CAT_II' | 'CAT_III';
  autoRemediable: boolean;
}

export class ContinuousComplianceMonitor {
  private monitoringIntervals: Map<string, NodeJS.Timeout> = new Map();

  /**
   * Start continuous monitoring for an asset
   */
  async startMonitoring(
    assetId: string,
    organizationId: string,
    policy: MonitoringPolicy
  ): Promise<void> {
    // Stop existing monitoring if any
    this.stopMonitoring(assetId);

    // Initial compliance check
    await this.performComplianceCheck(assetId, organizationId, policy);

    // Schedule continuous checks
    const intervalMs = policy.enforcementInterval * 60 * 1000;
    const intervalId = setInterval(async () => {
      await this.performComplianceCheck(assetId, organizationId, policy);
    }, intervalMs);

    this.monitoringIntervals.set(assetId, intervalId);

    // Log monitoring start in audit logs
    await supabase.from('audit_logs').insert({
      action: 'continuous_monitoring_started',
      resource_type: 'security_asset',
      resource_id: assetId,
      details: {
        policy_id: policy.id,
        enforcement_interval: policy.enforcementInterval,
        auto_remediate: policy.autoRemediate,
        next_check: new Date(Date.now() + intervalMs).toISOString(),
      },
    });
  }

  /**
   * Stop monitoring for an asset
   */
  stopMonitoring(assetId: string): void {
    const intervalId = this.monitoringIntervals.get(assetId);
    if (intervalId) {
      clearInterval(intervalId);
      this.monitoringIntervals.delete(assetId);
    }
  }

  /**
   * Perform a single compliance check
   */
  private async performComplianceCheck(
    assetId: string,
    organizationId: string,
    policy: MonitoringPolicy
  ): Promise<ComplianceCheckResult> {
    console.log(`[ContinuousMonitor] Checking compliance for asset ${assetId}`);

    // Fetch current asset configuration
    const { data: currentSnapshot } = await supabase
      .from('asset_configuration_snapshots')
      .select('*')
      .eq('asset_id', assetId)
      .order('captured_at', { ascending: false })
      .limit(1)
      .single();

    // Fetch baseline configuration
    const { data: baseline } = await supabase
      .from('stig_baselines')
      .select('*')
      .eq('organization_id', organizationId)
      .single();

    // Detect drift
    const currentConfig = currentSnapshot?.configuration_data as Record<string, any> | null;
    const baselineConfig = baseline?.configuration as Record<string, any> | null;
    
    const findings = await this.detectDrift(
      currentConfig,
      baselineConfig,
      policy.stigRules
    );

    const result: ComplianceCheckResult = {
      assetId,
      checkTimestamp: new Date().toISOString(),
      driftDetected: findings.length > 0,
      findings,
      remediationAttempted: false,
    };

    // Log drift event if detected
    if (findings.length > 0) {
      await this.logDriftEvent(assetId, organizationId, findings);

      // Attempt auto-remediation if enabled
      if (policy.autoRemediate) {
        result.remediationAttempted = true;
        result.remediationSuccess = await this.attemptRemediation(
          assetId,
          organizationId,
          findings.filter(f => f.autoRemediable)
        );
      }

      // Send alerts
      await this.sendAlerts(assetId, organizationId, findings, policy);
    }

    return result;
  }

  /**
   * Detect configuration drift
   */
  private async detectDrift(
    current: any,
    baseline: any,
    stigRules: string[]
  ): Promise<DriftFinding[]> {
    const findings: DriftFinding[] = [];

    if (!current || !baseline) return findings;

    // Compare each STIG rule configuration
    for (const ruleId of stigRules) {
      const currentValue = current[ruleId];
      const baselineValue = baseline[ruleId];

      if (JSON.stringify(currentValue) !== JSON.stringify(baselineValue)) {
        findings.push({
          stigRuleId: ruleId,
          expectedState: baselineValue,
          actualState: currentValue,
          severity: this.getSeverityForRule(ruleId),
          autoRemediable: this.isAutoRemediable(ruleId),
        });
      }
    }

    return findings;
  }

  /**
   * Attempt automated remediation
   */
  private async attemptRemediation(
    assetId: string,
    organizationId: string,
    findings: DriftFinding[]
  ): Promise<boolean> {
    try {
      const { data, error } = await supabase.functions.invoke(
        'automated-remediation-engine',
        {
          body: {
            organizationId,
            assetId,
            stigRules: findings.map(f => f.stigRuleId),
            executionMode: 'execute',
            triggeredBy: 'continuous_monitor',
          },
        }
      );

      if (error) throw error;
      return data.success === true;
    } catch (error) {
      console.error('[ContinuousMonitor] Remediation failed:', error);
      return false;
    }
  }

  /**
   * Log drift event to database
   */
  private async logDriftEvent(
    assetId: string,
    organizationId: string,
    findings: DriftFinding[]
  ): Promise<void> {
    await supabase.from('compliance_drift_events').insert(
      findings.map(finding => ({
        organization_id: organizationId,
        asset_id: assetId,
        stig_rule_id: finding.stigRuleId,
        severity: finding.severity,
        drift_type: 'configuration_change',
        previous_state: finding.expectedState,
        current_state: finding.actualState,
        detection_method: 'continuous_monitoring',
        auto_remediated: false,
      }))
    );
  }

  /**
   * Send alerts based on policy
   */
  private async sendAlerts(
    assetId: string,
    organizationId: string,
    findings: DriftFinding[],
    policy: MonitoringPolicy
  ): Promise<void> {
    const criticalFindings = findings.filter(f => f.severity === 'CAT_I');

    if (
      policy.alertThreshold === 'immediate' ||
      (criticalFindings.length > 0 && policy.alertThreshold === 'after_retry')
    ) {
      await supabase.from('alerts').insert({
        organization_id: organizationId,
        title: `Compliance Drift Detected: ${assetId}`,
        description: `${findings.length} STIG violations detected during continuous monitoring`,
        severity: criticalFindings.length > 0 ? 'CRITICAL' : 'HIGH',
        alert_type: 'compliance_drift',
        source_type: 'continuous_monitor',
        source_id: assetId,
        status: 'OPEN',
        metadata: {
          findings_count: findings.length,
          critical_count: criticalFindings.length,
          affected_rules: findings.map(f => f.stigRuleId),
        },
      });
    }
  }

  /**
   * Get severity for a STIG rule
   */
  private getSeverityForRule(ruleId: string): 'CAT_I' | 'CAT_II' | 'CAT_III' {
    // In production, fetch from database
    return 'CAT_II';
  }

  /**
   * Check if a rule is auto-remediable
   */
  private isAutoRemediable(ruleId: string): boolean {
    // In production, check against remediation playbook library
    return true;
  }

  /**
   * Get active monitoring sessions
   */
  getActiveMonitoring(): string[] {
    return Array.from(this.monitoringIntervals.keys());
  }
}

// Singleton instance
export const continuousComplianceMonitor = new ContinuousComplianceMonitor();
