import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export interface STIGFinding {
  id: string;
  scan_id: string;
  asset_id: string;
  rule_id: string;
  organization_id: string;
  finding_status: 'Open' | 'NotAFinding' | 'Not_Applicable' | 'Not_Reviewed';
  severity: 'CAT_I' | 'CAT_II' | 'CAT_III';
  comments?: string;
  finding_details: any;
  evidence: any[];
  assigned_to?: string;
  due_date?: string;
  remediation_status: 'pending' | 'in_progress' | 'completed' | 'verified' | 'exception_granted';
  remediation_priority: number;
  created_at: string;
  updated_at: string;
  environment_assets?: {
    asset_name: string;
    platform: string;
    operating_system: string;
  };
}

export interface STIGScan {
  id: string;
  organization_id: string;
  asset_id: string;
  scan_type: string;
  scan_status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  initiated_at: string;
  completed_at?: string;
  total_rules: number;
  passed_rules: number;
  failed_rules: number;
  cat_i_open: number;
  cat_ii_open: number;
  cat_iii_open: number;
  overall_score: number;
}

export interface ComplianceMetrics {
  total_assets: number;
  compliant_assets: number;
  non_compliant_assets: number;
  overall_compliance_percentage: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  recent_scans: number;
  automated_remediations: number;
}

export const useSTIGCompliance = (organizationId: string) => {
  const [findings, setFindings] = useState<STIGFinding[]>([]);
  const [scans, setScans] = useState<STIGScan[]>([]);
  const [metrics, setMetrics] = useState<ComplianceMetrics | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  // Fetch STIG findings
  const fetchFindings = async (filters?: {
    asset_id?: string;
    severity?: string;
    status?: string;
  }) => {
    try {
      setLoading(true);
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'get_findings',
          organization_id: organizationId,
          ...filters
        }
      });

      if (error) throw error;
      setFindings(data.findings || []);
    } catch (err) {
      console.error('Error fetching findings:', err);
      setError('Failed to fetch STIG findings');
      toast({
        title: "Error",
        description: "Failed to fetch STIG findings",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  // Awaiting telemetry for real scan data
  const fetchScans = async () => {
    try {
      const emptyScans: STIGScan[] = [];
      setScans(emptyScans);
    } catch (err) {
      console.error('Error fetching scans:', err);
      setError('Failed to fetch scans');
    }
  };

  // Calculate compliance metrics
  const calculateMetrics = async () => {
    try {
      // Get asset count
      const { data: assets, error: assetsError } = await supabase
        .from('environment_assets')
        .select('id, compliance_status')
        .eq('organization_id', organizationId);

      if (assetsError) throw assetsError;

      // Use edge function to get metrics data
      const { data: metricsData, error: metricsError } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'get_metrics',
          organization_id: organizationId
        }
      });

      if (metricsError) throw metricsError;

      const recentFindings = metricsData?.findings || [];
      const recentScans = metricsData?.scans || [];
      const remediations = metricsData?.remediations || [];

      const totalAssets = assets?.length || 0;
      const compliantAssets = assets?.filter(a => a.compliance_status === 'compliant').length || 0;
      const criticalFindings = recentFindings?.filter((f: any) => f.severity === 'CAT_I' && f.finding_status === 'Open').length || 0;
      const highFindings = recentFindings?.filter((f: any) => f.severity === 'CAT_II' && f.finding_status === 'Open').length || 0;
      const mediumFindings = recentFindings?.filter((f: any) => f.severity === 'CAT_III' && f.finding_status === 'Open').length || 0;

      setMetrics({
        total_assets: totalAssets,
        compliant_assets: compliantAssets,
        non_compliant_assets: totalAssets - compliantAssets,
        overall_compliance_percentage: totalAssets > 0 ? Math.round((compliantAssets / totalAssets) * 100) : 0,
        critical_findings: criticalFindings,
        high_findings: highFindings,
        medium_findings: mediumFindings,
        recent_scans: recentScans?.length || 0,
        automated_remediations: remediations?.length || 0
      });
    } catch (err) {
      console.error('Error calculating metrics:', err);
      setError('Failed to calculate metrics');
    }
  };

  // Initiate STIG scan
  const initiateScan = async (assetId: string, scanType: 'automated' | 'manual' | 'scheduled' = 'automated') => {
    try {
      setLoading(true);
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'scan',
          asset_id: assetId,
          organization_id: organizationId,
          scan_type: scanType
        }
      });

      if (error) throw error;

      toast({
        title: "Scan Initiated",
        description: `STIG compliance scan started for asset. Scan ID: ${data.scan_id}`,
      });

      // Refresh data
      await Promise.all([fetchScans(), fetchFindings(), calculateMetrics()]);

      return data;
    } catch (err) {
      console.error('Error initiating scan:', err);
      toast({
        title: "Scan Failed",
        description: "Failed to initiate STIG compliance scan",
        variant: "destructive"
      });
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // Execute remediation
  const executeRemediation = async (findingId: string, actionType: 'immediate' | 'scheduled' | 'manual_approval' = 'immediate') => {
    try {
      setLoading(true);
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'remediate',
          finding_id: findingId,
          organization_id: organizationId,
          action_type: actionType
        }
      });

      if (error) throw error;

      toast({
        title: data.success ? "Remediation Successful" : "Remediation Failed",
        description: data.message,
        variant: data.success ? "default" : "destructive"
      });

      // Refresh findings
      await fetchFindings();

      return data;
    } catch (err) {
      console.error('Error executing remediation:', err);
      toast({
        title: "Remediation Failed",
        description: "Failed to execute automated remediation",
        variant: "destructive"
      });
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // Update finding
  const updateFinding = async (findingId: string, updates: Partial<STIGFinding>) => {
    try {
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'update_finding',
          finding_id: findingId,
          updates
        }
      });

      if (error) throw error;

      toast({
        title: "Finding Updated",
        description: "STIG finding has been updated successfully",
      });

      // Refresh findings
      await fetchFindings();

      return data;
    } catch (err) {
      console.error('Error updating finding:', err);
      toast({
        title: "Update Failed",
        description: "Failed to update STIG finding",
        variant: "destructive"
      });
      throw err;
    }
  };

  // Generate compliance report
  const generateReport = async (scopeAssets?: string[], reportType: string = 'comprehensive') => {
    try {
      setLoading(true);
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'generate_report',
          organization_id: organizationId,
          scope_assets: scopeAssets,
          report_type: reportType
        }
      });

      if (error) throw error;

      toast({
        title: "Report Generated",
        description: "STIG compliance report has been generated successfully",
      });

      return data;
    } catch (err) {
      console.error('Error generating report:', err);
      toast({
        title: "Report Generation Failed",
        description: "Failed to generate compliance report",
        variant: "destructive"
      });
      throw err;
    } finally {
      setLoading(false);
    }
  };

  // Initialize data on mount
  useEffect(() => {
    if (organizationId) {
      fetchFindings();
      fetchScans();
      calculateMetrics();
    }
  }, [organizationId]);

  return {
    findings,
    scans,
    metrics,
    loading,
    error,
    fetchFindings,
    fetchScans,
    calculateMetrics,
    initiateScan,
    executeRemediation,
    updateFinding,
    generateReport,
    refresh: () => Promise.all([fetchFindings(), fetchScans(), calculateMetrics()])
  };
};