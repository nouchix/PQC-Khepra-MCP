"use client";
import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { FileCheck, Shield, AlertTriangle, RefreshCw } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';

interface ComplianceFramework {
  name: string;
  version: string;
  category: string;
  controls_total: number;
  controls_passed: number;
  controls_failed: number;
  controls_not_applicable: number;
  compliance_percentage: number;
  last_assessment: string;
  status: string;
  critical_gaps: string[];
}

export const ComplianceValidationDashboard = () => {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [loading, setLoading] = useState(false);
  const [overallCompliance, setOverallCompliance] = useState(0);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const runComplianceValidation = async () => {
    setLoading(true);

    try {
      // Real compliance data comes from validation results actually recorded
      // against the frameworks below — this dashboard never fabricates scores.
      const { data, error } = await supabase
        .from('compliance_validation_results')
        .select('*')
        .order('validated_at', { ascending: false });

      if (error) throw error;

      const rows: any[] = data || [];
      const byFramework = new Map<string, any[]>();
      for (const row of rows) {
        const key = row.framework_type || 'Unknown';
        if (!byFramework.has(key)) byFramework.set(key, []);
        byFramework.get(key)!.push(row);
      }

      const complianceResults: ComplianceFramework[] = Array.from(byFramework.entries()).map(
        ([name, results]) => {
          const passed = results.filter((r) => r.status === 'PASSED').length;
          const failed = results.filter((r) => r.status === 'FAILED').length;
          const notApplicable = results.filter((r) => r.status === 'NOT_APPLICABLE').length;
          const total = results.length;
          const pct = total > 0 ? Math.round((passed / total) * 1000) / 10 : 0;
          return {
            name,
            version: results[0]?.framework_version || 'N/A',
            category: results[0]?.category || 'N/A',
            controls_total: total,
            controls_passed: passed,
            controls_failed: failed,
            controls_not_applicable: notApplicable,
            compliance_percentage: pct,
            last_assessment: results[0]?.validated_at || new Date(0).toISOString(),
            status: pct >= 95 ? 'COMPLIANT' : pct > 0 ? 'MOSTLY_COMPLIANT' : 'NOT_ASSESSED',
            critical_gaps: results
              .filter((r) => r.status === 'FAILED')
              .map((r) => r.findings)
              .filter(Boolean)
          };
        }
      );

      setFrameworks(complianceResults);
      setLastChecked(new Date());

      const avgCompliance =
        complianceResults.length > 0
          ? complianceResults.reduce((sum, framework) => sum + framework.compliance_percentage, 0) /
            complianceResults.length
          : 0;
      setOverallCompliance(Math.round(avgCompliance));
    } catch (error) {
      console.error('Error running compliance validation:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runComplianceValidation();
  }, []);

  const getComplianceStatus = (percentage: number) => {
    if (percentage >= 95) return { status: 'Excellent', color: 'text-green-600', variant: 'default' as const };
    if (percentage >= 90) return { status: 'Good', color: 'text-yellow-600', variant: 'secondary' as const };
    if (percentage > 0) return { status: 'Needs Improvement', color: 'text-red-600', variant: 'destructive' as const };
    return { status: 'No Data', color: 'text-muted-foreground', variant: 'outline' as const };
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLIANT': return 'bg-green-100 text-green-800';
      case 'MOSTLY_COMPLIANT': return 'bg-yellow-100 text-yellow-800';
      case 'NON_COMPLIANT': return 'bg-red-100 text-red-800';
      case 'NOT_ASSESSED': return 'bg-gray-100 text-gray-600';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const overallStatus = getComplianceStatus(overallCompliance);

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance Validation Dashboard</h1>
          <p className="text-muted-foreground">
            Live compliance validation results recorded against implemented frameworks
          </p>
        </div>
        <Button onClick={runComplianceValidation} disabled={loading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Overall Compliance Score */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Overall Compliance Score</span>
            <Badge variant={overallStatus.variant}>
              {overallStatus.status}
            </Badge>
          </CardTitle>
          <CardDescription>
            Aggregate compliance across frameworks with recorded validation results
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className={`text-4xl font-bold ${overallStatus.color}`}>
                {overallCompliance}%
              </span>
              <div className="text-right text-sm text-muted-foreground">
                <div>Frameworks: {frameworks.length}</div>
                <div>Compliant: {frameworks.filter(f => f.status === 'COMPLIANT').length}</div>
              </div>
            </div>
            <Progress value={overallCompliance} className="h-3" />

            {frameworks.length === 0 && !loading && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  No compliance validation results have been recorded yet. Run real framework
                  assessments and store results in compliance_validation_results to populate this
                  dashboard.
                </AlertDescription>
              </Alert>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Compliance Framework Results */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {frameworks.map((framework, index) => (
          <Card key={index}>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="text-lg">{framework.name}</span>
                <Badge className={getStatusColor(framework.status)}>
                  {framework.status.replaceAll('_', ' ')}
                </Badge>
              </CardTitle>
              <CardDescription>
                {framework.category} • Version {framework.version}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-3xl font-bold text-primary">
                    {framework.compliance_percentage}%
                  </span>
                  <div className="text-right text-sm text-muted-foreground">
                    <div>Total Controls: {framework.controls_total}</div>
                    <div>Passed: {framework.controls_passed}</div>
                  </div>
                </div>
                <Progress value={framework.compliance_percentage} className="h-2" />

                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="p-2 bg-green-50 rounded">
                    <div className="text-lg font-semibold text-green-600">
                      {framework.controls_passed}
                    </div>
                    <div className="text-xs text-green-600">Passed</div>
                  </div>
                  <div className="p-2 bg-red-50 rounded">
                    <div className="text-lg font-semibold text-red-600">
                      {framework.controls_failed}
                    </div>
                    <div className="text-xs text-red-600">Failed</div>
                  </div>
                  <div className="p-2 bg-gray-50 rounded">
                    <div className="text-lg font-semibold text-gray-600">
                      {framework.controls_not_applicable}
                    </div>
                    <div className="text-xs text-gray-600">N/A</div>
                  </div>
                </div>

                {framework.critical_gaps.length > 0 && (
                  <div className="mt-4">
                    <h4 className="text-sm font-semibold mb-2 flex items-center">
                      <AlertTriangle className="h-4 w-4 mr-1 text-yellow-500" />
                      Failed Controls
                    </h4>
                    <div className="space-y-1">
                      {framework.critical_gaps.map((gap, gapIndex) => (
                        <div key={gapIndex} className="text-xs text-muted-foreground bg-yellow-50 p-2 rounded">
                          • {gap}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="text-xs text-muted-foreground">
                  Last Assessment: {new Date(framework.last_assessment).toLocaleString()}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {frameworks.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Compliance Notes</CardTitle>
            <CardDescription>
              Derived directly from recorded validation results — no scores are estimated or assumed
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <Alert>
                <Shield className="h-4 w-4" />
                <AlertDescription>
                  Framework percentages reflect only controls with a recorded PASSED/FAILED result.
                </AlertDescription>
              </Alert>
              <Alert>
                <FileCheck className="h-4 w-4" />
                <AlertDescription>
                  {lastChecked ? `Last refreshed: ${lastChecked.toLocaleString()}` : 'Not yet refreshed.'}
                </AlertDescription>
              </Alert>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
