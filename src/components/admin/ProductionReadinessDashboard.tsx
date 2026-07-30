"use client";
import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Shield, AlertTriangle, CheckCircle, XCircle, RefreshCw, Network, Key } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';

interface SecurityFinding {
  id: string;
  level: 'error' | 'warn' | 'info';
  name: string;
  description: string;
  category: string;
}

interface PerformanceMetric {
  metric_name: string;
  value: number;
  metadata: any;
  recorded_at: string;
}

interface ComplianceResult {
  framework_type: string;
  control_id: string;
  status: string;
  score: number;
  findings: string;
}

export const ProductionReadinessDashboard = () => {
  const [securityFindings, setSecurityFindings] = useState<SecurityFinding[]>([]);
  const [performanceMetrics, setPerformanceMetrics] = useState<PerformanceMetric[]>([]);
  const [complianceResults, setComplianceResults] = useState<ComplianceResult[]>([]);
  const [overallScore, setOverallScore] = useState(0);
  const [loading, setLoading] = useState(true);
  const [lastScanTime, setLastScanTime] = useState<Date | null>(null);

  const fetchSecurityFindings = async () => {
    try {
      // No real security findings/scan table is wired up yet (checked
      // types.ts for security_findings/security_scan/vulnerability tables —
      // none exist that map to this shape). Rather than fabricate findings,
      // this dashboard reports an honest empty state until a real scanning
      // mechanism is implemented and its results are persisted.
      setSecurityFindings([]);
    } catch (error) {
      console.error('Error fetching security findings:', error);
    }
  };

  const fetchPerformanceMetrics = async () => {
    try {
      const { data, error } = await supabase
        .from('performance_metrics')
        .select('*')
        .order('recorded_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      setPerformanceMetrics(data || []);
    } catch (error) {
      console.error('Error fetching performance metrics:', error);
    }
  };

  const fetchComplianceResults = async () => {
    try {
      const { data, error } = await supabase
        .from('compliance_validation_results')
        .select('*')
        .order('validated_at', { ascending: false })
        .limit(100);

      if (error) throw error;
      setComplianceResults(data || []);
    } catch (error) {
      console.error('Error fetching compliance results:', error);
    }
  };

  const calculateOverallScore = () => {
    const securityScore = securityFindings.filter(f => f.level !== 'error').length / Math.max(securityFindings.length, 1) * 100;
    const complianceScore = complianceResults.filter(r => r.status === 'PASSED').length / Math.max(complianceResults.length, 1) * 100;
    // Derived from real recorded performance_metrics rows (average of the
    // numeric `value` field). 0 when there is no recorded data — never a
    // fabricated constant.
    const numericValues = performanceMetrics
      .map((m) => m.value)
      .filter((v): v is number => typeof v === 'number');
    const performanceScore = numericValues.length > 0
      ? Math.min(100, Math.max(0, numericValues.reduce((sum, v) => sum + v, 0) / numericValues.length))
      : 0;

    const overall = (securityScore + complianceScore + performanceScore) / 3;
    setOverallScore(Math.round(overall));
  };

  const runComprehensiveAudit = async () => {
    setLoading(true);
    setLastScanTime(new Date());
    
    await Promise.all([
      fetchSecurityFindings(),
      fetchPerformanceMetrics(),
      fetchComplianceResults()
    ]);
    
    calculateOverallScore();
    setLoading(false);
  };

  useEffect(() => {
    runComprehensiveAudit();
  }, []);

  useEffect(() => {
    calculateOverallScore();
  }, [securityFindings, performanceMetrics, complianceResults]);

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-600';
    if (score >= 70) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getScoreStatus = (score: number) => {
    if (score >= 90) return 'Production Ready';
    if (score >= 70) return 'Needs Attention';
    return 'Critical Issues';
  };

  // Real aggregation of compliance_validation_results by framework_type —
  // mirrors the logic in ComplianceValidationDashboard.tsx. Never fabricated.
  const complianceByFramework = (() => {
    const byFramework = new Map<string, ComplianceResult[]>();
    for (const r of complianceResults) {
      const key = r.framework_type || 'Unknown';
      if (!byFramework.has(key)) byFramework.set(key, []);
      byFramework.get(key)!.push(r);
    }
    return Array.from(byFramework.entries()).map(([name, results]) => {
      const passed = results.filter((r) => r.status === 'PASSED').length;
      const total = results.length;
      const pct = total > 0 ? Math.round((passed / total) * 1000) / 10 : 0;
      return { name, pct, total, passed };
    });
  })();

  // Real derivation from recorded performance_metrics rows. Falls back to an
  // honest "No data" placeholder rather than a fabricated number when no
  // matching metric has been recorded.
  const getMetricDisplay = (nameFragment: string, unit: string) => {
    const match = performanceMetrics.find(
      (m) => typeof m.metric_name === 'string' && m.metric_name.toLowerCase().includes(nameFragment)
    );
    if (match && typeof match.value === 'number') {
      return `${match.value}${unit}`;
    }
    return 'No data';
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Production Readiness Audit</h1>
          <p className="text-muted-foreground">
            Comprehensive security, performance, and compliance assessment
          </p>
        </div>
        <Button onClick={runComprehensiveAudit} disabled={loading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Run Audit
        </Button>
      </div>

      {/* Overall Score Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Overall Production Readiness Score</span>
            <Badge variant={overallScore >= 90 ? 'default' : overallScore >= 70 ? 'secondary' : 'destructive'}>
              {getScoreStatus(overallScore)}
            </Badge>
          </CardTitle>
          <CardDescription>
            Based on security, compliance, and performance metrics
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className={`text-4xl font-bold ${getScoreColor(overallScore)}`}>
                {overallScore}%
              </span>
              {lastScanTime && (
                <span className="text-sm text-muted-foreground">
                  Last scan: {lastScanTime.toLocaleString()}
                </span>
              )}
            </div>
            <Progress value={overallScore} className="h-3" />
            
            {overallScore < 90 && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  {overallScore < 70 
                    ? 'Critical issues detected. Platform requires immediate attention before production deployment.'
                    : 'Some issues detected. Address these before production deployment for optimal security.'}
                </AlertDescription>
              </Alert>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Detailed Audit Results */}
      <Tabs defaultValue="security" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="security" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="performance" className="flex items-center gap-2">
            <Network className="h-4 w-4" />
            Performance
          </TabsTrigger>
          <TabsTrigger value="compliance" className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4" />
            Compliance
          </TabsTrigger>
          <TabsTrigger value="integration" className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            Integration
          </TabsTrigger>
        </TabsList>

        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security Audit Results</CardTitle>
              <CardDescription>
                Database security, RLS policies, and authentication configuration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {securityFindings.map((finding) => (
                  <div key={finding.id} className="flex items-start space-x-4 p-4 border rounded-lg">
                    <div className="flex-shrink-0">
                      {finding.level === 'error' ? (
                        <XCircle className="h-5 w-5 text-red-500" />
                      ) : finding.level === 'warn' ? (
                        <AlertTriangle className="h-5 w-5 text-yellow-500" />
                      ) : (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <h4 className="font-semibold">{finding.name}</h4>
                        <Badge variant={
                          finding.level === 'error' ? 'destructive' : 
                          finding.level === 'warn' ? 'secondary' : 'default'
                        }>
                          {finding.level.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {finding.description}
                      </p>
                      <span className="text-xs text-muted-foreground">
                        Category: {finding.category}
                      </span>
                    </div>
                  </div>
                ))}
                
                {securityFindings.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-yellow-500" />
                    <p>No live security scan has been run yet.</p>
                    <p className="text-xs mt-2">
                      Security findings integration is not yet implemented for this dashboard —
                      this is not a clean scan result.
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="performance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Performance Metrics</CardTitle>
              <CardDescription>
                Real-time system performance and response times
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { label: 'Asset Discovery', fragment: 'discovery', unit: 's', caption: 'avg response' },
                  { label: 'Database Queries', fragment: 'quer', unit: 'ms', caption: 'avg query time' },
                  { label: 'Real-time Updates', fragment: 'realtime', unit: 'ms', caption: 'websocket latency' }
                ].map((item) => {
                  const display = getMetricDisplay(item.fragment, item.unit);
                  const hasData = display !== 'No data';
                  return (
                    <div key={item.label} className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">{item.label}</span>
                        <Badge variant={hasData ? 'default' : 'outline'}>
                          {hasData ? 'Measured' : 'No data'}
                        </Badge>
                      </div>
                      <div className="mt-2">
                        <span className="text-2xl font-bold">{display}</span>
                        {hasData && (
                          <span className="text-sm text-muted-foreground ml-2">{item.caption}</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
              {performanceMetrics.length === 0 && (
                <Alert className="mt-4">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    No performance metrics have been recorded yet in performance_metrics.
                  </AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Compliance Validation</CardTitle>
              <CardDescription>
                CMMC, NIST, and DoD compliance framework status
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {complianceByFramework.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {complianceByFramework.map((framework) => (
                      <div key={framework.name} className="p-4 border rounded-lg">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">{framework.name}</span>
                          <Badge variant="default">{framework.pct}% Complete</Badge>
                        </div>
                        <Progress value={framework.pct} className="mt-2" />
                        <div className="text-xs text-muted-foreground mt-1">
                          {framework.passed}/{framework.total} controls passed
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      No compliance validation results have been recorded yet in
                      compliance_validation_results.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="integration" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Integration Status</CardTitle>
              <CardDescription>
                Security tool integrations and data flow validation
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Alert className="mb-4">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  None of these integrations are wired up to a live connection check yet.
                  Status shown below is honest — connecting the real integration is required
                  before this can report anything other than "Not Configured".
                </AlertDescription>
              </Alert>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {[
                  'CrowdStrike EDR',
                  'Wiz Cloud Security',
                  'Splunk SIEM',
                  'Zscaler Zero Trust',
                  'NVIDIA Morpheus',
                  'KHEPRA Protocol'
                ].map((name) => (
                  <div key={name} className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">{name}</span>
                      <Badge variant="outline">Not Configured</Badge>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      Real connection status requires this integration to be wired up.
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};