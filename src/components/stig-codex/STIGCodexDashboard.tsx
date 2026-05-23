/**
 * STIG-Codex Dashboard
 * Comprehensive STIG-first compliance automation interface
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Shield,
  Activity,
  Zap,
  Brain,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Eye,
  Settings,
  FileText,
  Globe
} from 'lucide-react';
import { STIGCodexState, STIGCodexOperations } from '@/hooks/useSTIGCodex';

interface STIGCodexDashboardProps extends STIGCodexState, STIGCodexOperations { }

export const STIGCodexDashboard: React.FC<STIGCodexDashboardProps> = (props) => {
  const {
    // State
    complianceScore,
    complianceBreakdown,
    riskAnalysis,
    agents,
    driftEvents,
    threatCorrelations,
    aiAnalyses,
    loading,
    error,
    lastUpdated,

    // Operations
    initializeMonitoring,
    detectDrift,
    executeRemediation,
    correlateThreatIntel,
    calculateCompliance,
    refreshAllData
  } = props;

  const handleInitializeMonitoring = async () => {
    // Awaiting telemetry for real asset and STIG rule data
    const pendingAssets: string[] = [];
    const pendingSTIGRules: string[] = [];
    await initializeMonitoring(pendingAssets, pendingSTIGRules);
  };

  const getComplianceColor = (score: number) => {
    if (score >= 90) return 'text-green-600 dark:text-green-400';
    if (score >= 75) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-red-600 dark:text-red-400';
  };

  const getSeverityBadge = (severity: string): "default" | "destructive" | "outline" | "secondary" => {
    const colors: Record<string, "default" | "destructive" | "outline" | "secondary"> = {
      critical: 'destructive',
      high: 'secondary',
      medium: 'outline',
      low: 'default'
    };
    return colors[severity] || 'default';
  };

  if (error) {
    return (
      <Alert className="m-4">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          STIG-Codex Error: {error}
          <Button
            variant="outline"
            size="sm"
            className="ml-2"
            onClick={refreshAllData}
          >
            Retry
          </Button>
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">STIG-Codex Dashboard</h1>
          <p className="text-muted-foreground">
            STIG-First Compliance Autopilot - Transform CMMC mandates into actionable STIG implementations
          </p>
        </div>
        <div className="flex items-center gap-2">
          {lastUpdated && (
            <Badge variant="outline" className="text-xs">
              <Clock className="h-3 w-3 mr-1" />
              Updated {new Date(lastUpdated).toLocaleTimeString()}
            </Badge>
          )}
          <Button onClick={refreshAllData} disabled={loading}>
            <Activity className="h-4 w-4 mr-2" />
            {loading ? 'Updating...' : 'Refresh'}
          </Button>
        </div>
      </div>

      {/* Compliance Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Overall Compliance</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <div className={`text-2xl font-bold ${getComplianceColor(complianceScore)}`}>
                {complianceScore}%
              </div>
              <Shield className="h-5 w-5 text-muted-foreground" />
            </div>
            <Progress value={complianceScore} className="mt-2" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Active Agents</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <div className="text-2xl font-bold">{agents.length}</div>
              <Eye className="h-5 w-5 text-muted-foreground" />
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Monitoring configurations
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Drift Events</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <div className="text-2xl font-bold text-orange-600">
                {driftEvents.filter(e => !e.acknowledged).length}
              </div>
              <AlertTriangle className="h-5 w-5 text-muted-foreground" />
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Unacknowledged violations
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Threat Correlations</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <div className="text-2xl font-bold text-red-600">
                {threatCorrelations.filter(t => t.risk_elevation === 'critical').length}
              </div>
              <Globe className="h-5 w-5 text-muted-foreground" />
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Critical threat matches
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="agents">STIG Agents</TabsTrigger>
          <TabsTrigger value="drift">Drift Detection</TabsTrigger>
          <TabsTrigger value="intelligence">Threat Intelligence</TabsTrigger>
          <TabsTrigger value="remediation">Automated Remediation</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Compliance Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <CheckCircle className="h-5 w-5 mr-2" />
                  Compliance Breakdown
                </CardTitle>
              </CardHeader>
              <CardContent>
                {complianceBreakdown ? (
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Compliant</span>
                      <Badge variant="default">{complianceBreakdown.compliant}</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Non-Compliant</span>
                      <Badge variant="destructive">{complianceBreakdown.non_compliant}</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Not Applicable</span>
                      <Badge variant="outline">{complianceBreakdown.not_applicable}</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Exceptions</span>
                      <Badge variant="secondary">{complianceBreakdown.exceptions_granted}</Badge>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-4">
                    <Button onClick={calculateCompliance} disabled={loading}>
                      Calculate Compliance
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Risk Analysis */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <TrendingUp className="h-5 w-5 mr-2" />
                  Risk Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                {riskAnalysis ? (
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Critical Violations</span>
                      <Badge variant="destructive">{riskAnalysis.critical_violations}</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">High Risk Assets</span>
                      <Badge variant="secondary">{riskAnalysis.high_risk_assets?.length || 0}</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm">Trend</span>
                      <Badge
                        variant={riskAnalysis.trending === 'improving' ? 'default' :
                          riskAnalysis.trending === 'declining' ? 'destructive' : 'outline'}
                      >
                        {riskAnalysis.trending}
                      </Badge>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-4 text-muted-foreground">
                    No risk analysis available
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="agents" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">STIG Monitoring Agents</h3>
            <Button onClick={handleInitializeMonitoring} disabled={loading}>
              <Settings className="h-4 w-4 mr-2" />
              Initialize Monitoring
            </Button>
          </div>

          {agents.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {agents.map((agent) => (
                <Card key={agent.id}>
                  <CardHeader className="pb-2">
                    <div className="flex justify-between items-start">
                      <CardTitle className="text-sm">{agent.agent_type}</CardTitle>
                      <Badge variant={agent.status === 'active' ? 'default' : 'outline'}>
                        {agent.status}
                      </Badge>
                    </div>
                    <CardDescription>{agent.deployment_mode} deployment</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 text-xs">
                      <div className="flex justify-between">
                        <span>Monitored:</span>
                        <span>{agent.performance_metrics.configurations_monitored}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Violations:</span>
                        <span className="text-red-600">{agent.performance_metrics.violations_detected}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Remediations:</span>
                        <span className="text-green-600">{agent.performance_metrics.successful_remediations}</span>
                      </div>
                      <Badge variant="outline" className="w-full justify-center">
                        {agent.operational_mode} mode
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="text-center py-8">
                <Eye className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground mb-4">No STIG agents deployed</p>
                <Button onClick={handleInitializeMonitoring} disabled={loading}>
                  Deploy First Agent
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="drift" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Configuration Drift Detection</h3>
            <Button onClick={() => detectDrift('pending-asset')} disabled={loading}>
              <Zap className="h-4 w-4 mr-2" />
              Scan for Drift
            </Button>
          </div>

          {driftEvents.length > 0 ? (
            <div className="space-y-4">
              {driftEvents.map((event) => (
                <Card key={event.id}>
                  <CardHeader className="pb-2">
                    <div className="flex justify-between items-start">
                      <CardTitle className="text-sm">{event.drift_type}</CardTitle>
                      <Badge variant={getSeverityBadge(event.severity) as "default" | "destructive" | "outline" | "secondary"}>
                        {event.severity}
                      </Badge>
                    </div>
                    <CardDescription>
                      STIG Rule: {event.stig_rule_id} • {event.detection_method}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Auto-remediated:</span>
                        <Badge variant={event.auto_remediated ? 'default' : 'outline'}>
                          {event.auto_remediated ? 'Yes' : 'No'}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Acknowledged:</span>
                        <Badge variant={event.acknowledged ? 'default' : 'destructive'}>
                          {event.acknowledged ? 'Yes' : 'Pending'}
                        </Badge>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Detected: {new Date(event.detected_at).toLocaleString()}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="text-center py-8">
                <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                <p className="text-muted-foreground">No configuration drift detected</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="intelligence" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Threat Intelligence</h3>
            <Button onClick={() => correlateThreatIntel()} disabled={loading}>
              <Brain className="h-4 w-4 mr-2" />
              Correlate Threats
            </Button>
          </div>

          {threatCorrelations.length > 0 ? (
            <div className="space-y-4">
              {threatCorrelations.slice(0, 5).map((correlation) => (
                <Card key={correlation.id}>
                  <CardHeader className="pb-2">
                    <div className="flex justify-between items-start">
                      <CardTitle className="text-sm">Threat: {correlation.threat_id}</CardTitle>
                      <Badge variant={getSeverityBadge(correlation.risk_elevation) as "default" | "destructive" | "outline" | "secondary"}>
                        {correlation.risk_elevation}
                      </Badge>
                    </div>
                    <CardDescription>
                      STIG Rule: {correlation.stig_rule_id}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Correlation Strength:</span>
                        <Progress value={correlation.correlation_strength * 100} className="w-20" />
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm">Urgency:</span>
                        <Badge variant="outline">{correlation.temporal_urgency}</Badge>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Platforms: {correlation.affected_platforms.join(', ')}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="text-center py-8">
                <Shield className="h-12 w-12 text-blue-500 mx-auto mb-4" />
                <p className="text-muted-foreground mb-4">No active threat correlations</p>
                <Button onClick={() => correlateThreatIntel()} disabled={loading}>
                  Run Threat Analysis
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="remediation" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Automated Remediation</h3>
            <Button
              onClick={() => executeRemediation('pending-violation')}
              disabled={loading}
              variant="default"
            >
              <Zap className="h-4 w-4 mr-2" />
              Test Remediation
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Remediation Queue</CardTitle>
                <CardDescription>Pending automated fixes</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-4 text-muted-foreground">
                  No pending remediations
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Recent Remediations</CardTitle>
                <CardDescription>Successfully applied fixes</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-4 text-muted-foreground">
                  No recent remediations
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};