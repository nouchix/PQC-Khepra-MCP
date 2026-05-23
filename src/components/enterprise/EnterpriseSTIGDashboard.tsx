import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Activity,
  TrendingUp,
  FileText,
  Settings,
  RefreshCw,
  Zap,
  Database,
  Network
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface ComplianceMetrics {
  total_assets: number;
  compliant_assets: number;
  compliance_percentage: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  drift_events: number;
  auto_remediations: number;
}

interface STIGBaseline {
  id: string;
  stig_id: string;
  stig_version: string;
  baseline_name: string;
  platform: string;
  implementation_status: string;
  created_at: string;
}

export const EnterpriseSTIGDashboard: React.FC = () => {
  const { toast } = useToast();
  const [metrics, setMetrics] = useState<ComplianceMetrics | null>(null);
  const [baselines, setBaselines] = useState<STIGBaseline[]>([]);
  const [recentEvents, setRecentEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);

      // Fetch compliance metrics
      const metricsData = await calculateComplianceMetrics();
      setMetrics(metricsData);

      // Fetch STIG baselines
      const { data: baselinesData, error: baselinesError } = await supabase
        .from('stig_baselines')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(10);

      if (baselinesError) throw baselinesError;
      setBaselines(baselinesData || []);

      // Fetch recent compliance events
      const { data: eventsData, error: eventsError } = await supabase
        .from('compliance_drift_events')
        .select(`
          *,
          environment_assets!inner(asset_name, asset_type)
        `)
        .order('detected_at', { ascending: false })
        .limit(20);

      if (eventsError) throw eventsError;
      setRecentEvents(eventsData || []);

    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      toast({
        title: "Error",
        description: "Failed to load dashboard data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const calculateComplianceMetrics = async (): Promise<ComplianceMetrics> => {
    // Fetch assets
    const { data: assets } = await supabase
      .from('environment_assets')
      .select('id, compliance_status');

    // Fetch implementations
    const { data: implementations } = await supabase
      .from('stig_rule_implementations')
      .select('compliance_status, severity');

    // Fetch drift events
    const { data: driftEvents } = await supabase
      .from('compliance_drift_events')
      .select('id, auto_remediated')
      .gte('detected_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());

    const totalAssets = assets?.length || 0;
    const compliantAssets = assets?.filter(a => 
      Object.values(a.compliance_status || {}).every(status => status === 'COMPLIANT')
    ).length || 0;

    const criticalFindings = implementations?.filter(i => 
      i.compliance_status !== 'COMPLIANT' && i.severity === 'CRITICAL'
    ).length || 0;

    const highFindings = implementations?.filter(i => 
      i.compliance_status !== 'COMPLIANT' && i.severity === 'HIGH'
    ).length || 0;

    const mediumFindings = implementations?.filter(i => 
      i.compliance_status !== 'COMPLIANT' && i.severity === 'MEDIUM'
    ).length || 0;

    const lowFindings = implementations?.filter(i => 
      i.compliance_status !== 'COMPLIANT' && i.severity === 'LOW'
    ).length || 0;

    return {
      total_assets: totalAssets,
      compliant_assets: compliantAssets,
      compliance_percentage: totalAssets > 0 ? (compliantAssets / totalAssets) * 100 : 0,
      critical_findings: criticalFindings,
      high_findings: highFindings,
      medium_findings: mediumFindings,
      low_findings: lowFindings,
      drift_events: driftEvents?.length || 0,
      auto_remediations: driftEvents?.filter(e => e.auto_remediated).length || 0
    };
  };

  const triggerFullScan = async () => {
    try {
      setScanning(true);
      
      const { data, error } = await supabase.functions.invoke('stig-compliance-monitor', {
        body: {
          organization_id: 'default', // In real app, get from context
          scan_type: 'full',
          remediation_mode: 'safe'
        }
      });

      if (error) throw error;

      toast({
        title: "Compliance Scan Initiated",
        description: `Full STIG compliance scan started. Results will be available shortly.`
      });

      // Refresh dashboard data after scan
      setTimeout(() => {
        fetchDashboardData();
      }, 2000);

    } catch (error) {
      console.error('Error triggering scan:', error);
      toast({
        title: "Scan Failed",
        description: "Failed to initiate compliance scan",
        variant: "destructive"
      });
    } finally {
      setScanning(false);
    }
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'default';
      case 'LOW': return 'secondary';
      default: return 'outline';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toUpperCase()) {
      case 'COMPLIANT':
      case 'IMPLEMENTED':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'NOT_COMPLIANT':
      case 'FAILED':
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'PENDING':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      default:
        return <Activity className="h-4 w-4 text-blue-500" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Enterprise STIG Compliance</h1>
          <p className="text-muted-foreground">
            Continuous STIG monitoring and automated remediation for DOD contractors
          </p>
        </div>
        <div className="flex gap-2">
          <Button 
            onClick={triggerFullScan}
            disabled={scanning}
            variant="outline"
          >
            {scanning ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Shield className="h-4 w-4 mr-2" />
            )}
            {scanning ? 'Scanning...' : 'Full Scan'}
          </Button>
          <Button onClick={fetchDashboardData} variant="outline">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Overall Compliance</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {metrics.compliance_percentage.toFixed(1)}%
              </div>
              <Progress value={metrics.compliance_percentage} className="mt-2" />
              <p className="text-xs text-muted-foreground mt-2">
                {metrics.compliant_assets} of {metrics.total_assets} assets compliant
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Critical Findings</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">
                {metrics.critical_findings}
              </div>
              <div className="flex gap-2 mt-2">
                <Badge variant="destructive">Critical: {metrics.critical_findings}</Badge>
                <Badge variant="destructive">High: {metrics.high_findings}</Badge>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Drift Events</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.drift_events}</div>
              <p className="text-xs text-muted-foreground">
                {metrics.auto_remediations} auto-remediated
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Auto-Remediation</CardTitle>
              <Zap className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">
                {metrics.auto_remediations}
              </div>
              <p className="text-xs text-muted-foreground">
                Successful automations today
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="baselines">STIG Baselines</TabsTrigger>
          <TabsTrigger value="events">Drift Events</TabsTrigger>
          <TabsTrigger value="remediation">Remediation</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Compliance Status by Platform
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {['Windows Server', 'Linux', 'Network Devices', 'Database'].map((platform) => (
                    <div key={platform} className="flex items-center justify-between">
                      <span className="font-medium">{platform}</span>
                      <div className="flex items-center gap-2">
                        <Progress
                          value={0}
                          className="w-24"
                        />
                        <span className="text-sm text-muted-foreground">
                          {'N/A'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Recent Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {recentEvents.slice(0, 5).map((event, index) => (
                    <div key={event.id || index} className="flex items-center justify-between border-b pb-2">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(event.drift_type)}
                        <div>
                          <p className="text-sm font-medium">
                            {event.environment_assets?.asset_name || 'Unknown Asset'}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {event.stig_rule_id} - {event.drift_type}
                          </p>
                        </div>
                      </div>
                      <Badge variant={getSeverityColor(event.severity) as any}>
                        {event.severity}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="baselines">
          <Card>
            <CardHeader>
              <CardTitle>STIG Baselines</CardTitle>
              <CardDescription>
                Configured STIG baselines for automated compliance checking
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {baselines.map((baseline) => (
                  <div key={baseline.id} className="flex items-center justify-between border rounded-lg p-4">
                    <div className="flex items-center gap-4">
                      <Database className="h-8 w-8 text-muted-foreground" />
                      <div>
                        <h3 className="font-medium">{baseline.baseline_name}</h3>
                        <p className="text-sm text-muted-foreground">
                          {baseline.stig_id} v{baseline.stig_version} - {baseline.platform}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {getStatusIcon(baseline.implementation_status)}
                      <Badge variant={getSeverityColor(baseline.implementation_status) as any}>
                        {baseline.implementation_status}
                      </Badge>
                    </div>
                  </div>
                ))}
                {baselines.length === 0 && (
                  <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      No STIG baselines configured. Set up baselines to enable automated compliance monitoring.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="events">
          <Card>
            <CardHeader>
              <CardTitle>Compliance Drift Events</CardTitle>
              <CardDescription>
                Real-time monitoring of compliance drift and configuration changes
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentEvents.map((event) => (
                  <div key={event.id} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(event.drift_type)}
                        <h3 className="font-medium">
                          {event.environment_assets?.asset_name || 'Unknown Asset'}
                        </h3>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={getSeverityColor(event.severity) as any}>
                          {event.severity}
                        </Badge>
                        {event.auto_remediated && (
                          <Badge variant="secondary">
                            <Zap className="h-3 w-3 mr-1" />
                            Auto-Fixed
                          </Badge>
                        )}
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground mb-2">
                      STIG Rule: {event.stig_rule_id} - {event.drift_type}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Detected: {new Date(event.detected_at).toLocaleString()}
                    </p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="remediation">
          <Card>
            <CardHeader>
              <CardTitle>Automated Remediation</CardTitle>
              <CardDescription>
                Manage automated STIG remediation playbooks and execution
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Alert>
                <Settings className="h-4 w-4" />
                <AlertDescription>
                  Remediation orchestrator component will be integrated here for managing 
                  automated STIG remediation workflows, playbooks, and execution policies.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports">
          <Card>
            <CardHeader>
              <CardTitle>Compliance Reports</CardTitle>
              <CardDescription>
                Generate and manage STIG compliance reports for audits
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Alert>
                <FileText className="h-4 w-4" />
                <AlertDescription>
                  STIG compliance reporting and audit evidence collection will be available here.
                  Reports will be generated automatically and can be exported for compliance audits.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};