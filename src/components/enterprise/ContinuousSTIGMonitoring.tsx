import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  RefreshCw,
  TrendingUp,
  Eye,
  Settings
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface MonitoringMetrics {
  total_assets: number;
  monitored_assets: number;
  compliance_percentage: number;
  active_scans: number;
  recent_findings: number;
  drift_events: number;
}

export const ContinuousSTIGMonitoring: React.FC = () => {
  const { toast } = useToast();
  const [metrics, setMetrics] = useState<MonitoringMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    fetchMonitoringData();
    // Set up real-time updates
    const interval = setInterval(fetchMonitoringData, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchMonitoringData = async () => {
    try {
      setLoading(true);

      // Fetch assets
      const { data: assets } = await supabase
        .from('environment_assets')
        .select('id, compliance_status');

      // Fetch recent implementations
      const { data: implementations } = await supabase
        .from('stig_rule_implementations')
        .select('compliance_status, severity')
        .gte('updated_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());

      // Fetch drift events
      const { data: driftEvents } = await supabase
        .from('compliance_drift_events')
        .select('id')
        .gte('detected_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());

      const totalAssets = assets?.length || 0;
      const monitoredAssets = assets?.filter(a => a.compliance_status).length || 0;
      const compliancePercentage = totalAssets > 0 ? (monitoredAssets / totalAssets) * 100 : 0;

      setMetrics({
        total_assets: totalAssets,
        monitored_assets: monitoredAssets,
        compliance_percentage: compliancePercentage,
        active_scans: 0, // Real value requires scan orchestration engine
        recent_findings: implementations?.length || 0,
        drift_events: driftEvents?.length || 0
      });

    } catch (error) {
      console.error('Error fetching monitoring data:', error);
    } finally {
      setLoading(false);
    }
  };

  const startFullScan = async () => {
    try {
      setScanning(true);
      
      const { data, error } = await supabase.functions.invoke('stig-compliance-monitor', {
        body: {
          organization_id: 'default',
          scan_type: 'full',
          remediation_mode: 'monitor'
        }
      });

      if (error) throw error;

      toast({
        title: "Full Scan Initiated",
        description: "Comprehensive STIG compliance scan has been started."
      });

      // Refresh data after scan
      setTimeout(fetchMonitoringData, 3000);

    } catch (error) {
      console.error('Error starting scan:', error);
      toast({
        title: "Scan Failed",
        description: "Failed to start compliance scan",
        variant: "destructive"
      });
    } finally {
      setScanning(false);
    }
  };

  if (loading && !metrics) {
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
          <h1 className="text-3xl font-bold">Continuous STIG Monitoring</h1>
          <p className="text-muted-foreground">
            Real-time compliance validation across all assets
          </p>
        </div>
        <div className="flex gap-2">
          <Button 
            onClick={startFullScan}
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
          <Button onClick={fetchMonitoringData} variant="outline">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Assets Monitored</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {metrics.monitored_assets}/{metrics.total_assets}
              </div>
              <Progress value={metrics.compliance_percentage} className="mt-2" />
              <p className="text-xs text-muted-foreground mt-2">
                {metrics.compliance_percentage.toFixed(1)}% coverage
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">
                {metrics.active_scans}
              </div>
              <p className="text-xs text-muted-foreground">
                Running compliance checks
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Recent Findings</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-600">
                {metrics.recent_findings}
              </div>
              <p className="text-xs text-muted-foreground">
                Last 24 hours
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Monitoring Dashboard */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="assets">Assets</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="trends">Trends</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Real-time Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span>Windows Servers</span>
                    <div className="flex items-center gap-2">
                      <Progress value={85} className="w-20" />
                      <span className="text-sm text-muted-foreground">85%</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Linux Systems</span>
                    <div className="flex items-center gap-2">
                      <Progress value={92} className="w-20" />
                      <span className="text-sm text-muted-foreground">92%</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Network Devices</span>
                    <div className="flex items-center gap-2">
                      <Progress value={78} className="w-20" />
                      <span className="text-sm text-muted-foreground">78%</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Databases</span>
                    <div className="flex items-center gap-2">
                      <Progress value={95} className="w-20" />
                      <span className="text-sm text-muted-foreground">95%</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Scan Activity</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    { time: '2 min ago', action: 'Windows Server scan completed', status: 'success' },
                    { time: '5 min ago', action: 'Linux baseline check started', status: 'running' },
                    { time: '12 min ago', action: 'Network device compliance verified', status: 'success' },
                    { time: '18 min ago', action: 'Database STIG validation finished', status: 'success' },
                    { time: '25 min ago', action: 'Critical finding detected', status: 'warning' }
                  ].map((activity, index) => (
                    <div key={index} className="flex items-center justify-between border-b pb-2">
                      <div>
                        <p className="text-sm font-medium">{activity.action}</p>
                        <p className="text-xs text-muted-foreground">{activity.time}</p>
                      </div>
                      <Badge variant={
                        activity.status === 'success' ? 'default' :
                        activity.status === 'warning' ? 'destructive' : 'secondary'
                      }>
                        {activity.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="assets">
          <Card>
            <CardHeader>
              <CardTitle>Monitored Assets</CardTitle>
              <CardDescription>
                All assets under continuous STIG compliance monitoring
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[
                  { name: 'DC-WIN-01', type: 'Windows Server 2022', status: 'Compliant', lastScan: '2 min ago' },
                  { name: 'WEB-LINUX-01', type: 'Ubuntu 22.04 LTS', status: 'Minor Issues', lastScan: '5 min ago' },
                  { name: 'FW-CISCO-01', type: 'Cisco ASA 5520', status: 'Compliant', lastScan: '8 min ago' },
                  { name: 'DB-SQL-01', type: 'SQL Server 2022', status: 'Compliant', lastScan: '12 min ago' }
                ].map((asset, index) => (
                  <div key={index} className="flex items-center justify-between border rounded-lg p-4">
                    <div>
                      <h3 className="font-medium">{asset.name}</h3>
                      <p className="text-sm text-muted-foreground">{asset.type}</p>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <Badge variant={asset.status === 'Compliant' ? 'default' : 'destructive'}>
                          {asset.status}
                        </Badge>
                        <p className="text-xs text-muted-foreground mt-1">
                          Last scan: {asset.lastScan}
                        </p>
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline">
                          <Eye className="h-3 w-3 mr-1" />
                          View
                        </Button>
                        <Button size="sm" variant="outline">
                          <Settings className="h-3 w-3 mr-1" />
                          Configure
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="findings">
          <Card>
            <CardHeader>
              <CardTitle>Recent Findings</CardTitle>
              <CardDescription>
                Latest compliance findings and drift detection results
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[
                  { 
                    finding: 'Password policy not enforced', 
                    asset: 'DC-WIN-01', 
                    severity: 'High', 
                    rule: 'WN22-AU-000070',
                    detected: '15 min ago'
                  },
                  { 
                    finding: 'Unused service running', 
                    asset: 'WEB-LINUX-01', 
                    severity: 'Medium', 
                    rule: 'UBTU-22-291010',
                    detected: '32 min ago'
                  },
                  { 
                    finding: 'Firewall rule drift', 
                    asset: 'FW-CISCO-01', 
                    severity: 'Low', 
                    rule: 'CSCO-FW-000123',
                    detected: '1 hour ago'
                  }
                ].map((finding, index) => (
                  <div key={index} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <h3 className="font-medium">{finding.finding}</h3>
                        <p className="text-sm text-muted-foreground">
                          Asset: {finding.asset} | Rule: {finding.rule}
                        </p>
                      </div>
                      <Badge variant={
                        finding.severity === 'High' ? 'destructive' :
                        finding.severity === 'Medium' ? 'default' : 'secondary'
                      }>
                        {finding.severity}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Detected: {finding.detected}
                    </p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="trends">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Compliance Trends</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span>Overall Compliance</span>
                    <div className="flex items-center gap-2">
                      <TrendingUp className="h-4 w-4 text-green-500" />
                      <span className="text-green-600">+2.3%</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Critical Findings</span>
                    <div className="flex items-center gap-2">
                      <TrendingUp className="h-4 w-4 text-red-500 rotate-180" />
                      <span className="text-red-600">-15%</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Drift Events</span>
                    <div className="flex items-center gap-2">
                      <TrendingUp className="h-4 w-4 text-green-500" />
                      <span className="text-green-600">-8%</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Performance Metrics</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span>Scan Completion Rate</span>
                    <span className="font-medium">98.7%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Average Scan Time</span>
                    <span className="font-medium">4.2 min</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>False Positive Rate</span>
                    <span className="font-medium">2.1%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>System Uptime</span>
                    <span className="font-medium">99.9%</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ContinuousSTIGMonitoring;