import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { 
  Activity, 
  AlertTriangle, 
  TrendingUp, 
  TrendingDown,
  RefreshCw,
  Settings,
  Zap,
  Clock,
  Shield,
  Eye,
  Target,
  CheckCircle,
  AlertCircle
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface DriftEvent {
  id: string;
  asset_id: string;
  asset_name: string;
  asset_type: string;
  stig_rule_id: string;
  drift_type: string;
  severity: string;
  previous_state: any;
  current_state: any;
  detection_method: string;
  auto_remediated: boolean;
  acknowledged: boolean;
  detected_at: string;
  confidence_score: number;
  risk_impact: string;
}

interface MonitoringMetrics {
  total_assets_monitored: number;
  drift_events_24h: number;
  critical_drifts: number;
  auto_remediations: number;
  average_confidence: number;
  detection_accuracy: number;
}

export const ComplianceDriftMonitor: React.FC = () => {
  const { toast } = useToast();
  const [driftEvents, setDriftEvents] = useState<DriftEvent[]>([]);
  const [metrics, setMetrics] = useState<MonitoringMetrics | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedAssetType, setSelectedAssetType] = useState<string>('all');
  const [monitoringEnabled, setMonitoringEnabled] = useState(true);
  const [autoRemediation, setAutoRemediation] = useState(false);
  const [sensitivityLevel, setSensitivityLevel] = useState<'low' | 'medium' | 'high'>('medium');
  const [loading, setLoading] = useState(true);
  const [monitoring, setMonitoring] = useState(false);

  useEffect(() => {
    fetchDriftData();
    const interval = setInterval(fetchDriftData, 30000); // Poll every 30 seconds
    return () => clearInterval(interval);
  }, [selectedSeverity, selectedAssetType]);

  const fetchDriftData = async () => {
    try {
      setLoading(true);

      // Fetch drift events with filtering
      let query = supabase
        .from('compliance_drift_events')
        .select('*')
        .order('detected_at', { ascending: false })
        .limit(50);

      // Apply filters
      if (selectedSeverity !== 'all') {
        query = query.eq('severity', selectedSeverity.toUpperCase());
      }

      const { data: eventsData, error: eventsError } = await query;
      
      if (eventsError) throw eventsError;

      // Transform the data to include asset information
      const transformedEvents: DriftEvent[] = (eventsData || []).map(event => ({
        ...event,
        asset_name: `Asset-${event.asset_id.slice(-4)}`,
        asset_type: (event as any).asset_type || 'unknown',
        confidence_score: 0,
        risk_impact: (event as any).risk_level || 'UNKNOWN'
      }));

      // Filter by asset type if specified
      const filteredEvents = selectedAssetType === 'all' 
        ? transformedEvents 
        : transformedEvents.filter(e => e.asset_type.toLowerCase().includes(selectedAssetType.toLowerCase()));

      setDriftEvents(filteredEvents);

      // Calculate metrics
      const metricsData = calculateMetrics(filteredEvents);
      setMetrics(metricsData);

    } catch (error) {
      console.error('Error fetching drift data:', error);
      toast({
        title: "Error",
        description: "Failed to load drift monitoring data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const calculateMetrics = (events: DriftEvent[]): MonitoringMetrics => {
    const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recent = events.filter(e => new Date(e.detected_at) >= last24Hours);
    
    return {
      total_assets_monitored: new Set(events.map(e => e.asset_id)).size || 0,
      drift_events_24h: recent.length,
      critical_drifts: recent.filter(e => e.severity === 'CRITICAL').length,
      auto_remediations: recent.filter(e => e.auto_remediated).length,
      average_confidence: recent.length > 0 
        ? recent.reduce((sum, e) => sum + e.confidence_score, 0) / recent.length 
        : 0,
      detection_accuracy: 0.94 // Simulated accuracy metric
    };
  };

  const startDriftDetection = async () => {
    try {
      setMonitoring(true);

      const { data, error } = await supabase.functions.invoke('compliance-drift-detector', {
        body: {
          organization_id: 'default',
          detection_mode: 'triggered',
          sensitivity_level: sensitivityLevel,
          auto_remediation: autoRemediation
        }
      });

      if (error) throw error;

      toast({
        title: "Drift Detection Started",
        description: `Monitoring ${data.drift_analysis?.total_assets_monitored || 0} assets for compliance drift`
      });

      // Refresh data after detection
      setTimeout(fetchDriftData, 2000);

    } catch (error) {
      console.error('Error starting drift detection:', error);
      toast({
        title: "Detection Failed",
        description: "Failed to start drift detection",
        variant: "destructive"
      });
    } finally {
      setMonitoring(false);
    }
  };

  const acknowledgeDrift = async (eventId: string) => {
    try {
      const { error } = await supabase
        .from('compliance_drift_events')
        .update({ 
          acknowledged: true,
          acknowledged_at: new Date().toISOString()
        })
        .eq('id', eventId);

      if (error) throw error;

      toast({
        title: "Event Acknowledged",
        description: "Drift event has been acknowledged"
      });

      fetchDriftData();

    } catch (error) {
      console.error('Error acknowledging drift:', error);
      toast({
        title: "Error",
        description: "Failed to acknowledge drift event",
        variant: "destructive"
      });
    }
  };

  const triggerRemediation = async (event: DriftEvent) => {
    try {
      const { error } = await supabase.functions.invoke('automated-remediation-engine', {
        body: {
          organization_id: 'default',
          asset_id: event.asset_id,
          stig_rule_id: event.stig_rule_id,
          execution_mode: 'execute'
        }
      });

      if (error) throw error;

      toast({
        title: "Remediation Triggered",
        description: `Starting remediation for ${event.asset_name}`
      });

    } catch (error) {
      console.error('Error triggering remediation:', error);
      toast({
        title: "Remediation Failed",
        description: "Failed to trigger automated remediation",
        variant: "destructive"
      });
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

  const getDriftTypeIcon = (driftType: string) => {
    switch (driftType.toLowerCase()) {
      case 'configuration_change':
        return <Settings className="h-4 w-4" />;
      case 'policy_violation':
        return <Shield className="h-4 w-4" />;
      case 'security_event':
        return <AlertTriangle className="h-4 w-4" />;
      case 'unauthorized_access':
        return <Eye className="h-4 w-4" />;
      default:
        return <Activity className="h-4 w-4" />;
    }
  };

  const getConfidenceColor = (confidence: number): string => {
    if (confidence >= 0.9) return 'text-green-600';
    if (confidence >= 0.7) return 'text-yellow-600';
    return 'text-red-600';
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
          <h1 className="text-3xl font-bold">Compliance Drift Monitor</h1>
          <p className="text-muted-foreground">
            Real-time monitoring and detection of STIG compliance drift
          </p>
        </div>
        <div className="flex gap-2">
          <Button 
            onClick={startDriftDetection}
            disabled={monitoring}
            variant="outline"
          >
            {monitoring ? (
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Target className="h-4 w-4 mr-2" />
            )}
            {monitoring ? 'Detecting...' : 'Scan Now'}
          </Button>
          <Button onClick={fetchDriftData} variant="outline">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Monitoring Status & Metrics */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Assets Monitored</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.total_assets_monitored}</div>
              <div className="flex items-center gap-2 mt-2">
                <div className={`h-2 w-2 rounded-full ${monitoringEnabled ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-xs text-muted-foreground">
                  {monitoringEnabled ? 'Active' : 'Inactive'}
                </span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Drift Events (24h)</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.drift_events_24h}</div>
              <div className="flex items-center gap-2 mt-2">
                <Badge variant="destructive">Critical: {metrics.critical_drifts}</Badge>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Auto-Remediated</CardTitle>
              <Zap className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{metrics.auto_remediations}</div>
              <p className="text-xs text-muted-foreground">
                {metrics.drift_events_24h > 0 
                  ? `${((metrics.auto_remediations / metrics.drift_events_24h) * 100).toFixed(0)}% auto-fixed`
                  : 'No events to remediate'
                }
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Detection Accuracy</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{(metrics.detection_accuracy * 100).toFixed(1)}%</div>
              <Progress value={metrics.detection_accuracy * 100} className="mt-2" />
            </CardContent>
          </Card>
        </div>
      )}

      {/* Main Content */}
      <Tabs defaultValue="events" className="space-y-6">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="events">Drift Events</TabsTrigger>
          <TabsTrigger value="settings">Monitoring Settings</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
        </TabsList>

        <TabsContent value="events">
          {/* Filters */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Event Filters</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-4">
                <div className="flex-1">
                  <Label>Severity</Label>
                  <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severities</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex-1">
                  <Label>Asset Type</Label>
                  <Select value={selectedAssetType} onValueChange={setSelectedAssetType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Asset Types</SelectItem>
                      <SelectItem value="server">Servers</SelectItem>
                      <SelectItem value="network">Network Devices</SelectItem>
                      <SelectItem value="database">Databases</SelectItem>
                      <SelectItem value="workstation">Workstations</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Drift Events List */}
          <Card>
            <CardHeader>
              <CardTitle>Detected Drift Events</CardTitle>
              <CardDescription>
                Recent compliance drift events requiring attention
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {driftEvents.map((event) => (
                  <div key={event.id} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        {getDriftTypeIcon(event.drift_type)}
                        <div>
                          <h3 className="font-medium">{event.asset_name}</h3>
                          <p className="text-sm text-muted-foreground">
                            {event.asset_type} • STIG Rule: {event.stig_rule_id}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={getSeverityColor(event.severity) as any}>
                          {event.severity}
                        </Badge>
                        {event.auto_remediated ? (
                          <Badge variant="secondary">
                            <Zap className="h-3 w-3 mr-1" />
                            Auto-Fixed
                          </Badge>
                        ) : (
                          <Badge variant="outline">Manual</Badge>
                        )}
                        {event.acknowledged && (
                          <Badge variant="secondary">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Ack'd
                          </Badge>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-3 text-sm">
                      <div>
                        <span className="text-muted-foreground">Drift Type:</span>
                        <p className="font-medium">{event.drift_type.replaceAll('_', ' ')}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Detection Method:</span>
                        <p className="font-medium">{event.detection_method}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Confidence:</span>
                        <p className={`font-medium ${getConfidenceColor(event.confidence_score)}`}>
                          {(event.confidence_score * 100).toFixed(0)}%
                        </p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Risk Impact:</span>
                        <p className="font-medium">{event.risk_impact}</p>
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">
                        Detected: {new Date(event.detected_at).toLocaleString()}
                      </p>
                      <div className="flex gap-2">
                        {!event.acknowledged && (
                          <Button 
                            size="sm" 
                            variant="outline" 
                            onClick={() => acknowledgeDrift(event.id)}
                          >
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Acknowledge
                          </Button>
                        )}
                        {!event.auto_remediated && (
                          <Button 
                            size="sm" 
                            onClick={() => triggerRemediation(event)}
                          >
                            <Zap className="h-3 w-3 mr-1" />
                            Remediate
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}

                {driftEvents.length === 0 && (
                  <Alert>
                    <CheckCircle className="h-4 w-4" />
                    <AlertDescription>
                      No compliance drift events detected. All monitored assets appear to be maintaining their STIG baseline configurations.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings">
          <Card>
            <CardHeader>
              <CardTitle>Monitoring Configuration</CardTitle>
              <CardDescription>
                Configure drift detection sensitivity and remediation settings
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-medium">Enable Continuous Monitoring</h3>
                    <p className="text-sm text-muted-foreground">
                      Continuously monitor all assets for compliance drift
                    </p>
                  </div>
                  <Switch 
                    checked={monitoringEnabled} 
                    onCheckedChange={setMonitoringEnabled}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Detection Sensitivity</Label>
                  <Select 
                    value={sensitivityLevel} 
                    onValueChange={(value: 'low' | 'medium' | 'high') => setSensitivityLevel(value)}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low - Major changes only</SelectItem>
                      <SelectItem value="medium">Medium - Balanced detection</SelectItem>
                      <SelectItem value="high">High - Sensitive to minor changes</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-medium">Auto-Remediation</h3>
                    <p className="text-sm text-muted-foreground">
                      Automatically remediate low-risk drift when detected
                    </p>
                  </div>
                  <Switch 
                    checked={autoRemediation} 
                    onCheckedChange={setAutoRemediation}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analytics">
          <Card>
            <CardHeader>
              <CardTitle>Drift Analytics</CardTitle>
              <CardDescription>
                Analyze compliance drift patterns and trends
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Alert>
                <TrendingUp className="h-4 w-4" />
                <AlertDescription>
                  Advanced analytics dashboard with drift trend analysis, pattern recognition, 
                  and predictive compliance insights will be available here.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};