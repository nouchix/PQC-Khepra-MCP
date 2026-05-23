import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { Activity, AlertTriangle, CheckCircle, Clock, TrendingUp, Zap, Eye, BarChart3 } from 'lucide-react';

interface MetricData {
  timestamp: string;
  latency: number;
  throughput: number;
  errorRate: number;
  availability: number;
}

interface TraceData {
  id: string;
  operation: string;
  duration: number;
  status: 'success' | 'error' | 'warning';
  spans: number;
  timestamp: string;
}

export const ObservabilityDashboard = () => {
  const [metrics, setMetrics] = useState<MetricData[]>([]);
  const [traces, setTraces] = useState<TraceData[]>([]);
  const [alerts, setAlerts] = useState([
    { id: 1, type: 'latency', message: 'API latency spike detected', severity: 'warning', time: '2 min ago' },
    { id: 2, type: 'error', message: 'Error rate threshold exceeded', severity: 'critical', time: '5 min ago' },
    { id: 3, type: 'throughput', message: 'Throughput degradation', severity: 'info', time: '8 min ago' }
  ]);

  useEffect(() => {
    // Real-time metrics and trace data require APM integration (Datadog, Jaeger, etc.)
    // Returning empty arrays until real data sources are connected
    setMetrics([]);
    setTraces([]);
    // No interval needed without real data source
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'warning': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'error': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'warning': return 'text-yellow-600 bg-yellow-50';
      case 'info': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const currentMetrics = metrics.at(-1);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Observability Dashboard</h2>
          <p className="text-muted-foreground">Distributed tracing, metrics, and monitoring</p>
        </div>
        <Badge variant="secondary" className="bg-primary/10 text-primary">
          Phase 3 Implementation
        </Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Latency</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {currentMetrics ? `${currentMetrics.latency.toFixed(0)}ms` : '---'}
            </div>
            <p className="text-xs text-muted-foreground">
              -12% from last hour
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Throughput</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {currentMetrics ? `${currentMetrics.throughput.toFixed(0)}/s` : '---'}
            </div>
            <p className="text-xs text-muted-foreground">
              +23% from last hour
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Error Rate</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {currentMetrics ? `${currentMetrics.errorRate.toFixed(2)}%` : '---'}
            </div>
            <p className="text-xs text-muted-foreground">
              +0.2% from last hour
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Availability</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {currentMetrics ? `${currentMetrics.availability.toFixed(2)}%` : '---'}
            </div>
            <p className="text-xs text-muted-foreground">
              99.99% SLA target
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="metrics" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
          <TabsTrigger value="traces">Traces</TabsTrigger>
          <TabsTrigger value="logs">Logs</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
        </TabsList>

        <TabsContent value="metrics" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <BarChart3 className="h-4 w-4" />
                  <span>Latency Trends</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={metrics}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                    />
                    <YAxis />
                    <Line 
                      type="monotone" 
                      dataKey="latency" 
                      stroke="hsl(var(--primary))" 
                      strokeWidth={2}
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Activity className="h-4 w-4" />
                  <span>Throughput & Error Rate</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={metrics}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                    />
                    <YAxis />
                    <Area
                      type="monotone"
                      dataKey="throughput"
                      stackId="1"
                      stroke="hsl(var(--primary))"
                      fill="hsl(var(--primary))"
                      fillOpacity={0.3}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="errorRate" 
                      stroke="hsl(var(--destructive))" 
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Service Level Objectives (SLOs)</CardTitle>
              <CardDescription>Current performance against defined SLOs</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>API Latency (&lt; 100ms)</span>
                    <span className="font-medium">94.2%</span>
                  </div>
                  <Progress value={94.2} className="h-2" />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Error Rate (&lt; 1%)</span>
                    <span className="font-medium">98.7%</span>
                  </div>
                  <Progress value={98.7} className="h-2" />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Availability (99.9%)</span>
                    <span className="font-medium">99.95%</span>
                  </div>
                  <Progress value={99.95} className="h-2" />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="traces" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Eye className="h-4 w-4" />
                <span>Distributed Traces</span>
              </CardTitle>
              <CardDescription>Recent trace spans with performance details</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {traces.map((trace) => (
                  <div key={trace.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      {getStatusIcon(trace.status)}
                      <div>
                        <p className="font-medium text-sm">{trace.operation}</p>
                        <p className="text-xs text-muted-foreground">
                          {trace.spans} spans • {new Date(trace.timestamp).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="font-mono text-sm">{trace.duration.toFixed(1)}ms</p>
                      <Badge variant={trace.status === 'success' ? 'default' : 'destructive'} className="text-xs">
                        {trace.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4">
                <Button variant="outline" className="w-full">View All Traces</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="logs" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Structured Logging</CardTitle>
              <CardDescription>Application and system logs with correlation IDs</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 font-mono text-xs">
                <div className="p-2 bg-muted rounded">
                  <span className="text-blue-600">[INFO]</span> 2024-01-20 14:35:22 | trace_id=abc123 | API request processed successfully
                </div>
                <div className="p-2 bg-muted rounded">
                  <span className="text-yellow-600">[WARN]</span> 2024-01-20 14:35:18 | trace_id=def456 | Rate limit threshold approaching
                </div>
                <div className="p-2 bg-muted rounded">
                  <span className="text-red-600">[ERROR]</span> 2024-01-20 14:35:15 | trace_id=ghi789 | Database connection timeout
                </div>
                <div className="p-2 bg-muted rounded">
                  <span className="text-blue-600">[INFO]</span> 2024-01-20 14:35:10 | trace_id=jkl012 | User authentication successful
                </div>
              </div>
              <div className="mt-4">
                <Button variant="outline" className="w-full">Open Log Explorer</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Active Alerts</CardTitle>
              <CardDescription>Real-time alerts and notifications</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {alerts.map((alert) => (
                  <div key={alert.id} className={`p-3 rounded-lg ${getSeverityColor(alert.severity)}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <AlertTriangle className="h-4 w-4" />
                        <span className="font-medium text-sm">{alert.message}</span>
                      </div>
                      <div className="text-right">
                        <Badge variant="outline" className="text-xs">
                          {alert.severity}
                        </Badge>
                        <p className="text-xs mt-1">{alert.time}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4">
                <Button variant="outline" className="w-full">Manage Alert Rules</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};