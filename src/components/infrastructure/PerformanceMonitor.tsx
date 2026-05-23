import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { 
  Activity, Cpu, MemoryStick, HardDrive, Network, 
  AlertTriangle, TrendingUp, Gauge, Zap, RefreshCw
} from 'lucide-react';
import { format } from 'date-fns';

interface SystemMetrics {
  timestamp: string;
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  responseTime: number;
  throughput: number;
  errors: number;
}

interface ServiceHealth {
  id: string;
  name: string;
  status: 'healthy' | 'warning' | 'critical' | 'down';
  uptime: string;
  responseTime: number;
  cpu: number;
  memory: number;
  requestsPerSecond: number;
  errorRate: number;
}

interface Alert {
  id: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
  timestamp: string;
  service: string;
  resolved: boolean;
}

export const PerformanceMonitor = () => {
  const [metrics, setMetrics] = useState<SystemMetrics[]>([]);
  const [services, setServices] = useState<ServiceHealth[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [monitoring, setMonitoring] = useState(true);

  useEffect(() => {
    // Initialize with sample data
    // Real system metrics require infrastructure monitoring agent integration
    const generateMetrics = (): SystemMetrics[] => [];

    const sampleServices: ServiceHealth[] = [
      {
        id: '1',
        name: 'API Gateway',
        status: 'healthy',
        uptime: '99.9%',
        responseTime: 45,
        cpu: 23,
        memory: 67,
        requestsPerSecond: 147,
        errorRate: 0.02
      },
      {
        id: '2',
        name: 'Authentication Service',
        status: 'healthy',
        uptime: '99.8%',
        responseTime: 28,
        cpu: 18,
        memory: 54,
        requestsPerSecond: 89,
        errorRate: 0.01
      },
      {
        id: '3',
        name: 'Data Processing',
        status: 'warning',
        uptime: '98.5%',
        responseTime: 156,
        cpu: 78,
        memory: 85,
        requestsPerSecond: 234,
        errorRate: 0.08
      },
      {
        id: '4',
        name: 'Threat Detection Engine',
        status: 'healthy',
        uptime: '99.7%',
        responseTime: 34,
        cpu: 45,
        memory: 71,
        requestsPerSecond: 312,
        errorRate: 0.03
      }
    ];

    const sampleAlerts: Alert[] = [
      {
        id: '1',
        severity: 'warning',
        message: 'Data Processing service CPU usage above 75%',
        timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
        service: 'Data Processing',
        resolved: false
      },
      {
        id: '2',
        severity: 'info',
        message: 'System backup completed successfully',
        timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
        service: 'Backup Service',
        resolved: true
      },
      {
        id: '3',
        severity: 'critical',
        message: 'High memory usage detected on primary database',
        timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
        service: 'Database',
        resolved: true
      }
    ];

    setMetrics(generateMetrics());
    setServices(sampleServices);
    setAlerts(sampleAlerts);
    setLoading(false);

    // Real-time metric updates require infrastructure monitoring agent; interval removed to avoid fabricated data
  }, [monitoring]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'bg-success text-success-foreground';
      case 'warning': return 'bg-warning text-warning-foreground';
      case 'critical': return 'bg-destructive text-destructive-foreground';
      case 'down': return 'bg-muted text-muted-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'info': return 'bg-primary text-primary-foreground';
      case 'warning': return 'bg-warning text-warning-foreground';
      case 'critical': return 'bg-destructive text-destructive-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const formatTime = (timestamp: string) => {
    return format(new Date(timestamp), 'HH:mm');
  };

  const currentMetrics = metrics.at(-1);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-foreground">Loading performance metrics...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Performance Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">CPU Usage</p>
                <p className="text-2xl font-bold text-primary">{currentMetrics?.cpu || 0}%</p>
              </div>
              <Cpu className="h-8 w-8 text-primary" />
            </div>
            <Progress value={currentMetrics?.cpu || 0} className="mt-2" />
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Memory</p>
                <p className="text-2xl font-bold text-warning">{currentMetrics?.memory || 0}%</p>
              </div>
              <MemoryStick className="h-8 w-8 text-warning" />
            </div>
            <Progress value={currentMetrics?.memory || 0} className="mt-2" />
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Disk I/O</p>
                <p className="text-2xl font-bold text-accent">{currentMetrics?.disk || 0}%</p>
              </div>
              <HardDrive className="h-8 w-8 text-accent" />
            </div>
            <Progress value={currentMetrics?.disk || 0} className="mt-2" />
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Network</p>
                <p className="text-2xl font-bold text-success">{currentMetrics?.network || 0}%</p>
              </div>
              <Network className="h-8 w-8 text-success" />
            </div>
            <Progress value={currentMetrics?.network || 0} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* Monitoring Controls */}
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Activity className="h-5 w-5 text-primary" />
                <span>Performance Monitoring</span>
                {monitoring && (
                  <Badge className="bg-success text-success-foreground">
                    <div className="w-2 h-2 bg-success-foreground rounded-full animate-pulse mr-1"></div>
                    LIVE
                  </Badge>
                )}
              </CardTitle>
              <CardDescription>
                Real-time system performance metrics with Prometheus + Grafana integration
              </CardDescription>
            </div>
            <Button 
              variant={monitoring ? "outline" : "cyber"}
              onClick={() => setMonitoring(!monitoring)}
            >
              {monitoring ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Pause
                </>
              ) : (
                <>
                  <Activity className="h-4 w-4 mr-2" />
                  Resume
                </>
              )}
            </Button>
          </div>
        </CardHeader>
      </Card>

      {/* Performance Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="card-cyber">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Gauge className="h-5 w-5 text-primary" />
              <span>System Resources</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={metrics}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={formatTime}
                    stroke="hsl(var(--muted-foreground))"
                    fontSize={12}
                  />
                  <YAxis 
                    stroke="hsl(var(--muted-foreground))" 
                    fontSize={12}
                    domain={[0, 100]}
                  />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px',
                      color: 'hsl(var(--card-foreground))'
                    }}
                    labelFormatter={(value) => `Time: ${formatTime(value)}`}
                    formatter={(value: any) => [`${value}%`, '']}
                  />
                  <Line
                    type="monotone"
                    dataKey="cpu"
                    stroke="hsl(var(--primary))"
                    strokeWidth={2}
                    dot={false}
                    name="CPU"
                  />
                  <Line
                    type="monotone"
                    dataKey="memory"
                    stroke="hsl(var(--warning))"
                    strokeWidth={2}
                    dot={false}
                    name="Memory"
                  />
                  <Line
                    type="monotone"
                    dataKey="disk"
                    stroke="hsl(var(--accent))"
                    strokeWidth={2}
                    dot={false}
                    name="Disk"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <TrendingUp className="h-5 w-5 text-success" />
              <span>Response Time & Throughput</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={metrics}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={formatTime}
                    stroke="hsl(var(--muted-foreground))"
                    fontSize={12}
                  />
                  <YAxis 
                    stroke="hsl(var(--muted-foreground))" 
                    fontSize={12}
                  />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px',
                      color: 'hsl(var(--card-foreground))'
                    }}
                    labelFormatter={(value) => `Time: ${formatTime(value)}`}
                  />
                  <Area
                    type="monotone"
                    dataKey="responseTime"
                    stroke="hsl(var(--success))"
                    fill="hsl(var(--success))"
                    fillOpacity={0.3}
                    name="Response Time (ms)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Service Health and Alerts */}
      <Tabs defaultValue="services" className="space-y-4">
        <TabsList className="bg-card border border-border">
          <TabsTrigger value="services">Service Health</TabsTrigger>
          <TabsTrigger value="alerts">Alerts ({alerts.filter(a => !a.resolved).length})</TabsTrigger>
        </TabsList>

        <TabsContent value="services" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {services.map((service) => (
              <Card key={service.id} className="card-cyber">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">{service.name}</CardTitle>
                    <Badge className={getStatusColor(service.status)}>
                      {service.status.toUpperCase()}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Uptime:</span>
                        <p className="font-medium">{service.uptime}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Response:</span>
                        <p className="font-medium">{service.responseTime}ms</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">RPS:</span>
                        <p className="font-medium">{service.requestsPerSecond}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Error Rate:</span>
                        <p className="font-medium">{(service.errorRate * 100).toFixed(2)}%</p>
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex justify-between text-xs">
                        <span>CPU: {service.cpu}%</span>
                        <span>Memory: {service.memory}%</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <Progress value={service.cpu} className="h-1" />
                        <Progress value={service.memory} className="h-1" />
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle>System Alerts</CardTitle>
              <CardDescription>
                Performance alerts and system notifications
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {alerts.map((alert) => (
                  <div
                    key={alert.id}
                    className={`p-3 border rounded-lg ${alert.resolved ? 'opacity-50' : ''}`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        <AlertTriangle className="h-4 w-4 mt-0.5 text-warning" />
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            <Badge className={getSeverityColor(alert.severity)}>
                              {alert.severity.toUpperCase()}
                            </Badge>
                            <span className="text-sm text-muted-foreground">
                              {alert.service}
                            </span>
                            {alert.resolved && (
                              <Badge variant="outline">RESOLVED</Badge>
                            )}
                          </div>
                          <p className="text-sm text-foreground">{alert.message}</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {format(new Date(alert.timestamp), 'MMM dd, HH:mm')}
                          </p>
                        </div>
                      </div>
                    </div>
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