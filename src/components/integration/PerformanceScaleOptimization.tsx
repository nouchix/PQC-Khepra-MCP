import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { 
  Zap, 
  TrendingUp, 
  Server, 
  Globe, 
  Database, 
  BarChart3,
  Activity,
  Clock,
  ArrowUp,
  Target
} from 'lucide-react';

interface PerformanceMetric {
  timestamp: string;
  latency: number;
  throughput: number;
  cpuUsage: number;
  memoryUsage: number;
  errorRate: number;
}

interface SLOTarget {
  id: string;
  name: string;
  target: string;
  current: string;
  status: 'meeting' | 'at-risk' | 'breached';
  trend: 'up' | 'down' | 'stable';
}

interface ScalingRule {
  id: string;
  name: string;
  metric: string;
  threshold: number;
  action: string;
  enabled: boolean;
  lastTriggered?: string;
}

export const PerformanceScaleOptimization = () => {
  const [metrics, setMetrics] = useState<PerformanceMetric[]>([]);
  const [sloTargets] = useState<SLOTarget[]>([
    {
      id: 'latency-p99',
      name: 'API Latency (P99)',
      target: '< 100ms',
      current: '87ms',
      status: 'meeting',
      trend: 'down'
    },
    {
      id: 'throughput',
      name: 'Throughput',
      target: '> 10K TPS',
      current: '12.5K TPS',
      status: 'meeting',
      trend: 'up'
    },
    {
      id: 'availability',
      name: 'Availability',
      target: '99.99%',
      current: '99.95%',
      status: 'at-risk',
      trend: 'stable'
    },
    {
      id: 'error-rate',
      name: 'Error Rate',
      target: '< 0.1%',
      current: '0.05%',
      status: 'meeting',
      trend: 'down'
    }
  ]);

  const [scalingRules, setScalingRules] = useState<ScalingRule[]>([
    {
      id: 'cpu-scale-up',
      name: 'CPU Scale Up',
      metric: 'CPU Usage',
      threshold: 70,
      action: 'Add 2 instances',
      enabled: true,
      lastTriggered: '2024-01-19 14:23:00'
    },
    {
      id: 'memory-scale-up',
      name: 'Memory Scale Up',
      metric: 'Memory Usage',
      threshold: 80,
      action: 'Add 1 instance',
      enabled: true
    },
    {
      id: 'latency-scale-up',
      name: 'Latency Scale Up',
      metric: 'Response Time',
      threshold: 150,
      action: 'Add 3 instances',
      enabled: true
    },
    {
      id: 'queue-scale-up',
      name: 'Queue Scale Up',
      metric: 'Queue Depth',
      threshold: 100,
      action: 'Add worker nodes',
      enabled: false
    }
  ]);

  useEffect(() => {
    // Performance metrics require real monitoring integration (Datadog, CloudWatch, etc.)
    // Returning empty array until real data source is connected
    setMetrics([]);
    // No interval needed without real data source
  }, []);

  const toggleScalingRule = (id: string) => {
    setScalingRules(prev => prev.map(rule => 
      rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
    ));
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'meeting': return <Target className="h-4 w-4 text-green-500" />;
      case 'at-risk': return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'breached': return <ArrowUp className="h-4 w-4 text-red-500" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <TrendingUp className="h-3 w-3 text-green-500" />;
      case 'down': return <TrendingUp className="h-3 w-3 text-red-500 rotate-180" />;
      default: return <div className="h-3 w-3 bg-gray-400 rounded-full" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'meeting': return 'text-green-600 bg-green-50';
      case 'at-risk': return 'text-yellow-600 bg-yellow-50';
      case 'breached': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const currentMetrics = metrics.at(-1);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Performance & Scale Optimization</h2>
          <p className="text-muted-foreground">Auto-scaling, performance guarantees, and SLA monitoring</p>
        </div>
        <Badge variant="secondary" className="bg-primary/10 text-primary">
          Phase 6 Implementation
        </Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Latency (P99)</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {currentMetrics ? `${currentMetrics.latency.toFixed(0)}ms` : '---'}
            </div>
            <div className="flex items-center text-xs text-muted-foreground">
              <TrendingUp className="h-3 w-3 text-green-500 mr-1" />
              <span>-12% vs SLA target</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Throughput</CardTitle>
            <BarChart3 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {currentMetrics ? `${(currentMetrics.throughput / 1000).toFixed(1)}K TPS` : '---'}
            </div>
            <div className="flex items-center text-xs text-muted-foreground">
              <TrendingUp className="h-3 w-3 text-green-500 mr-1" />
              <span>+25% above target</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">CPU Usage</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {currentMetrics ? `${currentMetrics.cpuUsage.toFixed(0)}%` : '---'}
            </div>
            <div className="flex items-center text-xs text-muted-foreground">
              <div className="h-3 w-3 bg-gray-400 rounded-full mr-1" />
              <span>Optimal range</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Memory Usage</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {currentMetrics ? `${currentMetrics.memoryUsage.toFixed(0)}%` : '---'}
            </div>
            <div className="flex items-center text-xs text-muted-foreground">
              <div className="h-3 w-3 bg-gray-400 rounded-full mr-1" />
              <span>Within limits</span>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="performance" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="scaling">Auto-Scaling</TabsTrigger>
          <TabsTrigger value="slo">SLO Management</TabsTrigger>
          <TabsTrigger value="optimization">Optimization</TabsTrigger>
          <TabsTrigger value="capacity">Capacity Planning</TabsTrigger>
        </TabsList>

        <TabsContent value="performance" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Activity className="h-4 w-4" />
                  <span>Latency & Throughput</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={metrics}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).getHours() + ':00'}
                    />
                    <YAxis yAxisId="left" />
                    <YAxis yAxisId="right" orientation="right" />
                    <Line 
                      yAxisId="left"
                      type="monotone" 
                      dataKey="latency" 
                      stroke="hsl(var(--primary))" 
                      strokeWidth={2}
                      dot={false}
                    />
                    <Line 
                      yAxisId="right"
                      type="monotone" 
                      dataKey="throughput" 
                      stroke="hsl(var(--secondary))" 
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
                  <Server className="h-4 w-4" />
                  <span>Resource Utilization</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={metrics}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="timestamp" 
                      tickFormatter={(value) => new Date(value).getHours() + ':00'}
                    />
                    <YAxis />
                    <Area
                      type="monotone"
                      dataKey="cpuUsage"
                      stackId="1"
                      stroke="hsl(var(--primary))"
                      fill="hsl(var(--primary))"
                      fillOpacity={0.3}
                    />
                    <Area
                      type="monotone"
                      dataKey="memoryUsage"
                      stackId="1"
                      stroke="hsl(var(--secondary))"
                      fill="hsl(var(--secondary))"
                      fillOpacity={0.3}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Performance Optimization Features</CardTitle>
              <CardDescription>Advanced performance enhancement capabilities</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <h4 className="font-medium">Connection Optimization</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Connection pooling</li>
                    <li>• Keep-alive optimization</li>
                    <li>• Load balancing</li>
                    <li>• Circuit breakers</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Caching Strategy</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Multi-tier caching</li>
                    <li>• CDN integration</li>
                    <li>• Cache invalidation</li>
                    <li>• Smart prefetching</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Data Optimization</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Compression algorithms</li>
                    <li>• Data deduplication</li>
                    <li>• Streaming processing</li>
                    <li>• Batch optimization</li>
                  </ul>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Apply Optimizations</Button>
                <Button variant="outline">Performance Report</Button>
                <Button variant="outline">Benchmark Tests</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scaling" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Zap className="h-4 w-4" />
                  <span>Auto-Scaling Rules</span>
                </CardTitle>
                <CardDescription>Automated scaling triggers and actions</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  {scalingRules.map((rule) => (
                    <div key={rule.id} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <Switch
                          checked={rule.enabled}
                          onCheckedChange={() => toggleScalingRule(rule.id)}
                        />
                        <div>
                          <p className="font-medium text-sm">{rule.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {rule.metric} &gt; {rule.threshold}% → {rule.action}
                          </p>
                        </div>
                      </div>
                      <div className="text-right">
                        {rule.lastTriggered && (
                          <p className="text-xs text-muted-foreground">
                            Last: {new Date(rule.lastTriggered).toLocaleString()}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Globe className="h-4 w-4" />
                  <span>Scaling Status</span>
                </CardTitle>
                <CardDescription>Current scaling configuration and activity</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Current Instances</span>
                    <span className="font-bold">8/15</span>
                  </div>
                  <Progress value={53} className="h-2" />
                  
                  <div className="grid grid-cols-2 gap-4 mt-4">
                    <div className="text-center">
                      <p className="text-xl font-bold text-green-600">12</p>
                      <p className="text-xs text-muted-foreground">Scale Up Events</p>
                    </div>
                    <div className="text-center">
                      <p className="text-xl font-bold text-blue-600">5</p>
                      <p className="text-xs text-muted-foreground">Scale Down Events</p>
                    </div>
                  </div>
                  
                  <div className="space-y-2 mt-4">
                    <h4 className="font-medium text-sm">Recent Activity</h4>
                    <div className="text-xs space-y-1 text-muted-foreground">
                      <div>• 14:23 - Scaled up by 2 instances (CPU threshold)</div>
                      <div>• 13:45 - Scaled down by 1 instance (low usage)</div>
                      <div>• 12:30 - Scaled up by 1 instance (memory threshold)</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Multi-Cloud Scaling</CardTitle>
              <CardDescription>Distributed scaling across cloud providers</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-3">
                  <h4 className="font-medium">AWS Auto Scaling</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>EC2 Instances:</span>
                      <span>5/10</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>ECS Tasks:</span>
                      <span>12/20</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Lambda Concurrency:</span>
                      <span>150/1000</span>
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <h4 className="font-medium">Azure Scaling</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>VM Scale Sets:</span>
                      <span>3/8</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Container Instances:</span>
                      <span>8/15</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Functions:</span>
                      <span>25/100</span>
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <h4 className="font-medium">On-Premise</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>K8s Pods:</span>
                      <span>18/30</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Docker Containers:</span>
                      <span>45/80</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Physical Servers:</span>
                      <span>6/10</span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Configure Scaling</Button>
                <Button variant="outline">Scaling Policies</Button>
                <Button variant="outline">Cost Optimization</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="slo" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Target className="h-4 w-4" />
                <span>Service Level Objectives</span>
              </CardTitle>
              <CardDescription>Performance targets and SLA monitoring</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                {sloTargets.map((slo) => (
                  <div key={slo.id} className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        {getStatusIcon(slo.status)}
                        <span className="font-medium text-sm">{slo.name}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        {getTrendIcon(slo.trend)}
                        <Badge className={getStatusColor(slo.status)}>
                          {slo.status}
                        </Badge>
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Target:</span>
                        <span>{slo.target}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Current:</span>
                        <span className="font-medium">{slo.current}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex space-x-2">
                <Button>Update SLOs</Button>
                <Button variant="outline">SLO Report</Button>
                <Button variant="outline">Alert Rules</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="optimization">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <TrendingUp className="h-4 w-4" />
                <span>Performance Optimization</span>
              </CardTitle>
              <CardDescription>Advanced optimization strategies and recommendations</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <h4 className="font-medium">Optimization Strategies</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Database Query Optimization</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Content Compression</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Image Optimization</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Code Minification</span>
                      <Switch defaultChecked />
                    </div>
                  </div>
                </div>
                <div className="space-y-4">
                  <h4 className="font-medium">Performance Impact</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm">Latency Reduction:</span>
                      <span className="font-medium text-green-600">-23%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm">Throughput Increase:</span>
                      <span className="font-medium text-green-600">+34%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm">Resource Efficiency:</span>
                      <span className="font-medium text-green-600">+18%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm">Cost Reduction:</span>
                      <span className="font-medium text-green-600">-15%</span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Apply All Optimizations</Button>
                <Button variant="outline">Performance Test</Button>
                <Button variant="outline">Rollback Plan</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="capacity">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <BarChart3 className="h-4 w-4" />
                <span>Capacity Planning</span>
              </CardTitle>
              <CardDescription>Predictive scaling and resource planning</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <h4 className="font-medium">Current Usage</h4>
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>CPU:</span>
                        <span>65%</span>
                      </div>
                      <Progress value={65} className="h-1" />
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>Memory:</span>
                        <span>58%</span>
                      </div>
                      <Progress value={58} className="h-1" />
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>Storage:</span>
                        <span>42%</span>
                      </div>
                      <Progress value={42} className="h-1" />
                    </div>
                  </div>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">30-Day Forecast</h4>
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>CPU:</span>
                        <span>78%</span>
                      </div>
                      <Progress value={78} className="h-1" />
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>Memory:</span>
                        <span>72%</span>
                      </div>
                      <Progress value={72} className="h-1" />
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>Storage:</span>
                        <span>55%</span>
                      </div>
                      <Progress value={55} className="h-1" />
                    </div>
                  </div>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">90-Day Forecast</h4>
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>CPU:</span>
                        <span>85%</span>
                      </div>
                      <Progress value={85} className="h-1" />
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>Memory:</span>
                        <span>82%</span>
                      </div>
                      <Progress value={82} className="h-1" />
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span>Storage:</span>
                        <span>68%</span>
                      </div>
                      <Progress value={68} className="h-1" />
                    </div>
                  </div>
                </div>
              </div>
              <div className="p-4 bg-muted rounded-lg">
                <h4 className="font-medium mb-2">Capacity Recommendations</h4>
                <ul className="text-sm text-muted-foreground space-y-1">
                  <li>• Add 2 additional compute instances within 3 weeks</li>
                  <li>• Increase memory allocation by 20% in the next month</li>
                  <li>• Consider storage expansion in 60-75 days</li>
                  <li>• Implement auto-scaling policies for peak traffic</li>
                </ul>
              </div>
              <div className="flex space-x-2">
                <Button>Execute Recommendations</Button>
                <Button variant="outline">Detailed Forecast</Button>
                <Button variant="outline">Cost Analysis</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};