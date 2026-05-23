import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Zap, 
  GitBranch, 
  Shield, 
  RotateCcw, 
  Database, 
  Workflow, 
  Network,
  CloudSnow,
  Activity
} from 'lucide-react';

interface IntegrationPattern {
  id: string;
  name: string;
  type: 'event-driven' | 'fault-tolerance' | 'data-processing' | 'hybrid-cloud';
  status: 'active' | 'inactive' | 'configuring';
  performance: {
    throughput: string;
    latency: string;
    reliability: number;
  };
  features: string[];
  description: string;
}

export const AdvancedIntegrationPatterns = () => {
  const [patterns, setPatterns] = useState<IntegrationPattern[]>([
    {
      id: 'event-streaming',
      name: 'Event Streaming',
      type: 'event-driven',
      status: 'active',
      performance: { throughput: '1M events/sec', latency: '<5ms', reliability: 99.9 },
      features: ['Kafka Integration', 'WebSocket Support', 'Event Sourcing', 'Replay Capability'],
      description: 'Real-time event processing with high throughput streaming'
    },
    {
      id: 'circuit-breaker',
      name: 'Circuit Breaker',
      type: 'fault-tolerance',
      status: 'active',
      performance: { throughput: '50K req/sec', latency: '<10ms', reliability: 99.95 },
      features: ['Auto Recovery', 'Fallback Logic', 'Health Monitoring', 'Metrics Collection'],
      description: 'Fault tolerance pattern preventing cascade failures'
    },
    {
      id: 'data-pipeline',
      name: 'Data Pipeline',
      type: 'data-processing',
      status: 'configuring',
      performance: { throughput: '10GB/hour', latency: '<30s', reliability: 99.5 },
      features: ['ETL Processing', 'Data Validation', 'Schema Evolution', 'Batch & Stream'],
      description: 'Advanced data transformation and processing pipelines'
    },
    {
      id: 'hybrid-cloud',
      name: 'Hybrid Cloud Sync',
      type: 'hybrid-cloud',
      status: 'active',
      performance: { throughput: '100MB/sec', latency: '<100ms', reliability: 99.8 },
      features: ['Multi-Cloud', 'On-Premise Bridge', 'Auto Sync', 'Disaster Recovery'],
      description: 'Seamless data synchronization across cloud and on-premise'
    }
  ]);

  const togglePattern = (id: string) => {
    setPatterns(prev => prev.map(pattern => 
      pattern.id === id 
        ? { ...pattern, status: pattern.status === 'active' ? 'inactive' : 'active' }
        : pattern
    ));
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'event-driven': return <Zap className="h-4 w-4" />;
      case 'fault-tolerance': return <Shield className="h-4 w-4" />;
      case 'data-processing': return <Database className="h-4 w-4" />;
      case 'hybrid-cloud': return <CloudSnow className="h-4 w-4" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-600 bg-green-50';
      case 'configuring': return 'text-yellow-600 bg-yellow-50';
      case 'inactive': return 'text-gray-600 bg-gray-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Advanced Integration Patterns</h2>
          <p className="text-muted-foreground">Event-driven architecture, fault tolerance, and data processing</p>
        </div>
        <Badge variant="secondary" className="bg-primary/10 text-primary">
          Phase 4 Implementation
        </Badge>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="event-driven">Event-Driven</TabsTrigger>
          <TabsTrigger value="fault-tolerance">Fault Tolerance</TabsTrigger>
          <TabsTrigger value="data-processing">Data Processing</TabsTrigger>
          <TabsTrigger value="hybrid-cloud">Hybrid Cloud</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {patterns.map((pattern) => (
              <Card key={pattern.id} className="relative">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {getTypeIcon(pattern.type)}
                      <CardTitle className="text-sm">{pattern.name}</CardTitle>
                    </div>
                    <Badge className={getStatusColor(pattern.status)}>
                      {pattern.status}
                    </Badge>
                  </div>
                  <CardDescription className="text-xs">
                    {pattern.description}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Reliability</span>
                      <span className="font-medium">{pattern.performance.reliability}%</span>
                    </div>
                    <Progress value={pattern.performance.reliability} className="h-1" />
                  </div>
                  
                  <div className="space-y-1">
                    <p className="text-xs text-muted-foreground">Performance</p>
                    <div className="text-xs space-y-1">
                      <div className="flex justify-between">
                        <span>Throughput:</span>
                        <span className="font-mono">{pattern.performance.throughput}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Latency:</span>
                        <span className="font-mono">{pattern.performance.latency}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">Enable</span>
                    <Switch
                      checked={pattern.status === 'active'}
                      onCheckedChange={() => togglePattern(pattern.id)}
                    />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Workflow className="h-4 w-4" />
                  <span>Integration Flow Patterns</span>
                </CardTitle>
                <CardDescription>Architecture patterns implementation status</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Pub/Sub Messaging</span>
                    <Badge variant="default">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Request/Reply</span>
                    <Badge variant="default">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Scatter/Gather</span>
                    <Badge variant="secondary">Configuring</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Pipeline Processing</span>
                    <Badge variant="default">Active</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Network className="h-4 w-4" />
                  <span>Network Resilience</span>
                </CardTitle>
                <CardDescription>Network-level fault tolerance features</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Connection Pooling</span>
                    <Badge variant="default">Enabled</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Load Balancing</span>
                    <Badge variant="default">Round Robin</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Retry Logic</span>
                    <Badge variant="default">Exponential</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Timeout Handling</span>
                    <Badge variant="default">Adaptive</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="event-driven">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Zap className="h-4 w-4" />
                  <span>Event Streaming Configuration</span>
                </CardTitle>
                <CardDescription>Kafka and WebSocket integration settings</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Kafka Cluster</label>
                    <Select defaultValue="production">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="production">Production Cluster</SelectItem>
                        <SelectItem value="staging">Staging Cluster</SelectItem>
                        <SelectItem value="development">Development Cluster</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Partition Strategy</label>
                    <Select defaultValue="key-based">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="key-based">Key-based</SelectItem>
                        <SelectItem value="round-robin">Round Robin</SelectItem>
                        <SelectItem value="custom">Custom</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-3">
                    <label className="text-sm font-medium">Event Features</label>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Event Sourcing</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Event Replay</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Schema Registry</span>
                        <Switch defaultChecked />
                      </div>
                    </div>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <Button>Apply Configuration</Button>
                  <Button variant="outline">Test Events</Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Event Topics & Consumers</CardTitle>
                <CardDescription>Active event streams and consumer groups</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">security.events</span>
                      <Badge variant="default">Active</Badge>
                    </div>
                    <div className="text-xs text-muted-foreground space-y-1">
                      <div className="flex justify-between">
                        <span>Messages/sec:</span>
                        <span className="font-mono">1,247</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Consumers:</span>
                        <span className="font-mono">3</span>
                      </div>
                    </div>
                  </div>
                  <div className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">audit.logs</span>
                      <Badge variant="default">Active</Badge>
                    </div>
                    <div className="text-xs text-muted-foreground space-y-1">
                      <div className="flex justify-between">
                        <span>Messages/sec:</span>
                        <span className="font-mono">892</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Consumers:</span>
                        <span className="font-mono">2</span>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="fault-tolerance">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-4 w-4" />
                  <span>Circuit Breaker Patterns</span>
                </CardTitle>
                <CardDescription>Fault tolerance and resilience configuration</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Failure Threshold</label>
                    <Select defaultValue="5">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="3">3 failures</SelectItem>
                        <SelectItem value="5">5 failures</SelectItem>
                        <SelectItem value="10">10 failures</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Recovery Timeout</label>
                    <Select defaultValue="30s">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="15s">15 seconds</SelectItem>
                        <SelectItem value="30s">30 seconds</SelectItem>
                        <SelectItem value="60s">60 seconds</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-3">
                    <label className="text-sm font-medium">Resilience Features</label>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Bulkhead Isolation</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Rate Limiting</span>
                        <Switch defaultChecked />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm">Fallback Logic</span>
                        <Switch defaultChecked />
                      </div>
                    </div>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <Button>Update Settings</Button>
                  <Button variant="outline">Test Circuit</Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <RotateCcw className="h-4 w-4" />
                  <span>Retry Policies</span>
                </CardTitle>
                <CardDescription>Automated retry and recovery strategies</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">Exponential Backoff</span>
                      <Badge variant="default">Active</Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Initial: 1s, Max: 60s, Multiplier: 2x
                    </div>
                  </div>
                  <div className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">Jitter Strategy</span>
                      <Badge variant="default">Enabled</Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Random jitter up to 25% of delay
                    </div>
                  </div>
                  <div className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">Dead Letter Queue</span>
                      <Badge variant="default">Configured</Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Max retries: 3, TTL: 24h
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="data-processing">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Database className="h-4 w-4" />
                <span>Data Processing Pipelines</span>
              </CardTitle>
              <CardDescription>ETL, data transformation, and pipeline management</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <h4 className="font-medium">Extract</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Multi-source ingestion</li>
                    <li>• Schema detection</li>
                    <li>• Change data capture</li>
                    <li>• Real-time streaming</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Transform</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Data validation</li>
                    <li>• Type conversion</li>
                    <li>• Aggregation</li>
                    <li>• Custom logic</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Load</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Batch processing</li>
                    <li>• Incremental updates</li>
                    <li>• Error handling</li>
                    <li>• Performance optimization</li>
                  </ul>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Create Pipeline</Button>
                <Button variant="outline">Monitor Jobs</Button>
                <Button variant="outline">View Lineage</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="hybrid-cloud">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <CloudSnow className="h-4 w-4" />
                <span>Hybrid Cloud Integration</span>
              </CardTitle>
              <CardDescription>Multi-cloud and on-premise connectivity</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-4">
                  <h4 className="font-medium">Cloud Providers</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">AWS Integration</span>
                      <Badge variant="default">Connected</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Azure Integration</span>
                      <Badge variant="default">Connected</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Google Cloud</span>
                      <Badge variant="secondary">Configuring</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">On-Premise</span>
                      <Badge variant="default">Active</Badge>
                    </div>
                  </div>
                </div>
                <div className="space-y-4">
                  <h4 className="font-medium">Sync Capabilities</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Real-time Sync</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Conflict Resolution</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Disaster Recovery</span>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Data Encryption</span>
                      <Switch defaultChecked />
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Configure Sync</Button>
                <Button variant="outline">Test Connectivity</Button>
                <Button variant="outline">DR Dashboard</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};