import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { AlertCircle, CheckCircle, Code, Globe, Zap, Shield } from 'lucide-react';

interface APIStandard {
  id: string;
  name: string;
  type: 'rest' | 'graphql' | 'grpc' | 'websocket';
  status: 'enabled' | 'disabled' | 'configuring';
  compliance: number;
  features: string[];
  performance: {
    latency: string;
    throughput: string;
    availability: string;
  };
}

export const ModernAPIStandards = () => {
  const [standards, setStandards] = useState<APIStandard[]>([
    {
      id: 'rest-api',
      name: 'REST API v3.1',
      type: 'rest',
      status: 'enabled',
      compliance: 95,
      features: ['OpenAPI 3.1', 'Auto Documentation', 'Versioning', 'Rate Limiting'],
      performance: { latency: '<100ms', throughput: '10K TPS', availability: '99.99%' }
    },
    {
      id: 'graphql',
      name: 'GraphQL Federation',
      type: 'graphql',
      status: 'enabled',
      compliance: 88,
      features: ['Schema Stitching', 'Subscriptions', 'Introspection', 'Federation'],
      performance: { latency: '<150ms', throughput: '5K TPS', availability: '99.9%' }
    },
    {
      id: 'grpc',
      name: 'gRPC Protocol',
      type: 'grpc',
      status: 'configuring',
      compliance: 70,
      features: ['Protobuf Schema', 'Health Checks', 'Reflection', 'Gateway'],
      performance: { latency: '<50ms', throughput: '15K TPS', availability: '99.95%' }
    },
    {
      id: 'websocket',
      name: 'WebSocket Streaming',
      type: 'websocket',
      status: 'enabled',
      compliance: 92,
      features: ['Real-time Events', 'Multiplexing', 'Compression', 'Heartbeat'],
      performance: { latency: '<10ms', throughput: '50K msgs/s', availability: '99.9%' }
    }
  ]);

  const toggleStandard = (id: string) => {
    setStandards(prev => prev.map(std => 
      std.id === id 
        ? { ...std, status: std.status === 'enabled' ? 'disabled' : 'enabled' }
        : std
    ));
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'enabled': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'configuring': return <AlertCircle className="h-4 w-4 text-yellow-500" />;
      default: return <AlertCircle className="h-4 w-4 text-red-500" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'rest': return <Globe className="h-4 w-4" />;
      case 'graphql': return <Code className="h-4 w-4" />;
      case 'grpc': return <Zap className="h-4 w-4" />;
      case 'websocket': return <Shield className="h-4 w-4" />;
      default: return <Globe className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Modern API Standards</h2>
          <p className="text-muted-foreground">Enterprise-grade API protocols and standards implementation</p>
        </div>
        <Badge variant="secondary" className="bg-primary/10 text-primary">
          Phase 1 Implementation
        </Badge>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="rest">REST API</TabsTrigger>
          <TabsTrigger value="graphql">GraphQL</TabsTrigger>
          <TabsTrigger value="grpc">gRPC</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {standards.map((standard) => (
              <Card key={standard.id} className="relative">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {getTypeIcon(standard.type)}
                      <CardTitle className="text-sm">{standard.name}</CardTitle>
                    </div>
                    {getStatusIcon(standard.status)}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Compliance</span>
                      <span className="font-medium">{standard.compliance}%</span>
                    </div>
                    <Progress value={standard.compliance} className="h-1" />
                  </div>
                  
                  <div className="space-y-1">
                    <p className="text-xs text-muted-foreground">Performance</p>
                    <div className="text-xs space-y-1">
                      <div className="flex justify-between">
                        <span>Latency:</span>
                        <span className="font-mono">{standard.performance.latency}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Throughput:</span>
                        <span className="font-mono">{standard.performance.throughput}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">Enable</span>
                    <Switch
                      checked={standard.status === 'enabled'}
                      onCheckedChange={() => toggleStandard(standard.id)}
                    />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Integration Capabilities Matrix</CardTitle>
              <CardDescription>
                Current implementation status of modern API standards and protocols
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {standards.map((standard) => (
                  <div key={standard.id} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        {getTypeIcon(standard.type)}
                        <span className="font-medium">{standard.name}</span>
                        <Badge variant={standard.status === 'enabled' ? 'default' : 'secondary'}>
                          {standard.status}
                        </Badge>
                      </div>
                      <Button size="sm" variant="outline">Configure</Button>
                    </div>
                    <div className="flex flex-wrap gap-1 ml-7">
                      {standard.features.map((feature) => (
                        <Badge key={feature} variant="outline" className="text-xs">
                          {feature}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rest">
          <Card>
            <CardHeader>
              <CardTitle>REST API v3.1 Configuration</CardTitle>
              <CardDescription>OpenAPI specification and advanced REST features</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <h4 className="font-medium">OpenAPI 3.1 Features</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Automatic schema generation</li>
                    <li>• Interactive API documentation</li>
                    <li>• Request/response validation</li>
                    <li>• Code generation support</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Performance Optimizations</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Advanced HTTP caching</li>
                    <li>• Request compression</li>
                    <li>• Connection pooling</li>
                    <li>• Rate limiting</li>
                  </ul>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Configure OpenAPI</Button>
                <Button variant="outline">View Documentation</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="graphql">
          <Card>
            <CardHeader>
              <CardTitle>GraphQL Federation Setup</CardTitle>
              <CardDescription>Advanced GraphQL capabilities and schema management</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <h4 className="font-medium">Federation Features</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Schema stitching across services</li>
                    <li>• Real-time subscriptions</li>
                    <li>• Query optimization</li>
                    <li>• Type federation</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Development Tools</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• GraphQL Playground</li>
                    <li>• Schema introspection</li>
                    <li>• Query analysis</li>
                    <li>• Performance monitoring</li>
                  </ul>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Setup Federation</Button>
                <Button variant="outline">Schema Explorer</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="grpc">
          <Card>
            <CardHeader>
              <CardTitle>gRPC Protocol Implementation</CardTitle>
              <CardDescription>High-performance binary protocol configuration</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <h4 className="font-medium">Protocol Features</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Protocol Buffers schema</li>
                    <li>• Bi-directional streaming</li>
                    <li>• Load balancing</li>
                    <li>• Health checking</li>
                  </ul>
                </div>
                <div className="space-y-2">
                  <h4 className="font-medium">Enterprise Features</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• TLS encryption</li>
                    <li>• Authentication interceptors</li>
                    <li>• Request tracing</li>
                    <li>• Circuit breakers</li>
                  </ul>
                </div>
              </div>
              <div className="flex space-x-2">
                <Button>Enable gRPC</Button>
                <Button variant="outline">Protobuf Schema</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};