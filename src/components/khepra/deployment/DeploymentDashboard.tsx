import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Eye,
  Zap,
  Network,
  Database,
  Cpu,
  HardDrive,
  Users,
  Globe,
  Lock,
  Brain,
  TrendingUp,
  TrendingDown,
  Minus,
  RefreshCw,
  Settings,
  Download,
  Upload,
  Play,
  Pause,
  RotateCcw
} from 'lucide-react';
import { AdinkraSymbolDisplay } from '../AdinkraSymbolDisplay';

interface DeploymentStatus {
  id: string;
  name: string;
  status: 'active' | 'degraded' | 'offline' | 'deploying';
  health_score: number;
  last_updated: string;
  protected_assets: number;
  active_agents: number;
  cultural_symbols: string[];
  metrics: {
    cpu_usage: number;
    memory_usage: number;
    storage_usage: number;
    network_throughput: number;
    threat_blocked: number;
    anomalies_detected: number;
  };
}

interface ThreatEvent {
  id: string;
  type: 'blocked' | 'detected' | 'mitigated' | 'investigating';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  source: string;
  target: string;
  timestamp: string;
  cultural_pattern?: string;
}

interface AgentInfo {
  id: string;
  name: string;
  type: 'guardian' | 'scout' | 'analyst' | 'orchestrator';
  status: 'active' | 'idle' | 'busy' | 'offline';
  location: string;
  cultural_symbol: string;
  tasks_completed: number;
  uptime: string;
}

interface DeploymentDashboardProps {
  deploymentId?: string;
  onManageDeployment?: (action: string) => void;
}

export const DeploymentDashboard: React.FC<DeploymentDashboardProps> = ({
  deploymentId,
  onManageDeployment
}) => {
  const [deploymentStatus, setDeploymentStatus] = useState<DeploymentStatus | null>(null);
  const [recentThreats, setRecentThreats] = useState<ThreatEvent[]>([]);
  const [activeAgents, setActiveAgents] = useState<AgentInfo[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Simulate real-time data
  useEffect(() => {
    const loadDashboardData = () => {
      const pendingStatus: DeploymentStatus = {
        id: deploymentId || 'pending-deployment',
        name: 'Pending Deployment Telemetry',
        status: 'deploying',
        health_score: 0,
        last_updated: new Date().toISOString(),
        protected_assets: 0,
        active_agents: 0,
        cultural_symbols: [],
        metrics: {
          cpu_usage: 0,
          memory_usage: 0,
          storage_usage: 0,
          network_throughput: 0,
          threat_blocked: 0,
          anomalies_detected: 0
        }
      };

      const pendingThreats: ThreatEvent[] = [];
      const pendingAgents: AgentInfo[] = [];

      setDeploymentStatus(pendingStatus);
      setRecentThreats(pendingThreats);
      setActiveAgents(pendingAgents);
      setIsLoading(false);
    };

    loadDashboardData();

    if (autoRefresh) {
      const interval = setInterval(loadDashboardData, 30000); // Refresh every 30 seconds
      return () => clearInterval(interval);
    }
  }, [deploymentId, autoRefresh]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-500';
      case 'degraded': return 'text-yellow-500';
      case 'offline': return 'text-red-500';
      case 'deploying': return 'text-blue-500';
      default: return 'text-muted-foreground';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'degraded': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'offline': return <Clock className="h-4 w-4 text-red-500" />;
      case 'deploying': return <Zap className="h-4 w-4 text-blue-500 animate-pulse" />;
      default: return <Minus className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-500/10';
      case 'high': return 'text-orange-500 bg-orange-500/10';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10';
      case 'low': return 'text-blue-500 bg-blue-500/10';
      default: return 'text-muted-foreground bg-muted/10';
    }
  };

  const getAgentTypeIcon = (type: string) => {
    switch (type) {
      case 'guardian': return <Shield className="h-4 w-4" />;
      case 'scout': return <Eye className="h-4 w-4" />;
      case 'analyst': return <Brain className="h-4 w-4" />;
      case 'orchestrator': return <Network className="h-4 w-4" />;
      default: return <Zap className="h-4 w-4" />;
    }
  };

  const getHealthColor = (score: number) => {
    if (score >= 90) return 'text-green-500';
    if (score >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        {[...new Array(3)].map((_, i) => (
          <Card key={i} className="border-border">
            <CardContent className="p-6">
              <div className="animate-pulse space-y-4">
                <div className="h-6 bg-muted rounded"></div>
                <div className="h-20 bg-muted rounded"></div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (!deploymentStatus) {
    return (
      <Card className="border-border">
        <CardContent className="p-8 text-center">
          <div className="text-muted-foreground">No deployment data available</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Deployment Overview */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-6 w-6 text-primary" />
              <div>
                <CardTitle>{deploymentStatus.name}</CardTitle>
                <div className="flex items-center space-x-2 mt-1">
                  {getStatusIcon(deploymentStatus.status)}
                  <span className={`text-sm font-medium ${getStatusColor(deploymentStatus.status)}`}>
                    {deploymentStatus.status.charAt(0).toUpperCase() + deploymentStatus.status.slice(1)}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    • Health Score: <span className={getHealthColor(deploymentStatus.health_score)}>
                      {deploymentStatus.health_score}%
                    </span>
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setAutoRefresh(!autoRefresh)}
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />
                {autoRefresh ? 'Auto' : 'Manual'}
              </Button>
              <Button variant="outline" size="sm" onClick={() => onManageDeployment?.('settings')}>
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Key Metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{deploymentStatus.protected_assets}</div>
              <div className="text-sm text-muted-foreground">Protected Assets</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">{deploymentStatus.active_agents}</div>
              <div className="text-sm text-muted-foreground">Active Agents</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">{deploymentStatus.metrics.threat_blocked}</div>
              <div className="text-sm text-muted-foreground">Threats Blocked</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-500">{deploymentStatus.cultural_symbols.length}</div>
              <div className="text-sm text-muted-foreground">Cultural Symbols</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-500">{deploymentStatus.metrics.anomalies_detected}</div>
              <div className="text-sm text-muted-foreground">Anomalies</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-cyan-500">{deploymentStatus.metrics.network_throughput}</div>
              <div className="text-sm text-muted-foreground">Mbps</div>
            </div>
          </div>

          {/* Cultural Symbols */}
          <div className="flex items-center space-x-4">
            <span className="text-sm text-muted-foreground">Active Cultural Symbols:</span>
            <div className="flex items-center space-x-2">
              {deploymentStatus.cultural_symbols.map(symbol => (
                <div key={symbol} className="w-6 h-6">
                  <AdinkraSymbolDisplay
                    symbolName={symbol}
                    size="small"
                    showMatrix={false}
                    className="animate-cultural-pulse"
                  />
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Main Dashboard Tabs */}
      <Card className="border-border">
        <Tabs defaultValue="overview" className="w-full">
          <div className="border-b border-border p-4">
            <TabsList className="grid grid-cols-4 w-full max-w-md">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="threats">Threats</TabsTrigger>
              <TabsTrigger value="agents">Agents</TabsTrigger>
              <TabsTrigger value="metrics">Metrics</TabsTrigger>
            </TabsList>
          </div>

          <div className="p-6">
            <TabsContent value="overview" className="space-y-6 mt-0">
              {/* Resource Usage */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card className="border-border">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Cpu className="h-5 w-5" />
                      <span>Resource Usage</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-3">
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span>CPU Usage</span>
                          <span>{deploymentStatus.metrics.cpu_usage}%</span>
                        </div>
                        <Progress value={deploymentStatus.metrics.cpu_usage} className="h-2" />
                      </div>

                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span>Memory Usage</span>
                          <span>{deploymentStatus.metrics.memory_usage}%</span>
                        </div>
                        <Progress value={deploymentStatus.metrics.memory_usage} className="h-2" />
                      </div>

                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span>Storage Usage</span>
                          <span>{deploymentStatus.metrics.storage_usage}%</span>
                        </div>
                        <Progress value={deploymentStatus.metrics.storage_usage} className="h-2" />
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Activity className="h-5 w-5" />
                      <span>Security Status</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="text-center">
                        <div className="text-2xl font-bold text-green-500">
                          {deploymentStatus.metrics.threat_blocked}
                        </div>
                        <div className="text-sm text-muted-foreground">Threats Blocked Today</div>
                      </div>
                      <div className="text-center">
                        <div className="text-2xl font-bold text-yellow-500">
                          {deploymentStatus.metrics.anomalies_detected}
                        </div>
                        <div className="text-sm text-muted-foreground">Anomalies Detected</div>
                      </div>
                    </div>

                    <div className="text-center">
                      <div className="text-sm text-muted-foreground mb-2">Overall Security Health</div>
                      <div className="flex items-center justify-center space-x-2">
                        <Progress value={deploymentStatus.health_score} className="flex-1 h-3" />
                        <span className={`font-bold ${getHealthColor(deploymentStatus.health_score)}`}>
                          {deploymentStatus.health_score}%
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Recent Activity */}
              <Card className="border-border">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Clock className="h-5 w-5" />
                    <span>Recent Activity</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-48">
                    <div className="space-y-3">
                      {recentThreats.slice(0, 5).map((threat) => (
                        <div key={threat.id} className="flex items-center justify-between p-3 border border-border rounded-lg">
                          <div className="flex items-center space-x-3">
                            <Badge variant="outline" className={getSeverityColor(threat.severity)}>
                              {threat.severity}
                            </Badge>
                            <div>
                              <div className="font-medium">{threat.description}</div>
                              <div className="text-sm text-muted-foreground">
                                {threat.source} → {threat.target}
                              </div>
                            </div>
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(threat.timestamp).toLocaleTimeString()}
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="threats" className="space-y-6 mt-0">
              <Card className="border-border">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <AlertTriangle className="h-5 w-5" />
                    <span>Threat Events</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-96">
                    <div className="space-y-3">
                      {recentThreats.map((threat) => (
                        <div key={threat.id} className="p-4 border border-border rounded-lg">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start space-x-3">
                              <Badge variant="outline" className={getSeverityColor(threat.severity)}>
                                {threat.severity}
                              </Badge>
                              <div className="flex-1">
                                <div className="font-medium">{threat.description}</div>
                                <div className="text-sm text-muted-foreground mt-1">
                                  Source: {threat.source} → Target: {threat.target}
                                </div>
                                {threat.cultural_pattern && (
                                  <div className="text-sm text-purple-400 mt-1">
                                    Cultural Pattern: {threat.cultural_pattern}
                                  </div>
                                )}
                                <div className="flex items-center space-x-2 mt-2">
                                  <Badge variant={threat.type === 'blocked' ? 'default' : 'secondary'}>
                                    {threat.type}
                                  </Badge>
                                  <span className="text-xs text-muted-foreground">
                                    {new Date(threat.timestamp).toLocaleString()}
                                  </span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="agents" className="space-y-6 mt-0">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {activeAgents.map((agent) => (
                  <Card key={agent.id} className="border-border">
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div className="w-8 h-8">
                            <AdinkraSymbolDisplay
                              symbolName={agent.cultural_symbol}
                              size="small"
                              showMatrix={false}
                            />
                          </div>
                          <div>
                            <CardTitle className="text-base">{agent.name}</CardTitle>
                            <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                              {getAgentTypeIcon(agent.type)}
                              <span className="capitalize">{agent.type}</span>
                            </div>
                          </div>
                        </div>
                        <Badge variant={agent.status === 'active' ? 'default' : 'secondary'}>
                          {agent.status}
                        </Badge>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Location:</span>
                          <span>{agent.location}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Tasks Completed:</span>
                          <span>{agent.tasks_completed}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Uptime:</span>
                          <span>{agent.uptime}</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="metrics" className="space-y-6 mt-0">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <Card className="border-border">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <TrendingUp className="h-5 w-5 text-green-500" />
                      <span>Performance</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Response Time</span>
                      <span className="text-sm font-medium">12ms</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Throughput</span>
                      <span className="text-sm font-medium">{deploymentStatus.metrics.network_throughput} Mbps</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Availability</span>
                      <span className="text-sm font-medium text-green-500">99.98%</span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Shield className="h-5 w-5 text-blue-500" />
                      <span>Security</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Threats Blocked</span>
                      <span className="text-sm font-medium">{deploymentStatus.metrics.threat_blocked}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">False Positives</span>
                      <span className="text-sm font-medium">2</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Detection Rate</span>
                      <span className="text-sm font-medium text-green-500">98.7%</span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Brain className="h-5 w-5 text-purple-500" />
                      <span>AI Intelligence</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Learning Rate</span>
                      <span className="text-sm font-medium">94%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Cultural Alignment</span>
                      <span className="text-sm font-medium text-purple-500">97%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Prediction Accuracy</span>
                      <span className="text-sm font-medium text-green-500">91%</span>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </div>
        </Tabs>
      </Card>
    </div>
  );
};