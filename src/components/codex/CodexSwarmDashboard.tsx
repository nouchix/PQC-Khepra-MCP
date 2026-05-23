/**
 * Codex Agent Swarm Dashboard
 * Master interface for AI-powered STIG-Connector SuperPolymorphic API
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Brain, 
  Zap, 
  Network, 
  Code, 
  Activity, 
  TrendingUp, 
  Shield,
  Cpu,
  Database,
  GitBranch,
  Layers,
  Workflow,
  Bot,
  Sparkles,
  Rocket,
  AlertTriangle,
  Loader2
} from 'lucide-react';
import { useCodexSwarm } from '@/hooks/useCodexSwarm';
import { useOrganization } from '@/hooks/useOrganization';

// Interfaces moved to useCodexSwarm hook

export const CodexSwarmDashboard: React.FC = () => {
  const { currentOrganization } = useOrganization();
  const {
    agents,
    polymorphicAPIs,
    activeTasks,
    swarmPerformance,
    competitiveAnalysis,
    loading,
    error,
    initializeSwarm,
    orchestrateTask,
    evolveAPI: evolveAPIHook,
    exportChatGPTInstructions,
    refreshData
  } = useCodexSwarm(currentOrganization?.id || '');

  const deployNewAgent = async () => {
    if (!currentOrganization?.id) return;
    
    await initializeSwarm({
      agent_types: [
        { type: 'discovery', count: 1, ai_model: 'gpt-5', specialized_knowledge: ['network_scanning', 'asset_discovery'] }
      ],
      coordination_strategy: 'hybrid',
      learning_enabled: true,
      auto_scaling: true
    });
  };

  const evolveAPI = async (apiId: string) => {
    await evolveAPIHook({
      discovered_systems: [
        {
          system_name: 'Target System',
          api_endpoints: ['/api/v1/data'],
          data_schemas: { data: { id: 'string', value: 'any' } },
          authentication: { type: 'oauth2' },
          compliance_posture: { stig_score: 85 }
        }
      ],
      usage_patterns: { peak_hours: '9-17', avg_requests: 1000 },
      performance_metrics: { avg_response_time: 150, error_rate: 0.02 }
    });
  };

  const handleExportChatGPT = async () => {
    await exportChatGPTInstructions();
  };

  // Calculate derived metrics
  const totalActiveAgents = agents.length;
  const averagePerformance = agents.length > 0 
    ? agents.reduce((sum, agent) => sum + (agent.performance_metrics?.success_rate || 0), 0) / agents.length 
    : 0;
  const totalAPIs = polymorphicAPIs.length;
  const activeTotalTasks = activeTasks.length;
  const palantirAdvantage = competitiveAnalysis?.palantir_comparison?.cost_advantage || 0;

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <Activity className="h-4 w-4 text-green-500" />;
      case 'processing': return <Cpu className="h-4 w-4 text-blue-500" />;
      case 'learning': return <Brain className="h-4 w-4 text-purple-500" />;
      case 'evolving': return <Sparkles className="h-4 w-4 text-yellow-500" />;
      default: return <Bot className="h-4 w-4 text-gray-500" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'discovery': return <Network className="h-4 w-4" />;
      case 'analysis': return <Brain className="h-4 w-4" />;
      case 'compliance': return <Shield className="h-4 w-4" />;
      case 'connector': return <GitBranch className="h-4 w-4" />;
      default: return <Code className="h-4 w-4" />;
    }
  };

  if (!currentOrganization?.id) {
    return (
      <div className="flex items-center justify-center h-64">
        <Alert className="max-w-md">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Please select an organization to view the Codex Agent Swarm dashboard.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <Alert variant="destructive" className="max-w-md">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Error loading swarm data: {error}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <Rocket className="h-8 w-8 text-blue-500" />
            Codex Agent Swarm
            {loading && <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />}
          </h1>
          <p className="text-muted-foreground">
            SuperPolymorphic API Architecture - Production-Ready AI Integration System
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="bg-gradient-to-r from-green-500/20 to-blue-500/20 border-green-500/50">
            <TrendingUp className="h-3 w-3 mr-1" />
            {palantirAdvantage > 0 ? `${palantirAdvantage}% Faster than Palantir` : 'Performance Analysis...'}
          </Badge>
          <Button onClick={deployNewAgent} disabled={loading} className="bg-gradient-to-r from-blue-600 to-purple-600">
            <Bot className="h-4 w-4 mr-2" />
            {loading ? 'Deploying...' : 'Deploy Agent'}
          </Button>
        </div>
      </div>

      {/* Performance Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-950/20 dark:to-indigo-950/20 border-blue-200 dark:border-blue-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center">
              <Brain className="h-4 w-4 mr-2 text-blue-600" />
              Active Agents
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{totalActiveAgents}</div>
            <p className="text-xs text-muted-foreground mt-1">AI models deployed</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-50 to-emerald-50 dark:from-green-950/20 dark:to-emerald-950/20 border-green-200 dark:border-green-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center">
              <Zap className="h-4 w-4 mr-2 text-green-600" />
              Performance Score
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{averagePerformance.toFixed(1)}%</div>
            <Progress value={averagePerformance} className="mt-2" />
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-50 to-violet-50 dark:from-purple-950/20 dark:to-violet-950/20 border-purple-200 dark:border-purple-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center">
              <Layers className="h-4 w-4 mr-2 text-purple-600" />
              Polymorphic APIs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-purple-600">{totalAPIs}</div>
            <p className="text-xs text-muted-foreground mt-1">Self-evolving integrations</p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-50 to-red-50 dark:from-orange-950/20 dark:to-red-950/20 border-orange-200 dark:border-orange-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center">
              <Workflow className="h-4 w-4 mr-2 text-orange-600" />
              Active Tasks
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">{activeTotalTasks}</div>
            <p className="text-xs text-muted-foreground mt-1">Processing integrations</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="agents" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="agents">AI Agents</TabsTrigger>
          <TabsTrigger value="apis">Polymorphic APIs</TabsTrigger>
          <TabsTrigger value="evolution">Schema Evolution</TabsTrigger>
          <TabsTrigger value="chatgpt">ChatGPT Export</TabsTrigger>
        </TabsList>

        <TabsContent value="agents" className="space-y-4">
          {agents.length === 0 && !loading ? (
            <Alert>
              <Bot className="h-4 w-4" />
              <AlertDescription>
                No agents deployed yet. Click "Deploy Agent" to start your AI swarm.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {agents.map((agent) => (
                <Card key={agent.id} className="border-l-4 border-l-blue-500">
                  <CardHeader className="pb-3">
                    <div className="flex justify-between items-start">
                      <div className="flex items-center gap-2">
                        {getTypeIcon(agent.type)}
                        <CardTitle className="text-sm">{agent.name}</CardTitle>
                      </div>
                      <div className="flex items-center gap-2">
                        {getStatusIcon(agent.status)}
                        <Badge variant="outline">{agent.ai_model}</Badge>
                      </div>
                    </div>
                    <CardDescription className="capitalize">{agent.type} Specialist</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 text-xs">
                      <div className="flex justify-between">
                        <span>Tasks Completed:</span>
                        <span className="font-bold">{agent.performance_metrics?.tasks_completed || 0}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Success Rate:</span>
                        <span className="text-green-600 font-bold">{agent.performance_metrics?.success_rate || 0}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Avg Response:</span>
                        <span className="text-blue-600 font-bold">{agent.performance_metrics?.avg_execution_time || 0}s</span>
                      </div>
                      <Progress value={agent.performance_metrics?.success_rate || 0} className="mt-2" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="apis" className="space-y-4">
          {polymorphicAPIs.length === 0 && !loading ? (
            <Alert>
              <Database className="h-4 w-4" />
              <AlertDescription>
                No polymorphic APIs created yet. Deploy agents and run tasks to generate adaptive APIs.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="space-y-4">
              {polymorphicAPIs.map((api) => (
                <Card key={api.id} className="border-l-4 border-l-purple-500">
                  <CardHeader className="pb-3">
                    <div className="flex justify-between items-start">
                      <CardTitle className="flex items-center gap-2">
                        <Database className="h-4 w-4" />
                        {api.api_name}
                      </CardTitle>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">
                          v{api.version}
                        </Badge>
                        <Button size="sm" variant="outline" onClick={() => evolveAPI(api.id)} disabled={loading}>
                          <Sparkles className="h-3 w-3 mr-1" />
                          Evolve
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <div className="text-muted-foreground">Auto Evolution</div>
                        <div className="font-bold text-green-600">
                          {api.auto_evolution_enabled ? 'Enabled' : 'Disabled'}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Endpoints</div>
                        <div className="font-bold text-blue-600">{api.endpoints?.length || 0}</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="evolution" className="space-y-4">
          <Alert className="border-blue-200 bg-blue-50 dark:bg-blue-950/20">
            <Sparkles className="h-4 w-4" />
            <AlertDescription>
              <strong>Real-Time Schema Evolution:</strong> AI agents continuously optimize data structures 
              based on performance metrics and integration patterns. Production-ready system with live learning capabilities.
            </AlertDescription>
          </Alert>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Active Schemas</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-blue-600">{swarmPerformance?.learning_metrics?.active_schemas || 0}</div>
                <p className="text-xs text-muted-foreground">Currently managed</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Performance Gains</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">
                  +{swarmPerformance?.learning_metrics?.performance_improvement || 0}%
                </div>
                <p className="text-xs text-muted-foreground">vs baseline</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Learning Cycles</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-purple-600">
                  {swarmPerformance?.learning_metrics?.completed_cycles || 0}
                </div>
                <p className="text-xs text-muted-foreground">Completed optimizations</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="chatgpt" className="space-y-4">
          <Card className="border-orange-200 bg-gradient-to-br from-orange-50 to-yellow-50 dark:from-orange-950/20 dark:to-yellow-950/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Code className="h-5 w-5 text-orange-600" />
                Export to ChatGPT Codex
              </CardTitle>
              <CardDescription>
                Generate comprehensive developer instructions based on actual swarm performance and learned patterns
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <Button 
                    className="bg-gradient-to-r from-orange-600 to-red-600"
                    onClick={handleExportChatGPT}
                    disabled={loading || polymorphicAPIs.length === 0}
                  >
                    <Code className="h-4 w-4 mr-2" />
                    Export API Patterns
                  </Button>
                  <Button 
                    variant="outline"
                    onClick={handleExportChatGPT}
                    disabled={loading || agents.length === 0}
                  >
                    <Database className="h-4 w-4 mr-2" />
                    Export Agent Configuration
                  </Button>
                </div>
                <Button 
                  className="w-full bg-gradient-to-r from-purple-600 to-pink-600" 
                  size="lg"
                  onClick={handleExportChatGPT}
                  disabled={loading || (agents.length === 0 && polymorphicAPIs.length === 0)}
                >
                  <Rocket className="h-4 w-4 mr-2" />
                  Generate Complete Developer Guide
                </Button>
                {(agents.length === 0 && polymorphicAPIs.length === 0) && (
                  <p className="text-xs text-muted-foreground text-center">
                    Deploy agents and create APIs to enable ChatGPT exports
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};