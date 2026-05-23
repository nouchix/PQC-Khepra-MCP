import { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Bot, Brain, Zap, CheckCircle, Clock, AlertCircle, Shield, Target, Cog } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface AIAgent {
  id: string;
  agent_name: string;
  control_family: string;
  execution_status: 'idle' | 'running' | 'complete' | 'error';
  recommendations_generated: number;
  automations_executed: number;
  confidence_score: number;
  last_execution: string;
}

interface ComplianceTask {
  id: string;
  control_id: string;
  task_type: 'assessment' | 'implementation' | 'validation' | 'remediation';
  status: 'queued' | 'in_progress' | 'completed' | 'failed';
  priority: number;
  ai_agent: string;
  estimated_completion: string;
  progress: number;
}

interface OrchestrationMetrics {
  totalTasks: number;
  completedTasks: number;
  activeAgents: number;
  avgConfidenceScore: number;
  automationRate: number;
}

export const AgenticComplianceOrchestrator: React.FC = () => {
  const [agents, setAgents] = useState<AIAgent[]>([]);
  const [tasks, setTasks] = useState<ComplianceTask[]>([]);
  const [metrics, setMetrics] = useState<OrchestrationMetrics>({
    totalTasks: 0,
    completedTasks: 0,
    activeAgents: 0,
    avgConfidenceScore: 0,
    automationRate: 0
  });
  const [orchestrationStatus, setOrchestrationStatus] = useState<'idle' | 'running' | 'paused'>('idle');
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  const controlFamilyAgents = [
    { family: 'AC', name: 'Access Control Guardian', icon: Shield, color: 'bg-blue-500' },
    { family: 'AU', name: 'Audit Analytics Agent', icon: Target, color: 'bg-purple-500' },
    { family: 'CM', name: 'Configuration Manager', icon: Cog, color: 'bg-red-500' },
    { family: 'IA', name: 'Identity Authenticator', icon: CheckCircle, color: 'bg-green-500' },
    { family: 'SC', name: 'Security Protector', icon: Shield, color: 'bg-orange-500' },
    { family: 'SI', name: 'Integrity Monitor', icon: Brain, color: 'bg-cyan-500' }
  ];

  useEffect(() => {
    fetchOrchestrationData();
    const interval = setInterval(fetchOrchestrationData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchOrchestrationData = async () => {
    try {
      // Fetch AI agents
      const { data: agentsData, error: agentsError } = await supabase
        .from('ai_compliance_agents')
        .select('*')
        .order('last_execution', { ascending: false });

      if (agentsError) throw agentsError;

      // Fetch compliance implementations as tasks
      const { data: tasksData, error: tasksError } = await supabase
        .from('compliance_implementations')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);

      if (tasksError) throw tasksError;

      setAgents((agentsData || []).map(a => ({ ...a, execution_status: a.execution_status as 'idle' | 'running' | 'complete' | 'error' })));
      
      // Transform compliance implementations to tasks
      const transformedTasks: ComplianceTask[] = (tasksData || []).map(impl => ({
        id: impl.id,
        control_id: impl.control_id,
        task_type: getTaskType(impl.implementation_status),
        status: mapImplementationStatus(impl.implementation_status),
        priority: impl.priority_score || 50,
        ai_agent: getAgentForControl(impl.control_id),
        estimated_completion: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        progress: getTaskProgress(impl.implementation_status, impl.validation_status)
      }));

      setTasks(transformedTasks);
      calculateMetrics((agentsData || []).map(a => ({ ...a, execution_status: a.execution_status as 'idle' | 'running' | 'complete' | 'error' })), transformedTasks);
      
    } catch (error) {
      console.error('Error fetching orchestration data:', error);
      toast({
        title: "Error",
        description: "Failed to load orchestration data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getTaskType = (status: string): ComplianceTask['task_type'] => {
    switch (status) {
      case 'planned': return 'assessment';
      case 'in_progress': return 'implementation';
      case 'implemented': return 'validation';
      default: return 'assessment';
    }
  };

  const mapImplementationStatus = (status: string): ComplianceTask['status'] => {
    switch (status) {
      case 'planned': return 'queued';
      case 'in_progress': return 'in_progress';
      case 'implemented': return 'completed';
      case 'failed': return 'failed';
      default: return 'queued';
    }
  };

  const getAgentForControl = (controlId: string): string => {
    const family = controlId.split('-')[0];
    const agent = controlFamilyAgents.find(a => a.family === family);
    return agent ? agent.name : 'General Compliance Agent';
  };

  const getTaskProgress = (implStatus: string, validStatus?: string): number => {
    if (implStatus === 'implemented' && validStatus === 'validated') return 100;
    if (implStatus === 'implemented') return 80;
    if (implStatus === 'in_progress') return 50;
    if (implStatus === 'planned') return 20;
    return 0;
  };

  const calculateMetrics = (agentsData: AIAgent[], tasksData: ComplianceTask[]) => {
    const totalTasks = tasksData.length;
    const completedTasks = tasksData.filter(t => t.status === 'completed').length;
    const activeAgents = agentsData.filter(a => a.execution_status === 'running').length;
    const avgConfidenceScore = agentsData.length > 0 
      ? agentsData.reduce((sum, a) => sum + a.confidence_score, 0) / agentsData.length 
      : 0;
    const automationRate = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;

    setMetrics({
      totalTasks,
      completedTasks,
      activeAgents,
      avgConfidenceScore,
      automationRate
    });
  };

  const startOrchestration = async () => {
    try {
      setOrchestrationStatus('running');
      
      const { data, error } = await supabase.functions.invoke('agentic-compliance-orchestrator', {
        body: {
          action: 'start_orchestration',
          organization_id: 'current' // This would be dynamic
        }
      });

      if (error) throw error;

      toast({
        title: "Orchestration Started",
        description: "AI agents are now analyzing and implementing compliance controls",
      });
      
      fetchOrchestrationData();
    } catch (error) {
      setOrchestrationStatus('idle');
      toast({
        title: "Failed to Start",
        description: "Could not start compliance orchestration",
        variant: "destructive"
      });
    }
  };

  const pauseOrchestration = () => {
    setOrchestrationStatus('paused');
    toast({
      title: "Orchestration Paused",
      description: "AI agents have been paused",
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return <Zap className="h-4 w-4 text-green-400 animate-pulse" />;
      case 'complete': return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'error': return <AlertCircle className="h-4 w-4 text-red-400" />;
      default: return <Clock className="h-4 w-4 text-gray-400" />;
    }
  };

  const getTaskStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500/10 text-green-400 border-green-500/30';
      case 'in_progress': return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'failed': return 'bg-red-500/10 text-red-400 border-red-500/30';
      default: return 'bg-gray-500/10 text-gray-400 border-gray-500/30';
    }
  };

  if (loading) {
    return (
      <Card className="bg-black/40 border-primary/30">
        <CardContent className="p-8">
          <div className="flex items-center justify-center">
            <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full"></div>
            <span className="ml-3 text-primary">Loading orchestration system...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Orchestration Control Panel */}
      <Card className="bg-gradient-to-r from-primary/10 to-primary/5 border-primary/30">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Bot className="h-6 w-6 text-primary" />
              <span className="text-primary">Agentic Compliance Orchestrator</span>
              <Badge 
                variant="outline" 
                className={orchestrationStatus === 'running' ? 'bg-green-500/10 text-green-400 border-green-500/30' : 'bg-gray-500/10 text-gray-400 border-gray-500/30'}
              >
                {orchestrationStatus.toUpperCase()}
              </Badge>
            </div>
            
            <div className="flex space-x-2">
              {orchestrationStatus === 'idle' && (
                <Button onClick={startOrchestration} className="bg-primary hover:bg-primary/90">
                  <Zap className="h-4 w-4 mr-2" />
                  Start Orchestration
                </Button>
              )}
              {orchestrationStatus === 'running' && (
                <Button onClick={pauseOrchestration} variant="outline" className="border-yellow-500/30">
                  <Clock className="h-4 w-4 mr-2" />
                  Pause
                </Button>
              )}
            </div>
          </CardTitle>
        </CardHeader>

        <CardContent>
          {/* Metrics Dashboard */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
            <Card className="bg-black/20 border-primary/20">
              <CardContent className="p-4 text-center">
                <p className="text-primary text-2xl font-bold">{metrics.totalTasks}</p>
                <p className="text-xs text-muted-foreground">Total Tasks</p>
              </CardContent>
            </Card>
            
            <Card className="bg-black/20 border-green-500/30">
              <CardContent className="p-4 text-center">
                <p className="text-green-400 text-2xl font-bold">{metrics.completedTasks}</p>
                <p className="text-xs text-muted-foreground">Completed</p>
              </CardContent>
            </Card>
            
            <Card className="bg-black/20 border-blue-500/30">
              <CardContent className="p-4 text-center">
                <p className="text-blue-400 text-2xl font-bold">{metrics.activeAgents}</p>
                <p className="text-xs text-muted-foreground">Active Agents</p>
              </CardContent>
            </Card>
            
            <Card className="bg-black/20 border-purple-500/30">
              <CardContent className="p-4 text-center">
                <p className="text-purple-400 text-2xl font-bold">{Math.round(metrics.avgConfidenceScore * 100)}%</p>
                <p className="text-xs text-muted-foreground">Avg Confidence</p>
              </CardContent>
            </Card>
            
            <Card className="bg-black/20 border-orange-500/30">
              <CardContent className="p-4 text-center">
                <p className="text-orange-400 text-2xl font-bold">{Math.round(metrics.automationRate)}%</p>
                <p className="text-xs text-muted-foreground">Automation Rate</p>
              </CardContent>
            </Card>
          </div>

          <div className="mb-4">
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm text-muted-foreground">Overall Progress</span>
              <span className="text-sm text-muted-foreground">{metrics.completedTasks}/{metrics.totalTasks} tasks</span>
            </div>
            <Progress value={metrics.totalTasks > 0 ? (metrics.completedTasks / metrics.totalTasks) * 100 : 0} className="h-3" />
          </div>
        </CardContent>
      </Card>

      {/* Main Tabs */}
      <Card className="bg-black/40 border-primary/30">
        <CardContent className="p-6">
          <Tabs defaultValue="agents">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="agents">AI Agents</TabsTrigger>
              <TabsTrigger value="tasks">Active Tasks</TabsTrigger>
              <TabsTrigger value="insights">AI Insights</TabsTrigger>
            </TabsList>

            <TabsContent value="agents" className="mt-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {controlFamilyAgents.map((agentConfig) => {
                  const agent = agents.find(a => a.agent_name === agentConfig.name) || {
                    id: agentConfig.family,
                    agent_name: agentConfig.name,
                    control_family: agentConfig.family,
                    execution_status: 'idle' as const,
                    recommendations_generated: 0,
                    automations_executed: 0,
                    confidence_score: 0.85,
                    last_execution: new Date().toISOString()
                  };

                  return (
                    <Card key={agentConfig.family} className="bg-slate-800/40 border-slate-600/30 hover:border-primary/30 transition-colors">
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center space-x-3">
                            <div className={`p-2 rounded-lg ${agentConfig.color}/20`}>
                              <agentConfig.icon className="h-5 w-5 text-white" />
                            </div>
                            <div>
                              <h4 className="font-semibold text-white text-sm">{agent.agent_name}</h4>
                              <p className="text-xs text-slate-400">{agentConfig.family} Family</p>
                            </div>
                          </div>
                          {getStatusIcon(agent.execution_status)}
                        </div>
                        
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between">
                            <span className="text-slate-400">Recommendations:</span>
                            <span className="text-white">{agent.recommendations_generated}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Automations:</span>
                            <span className="text-white">{agent.automations_executed}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Confidence:</span>
                            <span className="text-white">{Math.round(agent.confidence_score * 100)}%</span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </TabsContent>

            <TabsContent value="tasks" className="mt-6 space-y-4">
              <div className="space-y-3">
                {tasks.slice(0, 10).map((task) => (
                  <div key={task.id} className="p-4 bg-slate-800/40 rounded-lg border border-slate-600/30">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-3">
                        <Badge className={getTaskStatusColor(task.status)}>
                          {task.status}
                        </Badge>
                        <span className="font-semibold text-white">{task.control_id}</span>
                        <span className="text-sm text-slate-400">{task.task_type}</span>
                      </div>
                      <span className="text-xs text-slate-400">Priority: {task.priority}</span>
                    </div>
                    
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-slate-300">{task.ai_agent}</span>
                      <span className="text-xs text-slate-400">
                        Progress: {task.progress}%
                      </span>
                    </div>
                    
                    <Progress value={task.progress} className="h-2" />
                  </div>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="insights" className="mt-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card className="bg-slate-800/40 border-slate-600/30">
                  <CardHeader>
                    <CardTitle className="text-white text-sm">Top Recommendations</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded">
                      <p className="text-sm text-blue-300">Implement automated patch management for AC-02 controls</p>
                      <p className="text-xs text-blue-400 mt-1">Confidence: 94%</p>
                    </div>
                    <div className="p-3 bg-green-500/10 border border-green-500/30 rounded">
                      <p className="text-sm text-green-300">Deploy identity federation for IA-08 requirements</p>
                      <p className="text-xs text-green-400 mt-1">Confidence: 89%</p>
                    </div>
                    <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded">
                      <p className="text-sm text-yellow-300">Enhance audit logging for AU-02 compliance</p>
                      <p className="text-xs text-yellow-400 mt-1">Confidence: 87%</p>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-800/40 border-slate-600/30">
                  <CardHeader>
                    <CardTitle className="text-white text-sm">Risk Priorities</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="p-3 bg-red-500/10 border border-red-500/30 rounded">
                      <p className="text-sm text-red-300">Critical: 12 high-priority controls not implemented</p>
                      <p className="text-xs text-red-400 mt-1">Estimated risk: High</p>
                    </div>
                    <div className="p-3 bg-orange-500/10 border border-orange-500/30 rounded">
                      <p className="text-sm text-orange-300">Medium: 28 controls partially implemented</p>
                      <p className="text-xs text-orange-400 mt-1">Estimated risk: Medium</p>
                    </div>
                    <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded">
                      <p className="text-sm text-blue-300">Low: 156 controls ready for automation</p>
                      <p className="text-xs text-blue-400 mt-1">Automation potential: 78%</p>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};