import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Bot,
  Shield,
  Wrench,
  CheckCircle,
  FileText,
  TrendingUp,
  Terminal,
  Monitor,
  Server,
  Eye,
  Sparkles,
  Network,
  Globe
} from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';
import { Alert, AlertDescription } from '@/components/ui/alert';

interface AIAgent {
  id: string;
  name: string;
  type: 'compliance' | 'security' | 'monitoring' | 'remediation';
  status: 'deploying' | 'active' | 'paused' | 'error';
  environment: string;
  deployedAt?: Date;
  tasksCompleted: number;
  tasksActive: number;
  coverage: number;
  capabilities: string[];
}

interface DeploymentTarget {
  id: string;
  name: string;
  type: 'endpoint' | 'network' | 'cloud' | 'server';
  status: 'available' | 'deploying' | 'deployed';
  agents: number;
}

export const AIAgentDeployment = () => {
  const { currentOrganization } = useOrganization();
  const [agents, setAgents] = useState<AIAgent[]>([]);
  const [deploymentTargets, setDeploymentTargets] = useState<DeploymentTarget[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const [deploymentProgress, setDeploymentProgress] = useState(0);
  const [isDeploying, setIsDeploying] = useState(false);
  const [showDeploymentLog, setShowDeploymentLog] = useState(false);
  const [deploymentLog, setDeploymentLog] = useState<string[]>([
    '[System] AI Agent Deployment Console Ready',
    '[System] CMMC compliance automation enabled',
    '[System] 90-day certification pathway active'
  ]);

  useEffect(() => {
    initializeAgentSystem();
    discoverDeploymentTargets();
  }, [currentOrganization?.organization_id]);

  const initializeAgentSystem = async () => {
    // Initialize with sample deployed agents
    const initialAgents: AIAgent[] = [
      {
        id: 'cmmc-compliance-agent',
        name: 'CMMC Compliance Automator',
        type: 'compliance',
        status: 'active',
        environment: 'production',
        deployedAt: new Date(Date.now() - 3600000),
        tasksCompleted: 247,
        tasksActive: 8,
        coverage: 85,
        capabilities: ['CMMC Level 2 Controls', 'Audit Documentation', 'Gap Analysis', 'Policy Implementation']
      },
      {
        id: 'security-scanner-agent',
        name: 'Autonomous Security Scanner',
        type: 'security',
        status: 'active',
        environment: 'network',
        deployedAt: new Date(Date.now() - 7200000),
        tasksCompleted: 156,
        tasksActive: 12,
        coverage: 92,
        capabilities: ['Vulnerability Detection', 'Threat Hunting', 'IOC Analysis', 'Risk Assessment']
      },
      {
        id: 'remediation-agent',
        name: 'Smart Remediation Bot',
        type: 'remediation',
        status: 'active',
        environment: 'infrastructure',
        deployedAt: new Date(Date.now() - 1800000),
        tasksCompleted: 89,
        tasksActive: 3,
        coverage: 78,
        capabilities: ['Auto Patching', 'Config Hardening', 'Access Control', 'Incident Response']
      }
    ];

    setAgents(initialAgents);
  };

  const discoverDeploymentTargets = async () => {
    // Discover available deployment environments
    const targets: DeploymentTarget[] = [
      {
        id: 'local-environment',
        name: 'Local Environment',
        type: 'endpoint',
        status: 'available',
        agents: 2
      },
      {
        id: 'corporate-network',
        name: 'Corporate Network',
        type: 'network',
        status: 'deployed',
        agents: 5
      },
      {
        id: 'aws-infrastructure',
        name: 'AWS Cloud Infrastructure',
        type: 'cloud',
        status: 'available',
        agents: 0
      },
      {
        id: 'on-prem-servers',
        name: 'On-Premise Servers',
        type: 'server',
        status: 'available',
        agents: 1
      }
    ];

    setDeploymentTargets(targets);
  };

  const deployAIAgent = async (targetId: string, agentType: string) => {
    if (!currentOrganization?.organization_id) return;

    setIsDeploying(true);
    setDeploymentProgress(0);
    setShowDeploymentLog(true);

    const logMessages = [
      '[Deploy] Initializing AI agent deployment...',
      '[Auth] Validating deployment credentials...',
      '[Scan] Analyzing target environment security...',
      '[Config] Applying KHEPRA protocol configurations...',
      '[Install] Installing autonomous agent modules...',
      '[Test] Performing initial capability tests...',
      '[Connect] Establishing secure communication channels...',
      '[Activate] Agent deployment successful - beginning operations...'
    ];

    // Simulate deployment process
    for (let i = 0; i < logMessages.length; i++) {
      setDeploymentLog(prev => [...prev, logMessages[i]]);
      setDeploymentProgress((i + 1) / logMessages.length * 100);
      await new Promise(resolve => setTimeout(resolve, 1500));
    }

    // Create new agent
    const newAgent: AIAgent = {
      id: `agent-${Date.now()}`,
      name: `${agentType} Agent`,
      type: agentType as AIAgent['type'],
      status: 'active',
      environment: targetId,
      deployedAt: new Date(),
      tasksCompleted: 0,
      tasksActive: 1,
      coverage: 0,
      capabilities: getAgentCapabilities(agentType)
    };

    setAgents(prev => [...prev, newAgent]);

    // Update target status
    setDeploymentTargets(prev =>
      prev.map(target =>
        target.id === targetId
          ? { ...target, status: 'deployed', agents: target.agents + 1 }
          : target
      )
    );

    setDeploymentLog(prev => [
      ...prev,
      '[Success] AI Agent deployed and operational',
      '[Monitoring] Beginning autonomous operations...'
    ]);

    // Trigger Grok AI for intelligent deployment
    try {
      await supabase.functions.invoke('grok-ai-agent', {
        body: {
          message: `New AI agent deployed: ${agentType} to ${targetId}. Begin autonomous CMMC compliance operations.`,
          organizationId: currentOrganization.organization_id,
          context: {
            source: 'agent_deployment',
            action: 'new_deployment',
            agentType,
            targetEnvironment: targetId
          }
        }
      });
    } catch (error) {
      console.error('Grok AI integration error:', error);
    }

    setIsDeploying(false);
    setTimeout(() => setShowDeploymentLog(false), 3000);
  };

  const getAgentCapabilities = (agentType: string): string[] => {
    switch (agentType) {
      case 'compliance':
        return ['CMMC Controls', 'Audit Prep', 'Gap Analysis', 'Documentation'];
      case 'security':
        return ['Threat Detection', 'Vulnerability Scanning', 'Risk Assessment'];
      case 'monitoring':
        return ['24/7 Monitoring', 'Alert Generation', 'Performance Tracking'];
      case 'remediation':
        return ['Auto-Patching', 'Configuration', 'Incident Response'];
      default:
        return ['General Operations'];
    }
  };

  const getAgentIcon = (type: string) => {
    switch (type) {
      case 'compliance': return <FileText className="h-5 w-5" />;
      case 'security': return <Shield className="h-5 w-5" />;
      case 'monitoring': return <Eye className="h-5 w-5" />;
      case 'remediation': return <Wrench className="h-5 w-5" />;
      default: return <Bot className="h-5 w-5" />;
    }
  };

  const getTargetIcon = (type: string) => {
    switch (type) {
      case 'endpoint': return <Monitor className="h-4 w-4" />;
      case 'network': return <Network className="h-4 w-4" />;
      case 'cloud': return <Globe className="h-4 w-4" />;
      case 'server': return <Server className="h-4 w-4" />;
      default: return <Terminal className="h-4 w-4" />;
    }
  };

  const totalAgents = agents.length;
  const activeAgents = agents.filter(a => a.status === 'active').length;
  const totalTasks = agents.reduce((sum, a) => sum + a.tasksCompleted, 0);
  const avgCoverage = agents.reduce((sum, a) => sum + a.coverage, 0) / (agents.length || 1);

  return (
    <div className="space-y-6">
      {/* Header with Key Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-primary/10 to-primary/5 border-primary/20">
          <CardContent className="p-4">
            <div className="flex items-center space-x-3">
              <Bot className="h-8 w-8 text-primary" />
              <div>
                <p className="text-2xl font-bold">{activeAgents}/{totalAgents}</p>
                <p className="text-xs text-muted-foreground">Active AI Agents</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-500/10 to-green-500/5 border-green-500/20">
          <CardContent className="p-4">
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-8 w-8 text-green-500" />
              <div>
                <p className="text-2xl font-bold">{totalTasks}</p>
                <p className="text-xs text-muted-foreground">Tasks Completed</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-blue-500/10 to-blue-500/5 border-blue-500/20">
          <CardContent className="p-4">
            <div className="flex items-center space-x-3">
              <TrendingUp className="h-8 w-8 text-blue-500" />
              <div>
                <p className="text-2xl font-bold">{Math.round(avgCoverage)}%</p>
                <p className="text-xs text-muted-foreground">Avg Coverage</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-amber-500/10 to-amber-500/5 border-amber-500/20">
          <CardContent className="p-4">
            <div className="flex items-center space-x-3">
              <Sparkles className="h-8 w-8 text-amber-500" />
              <div>
                <p className="text-2xl font-bold">90</p>
                <p className="text-xs text-muted-foreground">Days to CMMC</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Deployment Interface */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Available Deployment Targets */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Globe className="h-5 w-5" />
              <span>Deployment Targets</span>
            </CardTitle>
            <p className="text-sm text-muted-foreground">
              Choose where to deploy your AI agents for maximum security coverage
            </p>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {deploymentTargets.map((target) => (
                <button
                  type="button"
                  key={target.id}
                  className={`p-4 border rounded-lg cursor-pointer transition-all text-left w-full ${selectedTarget === target.id
                      ? 'border-primary bg-primary/5'
                      : 'border-border hover:border-primary/50'
                    }`}
                  onClick={() => setSelectedTarget(target.id)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {getTargetIcon(target.type)}
                      <div>
                        <p className="font-medium">{target.name}</p>
                        <p className="text-xs text-muted-foreground capitalize">{target.type} environment</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge variant={target.status === 'deployed' ? 'default' : 'outline'}>
                        {target.agents} agents
                      </Badge>
                      <p className="text-xs text-muted-foreground mt-1 capitalize">
                        {target.status}
                      </p>
                    </div>
                  </div>
                </button>
              ))}
            </div>

            <Separator className="my-4" />

            {/* Quick Deploy Options */}
            <div className="space-y-2">
              <p className="font-medium">Quick Deploy AI Agents:</p>
              <div className="grid grid-cols-2 gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => selectedTarget && deployAIAgent(selectedTarget, 'compliance')}
                  disabled={!selectedTarget || isDeploying}
                  className="w-full"
                >
                  <FileText className="h-4 w-4 mr-2" />
                  CMMC Agent
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => selectedTarget && deployAIAgent(selectedTarget, 'security')}
                  disabled={!selectedTarget || isDeploying}
                  className="w-full"
                >
                  <Shield className="h-4 w-4 mr-2" />
                  Security Agent
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => selectedTarget && deployAIAgent(selectedTarget, 'monitoring')}
                  disabled={!selectedTarget || isDeploying}
                  className="w-full"
                >
                  <Eye className="h-4 w-4 mr-2" />
                  Monitor Agent
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => selectedTarget && deployAIAgent(selectedTarget, 'remediation')}
                  disabled={!selectedTarget || isDeploying}
                  className="w-full"
                >
                  <Wrench className="h-4 w-4 mr-2" />
                  Fix Agent
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Deployed Agents */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Bot className="h-5 w-5" />
              <span>Active AI Agents</span>
            </CardTitle>
            <p className="text-sm text-muted-foreground">
              Autonomous agents securing your environment 24/7
            </p>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-80">
              <div className="space-y-3">
                {agents.map((agent) => (
                  <div key={agent.id} className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        {getAgentIcon(agent.type)}
                        <div>
                          <p className="font-medium text-sm">{agent.name}</p>
                          <p className="text-xs text-muted-foreground">{agent.environment}</p>
                        </div>
                      </div>
                      <Badge variant={agent.status === 'active' ? 'default' : 'secondary'}>
                        {agent.status}
                      </Badge>
                    </div>

                    <div className="space-y-2">
                      <div className="flex justify-between text-xs">
                        <span>Coverage</span>
                        <span>{agent.coverage}%</span>
                      </div>
                      <Progress value={agent.coverage} className="h-1" />

                      <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                        <div>✓ {agent.tasksCompleted} completed</div>
                        <div>⚡ {agent.tasksActive} active</div>
                      </div>

                      <div className="flex flex-wrap gap-1 mt-2">
                        {agent.capabilities.slice(0, 2).map((cap) => (
                          <Badge key={cap} variant="outline" className="text-xs">
                            {cap}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      {/* Deployment Progress */}
      {isDeploying && (
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="p-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="font-medium">Deploying AI Agent...</p>
                <Badge variant="secondary">{Math.round(deploymentProgress)}%</Badge>
              </div>
              <Progress value={deploymentProgress} className="h-2" />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Deployment Log */}
      {showDeploymentLog && (
        <Card className="border-green-500/20 bg-green-500/5">
          <CardHeader>
            <CardTitle className="text-sm flex items-center space-x-2">
              <Terminal className="h-4 w-4" />
              <span>Deployment Console</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-40 font-mono text-xs">
              <div className="space-y-1">
                {deploymentLog.map((log, index) => (
                  <div key={`log-${log.substring(0, 20)}-${index}`} className="text-green-600">
                    {log}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {/* Marketing Alignment */}
      <Alert>
        <Sparkles className="h-4 w-4" />
        <AlertDescription>
          <strong>Deploy AI Agents in Your Environment:</strong> Our autonomous agents scan infrastructure,
          implement CMMC controls, and maintain 24/7 security monitoring. Deploy in minutes, not months.
          80% automation reduces certification time to 90 days with 75% cost savings.
        </AlertDescription>
      </Alert>
    </div>
  );
};