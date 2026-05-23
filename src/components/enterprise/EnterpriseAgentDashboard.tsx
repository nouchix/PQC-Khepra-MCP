import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { 
  Bot, 
  Brain, 
  Shield, 
  TrendingUp, 
  Users, 
  Settings,
  Play,
  Pause,
  AlertTriangle,
  CheckCircle,
  Clock,
  BarChart3,
  Plus,
  Zap
} from 'lucide-react';
import { useEnterpriseAgents, EnterpriseAgent } from '@/hooks/useEnterpriseAgents';
import { useToast } from '@/hooks/use-toast';
import SpecializedAgentTemplates from './SpecializedAgentTemplates';

const EnterpriseAgentDashboard: React.FC = () => {
  const { 
    agents, 
    loading, 
    createAgent, 
    updateAgent, 
    executeAgentAction,
    getAgentPerformance,
    promoteAgent,
    deployAgent,
    suspendAgent 
  } = useEnterpriseAgents();
  
  const { toast } = useToast();
  const [selectedAgent, setSelectedAgent] = useState<EnterpriseAgent | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [performanceData, setPerformanceData] = useState<any>(null);

  const agentTypeIcons = {
    finance: TrendingUp,
    hr: Users,
    security: Shield,
    operations: Settings,
    legal: CheckCircle
  };

  const getTrustLevelColor = (level: number) => {
    if (level < 25) return 'bg-red-500';
    if (level < 50) return 'bg-yellow-500';
    if (level < 75) return 'bg-blue-500';
    return 'bg-green-500';
  };

  const getStatusVariant = (status: string) => {
    switch (status) {
      case 'active': return 'default';
      case 'training': return 'secondary';
      case 'suspended': return 'destructive';
      default: return 'outline';
    }
  };

  const handleCreateAgent = async (formData: FormData) => {
    const agentData = {
      agent_name: formData.get('name') as string,
      agent_type: formData.get('type') as any,
      specialization: formData.get('specialization') as string,
      capabilities: (formData.get('capabilities') as string).split(',').map(c => c.trim())
    };

    const newAgent = await createAgent(agentData);
    if (newAgent) {
      setShowCreateDialog(false);
    }
  };

  const handleAgentAction = async (agentId: string, actionType: string) => {
    try {
      switch (actionType) {
        case 'promote':
          await promoteAgent(agentId);
          break;
        case 'deploy':
          await deployAgent(agentId);
          break;
        case 'suspend':
          await suspendAgent(agentId, 'Manual suspension');
          break;
        default:
          await executeAgentAction(agentId, {
            type: actionType,
            context: `Manual ${actionType} action`
          });
      }
    } catch (error) {
      console.error('Agent action failed:', error);
    }
  };

  const loadPerformanceData = async (agent: EnterpriseAgent) => {
    const data = await getAgentPerformance(agent.id);
    setPerformanceData(data);
    setSelectedAgent(agent);
  };

  const agentStats = {
    total: agents.length,
    active: agents.filter(a => a.status === 'active').length,
    training: agents.filter(a => a.status === 'training').length,
    production: agents.filter(a => a.deployment_status === 'production').length
  };

  return (
    <div className="container mx-auto py-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Enterprise AI Agent Management</h1>
          <p className="text-muted-foreground">
            Manage and monitor your specialized AI agents with enterprise-grade controls
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="w-4 h-4 mr-2" />
              Create Agent
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New AI Agent</DialogTitle>
            </DialogHeader>
            <form onSubmit={(e) => {
              e.preventDefault();
              handleCreateAgent(new FormData(e.currentTarget));
            }} className="space-y-4">
              <div>
                <Label htmlFor="name">Agent Name</Label>
                <Input id="name" name="name" placeholder="Finance Assistant" required />
              </div>
              <div>
                <Label htmlFor="type">Agent Type</Label>
                <Select name="type" required>
                  <SelectTrigger>
                    <SelectValue placeholder="Select agent type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="finance">Finance</SelectItem>
                    <SelectItem value="hr">Human Resources</SelectItem>
                    <SelectItem value="security">Security</SelectItem>
                    <SelectItem value="operations">Operations</SelectItem>
                    <SelectItem value="legal">Legal</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="specialization">Specialization</Label>
                <Input id="specialization" name="specialization" placeholder="Budget analysis and cost optimization" required />
              </div>
              <div>
                <Label htmlFor="capabilities">Capabilities (comma-separated)</Label>
                <Textarea id="capabilities" name="capabilities" placeholder="data analysis, reporting, compliance checking" />
              </div>
              <Button type="submit" className="w-full">Create Agent</Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Agents</CardTitle>
            <Bot className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{agentStats.total}</div>
            <p className="text-xs text-muted-foreground">Across all departments</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Active Agents</CardTitle>
            <CheckCircle className="w-4 h-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{agentStats.active}</div>
            <p className="text-xs text-muted-foreground">Currently operational</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">In Training</CardTitle>
            <Brain className="w-4 h-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{agentStats.training}</div>
            <p className="text-xs text-muted-foreground">Building capabilities</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Production Ready</CardTitle>
            <BarChart3 className="w-4 h-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{agentStats.production}</div>
            <p className="text-xs text-muted-foreground">Deployed to production</p>
          </CardContent>
        </Card>
      </div>

      {/* Agents Management */}
      <Tabs defaultValue="templates" className="w-full">
        <TabsList>
          <TabsTrigger value="templates">
            <Zap className="w-4 h-4 mr-2" />
            Agent Templates
          </TabsTrigger>
          <TabsTrigger value="agents">My Agents</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="workflows">Workflows</TabsTrigger>
        </TabsList>

        <TabsContent value="templates">
          <SpecializedAgentTemplates />
        </TabsContent>

        <TabsContent value="agents" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {agents.map((agent) => {
              const Icon = agentTypeIcons[agent.agent_type] || Bot;
              return (
                <Card key={agent.id} className="hover:shadow-lg transition-shadow cursor-pointer">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <div className="p-2 rounded-lg bg-primary/10">
                          <Icon className="w-5 h-5 text-primary" />
                        </div>
                        <div>
                          <CardTitle className="text-base">{agent.agent_name}</CardTitle>
                          <p className="text-sm text-muted-foreground capitalize">{agent.agent_type}</p>
                        </div>
                      </div>
                      <Badge variant={getStatusVariant(agent.status)}>
                        {agent.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Trust Level</span>
                        <span>{agent.trust_level}%</span>
                      </div>
                      <Progress 
                        value={agent.trust_level} 
                        className={`h-2 ${getTrustLevelColor(agent.trust_level)}`}
                      />
                    </div>
                    
                    <div className="text-sm text-muted-foreground">
                      {agent.specialization}
                    </div>
                    
                    <div className="flex flex-wrap gap-1">
                      {agent.capabilities.slice(0, 2).map((capability, idx) => (
                        <Badge key={idx} variant="outline" className="text-xs">
                          {capability}
                        </Badge>
                      ))}
                      {agent.capabilities.length > 2 && (
                        <Badge variant="outline" className="text-xs">
                          +{agent.capabilities.length - 2}
                        </Badge>
                      )}
                    </div>

                    <div className="flex space-x-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => loadPerformanceData(agent)}
                        className="flex-1"
                      >
                        <BarChart3 className="w-3 h-3 mr-1" />
                        View
                      </Button>
                      {agent.status === 'training' && agent.trust_level >= 25 && (
                        <Button
                          size="sm"
                          onClick={() => handleAgentAction(agent.id, 'promote')}
                          className="flex-1"
                        >
                          <TrendingUp className="w-3 h-3 mr-1" />
                          Promote
                        </Button>
                      )}
                      {agent.status === 'active' && agent.deployment_status !== 'production' && (
                        <Button
                          size="sm"
                          onClick={() => handleAgentAction(agent.id, 'deploy')}
                          className="flex-1"
                        >
                          <Play className="w-3 h-3 mr-1" />
                          Deploy
                        </Button>
                      )}
                      {agent.status === 'active' && (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => handleAgentAction(agent.id, 'suspend')}
                        >
                          <Pause className="w-3 h-3" />
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>

        <TabsContent value="performance" className="space-y-4">
          {selectedAgent && performanceData ? (
            <Card>
              <CardHeader>
                <CardTitle>Performance Analytics - {selectedAgent.agent_name}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-600">
                      {performanceData.successRate.toFixed(1)}%
                    </div>
                    <p className="text-sm text-muted-foreground">Success Rate</p>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">
                      {performanceData.actionsLast24h}
                    </div>
                    <p className="text-sm text-muted-foreground">Actions (24h)</p>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-purple-600">
                      {performanceData.totalActions}
                    </div>
                    <p className="text-sm text-muted-foreground">Total Actions</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="flex items-center justify-center py-12">
                <div className="text-center text-muted-foreground">
                  Select an agent to view performance analytics
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="workflows">
          <Card>
            <CardHeader>
              <CardTitle>Agent Workflows</CardTitle>
              <p className="text-sm text-muted-foreground">
                Multi-agent collaboration and workflow management
              </p>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12 text-muted-foreground">
                Workflow management coming soon...
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default EnterpriseAgentDashboard;