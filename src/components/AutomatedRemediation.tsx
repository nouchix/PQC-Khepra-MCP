import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import {
  Zap, Settings, CheckCircle, Clock, AlertTriangle,
  Play, Pause, RotateCcw, Shield, Cpu, Database
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { formatDistanceToNow } from 'date-fns';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from '@/hooks/useOrganization';

interface RemediationTask {
  id: string;
  title: string;
  description: string;
  category: 'security_patch' | 'config_hardening' | 'compliance_fix' | 'vulnerability_mitigation';
  priority: 'low' | 'medium' | 'high' | 'critical';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'scheduled';
  progress: number;
  asset_name: string;
  asset_ip: string;
  estimated_duration: number; // minutes
  auto_approved: boolean;
  requires_reboot: boolean;
  risk_level: 'low' | 'medium' | 'high';
  created_at: string;
  started_at?: string;
  completed_at?: string;
  remediation_script: string;
}

interface AutomationRule {
  id: string;
  name: string;
  enabled: boolean;
  trigger_condition: string;
  action_type: 'patch' | 'configure' | 'isolate' | 'alert';
  auto_execute: boolean;
  approval_required: boolean;
  maintenance_window_only: boolean;
}

export const AutomatedRemediation = () => {
  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [automationRules, setAutomationRules] = useState<AutomationRule[]>([]);
  const [autoMode, setAutoMode] = useState(false);
  const [maintenanceWindow, setMaintenanceWindow] = useState(false);
  const { toast } = useToast();
  const { currentOrganization } = useOrganization();

  // Mock data
  useEffect(() => {
    // Awaiting telemetry for real tasks and rules
    const pendingTasks: RemediationTask[] = [];
    const activeRules: AutomationRule[] = [];

    setTasks(pendingTasks);
    setAutomationRules(activeRules);
  }, []);

  const updateTaskStatus = (taskId: string, updates: Partial<RemediationTask>) => {
    setTasks(prev => prev.map(t => t.id === taskId ? { ...t, ...updates } : t));
  };

  const toggleRule = (ruleId: string, checked: boolean) => {
    setAutomationRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled: checked } : r));
  };

  const executeTask = async (taskId: string) => {
    const task = tasks.find(t => t.id === taskId);
    if (!task) return;

    updateTaskStatus(taskId, { status: 'running', progress: 0, started_at: new Date().toISOString() });

    toast({
      title: "Remediation Started",
      description: `Executing: ${task.title}`,
      variant: "default"
    });

    try {
      // Map task category to remediation action
      let action = 'patch_management';
      switch (task.category) {
        case 'security_patch':
          action = 'patch_management';
          break;
        case 'config_hardening':
          action = 'configuration_hardening';
          break;
        case 'compliance_fix':
          action = 'compliance_automation';
          break;
        case 'vulnerability_mitigation':
          action = 'incident_response';
          break;
      }

      const { data, error } = await supabase.functions.invoke('automated-remediation', {
        body: {
          action,
          targets: [task.asset_ip],
          remediation_type: task.category,
          organizationId: currentOrganization?.id,
          dry_run: false
        }
      });

      if (error) {
        console.error('Remediation error:', error);
        updateTaskStatus(taskId, { status: 'failed', completed_at: new Date().toISOString() });
        toast({
          title: "Remediation Failed",
          description: `Failed to execute: ${task.title}`,
          variant: "destructive"
        });
        return;
      }

      // Update task with real results
      updateTaskStatus(taskId, {
        status: 'completed',
        progress: 100,
        completed_at: new Date().toISOString()
      });

      toast({
        title: "Remediation Complete",
        description: `Successfully completed: ${task.title}. Success rate: ${data.summary?.success_rate || 100}%`,
        variant: "default"
      });

    } catch (error) {
      console.error('Remediation error:', error);
      updateTaskStatus(taskId, { status: 'failed', completed_at: new Date().toISOString() });
      toast({
        title: "Remediation Failed",
        description: `An unexpected error occurred while executing: ${task.title}`,
        variant: "destructive"
      });
    }
  };

  const executeAllPending = async () => {
    const pendingTasks = tasks.filter(t => t.status === 'pending' && t.auto_approved);

    for (const task of pendingTasks) {
      if (task.requires_reboot && !maintenanceWindow) {
        toast({
          title: "Maintenance Window Required",
          description: `Task "${task.title}" requires system reboot`,
          variant: "destructive"
        });
        continue;
      }
      await executeTask(task.id);
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'security_patch': return <Shield className="h-4 w-4" />;
      case 'config_hardening': return <Settings className="h-4 w-4" />;
      case 'compliance_fix': return <CheckCircle className="h-4 w-4" />;
      case 'vulnerability_mitigation': return <Zap className="h-4 w-4" />;
      default: return <Settings className="h-4 w-4" />;
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'bg-destructive text-destructive-foreground';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-warning text-warning-foreground';
      case 'low': return 'bg-success text-success-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending': return 'bg-warning text-warning-foreground';
      case 'running': return 'bg-primary text-primary-foreground';
      case 'completed': return 'bg-success text-success-foreground';
      case 'failed': return 'bg-destructive text-destructive-foreground';
      case 'scheduled': return 'bg-accent text-accent-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const pendingTasks = tasks.filter(t => t.status === 'pending').length;
  const runningTasks = tasks.filter(t => t.status === 'running').length;
  const completedTasks = tasks.filter(t => t.status === 'completed').length;
  const enabledRules = automationRules.filter(r => r.enabled).length;

  return (
    <div className="space-y-6">
      {/* Automation Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Pending Tasks</p>
                <p className="text-2xl font-bold text-warning">{pendingTasks}</p>
              </div>
              <Clock className="h-8 w-8 text-warning" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Running</p>
                <p className="text-2xl font-bold text-primary">{runningTasks}</p>
              </div>
              <Cpu className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Completed</p>
                <p className="text-2xl font-bold text-success">{completedTasks}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Rules</p>
                <p className="text-2xl font-bold text-accent">{enabledRules}</p>
              </div>
              <Database className="h-8 w-8 text-accent" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Automation Controls */}
      <Card className="card-cyber">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Zap className="h-5 w-5 text-primary" />
                <span>Automated Remediation Engine</span>
              </CardTitle>
              <CardDescription>
                AI-powered automated security remediation and compliance fixing
              </CardDescription>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Switch
                  checked={maintenanceWindow}
                  onCheckedChange={setMaintenanceWindow}
                />
                <span className="text-sm">Maintenance Window</span>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  checked={autoMode}
                  onCheckedChange={setAutoMode}
                />
                <span className="text-sm">Auto Mode</span>
              </div>
              <Button
                variant="cyber"
                onClick={executeAllPending}
                disabled={pendingTasks === 0}
              >
                <Play className="h-4 w-4 mr-2" />
                Execute All
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Main Tabs */}
      <Tabs defaultValue="tasks" className="space-y-4">
        <TabsList className="bg-card border border-border">
          <TabsTrigger value="tasks">Remediation Tasks</TabsTrigger>
          <TabsTrigger value="rules">Automation Rules</TabsTrigger>
        </TabsList>

        <TabsContent value="tasks" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle>Active Remediation Tasks</CardTitle>
              <CardDescription>
                Automated security fixes and compliance remediations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {tasks.map((task) => (
                  <div
                    key={task.id}
                    className="p-4 border border-border rounded-lg bg-card hover:bg-accent/30 transition-colors"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          {getCategoryIcon(task.category)}
                          <h4 className="font-medium text-foreground">{task.title}</h4>
                          <Badge className={getPriorityColor(task.priority)}>
                            {task.priority.toUpperCase()}
                          </Badge>
                          <Badge className={getStatusColor(task.status)}>
                            {task.status.toUpperCase()}
                          </Badge>
                          {task.requires_reboot && (
                            <Badge variant="outline">REBOOT REQUIRED</Badge>
                          )}
                        </div>

                        <p className="text-sm text-muted-foreground mb-3">
                          {task.description}
                        </p>

                        {task.status === 'running' && (
                          <div className="mb-3">
                            <div className="flex justify-between text-sm mb-1">
                              <span>Progress</span>
                              <span>{task.progress}%</span>
                            </div>
                            <Progress value={task.progress} className="w-full" />
                          </div>
                        )}

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-muted-foreground">
                          <span>Asset: {task.asset_name}</span>
                          <span>Duration: {task.estimated_duration}min</span>
                          <span>Risk: {task.risk_level.toUpperCase()}</span>
                          <span>Created: {formatDistanceToNow(new Date(task.created_at), { addSuffix: true })}</span>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 ml-4">
                        {task.status === 'pending' && (
                          <Button
                            variant="cyber"
                            size="sm"
                            onClick={() => executeTask(task.id)}
                          >
                            <Play className="h-3 w-3 mr-1" />
                            Execute
                          </Button>
                        )}
                        {task.status === 'running' && (
                          <Button variant="outline" size="sm" disabled>
                            <Pause className="h-3 w-3 mr-1" />
                            Running
                          </Button>
                        )}
                        {task.status === 'failed' && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => executeTask(task.id)}
                          >
                            <RotateCcw className="h-3 w-3 mr-1" />
                            Retry
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rules" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle>Automation Rules</CardTitle>
              <CardDescription>
                Configure automated responses to security events and compliance issues
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {automationRules.map((rule) => (
                  <div
                    key={rule.id}
                    className="p-4 border border-border rounded-lg bg-card"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h4 className="font-medium text-foreground">{rule.name}</h4>
                          <Badge variant={rule.enabled ? "default" : "outline"}>
                            {rule.enabled ? 'ENABLED' : 'DISABLED'}
                          </Badge>
                          <Badge variant="outline">{rule.action_type.toUpperCase()}</Badge>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm text-muted-foreground">
                          <span>Trigger: {rule.trigger_condition}</span>
                          <span>Auto-Execute: {rule.auto_execute ? 'Yes' : 'No'}</span>
                          <span>Approval: {rule.approval_required ? 'Required' : 'Not Required'}</span>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2">
                        <Switch
                          checked={rule.enabled}
                          onCheckedChange={(checked) => toggleRule(rule.id, checked)}
                        />
                        <Button variant="outline" size="sm">
                          <Settings className="h-3 w-3 mr-1" />
                          Configure
                        </Button>
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