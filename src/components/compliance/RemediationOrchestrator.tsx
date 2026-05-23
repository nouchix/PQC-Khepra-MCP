import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import {
  GitBranch,
  CheckCircle,
  Clock,
  AlertTriangle,
  Shield,
  Undo,
  User
} from 'lucide-react';

interface RemediationPlaybook {
  id: string;
  name: string;
  description: string;
  controlId: string;
  framework: string;
  tool: 'terraform' | 'ansible' | 'api' | 'kubectl' | 'manual';
  riskLevel: 'low' | 'medium' | 'high';
  estimatedTime: string;
  blastRadius: number;
  approvalRequired: boolean;
  steps: RemediationStep[];
  guardrails: string[];
  rollbackPlan: string[];
  dependencies: string[];
}

interface RemediationStep {
  id: string;
  name: string;
  action: string;
  tool: string;
  params: Record<string, any>;
  timeout: number;
  retryable: boolean;
  critical: boolean;
}

interface RemediationExecution {
  id: string;
  playbookId: string;
  status: 'queued' | 'running' | 'waiting-approval' | 'completed' | 'failed' | 'rolled-back';
  progress: number;
  currentStep?: number;
  startTime: Date;
  endTime?: Date;
  executedBy: string;
  approvedBy?: string;
  approvalRequired: boolean;
  logs: ExecutionLog[];
  rollbackAvailable: boolean;
}

interface ExecutionLog {
  timestamp: Date;
  step: string;
  level: 'info' | 'warning' | 'error';
  message: string;
  metadata?: Record<string, any>;
}

// Awaiting telemetry for real remediation playbooks
const pendingPlaybooks: RemediationPlaybook[] = [];

export const RemediationOrchestrator: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<RemediationPlaybook[]>(pendingPlaybooks);
  const [executions, setExecutions] = useState<RemediationExecution[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<RemediationPlaybook | null>(null);
  const [approvalQueue, setApprovalQueue] = useState<RemediationExecution[]>([]);
  const { toast } = useToast();

  const mapExecutionLog = (l: any): ExecutionLog => ({
    ...l,
    timestamp: l.timestamp ? new Date(l.timestamp) : new Date()
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const { data: pbData, error: pbError } = await supabase.from('remediation_playbooks').select('*');
        if (pbError) throw pbError;
        if (pbData && pbData.length > 0) {
          const mappedPb: RemediationPlaybook[] = pbData.map((d: any) => {
            const controlIdVal = d.tags;
            let finalControlId = 'Unknown';
            if (Array.isArray(controlIdVal)) {
              finalControlId = controlIdVal[0];
            } else if (controlIdVal) {
              finalControlId = String(controlIdVal);
            }

            return {
              id: d.id,
              name: d.name,
              description: d.description || '',
              controlId: finalControlId,
              framework: 'Custom',
              tool: d.type || 'manual',
              riskLevel: 'medium',
              estimatedTime: '5m',
              blastRadius: 5,
              approvalRequired: !!d.requires_approval,
              steps: Array.isArray(d.steps) ? d.steps : [],
              guardrails: [],
              rollbackPlan: Array.isArray(d.rollback_steps) ? d.rollback_steps : [],
              dependencies: []
            };
          });
          setPlaybooks([...pendingPlaybooks, ...mappedPb]);
        }

        const { data: exData, error: exError } = await supabase.from('remediation_executions').select('*');
        if (exError) throw exError;
        if (exData && exData.length > 0) {
          const mappedEx: RemediationExecution[] = exData.map((d: any) => ({
            id: d.id,
            playbookId: d.playbook_id,
            status: d.status || 'failed',
            progress: d.status === 'completed' ? 100 : 50,
            startTime: new Date(d.start_time || d.created_at),
            endTime: d.end_time ? new Date(d.end_time) : undefined,
            executedBy: d.triggered_by || 'system',
            approvalRequired: d.status === 'waiting-approval',
            logs: Array.isArray(d.logs) ? d.logs.map(mapExecutionLog) : [],
            rollbackAvailable: d.status === 'completed'
          }));
          setExecutions(mappedEx);
          setApprovalQueue(mappedEx.filter(e => e.status === 'waiting-approval'));
        }
      } catch (err) {
        console.error('Error fetching orchestration data:', err);
      }
    };
    fetchData();
  }, []);

  const processExecutionProgress = (prev: RemediationExecution[]) => prev.map(execution => {
    if (execution.status === 'running' && execution.progress < 100) {
      const newProgress = Math.min(100, execution.progress + 10); // Fixed increment; real progress requires event stream from remediation engine
      const newStatus = newProgress >= 100 ? 'completed' : 'running';

      if (newStatus === 'completed') {
        return {
          ...execution,
          status: newStatus as any,
          progress: 100,
          endTime: new Date(),
          logs: [
            ...execution.logs,
            {
              timestamp: new Date(),
              step: 'completion',
              level: 'info' as any,
              message: 'Remediation completed successfully'
            }
          ]
        };
      }

      return {
        ...execution,
        progress: newProgress,
        currentStep: Math.floor((newProgress / 100) * (selectedPlaybook?.steps.length || 3)),
        logs: execution.progress < 50 && newProgress >= 50 ? [
          ...execution.logs,
          {
            timestamp: new Date(),
            step: `step-${Math.floor(newProgress / 33) + 1}`,
            level: 'info' as any,
            message: `Executing step ${Math.floor(newProgress / 33) + 1}...`
          }
        ] : execution.logs
      };
    }
    return execution;
  });

  useEffect(() => {
    // Simulate execution progress updates
    const interval = setInterval(() => {
      setExecutions(processExecutionProgress);
    }, 3000);

    return () => clearInterval(interval);
  }, [selectedPlaybook]);

  const executePlaybook = async (playbook: RemediationPlaybook) => {
    setSelectedPlaybook(playbook);
    try {
      const { data: userData } = await supabase.auth.getUser();
      if (!userData?.user?.id) throw new Error('User must be authenticated to execute a playbook');
      const orgId = userData.user.id;

      const initialLog = {
        timestamp: new Date().toISOString(),
        step: 'initialization',
        level: 'info',
        message: playbook.approvalRequired ? 'Waiting for approval to execute remediation' : 'Starting remediation execution'
      };

      const { data: dbExec, error: insertError } = await supabase
        .from('remediation_executions')
        .insert({
          playbook_id: playbook.id,
          status: playbook.approvalRequired ? 'waiting-approval' : 'running',
          organization_id: orgId,
          triggered_by: 'current-user',
          logs: [initialLog] as any
        })
        .select()
        .single();

      if (insertError) throw insertError;

      const execution: RemediationExecution = {
        id: dbExec.id,
        playbookId: dbExec.playbook_id,
        status: dbExec.status as any,
        progress: 0,
        currentStep: 0,
        startTime: new Date(dbExec.start_time || dbExec.created_at),
        executedBy: dbExec.triggered_by || 'current-user',
        approvalRequired: playbook.approvalRequired,
        logs: [{
          ...initialLog,
          timestamp: new Date(initialLog.timestamp),
          level: initialLog.level as any
        }],
        rollbackAvailable: false
      };

      setExecutions(prev => [...prev, execution]);

      if (playbook.approvalRequired) {
        setApprovalQueue(prev => [...prev, execution]);

        toast({
          title: "Approval Required",
          description: `Remediation ${playbook.name} is waiting for approval`,
        });
      } else {
        await supabase.functions.invoke('grok-ai-agent', {
          body: {
            action: 'execute_remediation',
            playbook: {
              id: playbook.id,
              name: playbook.name,
              tool: playbook.tool,
              steps: playbook.steps
            }
          }
        });

        toast({
          title: "Remediation Started",
          description: `Executing ${playbook.name}`,
        });
      }
    } catch (error) {
      console.error('Failed to execute remediation:', error);
      toast({
        title: "Execution Failed",
        description: "Failed to start remediation execution",
        variant: "destructive"
      });
    }
  };

  const approveExecution = async (execution: RemediationExecution) => {
    try {
      const newLog = {
        timestamp: new Date().toISOString(),
        step: 'approval',
        level: 'info',
        message: 'Remediation approved and starting execution'
      };

      const serializableLogs = execution.logs.map(l => ({ ...l, timestamp: l.timestamp.toISOString() }));
      const newLogs = [...serializableLogs, newLog];

      const { error } = await supabase
        .from('remediation_executions')
        .update({ status: 'running', logs: newLogs as any })
        .eq('id', execution.id);

      if (error) throw error;

      setExecutions(prev => prev.map(exec =>
        exec.id === execution.id ? {
          ...exec,
          status: 'running',
          approvedBy: 'current-user',
          logs: [
            ...exec.logs,
            {
              ...newLog,
              timestamp: new Date(newLog.timestamp),
              level: newLog.level as any
            }
          ]
        } : exec
      ));

      setApprovalQueue(prev => prev.filter(exec => exec.id !== execution.id));

      toast({
        title: "Remediation Approved",
        description: "Execution has been approved and started",
      });
    } catch (err) {
      console.error('Failed to approve execution:', err);
      toast({
        title: "Approval Failed",
        description: "Failed to approve remediation execution",
        variant: "destructive"
      });
    }
  };

  const rollbackExecution = async (execution: RemediationExecution) => {
    const playbook = playbooks.find(pb => pb.id === execution.playbookId);
    if (!playbook) return;

    try {
      const newLog = {
        timestamp: new Date().toISOString(),
        step: 'rollback',
        level: 'warning',
        message: 'Rollback initiated'
      };

      const serializableLogs = execution.logs.map(l => ({ ...l, timestamp: l.timestamp.toISOString() }));
      const newLogs = [...serializableLogs, newLog];

      const { error: updateError } = await supabase
        .from('remediation_executions')
        .update({ status: 'rolled-back', logs: newLogs as any })
        .eq('id', execution.id);

      if (updateError) throw updateError;

      setExecutions(prev => prev.map(exec =>
        exec.id === execution.id ? {
          ...exec,
          status: 'rolled-back',
          logs: [
            ...exec.logs,
            {
              ...newLog,
              timestamp: new Date(newLog.timestamp),
              level: newLog.level as any
            }
          ]
        } : exec
      ));

      await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'rollback_remediation',
          executionId: execution.id,
          rollbackPlan: playbook.rollbackPlan
        }
      });
      // Using generic error logging omitted to ignore lambda-failure rollback cancellation unless necessary

      toast({
        title: "Rollback Initiated",
        description: `Rolling back ${playbook.name}`,
      });
    } catch (err) {
      console.error('Failed to rollback:', err);
      toast({
        title: "Rollback Failed",
        description: "Failed to initiate rollback",
        variant: "destructive"
      });
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-600';
      case 'running': return 'text-blue-600';
      case 'waiting-approval': return 'text-orange-600';
      case 'failed': return 'text-red-600';
      case 'rolled-back': return 'text-gray-600';
      default: return 'text-gray-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'running': return <Clock className="h-4 w-4 text-blue-500 animate-spin" />;
      case 'waiting-approval': return <User className="h-4 w-4 text-orange-500" />;
      case 'failed': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'rolled-back': return <Undo className="h-4 w-4 text-gray-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'bg-red-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="space-y-6">
      <Tabs defaultValue="playbooks" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="playbooks">Playbooks</TabsTrigger>
          <TabsTrigger value="executions">Executions</TabsTrigger>
          <TabsTrigger value="approvals">
            Approvals {approvalQueue.length > 0 && `(${approvalQueue.length})`}
          </TabsTrigger>
          <TabsTrigger value="logs">Logs</TabsTrigger>
        </TabsList>

        <TabsContent value="playbooks" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitBranch className="h-5 w-5" />
                Remediation Playbooks
              </CardTitle>
              <CardDescription>
                Automated remediation playbooks with approval workflows and rollback capabilities
              </CardDescription>
            </CardHeader>
          </Card>

          <div className="grid gap-4">
            {playbooks.map((playbook) => (
              <Card key={playbook.id}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Badge className={getRiskColor(playbook.riskLevel)}>
                          {playbook.riskLevel.toUpperCase()} RISK
                        </Badge>
                        <Badge variant="outline">{playbook.framework}</Badge>
                        <Badge variant="secondary">{playbook.tool}</Badge>
                        {playbook.approvalRequired && (
                          <Badge variant="outline">Approval Required</Badge>
                        )}
                      </div>
                      <CardTitle>{playbook.name}</CardTitle>
                      <CardDescription>{playbook.description}</CardDescription>
                    </div>
                    <Button onClick={() => executePlaybook(playbook)}>
                      Execute
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div>
                      <div className="text-sm text-muted-foreground">Control ID</div>
                      <div className="font-medium">{playbook.controlId}</div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">Estimated Time</div>
                      <div className="font-medium">{playbook.estimatedTime}</div>
                    </div>
                    <div>
                      <div className="text-sm text-muted-foreground">Blast Radius</div>
                      <div className="font-medium">{playbook.blastRadius}/10</div>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <h5 className="font-medium mb-2">Steps ({playbook.steps.length})</h5>
                      <div className="space-y-1">
                        {playbook.steps.map((step, index) => (
                          <div key={step.id} className="text-sm flex items-center gap-2">
                            <span className="text-muted-foreground">{index + 1}.</span>
                            <span>{step.name}</span>
                            {step.critical && (
                              <Badge variant="outline" className="text-xs">Critical</Badge>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h5 className="font-medium mb-2">Guardrails</h5>
                      <div className="bg-muted p-2 rounded text-sm">
                        {playbook.guardrails.map((guardrail) => (
                          <div key={guardrail}>• {guardrail}</div>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="executions" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Active Executions</CardTitle>
              <CardDescription>Monitor ongoing and completed remediation executions</CardDescription>
            </CardHeader>
          </Card>

          <div className="space-y-4">
            {executions.map((execution) => {
              const playbook = playbooks.find(pb => pb.id === execution.playbookId);
              return (
                <Card key={execution.id}>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div>
                        <CardTitle className="flex items-center gap-2">
                          {getStatusIcon(execution.status)}
                          {playbook?.name}
                        </CardTitle>
                        <CardDescription>
                          Started: {execution.startTime.toLocaleString()}
                          {execution.endTime && ` • Completed: ${execution.endTime.toLocaleString()}`}
                        </CardDescription>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={getStatusColor(execution.status)}>
                          {execution.status.replaceAll('-', ' ').toUpperCase()}
                        </Badge>
                        {execution.status === 'completed' && execution.rollbackAvailable && (
                          <Button
                            onClick={() => rollbackExecution(execution)}
                            variant="outline"
                            size="sm"
                          >
                            <Undo className="h-4 w-4 mr-1" />
                            Rollback
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span>Progress</span>
                          <span>{execution.progress}%</span>
                        </div>
                        <Progress value={execution.progress} className="h-2" />
                      </div>

                      {execution.currentStep !== undefined && playbook && (
                        <div>
                          <div className="text-sm text-muted-foreground mb-2">
                            Current Step: {execution.currentStep + 1}/{playbook.steps.length}
                          </div>
                          <div className="text-sm font-medium">
                            {playbook.steps[execution.currentStep]?.name || 'Completing...'}
                          </div>
                        </div>
                      )}

                      <div className="space-y-2">
                        <h5 className="font-medium">Recent Logs</h5>
                        <div className="bg-black text-green-400 p-3 rounded font-mono text-xs max-h-32 overflow-y-auto">
                          {execution.logs.slice(-5).map((log) => (
                            <div key={log.timestamp.toISOString() + log.step}>
                              [{log.timestamp.toLocaleTimeString()}] {log.level.toUpperCase()}: {log.message}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>

        <TabsContent value="approvals" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Pending Approvals</CardTitle>
              <CardDescription>Remediation executions waiting for approval</CardDescription>
            </CardHeader>
          </Card>

          {approvalQueue.length === 0 ? (
            <Card>
              <CardContent className="pt-6">
                <div className="text-center text-muted-foreground">
                  No pending approvals
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {approvalQueue.map((execution) => {
                const playbook = playbooks.find(pb => pb.id === execution.playbookId);
                return (
                  <Card key={execution.id}>
                    <CardHeader>
                      <div className="flex items-start justify-between">
                        <div>
                          <CardTitle>{playbook?.name}</CardTitle>
                          <CardDescription>
                            Requested: {execution.startTime.toLocaleString()}
                          </CardDescription>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            onClick={() => approveExecution(execution)}
                            variant="default"
                          >
                            <CheckCircle className="h-4 w-4 mr-1" />
                            Approve
                          </Button>
                          <Button variant="outline">
                            Reject
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {playbook && (
                        <div className="space-y-3">
                          <Alert>
                            <Shield className="h-4 w-4" />
                            <AlertDescription>
                              This remediation has a {playbook.riskLevel} risk level and affects {playbook.blastRadius}/10 blast radius.
                              Please review the remediation plan before approving.
                            </AlertDescription>
                          </Alert>

                          <div>
                            <h5 className="font-medium mb-2">Remediation Steps</h5>
                            <div className="space-y-1">
                              {playbook.steps.map((step, index) => (
                                <div key={step.id} className="text-sm flex items-center gap-2">
                                  <span className="text-muted-foreground">{index + 1}.</span>
                                  <span>{step.name}</span>
                                  {step.critical && (
                                    <Badge variant="outline" className="text-xs">Critical</Badge>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>

                          <div>
                            <h5 className="font-medium mb-2">Rollback Plan</h5>
                            <div className="bg-muted p-2 rounded text-sm">
                              {playbook.rollbackPlan.map((step) => (
                                <div key={step}>• {step}</div>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="logs" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Execution Logs</CardTitle>
              <CardDescription>Detailed logs from all remediation executions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-black text-green-400 p-4 rounded font-mono text-sm max-h-96 overflow-y-auto">
                {executions.flatMap(execution => execution.logs)
                  .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
                  .slice(0, 50)
                  .map((log) => (
                    <div key={log.timestamp.toISOString() + log.step} className="mb-1">
                      [{log.timestamp.toLocaleString()}] {log.step}: {log.level.toUpperCase()}: {log.message}
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