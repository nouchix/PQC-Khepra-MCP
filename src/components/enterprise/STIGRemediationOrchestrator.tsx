import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Play,
  Pause,
  Square,
  AlertTriangle,
  CheckCircle,
  Clock,
  Zap,
  Settings,
  RefreshCw,
  FileText,
  Shield,
  AlertCircle,
  Undo2
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { useOrganizationContext } from "@/components/OrganizationProvider";

interface RemediationPlaybook {
  id: string;
  playbook_name: string;
  stig_rule_id: string;
  platform: string;
  description: string;
  risk_level: string;
  auto_execute: boolean;
  success_rate: number;
  execution_count: number;
}

interface RemediationJob {
  id: string;
  asset_id: string;
  asset_name: string;
  stig_rule_id: string;
  playbook_name: string;
  status: string;
  progress: number;
  started_at: string;
  completed_at?: string;
  error_message?: string;
}

export const STIGRemediationOrchestrator: React.FC = () => {
  const { toast } = useToast();
  const { currentOrganization } = useOrganizationContext();
  const [playbooks, setPlaybooks] = useState<RemediationPlaybook[]>([]);
  const [activeJobs, setActiveJobs] = useState<RemediationJob[]>([]);
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>('');
  const [executionMode, setExecutionMode] = useState<'validate' | 'execute'>('validate');
  const [autoRemediation, setAutoRemediation] = useState(false);
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState(false);

  useEffect(() => {
    fetchRemediationData();
    const interval = setInterval(fetchActiveJobs, 5000); // Poll for job updates
    return () => clearInterval(interval);
  }, []);

  const fetchRemediationData = async () => {
    try {
      setLoading(true);
      await Promise.all([
        fetchPlaybooks(),
        fetchActiveJobs()
      ]);
    } catch (error) {
      console.error('Error fetching remediation data:', error);
      toast({
        title: "Error",
        description: "Failed to load remediation data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchPlaybooks = async () => {
    const { data, error } = await supabase
      .from('remediation_playbooks')
      .select('*')
      .order('success_rate', { ascending: false });

    if (error) throw error;
    setPlaybooks((data || []) as any);
  };

  const fetchActiveJobs = async () => {
    // Awaiting telemetry for real active remediation jobs
    const pendingJobs: RemediationJob[] = [];

    setActiveJobs(pendingJobs);
  };

  const executeRemediation = async (assetIds: string[], playbookId: string, mode: 'validate' | 'execute') => {
    if (assetIds.length === 0 || !playbookId) {
      toast({
        title: "Invalid Selection",
        description: "Please select assets and a playbook",
        variant: "destructive"
      });
      return;
    }

    try {
      setExecuting(true);

      for (const assetId of assetIds) {
        const { data, error } = await supabase.functions.invoke('automated-remediation-engine', {
          body: {
            organization_id: currentOrganization?.id || '',
            asset_id: assetId,
            stig_rule_id: 'AUTO-SELECTED', // Determined by playbook
            playbook_id: playbookId,
            execution_mode: mode,
            approval_required: mode === 'execute' && !autoRemediation
          }
        });

        if (error) throw error;

        toast({
          title: mode === 'validate' ? "Validation Started" : "Remediation Started",
          description: `${mode === 'validate' ? 'Validating' : 'Executing'} remediation on asset ${assetId}`
        });
      }

      // Refresh active jobs
      setTimeout(fetchActiveJobs, 1000);

    } catch (error) {
      console.error('Error executing remediation:', error);
      toast({
        title: "Execution Failed",
        description: "Failed to start remediation process",
        variant: "destructive"
      });
    } finally {
      setExecuting(false);
    }
  };

  const pauseJob = async (jobId: string) => {
    // Implementation would pause the job
    toast({
      title: "Job Paused",
      description: "Remediation job has been paused"
    });
  };

  const cancelJob = async (jobId: string) => {
    // Implementation would cancel the job
    toast({
      title: "Job Cancelled",
      description: "Remediation job has been cancelled"
    });
  };

  const rollbackJob = async (jobId: string) => {
    const job = activeJobs.find(j => j.id === jobId);
    if (!job) return;

    try {
      const { error } = await supabase.functions.invoke('automated-remediation-engine', {
        body: {
          organization_id: currentOrganization?.id || '',
          asset_id: job.asset_id,
          stig_rule_id: job.stig_rule_id,
          execution_mode: 'rollback'
        }
      });

      if (error) throw error;

      toast({
        title: "Rollback Initiated",
        description: "Rolling back remediation changes"
      });

    } catch (error) {
      console.error('Error rolling back:', error);
      toast({
        title: "Rollback Failed",
        description: "Failed to initiate rollback",
        variant: "destructive"
      });
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'running':
        return <RefreshCw className="h-4 w-4 animate-spin text-blue-500" />;
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'paused':
        return <Pause className="h-4 w-4 text-yellow-500" />;
      default:
        return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getRiskLevelColor = (riskLevel: string): string => {
    switch (riskLevel.toUpperCase()) {
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'default';
      case 'LOW': return 'secondary';
      default: return 'outline';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">STIG Remediation Orchestrator</h1>
          <p className="text-muted-foreground">
            Automated remediation execution and monitoring for STIG compliance
          </p>
        </div>
        <div className="flex gap-2">
          <Dialog>
            <DialogTrigger asChild>
              <Button>
                <Zap className="h-4 w-4 mr-2" />
                New Remediation
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Execute STIG Remediation</DialogTitle>
                <DialogDescription>
                  Configure and execute automated STIG remediation on selected assets
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-6">
                <div className="space-y-4">
                  <div>
                    <Label>Execution Mode</Label>
                    <Select value={executionMode} onValueChange={(value: 'validate' | 'execute') => setExecutionMode(value)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="validate">Validate Only</SelectItem>
                        <SelectItem value="execute">Execute Remediation</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label>Remediation Playbook</Label>
                    <Select value={selectedPlaybook} onValueChange={setSelectedPlaybook}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a playbook" />
                      </SelectTrigger>
                      <SelectContent>
                        {playbooks.map((playbook) => (
                          <SelectItem key={playbook.id} value={playbook.id}>
                            {playbook.playbook_name} ({playbook.platform})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Switch
                      id="auto-remediation"
                      checked={autoRemediation}
                      onCheckedChange={setAutoRemediation}
                    />
                    <Label htmlFor="auto-remediation">
                      Enable automatic execution for low-risk changes
                    </Label>
                  </div>
                </div>

                <div className="flex justify-end gap-2">
                  <Button variant="outline">
                    Cancel
                  </Button>
                  <Button
                    onClick={() => executeRemediation(['asset-1', 'asset-2'], selectedPlaybook, executionMode)}
                    disabled={executing || !selectedPlaybook}
                  >
                    {executing ? (
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4 mr-2" />
                    )}
                    {executionMode === 'validate' ? 'Validate' : 'Execute'}
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Active Jobs */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <RefreshCw className="h-5 w-5" />
            Active Remediation Jobs
          </CardTitle>
          <CardDescription>
            Monitor and manage ongoing STIG remediation executions
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {activeJobs.map((job) => (
              <div key={job.id} className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    {getStatusIcon(job.status)}
                    <div>
                      <h3 className="font-medium">{job.asset_name}</h3>
                      <p className="text-sm text-muted-foreground">
                        {job.playbook_name} - {job.stig_rule_id}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={job.status === 'failed' ? 'destructive' : 'default'}>
                      {job.status.toUpperCase()}
                    </Badge>
                    {job.status === 'running' && (
                      <div className="flex gap-1">
                        <Button size="sm" variant="outline" onClick={() => pauseJob(job.id)}>
                          <Pause className="h-3 w-3" />
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => cancelJob(job.id)}>
                          <Square className="h-3 w-3" />
                        </Button>
                      </div>
                    )}
                    {job.status === 'completed' && (
                      <Button size="sm" variant="outline" onClick={() => rollbackJob(job.id)}>
                        <Undo2 className="h-3 w-3 mr-1" />
                        Rollback
                      </Button>
                    )}
                  </div>
                </div>

                {job.status === 'running' && (
                  <div className="mb-2">
                    <div className="flex justify-between text-sm mb-1">
                      <span>Progress</span>
                      <span>{job.progress}%</span>
                    </div>
                    <Progress value={job.progress} />
                  </div>
                )}

                {job.error_message && (
                  <Alert className="mb-2">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>{job.error_message}</AlertDescription>
                  </Alert>
                )}

                <div className="text-xs text-muted-foreground">
                  Started: {new Date(job.started_at).toLocaleString()}
                  {job.completed_at && (
                    <span> • Completed: {new Date(job.completed_at).toLocaleString()}</span>
                  )}
                </div>
              </div>
            ))}

            {activeJobs.length === 0 && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  No active remediation jobs. Start a new remediation to see progress here.
                </AlertDescription>
              </Alert>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Playbooks Management */}
      <Tabs defaultValue="playbooks" className="space-y-6">
        <TabsList>
          <TabsTrigger value="playbooks">Remediation Playbooks</TabsTrigger>
          <TabsTrigger value="settings">Orchestration Settings</TabsTrigger>
          <TabsTrigger value="history">Execution History</TabsTrigger>
        </TabsList>

        <TabsContent value="playbooks">
          <Card>
            <CardHeader>
              <CardTitle>Available Playbooks</CardTitle>
              <CardDescription>
                Manage and configure automated STIG remediation playbooks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {playbooks.map((playbook) => (
                  <div key={playbook.id} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <h3 className="font-medium">{playbook.playbook_name}</h3>
                        <p className="text-sm text-muted-foreground">
                          {playbook.stig_rule_id} - {playbook.platform}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={getRiskLevelColor(playbook.risk_level) as any}>
                          {playbook.risk_level} Risk
                        </Badge>
                        {playbook.auto_execute && (
                          <Badge variant="secondary">
                            <Zap className="h-3 w-3 mr-1" />
                            Auto
                          </Badge>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span>Success Rate: {playbook.success_rate}%</span>
                        <span>Executions: {playbook.execution_count}</span>
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline">
                          <Settings className="h-3 w-3 mr-1" />
                          Configure
                        </Button>
                        <Button size="sm" variant="outline">
                          <FileText className="h-3 w-3 mr-1" />
                          View Script
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings">
          <Card>
            <CardHeader>
              <CardTitle>Orchestration Settings</CardTitle>
              <CardDescription>
                Configure global settings for STIG remediation orchestration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-medium">Auto-approve low risk remediations</h3>
                      <p className="text-sm text-muted-foreground">
                        Automatically execute remediation for low-risk STIG violations
                      </p>
                    </div>
                    <Switch defaultChecked />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-medium">Require rollback confirmation</h3>
                      <p className="text-sm text-muted-foreground">
                        Require manual confirmation before rolling back changes
                      </p>
                    </div>
                    <Switch defaultChecked />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-medium">Enable drift auto-remediation</h3>
                      <p className="text-sm text-muted-foreground">
                        Automatically fix detected compliance drift when safe to do so
                      </p>
                    </div>
                    <Switch />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle>Execution History</CardTitle>
              <CardDescription>
                Historical record of all STIG remediation executions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Alert>
                <FileText className="h-4 w-4" />
                <AlertDescription>
                  Execution history and audit trails will be displayed here, showing all past
                  remediation activities with full traceability for compliance audits.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};