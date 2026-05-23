import { useState, useEffect } from 'react';
import { useOrganizationContext } from "@/components/OrganizationProvider";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { Plus, Edit, Trash2, Play, Pause, Settings, Zap, Shield, AlertTriangle, CheckCircle, Activity } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";

interface RemediationWorkflow {
  id: string;
  workflow_name: string;
  workflow_type: string;
  trigger_conditions: any;
  remediation_steps: any;
  target_stig_rules: any;
  target_platforms: any;
  approval_required: boolean;
  risk_level: string;
  success_rate: number;
  execution_count: number;
  last_execution?: string;
  is_active: boolean;
}

interface RemediationExecution {
  id: string;
  workflow_id: string;
  asset_id: string;
  stig_rule_id: string;
  execution_status: string;
  started_at: string;
  completed_at?: string;
  execution_duration_seconds?: number;
  error_message?: string;
}

export const RemediationWorkflowBuilder = () => {
  const [workflows, setWorkflows] = useState<RemediationWorkflow[]>([]);
  const [executions, setExecutions] = useState<RemediationExecution[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingWorkflow, setEditingWorkflow] = useState<RemediationWorkflow | null>(null);
  const [activeTab, setActiveTab] = useState('workflows');
  const { currentOrganization } = useOrganizationContext();
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    workflow_name: '',
    workflow_type: 'automated',
    trigger_conditions: {},
    remediation_steps: [],
    target_stig_rules: [],
    target_platforms: [],
    approval_required: false,
    risk_level: 'medium'
  });

  useEffect(() => {
    if (currentOrganization?.id) {
      fetchWorkflows();
      fetchExecutions();
    }
  }, [currentOrganization?.id]);

  const fetchWorkflows = async () => {
    try {
      const { data, error } = await supabase
        .from('stig_remediation_workflows')
        .select('*')
        .eq('organization_id', currentOrganization?.id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setWorkflows(data || []);
    } catch (error) {
      console.error('Error fetching workflows:', error);
    }
  };

  const fetchExecutions = async () => {
    try {
      const { data, error } = await supabase
        .from('stig_remediation_executions')
        .select('*')
        .eq('organization_id', currentOrganization?.id)
        .order('started_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      setExecutions(data || []);
    } catch (error) {
      console.error('Error fetching executions:', error);
    } finally {
      setLoading(false);
    }
  };

  const createWorkflow = async () => {
    try {
      const { data, error } = await supabase
        .from('stig_remediation_workflows')
        .insert([{
          ...formData,
          organization_id: currentOrganization?.id,
          trigger_conditions: JSON.stringify(formData.trigger_conditions),
          remediation_steps: JSON.stringify(formData.remediation_steps),
          target_stig_rules: JSON.stringify(formData.target_stig_rules),
          target_platforms: JSON.stringify(formData.target_platforms)
        }])
        .select()
        .single();

      if (error) throw error;

      setWorkflows([data, ...workflows]);
      setShowCreateDialog(false);
      resetForm();
      toast({
        title: "Workflow Created",
        description: "Remediation workflow has been created successfully."
      });
    } catch (error) {
      console.error('Error creating workflow:', error);
      toast({
        title: "Error",
        description: "Failed to create workflow.",
        variant: "destructive"
      });
    }
  };

  const toggleWorkflow = async (workflowId: string, isActive: boolean) => {
    try {
      const { error } = await supabase
        .from('stig_remediation_workflows')
        .update({ is_active: !isActive })
        .eq('id', workflowId);

      if (error) throw error;

      setWorkflows(workflows.map(w => 
        w.id === workflowId ? { ...w, is_active: !isActive } : w
      ));

      toast({
        title: `Workflow ${!isActive ? 'Activated' : 'Deactivated'}`,
        description: `Workflow has been ${!isActive ? 'activated' : 'deactivated'} successfully.`
      });
    } catch (error) {
      console.error('Error toggling workflow:', error);
    }
  };

  const executeWorkflow = async (workflowId: string) => {
    try {
      const { data, error } = await supabase.functions.invoke('stig-intelligence-orchestrator', {
        body: {
          action: 'execute_remediation_workflow',
          workflow_id: workflowId,
          organization_id: currentOrganization?.id
        }
      });

      if (error) throw error;

      toast({
        title: "Workflow Execution Started",
        description: "Remediation workflow is now executing."
      });

      // Refresh executions
      fetchExecutions();
    } catch (error) {
      console.error('Error executing workflow:', error);
      toast({
        title: "Error",
        description: "Failed to execute workflow.",
        variant: "destructive"
      });
    }
  };

  const resetForm = () => {
    setFormData({
      workflow_name: '',
      workflow_type: 'automated',
      trigger_conditions: {},
      remediation_steps: [],
      target_stig_rules: [],
      target_platforms: [],
      approval_required: false,
      risk_level: 'medium'
    });
    setEditingWorkflow(null);
  };

  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'running': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'failed': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'pending': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-white">Loading remediation workflows...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Remediation Workflows</h2>
          <p className="text-gray-300">Automated STIG compliance remediation</p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="bg-gradient-to-r from-cyan-500 to-blue-500">
              <Plus className="h-4 w-4 mr-2" />
              Create Workflow
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Create Remediation Workflow</DialogTitle>
              <DialogDescription>
                Define an automated workflow to remediate STIG compliance issues
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="workflow_name">Workflow Name</Label>
                  <Input
                    id="workflow_name"
                    value={formData.workflow_name}
                    onChange={(e) => setFormData({...formData, workflow_name: e.target.value})}
                    placeholder="Enter workflow name"
                  />
                </div>
                <div>
                  <Label htmlFor="workflow_type">Type</Label>
                  <Select value={formData.workflow_type} onValueChange={(value) => setFormData({...formData, workflow_type: value})}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="automated">Fully Automated</SelectItem>
                      <SelectItem value="semi_automated">Semi-Automated</SelectItem>
                      <SelectItem value="manual">Manual</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              <div>
                <Label htmlFor="risk_level">Risk Level</Label>
                <Select value={formData.risk_level} onValueChange={(value) => setFormData({...formData, risk_level: value})}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low Risk</SelectItem>
                    <SelectItem value="medium">Medium Risk</SelectItem>
                    <SelectItem value="high">High Risk</SelectItem>
                    <SelectItem value="critical">Critical Risk</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center space-x-2">
                <Switch
                  id="approval_required"
                  checked={formData.approval_required}
                  onCheckedChange={(checked) => setFormData({...formData, approval_required: checked})}
                />
                <Label htmlFor="approval_required">Require Manual Approval</Label>
              </div>

              <div className="flex justify-end space-x-2">
                <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
                  Cancel
                </Button>
                <Button onClick={createWorkflow}>
                  Create Workflow
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Total Workflows</CardTitle>
              <Zap className="h-4 w-4 text-cyan-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{workflows.length}</div>
            <p className="text-xs text-gray-400">{workflows.filter(w => w.is_active).length} active</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Success Rate</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {workflows.length > 0 ? 
                (workflows.reduce((sum, w) => sum + w.success_rate, 0) / workflows.length).toFixed(1) :
                0
              }%
            </div>
            <p className="text-xs text-gray-400">Average success rate</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Total Executions</CardTitle>
              <Play className="h-4 w-4 text-blue-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {workflows.reduce((sum, w) => sum + w.execution_count, 0)}
            </div>
            <p className="text-xs text-gray-400">All time executions</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">Running Now</CardTitle>
              <Activity className="h-4 w-4 text-orange-400" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {executions.filter(e => e.execution_status === 'running').length}
            </div>
            <p className="text-xs text-gray-400">Active executions</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-slate-800/50 border border-slate-700">
          <TabsTrigger value="workflows">Workflows</TabsTrigger>
          <TabsTrigger value="executions">Executions</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
        </TabsList>

        <TabsContent value="workflows" className="space-y-4">
          <div className="grid gap-4">
            {workflows.map((workflow) => (
              <Card key={workflow.id} className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="space-y-2">
                      <div className="flex items-center space-x-3">
                        <h3 className="font-semibold text-white">{workflow.workflow_name}</h3>
                        <Badge variant="outline" className={getRiskLevelColor(workflow.risk_level)}>
                          {workflow.risk_level}
                        </Badge>
                        <Badge variant={workflow.is_active ? "default" : "secondary"}>
                          {workflow.is_active ? "Active" : "Inactive"}
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-4 text-sm text-gray-400">
                        <span>Type: {workflow.workflow_type}</span>
                        <span>Success Rate: {workflow.success_rate}%</span>
                        <span>Executions: {workflow.execution_count}</span>
                        {workflow.last_execution && (
                          <span>Last Run: {new Date(workflow.last_execution).toLocaleString()}</span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => executeWorkflow(workflow.id)}
                        disabled={!workflow.is_active}
                      >
                        <Play className="h-4 w-4 mr-1" />
                        Execute
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => toggleWorkflow(workflow.id, workflow.is_active)}
                      >
                        {workflow.is_active ? (
                          <Pause className="h-4 w-4 mr-1" />
                        ) : (
                          <Play className="h-4 w-4 mr-1" />
                        )}
                        {workflow.is_active ? 'Pause' : 'Activate'}
                      </Button>
                      <Button size="sm" variant="outline">
                        <Settings className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="executions" className="space-y-4">
          <div className="grid gap-4">
            {executions.map((execution) => (
              <Card key={execution.id} className="bg-slate-800/50 border-slate-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="space-y-2">
                      <div className="flex items-center space-x-3">
                        <h4 className="font-medium text-white">
                          {workflows.find(w => w.id === execution.workflow_id)?.workflow_name || 'Unknown Workflow'}
                        </h4>
                        <Badge variant="outline" className={getStatusColor(execution.execution_status)}>
                          {execution.execution_status}
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-4 text-sm text-gray-400">
                        <span>STIG Rule: {execution.stig_rule_id}</span>
                        <span>Started: {new Date(execution.started_at).toLocaleString()}</span>
                        {execution.execution_duration_seconds && (
                          <span>Duration: {execution.execution_duration_seconds}s</span>
                        )}
                      </div>
                      {execution.error_message && (
                        <p className="text-sm text-red-400">{execution.error_message}</p>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="templates" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <Card className="bg-slate-800/50 border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-white">Windows Security Configuration</CardTitle>
                <CardDescription>Automated Windows STIG compliance remediation</CardDescription>
              </CardHeader>
              <CardContent>
                <Badge variant="outline" className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                  Template
                </Badge>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-white">Linux Hardening</CardTitle>
                <CardDescription>RHEL/CentOS STIG compliance automation</CardDescription>
              </CardHeader>
              <CardContent>
                <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30">
                  Template
                </Badge>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-white">Network Device Configuration</CardTitle>
                <CardDescription>Cisco IOS STIG compliance workflow</CardDescription>
              </CardHeader>
              <CardContent>
                <Badge variant="outline" className="bg-purple-500/20 text-purple-400 border-purple-500/30">
                  Template
                </Badge>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};