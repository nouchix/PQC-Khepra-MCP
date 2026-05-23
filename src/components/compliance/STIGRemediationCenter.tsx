import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Wrench, 
  Play, 
  Clock, 
  CheckCircle, 
  AlertTriangle, 
  Shield,
  Settings,
  Zap,
  Target
} from 'lucide-react';
import { STIGFinding } from '@/hooks/useSTIGCompliance';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface STIGRemediationCenterProps {
  findings: STIGFinding[];
  organizationId: string;
  onRefresh: () => void;
}

interface RemediationAction {
  id: string;
  rule_id: string;
  action_name: string;
  description: string;
  action_type: 'script' | 'policy' | 'configuration' | 'manual';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  estimated_duration_minutes: number;
  automation_enabled: boolean;
  requires_reboot: boolean;
}

interface RemediationExecution {
  id: string;
  finding_id: string;
  action_id: string;
  execution_status: 'pending' | 'running' | 'success' | 'failed' | 'rolled_back';
  initiated_at: string;
  completed_at?: string;
  execution_log?: string;
  error_message?: string;
}

export const STIGRemediationCenter: React.FC<STIGRemediationCenterProps> = ({
  findings,
  organizationId,
  onRefresh
}) => {
  const [loading, setLoading] = useState(false);
  const [actions, setActions] = useState<RemediationAction[]>([]);
  const [executions, setExecutions] = useState<RemediationExecution[]>([]);
  const [selectedFindings, setSelectedFindings] = useState<string[]>([]);
  const [remediationProgress, setRemediationProgress] = useState<{ [key: string]: number }>({});
  const { toast } = useToast();

  useEffect(() => {
    fetchRemediationActions();
    fetchRemediationExecutions();
  }, [organizationId]);

  const fetchRemediationActions = async () => {
    try {
      setLoading(true);
      // Use edge function to get remediation actions
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'get_remediation_actions',
          organization_id: organizationId
        }
      });

      if (error) throw error;
      setActions(data?.actions || []);
    } catch (err) {
      console.error('Error fetching remediation actions:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchRemediationExecutions = async () => {
    try {
      // Use edge function to get remediation executions
      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'get_remediation_executions',
          organization_id: organizationId
        }
      });

      if (error) throw error;
      setExecutions(data?.executions || []);
    } catch (err) {
      console.error('Error fetching executions:', err);
    }
  };

  const executeRemediation = async (findingId: string, actionType: 'immediate' | 'scheduled' | 'manual_approval' = 'immediate') => {
    try {
      setLoading(true);
      setRemediationProgress(prev => ({ ...prev, [findingId]: 0 }));

      // Simulate progress
      const progressInterval = setInterval(() => {
        setRemediationProgress(prev => ({
          ...prev,
          [findingId]: Math.min((prev[findingId] || 0) + 10, 90)
        }));
      }, 500);

      const { data, error } = await supabase.functions.invoke('stig-compliance-orchestrator', {
        body: {
          action: 'remediate',
          finding_id: findingId,
          organization_id: organizationId,
          action_type: actionType
        }
      });

      clearInterval(progressInterval);

      if (error) throw error;

      setRemediationProgress(prev => ({ ...prev, [findingId]: 100 }));

      toast({
        title: data.success ? "Remediation Successful" : "Remediation Failed",
        description: data.message,
        variant: data.success ? "default" : "destructive"
      });

      // Refresh data
      await Promise.all([fetchRemediationExecutions(), onRefresh()]);

      // Clear progress after a delay
      setTimeout(() => {
        setRemediationProgress(prev => {
          const newProgress = { ...prev };
          delete newProgress[findingId];
          return newProgress;
        });
      }, 3000);

    } catch (err) {
      console.error('Error executing remediation:', err);
      toast({
        title: "Remediation Failed",
        description: "Failed to execute automated remediation",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const executeBulkRemediation = async () => {
    if (selectedFindings.length === 0) {
      toast({
        title: "No Selection",
        description: "Please select findings to remediate",
        variant: "destructive"
      });
      return;
    }

    try {
      setLoading(true);
      const promises = selectedFindings.map(findingId => executeRemediation(findingId, 'immediate'));
      await Promise.all(promises);
      setSelectedFindings([]);
    } catch (err) {
      console.error('Error executing bulk remediation:', err);
    } finally {
      setLoading(false);
    }
  };

  const criticalFindings = findings.filter(f => f.severity === 'CAT_I' && f.finding_status === 'Open');
  const highFindings = findings.filter(f => f.severity === 'CAT_II' && f.finding_status === 'Open');
  const mediumFindings = findings.filter(f => f.severity === 'CAT_III' && f.finding_status === 'Open');

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CAT_I': return 'hsl(var(--destructive))';
      case 'CAT_II': return 'hsl(var(--warning))';
      case 'CAT_III': return 'hsl(var(--primary))';
      default: return 'hsl(var(--muted))';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'running': return <Clock className="h-4 w-4 text-blue-500" />;
      case 'pending': return <Clock className="h-4 w-4 text-yellow-500" />;
      default: return <Shield className="h-4 w-4 text-gray-500" />;
    }
  };

  const recentExecutions = executions.slice(0, 10);

  return (
    <div className="space-y-6">
      {/* Control Panel */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Wrench className="h-5 w-5" />
            STIG Remediation Control Center
          </CardTitle>
          <CardDescription>
            Automated and manual remediation actions for STIG compliance violations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <Card className="border-red-200 bg-red-50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-red-900">Critical (CAT I)</p>
                    <p className="text-2xl font-bold text-red-700">{criticalFindings.length}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-500" />
                </div>
              </CardContent>
            </Card>
            
            <Card className="border-yellow-200 bg-yellow-50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-yellow-900">High (CAT II)</p>
                    <p className="text-2xl font-bold text-yellow-700">{highFindings.length}</p>
                  </div>
                  <Shield className="h-8 w-8 text-yellow-500" />
                </div>
              </CardContent>
            </Card>
            
            <Card className="border-blue-200 bg-blue-50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-blue-900">Medium (CAT III)</p>
                    <p className="text-2xl font-bold text-blue-700">{mediumFindings.length}</p>
                  </div>
                  <Settings className="h-8 w-8 text-blue-500" />
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="flex gap-2 mb-4">
            <Button 
              onClick={executeBulkRemediation}
              disabled={selectedFindings.length === 0 || loading}
              className="bg-hsl(var(--primary)) hover:bg-hsl(var(--primary))/90"
            >
              <Zap className="h-4 w-4 mr-2" />
              Remediate Selected ({selectedFindings.length})
            </Button>
            <Button variant="outline" onClick={fetchRemediationExecutions}>
              <Target className="h-4 w-4 mr-2" />
              Refresh Status
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="findings" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="findings">Active Findings</TabsTrigger>
          <TabsTrigger value="actions">Available Actions</TabsTrigger>
          <TabsTrigger value="history">Execution History</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Remediable Findings</CardTitle>
              <CardDescription>
                Select findings to apply automated remediation actions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {findings.filter(f => f.finding_status === 'Open').map((finding) => (
                  <div key={finding.id} className="flex items-center space-x-4 p-4 border rounded-lg">
                    <input
                      type="checkbox"
                      checked={selectedFindings.includes(finding.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedFindings([...selectedFindings, finding.id]);
                        } else {
                          setSelectedFindings(selectedFindings.filter(id => id !== finding.id));
                        }
                      }}
                      className="rounded"
                    />
                    
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge 
                          style={{ backgroundColor: getSeverityColor(finding.severity) }}
                          className="text-white"
                        >
                          {finding.severity}
                        </Badge>
                        <span className="font-medium">{finding.rule_id}</span>
                      </div>
                      
                      {remediationProgress[finding.id] !== undefined && (
                        <div className="mb-2">
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span>Remediation Progress</span>
                            <span>{remediationProgress[finding.id]}%</span>
                          </div>
                          <Progress value={remediationProgress[finding.id]} className="h-2" />
                        </div>
                      )}
                      
                      <p className="text-sm text-gray-600">
                        Asset: {finding.environment_assets?.asset_name} ({finding.environment_assets?.platform})
                      </p>
                    </div>
                    
                    <Button
                      size="sm"
                      onClick={() => executeRemediation(finding.id)}
                      disabled={loading || remediationProgress[finding.id] !== undefined}
                      className="bg-hsl(var(--primary)) hover:bg-hsl(var(--primary))/90"
                    >
                      <Play className="h-4 w-4 mr-1" />
                      Remediate
                    </Button>
                  </div>
                ))}
                
                {findings.filter(f => f.finding_status === 'Open').length === 0 && (
                  <Alert>
                    <CheckCircle className="h-4 w-4" />
                    <AlertDescription>
                      No open findings requiring remediation found.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="actions" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Remediation Actions Library</CardTitle>
              <CardDescription>
                Available automated remediation actions for STIG compliance
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {actions.length > 0 ? actions.map((action) => (
                  <div key={action.id} className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium">{action.action_name}</h4>
                      <div className="flex items-center gap-2">
                        <Badge variant={action.automation_enabled ? "default" : "secondary"}>
                          {action.automation_enabled ? "Automated" : "Manual"}
                        </Badge>
                        <Badge 
                          variant={action.risk_level === 'critical' ? "destructive" : 
                                  action.risk_level === 'high' ? "destructive" : "secondary"}
                        >
                          {action.risk_level}
                        </Badge>
                      </div>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{action.description}</p>
                    <div className="text-xs text-gray-500">
                      Duration: ~{action.estimated_duration_minutes}min | 
                      Reboot Required: {action.requires_reboot ? 'Yes' : 'No'}
                    </div>
                  </div>
                )) : (
                  <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      No remediation actions available. Actions will be loaded from the STIG rules database.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Remediation Execution History</CardTitle>
              <CardDescription>
                Recent automated remediation attempts and their status
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentExecutions.length > 0 ? recentExecutions.map((execution) => (
                  <div key={execution.id} className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(execution.execution_status)}
                        <span className="font-medium">Execution #{execution.id.slice(0, 8)}</span>
                      </div>
                      <Badge 
                        variant={execution.execution_status === 'success' ? "default" : 
                                execution.execution_status === 'failed' ? "destructive" : "secondary"}
                      >
                        {execution.execution_status}
                      </Badge>
                    </div>
                    <div className="text-sm text-gray-600">
                      <p>Finding: {execution.finding_id.slice(0, 8)}</p>
                      <p>Started: {new Date(execution.initiated_at).toLocaleString()}</p>
                      {execution.completed_at && (
                        <p>Completed: {new Date(execution.completed_at).toLocaleString()}</p>
                      )}
                      {execution.error_message && (
                        <p className="text-red-600 mt-2">Error: {execution.error_message}</p>
                      )}
                    </div>
                  </div>
                )) : (
                  <Alert>
                    <Clock className="h-4 w-4" />
                    <AlertDescription>
                      No remediation executions found. Start remediating findings to see history here.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};