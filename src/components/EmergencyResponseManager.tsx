import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  AlertTriangle, Shield, RotateCcw, CheckCircle, Clock, 
  Activity, Zap, Eye, PlayCircle, StopCircle
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { formatDistanceToNow } from 'date-fns';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from '@/hooks/useOrganization';

interface EmergencyAction {
  id: string;
  action_type: string;
  targets: any; // Json type from Supabase
  execution_status: string;
  results: any; // Json type from Supabase
  executed_at: string;
  successful_actions: number;
  total_actions: number;
  success_rate: number;
}

interface SecurityAlert {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  created_at: string;
  metadata: any; // Json type from Supabase
}

export const EmergencyResponseManager = () => {
  const [emergencyActions, setEmergencyActions] = useState<EmergencyAction[]>([]);
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();
  const { currentOrganization } = useOrganization();

  useEffect(() => {
    if (currentOrganization) {
      fetchEmergencyData();
    }
  }, [currentOrganization]);

  const fetchEmergencyData = async () => {
    if (!currentOrganization) return;
    
    try {
      setLoading(true);
      
      // Fetch emergency remediation actions
      const { data: actions, error: actionsError } = await supabase
        .from('remediation_activities')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .eq('execution_status', 'COMPLETED')
        .order('executed_at', { ascending: false })
        .limit(20);

      if (actionsError) throw actionsError;

      // Filter for emergency actions
      const emergencyActions = actions?.filter(action => {
        const results = action.results as any;
        return results?.emergency_execution === true;
      }) || [];

      setEmergencyActions(emergencyActions);

      // Fetch autonomous action alerts
      const { data: alerts, error: alertsError } = await supabase
        .from('alerts')
        .select('*')
        .eq('organization_id', currentOrganization.id)
        .eq('alert_type', 'autonomous_action')
        .order('created_at', { ascending: false })
        .limit(15);

      if (alertsError) throw alertsError;
      setSecurityAlerts(alerts || []);

    } catch (error) {
      console.error('Error fetching emergency data:', error);
      toast({
        title: "Error Loading Data",
        description: "Failed to load emergency response data.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const executeRollback = async (actionId: string) => {
    const action = emergencyActions.find(a => a.id === actionId);
    const results = action?.results as any;
    
    if (!action || !results?.rollback_script) {
      toast({
        title: "Rollback Not Available",
        description: "No rollback script available for this action.",
        variant: "destructive"
      });
      return;
    }

    try {
      // Call automated remediation with rollback script
      const { data, error } = await supabase.functions.invoke('automated-remediation', {
        body: {
          action: 'rollback_action',
          targets: Array.isArray(action.targets) ? action.targets : [action.targets],
          organizationId: currentOrganization?.id,
          dry_run: false,
          script: results.rollback_script,
          rollback_mode: true,
          original_action_id: actionId
        }
      });

      if (error) {
        throw error;
      }

      // Update the action status to indicate rollback
      await supabase
        .from('remediation_activities')
        .update({
          execution_status: 'ROLLED_BACK',
          results: {
            ...results,
            rolled_back_at: new Date().toISOString(),
            rollback_result: data
          }
        })
        .eq('id', actionId);

      // Create rollback alert
      await supabase.from('alerts').insert([{
        organization_id: currentOrganization?.id,
        alert_type: 'rollback_completed',
        title: '🔄 Emergency Action Rolled Back',
        description: `Successfully rolled back ${action.action_type} action on ${Array.isArray(action.targets) ? action.targets.join(', ') : action.targets}`,
        severity: 'MEDIUM',
        status: 'OPEN',
        source_type: 'ROLLBACK_SYSTEM',
        metadata: {
          original_action_id: actionId,
          rollback_targets: Array.isArray(action.targets) ? action.targets : [action.targets],
          rollback_success: true
        }
      }]);

      toast({
        title: "Rollback Successful",
        description: `Successfully rolled back ${action.action_type} action.`,
        variant: "default"
      });

      // Refresh data
      fetchEmergencyData();

    } catch (error) {
      console.error('Rollback failed:', error);
      toast({
        title: "Rollback Failed",
        description: `Failed to rollback action: ${error.message}`,
        variant: "destructive"
      });
    }
  };

  const getActionStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED': return 'bg-success text-success-foreground';
      case 'ROLLED_BACK': return 'bg-warning text-warning-foreground';
      case 'FAILED': return 'bg-destructive text-destructive-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-destructive text-destructive-foreground';
      case 'HIGH': return 'bg-orange-500 text-white';
      case 'MEDIUM': return 'bg-warning text-warning-foreground';
      case 'LOW': return 'bg-success text-success-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getActionIcon = (actionType: string) => {
    switch (actionType) {
      case 'network_isolation': return <Shield className="h-4 w-4" />;
      case 'endpoint_isolation': return <StopCircle className="h-4 w-4" />;
      case 'patch_management': return <Activity className="h-4 w-4" />;
      case 'configuration_hardening': return <PlayCircle className="h-4 w-4" />;
      default: return <Zap className="h-4 w-4" />;
    }
  };

  if (loading) {
    return (
      <Card className="card-cyber">
        <CardContent className="p-6">
          <div className="text-center text-muted-foreground">Loading emergency response data...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Emergency Status Overview */}
      <Alert className="border-destructive/50 bg-destructive/10">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription className="text-foreground">
          <strong>Emergency Response System Active:</strong> ARGUS AI is configured for autonomous high-risk action execution. 
          All emergency actions are logged and can be rolled back if needed.
        </AlertDescription>
      </Alert>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Emergency Actions</p>
                <p className="text-2xl font-bold text-destructive">{emergencyActions.length}</p>
              </div>
              <Zap className="h-8 w-8 text-destructive" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Alerts</p>
                <p className="text-2xl font-bold text-warning">{securityAlerts.filter(a => a.status === 'OPEN').length}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-warning" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Rollbacks Available</p>
                <p className="text-2xl font-bold text-success">
                  {emergencyActions.filter(a => {
                    const results = a.results as any;
                    return results?.rollback_script && a.execution_status === 'COMPLETED';
                  }).length}
                </p>
              </div>
              <RotateCcw className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Success Rate</p>
                <p className="text-2xl font-bold text-primary">
                  {emergencyActions.length > 0 
                    ? Math.round(emergencyActions.reduce((sum, a) => sum + a.success_rate, 0) / emergencyActions.length)
                    : 0}%
                </p>
              </div>
              <CheckCircle className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="actions" className="space-y-4">
        <TabsList className="bg-card border border-border">
          <TabsTrigger value="actions">Emergency Actions</TabsTrigger>
          <TabsTrigger value="alerts">Security Alerts</TabsTrigger>
          <TabsTrigger value="monitoring">Live Monitoring</TabsTrigger>
        </TabsList>

        <TabsContent value="actions" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Zap className="h-5 w-5 text-destructive" />
                <span>Autonomous Emergency Actions</span>
              </CardTitle>
              <CardDescription>
                High-risk actions automatically executed by ARGUS AI
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {emergencyActions.length > 0 ? (
                  emergencyActions.map((action) => (
                    <div
                      key={action.id}
                      className="p-4 border border-border rounded-lg bg-card hover:bg-accent/30 transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-2">
                            {getActionIcon(action.action_type)}
                            <h4 className="font-medium text-foreground">{action.action_type.replaceAll('_', ' ').toUpperCase()}</h4>
                            <Badge className={getActionStatusBadge(action.execution_status)}>
                              {action.execution_status}
                            </Badge>
                            <Badge variant="outline" className="bg-destructive/20 text-destructive border-destructive">
                              EMERGENCY
                            </Badge>
                          </div>
                          
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-muted-foreground mb-3">
                            <span>Targets: {Array.isArray(action.targets) ? action.targets.join(', ') : action.targets}</span>
                            <span>Success Rate: {action.success_rate}%</span>
                            <span>Actions: {action.successful_actions}/{action.total_actions}</span>
                            <span>Executed: {formatDistanceToNow(new Date(action.executed_at), { addSuffix: true })}</span>
                          </div>

                          {(action.results as any)?.rollback_script && (
                            <div className="text-xs bg-muted/50 p-2 rounded border">
                              <strong>Rollback Available:</strong> This action can be automatically reversed
                            </div>
                          )}
                        </div>
                        
                        <div className="flex items-center space-x-2 ml-4">
                          {(action.results as any)?.rollback_script && action.execution_status === 'COMPLETED' && (
                            <Button 
                              variant="outline" 
                              size="sm"
                              onClick={() => executeRollback(action.id)}
                              className="border-warning text-warning hover:bg-warning hover:text-warning-foreground"
                            >
                              <RotateCcw className="h-3 w-3 mr-1" />
                              Rollback
                            </Button>
                          )}
                          <Button variant="outline" size="sm">
                            <Eye className="h-3 w-3 mr-1" />
                            Details
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center text-muted-foreground py-8">
                    <Zap className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No emergency actions executed yet</p>
                    <p className="text-xs mt-1">ARGUS will automatically execute high-risk actions when threats are detected</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5 text-warning" />
                <span>Autonomous Action Alerts</span>
              </CardTitle>
              <CardDescription>
                Real-time notifications for AI-executed security actions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {securityAlerts.length > 0 ? (
                  securityAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="p-3 border border-border rounded-lg bg-card hover:bg-accent/30 transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            <Badge className={getSeverityBadge(alert.severity)}>
                              {alert.severity}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                            </span>
                          </div>
                          <h4 className="font-medium text-foreground mb-1">{alert.title}</h4>
                          <p className="text-sm text-muted-foreground">{alert.description}</p>
                          
                          {(alert.metadata as any)?.targets && (
                            <div className="text-xs text-muted-foreground mt-2">
                              Targets: {Array.isArray((alert.metadata as any).targets) 
                                ? (alert.metadata as any).targets.join(', ') 
                                : (alert.metadata as any).targets}
                            </div>
                          )}
                        </div>
                        
                        <Badge variant="outline" className={
                          alert.status === 'OPEN' ? 'border-warning text-warning' : 'border-success text-success'
                        }>
                          {alert.status}
                        </Badge>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center text-muted-foreground py-8">
                    <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No autonomous action alerts</p>
                    <p className="text-xs mt-1">Alerts will appear when ARGUS executes emergency actions</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Activity className="h-5 w-5 text-primary" />
                <span>Live Emergency Response Monitoring</span>
              </CardTitle>
              <CardDescription>
                Real-time monitoring of autonomous security actions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Alert className="border-primary/50 bg-primary/10">
                  <Activity className="h-4 w-4" />
                  <AlertDescription className="text-foreground">
                    <strong>ARGUS Autonomous Mode:</strong> AI agent is actively monitoring for threats and will execute emergency actions automatically.
                  </AlertDescription>
                </Alert>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-muted/30 rounded-lg border border-border">
                    <h4 className="font-medium text-foreground mb-2">Threat Detection</h4>
                    <div className="text-xs text-muted-foreground space-y-1">
                      <div className="flex justify-between">
                        <span>• Network monitoring</span>
                        <span className="text-success">Active</span>
                      </div>
                      <div className="flex justify-between">
                        <span>• Behavioral analysis</span>
                        <span className="text-success">Active</span>
                      </div>
                      <div className="flex justify-between">
                        <span>• Threat intelligence</span>
                        <span className="text-success">Active</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-4 bg-muted/30 rounded-lg border border-border">
                    <h4 className="font-medium text-foreground mb-2">Response Capabilities</h4>
                    <div className="text-xs text-muted-foreground space-y-1">
                      <div className="flex justify-between">
                        <span>• Network isolation</span>
                        <span className="text-warning">Emergency</span>
                      </div>
                      <div className="flex justify-between">
                        <span>• Endpoint quarantine</span>
                        <span className="text-warning">Emergency</span>
                      </div>
                      <div className="flex justify-between">
                        <span>• Critical patching</span>
                        <span className="text-warning">Emergency</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};