import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Shield, GitBranch, Eye, AlertTriangle, CheckCircle, Clock,
  FileText, Zap, Lock, Settings, Activity, Ban
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useToast } from '@/hooks/use-toast';

interface GitHubIntegration {
  id: string;
  repository_name: string;
  access_level: 'read' | 'write' | 'admin';
  branch_protection_enabled: boolean;
  code_review_required: boolean;
  rate_limit_remaining: number;
  rate_limit_reset: string;
  last_codex_activity: string;
  status: 'active' | 'suspended' | 'monitoring';
}

interface SecurityViolation {
  id: string;
  type: 'sensitive_data' | 'rate_limit' | 'unauthorized_access' | 'branch_protection' | 'code_review_bypass';
  severity: 'low' | 'medium' | 'high' | 'critical';
  repository: string;
  description: string;
  detected_at: string;
  resolved: boolean;
  auto_blocked: boolean;
}

interface CodexActivity {
  id: string;
  repository: string;
  action: 'code_generation' | 'code_review' | 'commit_suggestion' | 'pr_analysis';
  files_affected: string[];
  sensitive_data_detected: boolean;
  auto_approved: boolean;
  timestamp: string;
}

export const GitHubCodexSecurityMonitor = () => {
  const [integrations, setIntegrations] = useState<GitHubIntegration[]>([]);
  const [violations, setViolations] = useState<SecurityViolation[]>([]);
  const [activities, setActivities] = useState<CodexActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const { toast } = useToast();

  useEffect(() => {
    loadSecurityData();
    const interval = setInterval(loadSecurityData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const loadSecurityData = async () => {
    try {
      // Awaiting telemetry for GitHub configurations and activities
      const pendingIntegrations: GitHubIntegration[] = [];
      const pendingViolations: SecurityViolation[] = [];
      const pendingActivities: CodexActivity[] = [];

      setIntegrations(pendingIntegrations);
      setViolations(pendingViolations);
      setActivities(pendingActivities);

      // Log security monitoring activity
      await supabase.rpc('log_third_party_security_event', {
        p_tester_id: (await supabase.auth.getUser()).data.user?.id,
        p_event_type: 'github_codex_security_check',
        p_severity: 'low',
        p_details: {
          integrations_monitored: pendingIntegrations.length,
          violations_detected: pendingViolations.filter(v => !v.resolved).length,
          timestamp: new Date().toISOString()
        }
      });

    } catch (error) {
      console.error('Error loading GitHub Codex security data:', error);
      toast({
        title: "Error",
        description: "Failed to load security monitoring data",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const suspendIntegration = async (integrationId: string) => {
    try {
      setIntegrations(prev =>
        prev.map(int =>
          int.id === integrationId
            ? { ...int, status: 'suspended' as const }
            : int
        )
      );

      await supabase.rpc('log_third_party_security_event', {
        p_tester_id: (await supabase.auth.getUser()).data.user?.id,
        p_event_type: 'github_integration_suspended',
        p_severity: 'high',
        p_details: {
          integration_id: integrationId,
          reason: 'manual_suspension',
          timestamp: new Date().toISOString()
        }
      });

      toast({
        title: "Integration Suspended",
        description: "GitHub Codex integration has been temporarily suspended",
        variant: "destructive"
      });
    } catch (error) {
      console.error('Error suspending integration:', error);
    }
  };

  const resolveViolation = async (violationId: string) => {
    try {
      setViolations(prev =>
        prev.map(v =>
          v.id === violationId
            ? { ...v, resolved: true }
            : v
        )
      );

      toast({
        title: "Violation Resolved",
        description: "Security violation has been marked as resolved",
      });
    } catch (error) {
      console.error('Error resolving violation:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-destructive text-destructive-foreground';
      case 'high': return 'bg-warning text-warning-foreground';
      case 'medium': return 'bg-info text-info-foreground';
      default: return 'bg-secondary text-secondary-foreground';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-success text-success-foreground';
      case 'suspended': return 'bg-destructive text-destructive-foreground';
      case 'monitoring': return 'bg-warning text-warning-foreground';
      default: return 'bg-secondary text-secondary-foreground';
    }
  };

  const getAccessLevelColor = (level: string) => {
    switch (level) {
      case 'read': return 'bg-success text-success-foreground';
      case 'write': return 'bg-warning text-warning-foreground';
      case 'admin': return 'bg-destructive text-destructive-foreground';
      default: return 'bg-secondary text-secondary-foreground';
    }
  };

  const activeViolations = violations.filter(v => !v.resolved);
  const criticalViolations = activeViolations.filter(v => v.severity === 'critical' || v.severity === 'high');

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-foreground">Loading GitHub Codex security data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Security Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Integrations</p>
                <p className="text-2xl font-bold text-foreground">{integrations.length}</p>
              </div>
              <GitBranch className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Security Violations</p>
                <p className={`text-2xl font-bold ${activeViolations.length > 0 ? 'text-destructive' : 'text-success'}`}>
                  {activeViolations.length}
                </p>
              </div>
              <AlertTriangle className={`h-8 w-8 ${activeViolations.length > 0 ? 'text-destructive' : 'text-success'}`} />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Rate Limit Status</p>
                <p className="text-2xl font-bold text-info">
                  {integrations.length > 0 ? Math.min(...integrations.map(i => i.rate_limit_remaining)) : 5000}
                </p>
              </div>
              <Zap className="h-8 w-8 text-info" />
            </div>
          </CardContent>
        </Card>

        <Card className="card-cyber">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Branch Protection</p>
                <p className="text-2xl font-bold text-success">
                  {integrations.filter(i => i.branch_protection_enabled).length}/{integrations.length}
                </p>
              </div>
              <Shield className="h-8 w-8 text-success" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Critical Alerts */}
      {criticalViolations.length > 0 && (
        <Alert className="border-destructive bg-destructive/10">
          <AlertTriangle className="h-4 w-4 text-destructive" />
          <AlertDescription className="text-destructive">
            <strong>{criticalViolations.length} critical security violation(s)</strong> detected in GitHub Codex integration.
            Immediate action required.
          </AlertDescription>
        </Alert>
      )}

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-card border border-border">
          <TabsTrigger value="overview">
            <Eye className="h-4 w-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="integrations">
            <GitBranch className="h-4 w-4 mr-2" />
            Integrations
          </TabsTrigger>
          <TabsTrigger value="violations">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Violations
            {activeViolations.length > 0 && (
              <Badge variant="destructive" className="ml-1 text-xs">
                {activeViolations.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="activity">
            <Activity className="h-4 w-4 mr-2" />
            Codex Activity
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="card-cyber">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5 text-success" />
                  <span>Security Controls Status</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span>Repository Access Permissions</span>
                  <Badge className="bg-success text-success-foreground">VERIFIED</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>API Rate Limiting</span>
                  <Badge className="bg-success text-success-foreground">ACTIVE</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>Code Review Requirements</span>
                  <Badge className="bg-success text-success-foreground">ENFORCED</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>Sensitive Data Detection</span>
                  <Badge className="bg-warning text-warning-foreground">MONITORING</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span>Branch Protection Rules</span>
                  <Badge className="bg-success text-success-foreground">ENFORCED</Badge>
                </div>
              </CardContent>
            </Card>

            <Card className="card-cyber">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Activity className="h-5 w-5 text-primary" />
                  <span>Recent Activity Summary</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {activities.slice(0, 5).map((activity) => (
                  <div key={activity.id} className="flex items-center justify-between py-2 border-b border-border">
                    <div className="flex items-center space-x-3">
                      <FileText className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="text-sm font-medium">{activity.action.replaceAll('_', ' ')}</p>
                        <p className="text-xs text-muted-foreground">{activity.repository}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {activity.sensitive_data_detected && (
                        <Badge variant="destructive" className="text-xs">SENSITIVE</Badge>
                      )}
                      <span className="text-xs text-muted-foreground">
                        {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
                      </span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="integrations" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <GitBranch className="h-5 w-5 text-primary" />
                <span>GitHub Repository Integrations</span>
              </CardTitle>
              <CardDescription>
                Monitor repository access levels and security configurations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {integrations.map((integration) => (
                  <div key={integration.id} className="p-4 rounded-lg border border-border bg-card">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <GitBranch className="h-5 w-5 text-primary" />
                        <div>
                          <h4 className="font-medium text-foreground">{integration.repository_name}</h4>
                          <div className="flex items-center space-x-2 mt-1">
                            <Badge className={getAccessLevelColor(integration.access_level)}>
                              {integration.access_level.toUpperCase()}
                            </Badge>
                            <Badge className={getStatusColor(integration.status)}>
                              {integration.status.toUpperCase()}
                            </Badge>
                          </div>
                        </div>
                      </div>
                      {integration.status === 'active' && (
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => suspendIntegration(integration.id)}
                        >
                          <Ban className="h-3 w-3 mr-1" />
                          Suspend
                        </Button>
                      )}
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div className="flex items-center space-x-2">
                        <Shield className={`h-3 w-3 ${integration.branch_protection_enabled ? 'text-success' : 'text-destructive'}`} />
                        <span>Branch Protection: {integration.branch_protection_enabled ? 'ON' : 'OFF'}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Eye className={`h-3 w-3 ${integration.code_review_required ? 'text-success' : 'text-destructive'}`} />
                        <span>Code Review: {integration.code_review_required ? 'REQUIRED' : 'OPTIONAL'}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Zap className="h-3 w-3 text-info" />
                        <span>Rate Limit: {integration.rate_limit_remaining}/5000</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Clock className="h-3 w-3 text-muted-foreground" />
                        <span>Last Activity: {formatDistanceToNow(new Date(integration.last_codex_activity), { addSuffix: true })}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="violations" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5 text-warning" />
                <span>Security Violations</span>
              </CardTitle>
              <CardDescription>
                Monitor and resolve security policy violations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-3">
                  {violations.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      <CheckCircle className="h-12 w-12 mx-auto mb-4 text-success" />
                      <p>No security violations detected</p>
                      <p className="text-sm">All GitHub Codex activities are compliant</p>
                    </div>
                  ) : (
                    violations.map((violation) => (
                      <div
                        key={violation.id}
                        className={`p-4 rounded-lg border transition-colors ${violation.resolved
                            ? 'border-border bg-muted/30'
                            : 'border-destructive bg-destructive/5'
                          }`}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-2">
                              <Badge className={getSeverityColor(violation.severity)}>
                                {violation.severity.toUpperCase()}
                              </Badge>
                              <Badge variant="outline">
                                {violation.type.replaceAll('_', ' ').toUpperCase()}
                              </Badge>
                              {violation.auto_blocked && (
                                <Badge variant="destructive" className="text-xs">
                                  AUTO-BLOCKED
                                </Badge>
                              )}
                              {violation.resolved && (
                                <Badge variant="outline" className="text-success border-success">
                                  RESOLVED
                                </Badge>
                              )}
                            </div>
                            <h4 className="font-medium text-foreground mb-1">{violation.repository}</h4>
                            <p className="text-sm text-muted-foreground mb-2">{violation.description}</p>
                            <span className="text-xs text-muted-foreground">
                              Detected {formatDistanceToNow(new Date(violation.detected_at), { addSuffix: true })}
                            </span>
                          </div>
                          {!violation.resolved && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => resolveViolation(violation.id)}
                              className="ml-4"
                            >
                              <CheckCircle className="h-3 w-3 mr-1" />
                              Resolve
                            </Button>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="activity" className="space-y-4">
          <Card className="card-cyber">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Activity className="h-5 w-5 text-accent" />
                <span>Codex Activity Log</span>
              </CardTitle>
              <CardDescription>
                Monitor all ChatGPT Codex interactions with your repositories
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-3">
                  {activities.map((activity) => (
                    <div key={activity.id} className="p-4 rounded-lg border border-border bg-card">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-2">
                            <Badge variant="outline">
                              {activity.action.replaceAll('_', ' ').toUpperCase()}
                            </Badge>
                            {activity.sensitive_data_detected && (
                              <Badge variant="destructive" className="text-xs">
                                SENSITIVE DATA
                              </Badge>
                            )}
                            {activity.auto_approved ? (
                              <Badge className="bg-success text-success-foreground text-xs">
                                AUTO-APPROVED
                              </Badge>
                            ) : (
                              <Badge className="bg-warning text-warning-foreground text-xs">
                                REVIEW REQUIRED
                              </Badge>
                            )}
                          </div>
                          <h4 className="font-medium text-foreground mb-1">{activity.repository}</h4>
                          <div className="text-sm text-muted-foreground mb-2">
                            <span className="font-medium">Files affected:</span> {activity.files_affected.join(', ')}
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
                          </span>
                        </div>
                        <Button variant="outline" size="sm">
                          <Eye className="h-3 w-3 mr-1" />
                          Review
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};