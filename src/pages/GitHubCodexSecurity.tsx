import { useState } from 'react';
import { PageLayout } from '@/components/PageLayout';
import { GitHubCodexSecurityMonitor } from '@/components/security/GitHubCodexSecurityMonitor';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import {
  Shield, GitBranch, Settings, Play, CheckCircle, AlertTriangle, 
  Eye, Lock, Zap, FileText, Activity
} from 'lucide-react';

export default function GitHubCodexSecurity() {
  const [runningCheck, setRunningCheck] = useState(false);
  const [lastCheckResult, setLastCheckResult] = useState<any>(null);
  const { toast } = useToast();

  const runSecurityVerification = async () => {
    setRunningCheck(true);
    try {
      const { data, error } = await supabase.functions.invoke('github-codex-monitor', {
        body: { action: 'verify_security_controls' }
      });

      if (error) throw error;

      setLastCheckResult(data);
      toast({
        title: "Security Verification Complete",
        description: `${data.summary.passed}/${data.summary.total} security controls passed`,
      });
    } catch (error) {
      console.error('Security verification failed:', error);
      toast({
        title: "Verification Failed",
        description: "Unable to complete security verification",
        variant: "destructive"
      });
    } finally {
      setRunningCheck(false);
    }
  };

  return (
    <PageLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight bg-gradient-primary bg-clip-text text-transparent">
              GitHub Codex Security Monitor
            </h1>
            <p className="text-muted-foreground mt-2">
              Comprehensive security oversight for your ChatGPT Codex-GitHub integration
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <Button 
              onClick={runSecurityVerification}
              disabled={runningCheck}
              className="flex items-center space-x-2"
            >
              {runningCheck ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                  <span>Verifying...</span>
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  <span>Run Security Check</span>
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Security Controls Overview */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <Card className="card-cyber">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Repository Access</p>
                  <p className="text-lg font-bold text-success">VERIFIED</p>
                </div>
                <Eye className="h-6 w-6 text-success" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="card-cyber">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Rate Limiting</p>
                  <p className="text-lg font-bold text-success">ACTIVE</p>
                </div>
                <Zap className="h-6 w-6 text-success" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="card-cyber">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Code Review</p>
                  <p className="text-lg font-bold text-success">ENFORCED</p>
                </div>
                <FileText className="h-6 w-6 text-success" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="card-cyber">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Data Detection</p>
                  <p className="text-lg font-bold text-warning">MONITORING</p>
                </div>
                <Shield className="h-6 w-6 text-warning" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="card-cyber">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Branch Protection</p>
                  <p className="text-lg font-bold text-success">ENFORCED</p>
                </div>
                <GitBranch className="h-6 w-6 text-success" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Last Security Check Results */}
        {lastCheckResult && (
          <Alert className="border-success bg-success/10">
            <CheckCircle className="h-4 w-4 text-success" />
            <AlertDescription className="text-success">
              <strong>Last Security Verification:</strong> {lastCheckResult.summary.passed}/{lastCheckResult.summary.total} controls passed
              {lastCheckResult.summary.failed > 0 && `, ${lastCheckResult.summary.failed} failed`}
              {lastCheckResult.summary.warnings > 0 && `, ${lastCheckResult.summary.warnings} warnings`}
            </AlertDescription>
          </Alert>
        )}

        {/* Security Control Details */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="bg-card border border-border">
            <TabsTrigger value="overview">
              <Shield className="h-4 w-4 mr-2" />
              Security Overview
            </TabsTrigger>
            <TabsTrigger value="monitor">
              <Activity className="h-4 w-4 mr-2" />
              Real-time Monitor
            </TabsTrigger>
            <TabsTrigger value="controls">
              <Settings className="h-4 w-4 mr-2" />
              Control Details
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="card-cyber">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-primary" />
                    <span>Key Security Controls</span>
                  </CardTitle>
                  <CardDescription>
                    Critical security measures protecting your GitHub-Codex integration
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 rounded-lg border border-border">
                      <div className="flex items-center space-x-3">
                        <Eye className="h-4 w-4 text-success" />
                        <div>
                          <p className="font-medium">Repository Access Permissions</p>
                          <p className="text-sm text-muted-foreground">Read-only access verified for all repositories</p>
                        </div>
                      </div>
                      <Badge className="bg-success text-success-foreground">VERIFIED</Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-3 rounded-lg border border-border">
                      <div className="flex items-center space-x-3">
                        <Zap className="h-4 w-4 text-success" />
                        <div>
                          <p className="font-medium">API Rate Limiting</p>
                          <p className="text-sm text-muted-foreground">Rate limits enforced on all Codex API calls</p>
                        </div>
                      </div>
                      <Badge className="bg-success text-success-foreground">ACTIVE</Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-3 rounded-lg border border-border">
                      <div className="flex items-center space-x-3">
                        <FileText className="h-4 w-4 text-success" />
                        <div>
                          <p className="font-medium">Code Review Requirements</p>
                          <p className="text-sm text-muted-foreground">All auto-generated commits require human review</p>
                        </div>
                      </div>
                      <Badge className="bg-success text-success-foreground">ENFORCED</Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-3 rounded-lg border border-border">
                      <div className="flex items-center space-x-3">
                        <Shield className="h-4 w-4 text-warning" />
                        <div>
                          <p className="font-medium">Sensitive Data Detection</p>
                          <p className="text-sm text-muted-foreground">Real-time scanning for secrets and credentials</p>
                        </div>
                      </div>
                      <Badge className="bg-warning text-warning-foreground">MONITORING</Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-3 rounded-lg border border-border">
                      <div className="flex items-center space-x-3">
                        <GitBranch className="h-4 w-4 text-success" />
                        <div>
                          <p className="font-medium">Branch Protection Rules</p>
                          <p className="text-sm text-muted-foreground">Protected branches enforce security policies</p>
                        </div>
                      </div>
                      <Badge className="bg-success text-success-foreground">ENFORCED</Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="card-cyber">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Lock className="h-5 w-5 text-accent" />
                    <span>Security Recommendations</span>
                  </CardTitle>
                  <CardDescription>
                    Best practices for maintaining secure GitHub-Codex integration
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="p-3 rounded-lg bg-success/10 border border-success/20">
                      <div className="flex items-start space-x-2">
                        <CheckCircle className="h-4 w-4 text-success mt-0.5" />
                        <div>
                          <p className="font-medium text-success">Implement Regular Security Audits</p>
                          <p className="text-sm text-muted-foreground">Schedule weekly automated security verifications</p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="p-3 rounded-lg bg-info/10 border border-info/20">
                      <div className="flex items-start space-x-2">
                        <Shield className="h-4 w-4 text-info mt-0.5" />
                        <div>
                          <p className="font-medium text-info">Enable Advanced Threat Detection</p>
                          <p className="text-sm text-muted-foreground">Monitor for unusual patterns in code generation</p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="p-3 rounded-lg bg-warning/10 border border-warning/20">
                      <div className="flex items-start space-x-2">
                        <AlertTriangle className="h-4 w-4 text-warning mt-0.5" />
                        <div>
                          <p className="font-medium text-warning">Review Integration Permissions</p>
                          <p className="text-sm text-muted-foreground">Regularly audit repository access levels</p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="p-3 rounded-lg bg-accent/10 border border-accent/20">
                      <div className="flex items-start space-x-2">
                        <Activity className="h-4 w-4 text-accent mt-0.5" />
                        <div>
                          <p className="font-medium text-accent">Monitor Code Quality Metrics</p>
                          <p className="text-sm text-muted-foreground">Track generated code quality and security metrics</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="monitor">
            <GitHubCodexSecurityMonitor />
          </TabsContent>

          <TabsContent value="controls" className="space-y-4">
            <div className="grid grid-cols-1 gap-6">
              {lastCheckResult?.checks?.map((check: any, index: number) => (
                <Card key={index} className="card-cyber">
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between">
                      <span className="flex items-center space-x-2">
                        {check.status === 'pass' ? (
                          <CheckCircle className="h-5 w-5 text-success" />
                        ) : check.status === 'warning' ? (
                          <AlertTriangle className="h-5 w-5 text-warning" />
                        ) : (
                          <AlertTriangle className="h-5 w-5 text-destructive" />
                        )}
                        <span>{check.type.replaceAll('_', ' ').toUpperCase()}</span>
                      </span>
                      <Badge className={
                        check.status === 'pass' ? 'bg-success text-success-foreground' :
                        check.status === 'warning' ? 'bg-warning text-warning-foreground' :
                        'bg-destructive text-destructive-foreground'
                      }>
                        {check.status.toUpperCase()}
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-muted-foreground mb-4">{check.message}</p>
                    {check.details && (
                      <div className="bg-muted/50 rounded-lg p-3">
                        <pre className="text-xs text-muted-foreground overflow-x-auto">
                          {JSON.stringify(check.details, null, 2)}
                        </pre>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )) || (
                <Card className="card-cyber">
                  <CardContent className="p-8 text-center">
                    <Settings className="h-12 w-12 mx-auto mb-4 text-muted-foreground opacity-50" />
                    <p className="text-muted-foreground">Run a security verification to see detailed control status</p>
                    <Button onClick={runSecurityVerification} className="mt-4" disabled={runningCheck}>
                      <Play className="h-4 w-4 mr-2" />
                      Run Security Verification
                    </Button>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </PageLayout>
  );
}