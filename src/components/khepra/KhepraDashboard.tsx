import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { KhepraStatus } from './KhepraStatus';
import { AdinkraSymbolDisplay } from './AdinkraSymbolDisplay';
import { TrustedAgentRegistryComponent } from './TrustedAgentRegistry';
import { CulturalThreatIntelligence } from './CulturalThreatIntelligence';
import { KhepraPremiumGuard } from './KhepraPremiumGuard';
import { KipConnectionStatus } from './KipConnectionStatus';
import { useKhepraAuth } from '@/khepra/hooks/useKhepraAuth';
import { useKhepraDeployment } from '@/hooks/useKhepraDeployment';
import { Shield, Activity, Users, BookOpen, Zap, Eye, AlertTriangle } from 'lucide-react';
import { BrowserNavigation } from '@/components/ui/browser-navigation';

export const KhepraDashboard = () => {
  const { config, isLoading } = useKhepraDeployment();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Shield className="h-12 w-12 animate-pulse mx-auto mb-4 text-primary" />
          <p className="text-muted-foreground">Initializing Khepra Environment...</p>
        </div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="container mx-auto py-12">
        <Card className="border-warning/20 bg-warning/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-warning" />
              Environment Not Connected
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-muted-foreground">
              A Khepra environment connection is required to access the protocol dashboard.
              Please configure your VPS or Private Cloud connection in the Integrations Hub.
            </p>
            <Button onClick={() => globalThis.location.href = '/integrations'}>
              Go to Integrations
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <KhepraPremiumGuard
      feature="khepra-protocol"
      deploymentUrl={config.deploymentUrl}
      apiKey={config.apiKey}
    >
      <KhepraDashboardContent />
    </KhepraPremiumGuard>
  );
};

const KhepraDashboardContent = () => {
  const { authState, securityEvents, generateAuditTrail, validateAction } = useKhepraAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [auditTrail, setAuditTrail] = useState<any[]>([]);

  const handleGenerateAuditTrail = () => {
    const trail = generateAuditTrail();
    setAuditTrail(trail);
  };

  const handleTestAction = async (action: string, context: string = 'security') => {
    const isValid = await validateAction(action, context);
    console.log(`Action ${action} validation:`, isValid);
  };

  const recentEvents = securityEvents.slice(0, 10);
  const criticalEvents = securityEvents.filter(e => e.severity === 'high' || e.severity === 'critical');

  return (
    <div className="min-h-screen bg-background">
      {/* Browser-like Navigation */}
      <BrowserNavigation
        tabs={[
          { id: 'overview', title: 'KHEPRA Overview', path: '/khepra-protocol', isActive: activeTab === 'overview' },
          { id: 'symbols', title: 'Adinkra Symbols', path: '/khepra-protocol' },
          { id: 'events', title: 'Security Events', path: '/khepra-protocol', hasNotification: criticalEvents.length > 0, notificationCount: criticalEvents.length },
          { id: 'audit', title: 'Audit Trail', path: '/khepra-protocol' },
          { id: 'agents', title: 'Trusted Agents', path: '/khepra-protocol' },
          { id: 'testing', title: 'Protocol Testing', path: '/khepra-protocol' }
        ]}
        onTabChange={setActiveTab}
        title="KHEPRA Protocol Dashboard"
        subtitle="Afrofuturist Cryptographic Framework for Agentic AI Security • Patent Pending"
      />

      <div className="container mx-auto p-6 space-y-6">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">KHEPRA Protocol</h1>
            <p className="text-muted-foreground">
              Afrofuturist Cryptographic Framework for Agentic AI Security
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Badge variant="outline" className="text-xs">
              v1.0.0
            </Badge>
            <Badge variant="outline" className="text-xs bg-amber-500/10 text-amber-600 border-amber-500/20">
              Patent Pending
            </Badge>
            <Badge variant={authState.isAuthenticated ? 'default' : 'secondary'}>
              {authState.isAuthenticated ? 'Active' : 'Inactive'}
            </Badge>
          </div>
        </div>

        {/* Status Overview */}
        <KhepraStatus />

        {/* Main Content */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid w-full grid-cols-7">
            <TabsTrigger value="overview" className="flex items-center space-x-2">
              <Eye className="h-4 w-4" />
              <span>Overview</span>
            </TabsTrigger>
            <TabsTrigger value="symbols" className="flex items-center space-x-2">
              <BookOpen className="h-4 w-4" />
              <span>Symbols</span>
            </TabsTrigger>
            <TabsTrigger value="events" className="flex items-center space-x-2">
              <Activity className="h-4 w-4" />
              <span>Events</span>
            </TabsTrigger>
            <TabsTrigger value="audit" className="flex items-center space-x-2">
              <Shield className="h-4 w-4" />
              <span>Audit</span>
            </TabsTrigger>
            <TabsTrigger value="agents" className="flex items-center space-x-2">
              <Users className="h-4 w-4" />
              <span>Agents</span>
            </TabsTrigger>
            <TabsTrigger value="kip" className="flex items-center space-x-2">
              <Zap className="h-4 w-4" />
              <span>KIP</span>
            </TabsTrigger>
            <TabsTrigger value="testing" className="flex items-center space-x-2">
              <Zap className="h-4 w-4" />
              <span>Testing</span>
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Cultural Fingerprint */}
              <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-primary" />
                    <span>Cultural Fingerprint</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {authState.culturalFingerprint ? (
                    <div className="space-y-2">
                      <p className="text-sm font-mono break-all bg-muted/20 p-2 rounded">
                        {authState.culturalFingerprint}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Generated using Adinkra algebraic transformations
                      </p>
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      No cultural fingerprint generated
                    </p>
                  )}
                </CardContent>
              </Card>

              {/* Transformations History */}
              <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Activity className="h-5 w-5 text-primary" />
                    <span>Recent Transformations</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-32">
                    {authState.adinkraTransformations.length > 0 ? (
                      <div className="space-y-2">
                        {authState.adinkraTransformations.slice(-5).map((transform) => (
                          <div key={`${transform.symbol}-${transform.timestamp.getTime()}`} className="text-sm border-l-2 border-primary/30 pl-2">
                            <div className="flex items-center justify-between">
                              <span className="font-medium">{transform.symbol}</span>
                              <span className="text-xs text-muted-foreground">
                                {transform.timestamp.toLocaleTimeString()}
                              </span>
                            </div>
                            {transform.context && (
                              <p className="text-xs text-muted-foreground">
                                Context: {transform.context}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No transformations recorded
                      </p>
                    )}
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>

            {/* Critical Events */}
            {criticalEvents.length > 0 && (
              <Card className="border-destructive/20 bg-destructive/5">
                <CardHeader>
                  <CardTitle className="text-destructive">Critical Security Events</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {criticalEvents.slice(0, 3).map((event) => (
                      <div key={`${event.type}-${event.timestamp.getTime()}`} className="flex items-center justify-between p-2 border-l-2 border-destructive">
                        <div>
                          <p className="font-medium text-destructive">{event.type}</p>
                          <p className="text-sm text-muted-foreground">
                            {event.timestamp.toLocaleString()}
                          </p>
                        </div>
                        <Badge variant="destructive">{event.severity}</Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Symbols Tab */}
          <TabsContent value="symbols" className="space-y-4">
            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold mb-2">Adinkra Symbols</h2>
              <p className="text-muted-foreground">
                Cultural symbols used for cryptographic transformations
              </p>
            </div>
            <AdinkraSymbolDisplay showMatrix showMeaning />
          </TabsContent>

          {/* Events Tab */}
          <TabsContent value="events" className="space-y-4">
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Security Events</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96">
                  {recentEvents.length > 0 ? (
                    <div className="space-y-3">
                      {recentEvents.map((event) => (
                        <div key={`${event.type}-${event.timestamp.getTime()}`} className="border-l-2 border-primary/30 pl-4 py-2">
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-medium">{event.type}</span>
                            <Badge variant={(() => {
                              if (event.severity === 'critical' || event.severity === 'high') return 'destructive';
                              if (event.severity === 'medium') return 'secondary';
                              return 'default';
                            })()}>
                              {event.severity}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mb-2">
                            {event.timestamp.toLocaleString()}
                          </p>
                          {Object.keys(event.details).length > 0 && (
                            <div className="text-xs bg-muted/20 p-2 rounded">
                              <pre className="whitespace-pre-wrap">
                                {JSON.stringify(event.details, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-center text-muted-foreground py-8">
                      No security events recorded
                    </p>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Audit Tab */}
          <TabsContent value="audit" className="space-y-4">
            <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Audit Trail</CardTitle>
                <Button onClick={handleGenerateAuditTrail} size="sm">
                  Generate Trail
                </Button>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96">
                  {auditTrail.length > 0 ? (
                    <div className="space-y-3">
                      {auditTrail.map((entry) => (
                        <div key={`${entry.action}-${entry.nodeId}`} className="border border-muted rounded p-3">
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-medium">{entry.action}</span>
                            <Badge variant="outline">{entry.trustScore}</Badge>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                            <div>Node ID: {entry.nodeId.slice(0, 16)}...</div>
                            <div>Agent: {entry.agentId}</div>
                            <div>Symbol: {entry.culturalSymbol}</div>
                            <div>Valid: {entry.culturalValidation ? '✓' : '✗'}</div>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">
                            {entry.culturalMeaning}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-center text-muted-foreground py-8">
                      Click "Generate Trail" to view audit entries
                    </p>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Agents Tab */}
          <TabsContent value="agents" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Agent Information */}
              <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Agent Information</CardTitle>
                </CardHeader>
                <CardContent>
                  {authState.agentId ? (
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <p className="font-medium">Agent ID</p>
                          <p className="font-mono text-xs break-all bg-muted/20 p-2 rounded">
                            {authState.agentId}
                          </p>
                        </div>
                        <div>
                          <p className="font-medium">Cultural Context</p>
                          <p className="capitalize">{authState.culturalContext}</p>
                        </div>
                        <div>
                          <p className="font-medium">Trust Score</p>
                          <p className="text-lg font-bold">{authState.trustScore}</p>
                        </div>
                        <div>
                          <p className="font-medium">Last Interaction</p>
                          <p className="text-xs">
                            {authState.lastInteraction?.toLocaleString() || 'None'}
                          </p>
                        </div>
                      </div>
                      <Separator />
                      <div>
                        <p className="font-medium mb-2">Transformation History</p>
                        <p className="text-sm text-muted-foreground">
                          {authState.adinkraTransformations.length} transformations recorded
                        </p>
                      </div>
                    </div>
                  ) : (
                    <p className="text-center text-muted-foreground py-8">
                      No agent information available
                    </p>
                  )}
                </CardContent>
              </Card>

              {/* Trusted Agent Registry */}
              <TrustedAgentRegistryComponent />
            </div>
          </TabsContent>

          {/* KIP Connection Tab */}
          <TabsContent value="kip" className="space-y-6">
            <KipConnectionStatus />
          </TabsContent>

          {/* Testing Tab */}
          <TabsContent value="testing" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Action Testing */}
              <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Action Testing</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 gap-4">
                    <div className="space-y-2">
                      <p className="font-medium">Security Actions</p>
                      <div className="space-y-1">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleTestAction('security_scan', 'security')}
                          className="w-full justify-start"
                        >
                          Test Security Scan
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleTestAction('access_control', 'security')}
                          className="w-full justify-start"
                        >
                          Test Access Control
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleTestAction('threat_analysis', 'security')}
                          className="w-full justify-start"
                        >
                          Test Threat Analysis
                        </Button>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <p className="font-medium">Administrative Actions</p>
                      <div className="space-y-1">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleTestAction('policy_analysis', 'trust')}
                          className="w-full justify-start"
                        >
                          Test Policy Analysis
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleTestAction('system_update', 'transformation')}
                          className="w-full justify-start"
                        >
                          Test System Update
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleTestAction('collaboration', 'unity')}
                          className="w-full justify-start"
                        >
                          Test Collaboration
                        </Button>
                      </div>
                    </div>

                    <Separator className="my-2" />

                    <div className="text-center">
                      <p className="text-sm text-muted-foreground">
                        Test results will appear in the browser console and Events tab
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Cultural Threat Intelligence */}
              <CulturalThreatIntelligence />
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};