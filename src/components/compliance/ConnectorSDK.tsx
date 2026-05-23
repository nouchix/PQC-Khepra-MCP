import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useConnectorLearning } from '@/hooks/useConnectorLearning';
import { writeDAGNode } from '@/services/ConnectorDAG';
import {
  Plug,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Settings,
  Key,
  Globe,
  Database,
  Shield,
  Zap,
  Plus,
  Edit,
  Trash,
  TestTube,
  FileText,
  Github,
  Brain,
  Loader2
} from 'lucide-react';

interface Connector {
  id: string;
  name: string;
  provider: string;
  category: 'cloud' | 'identity' | 'security' | 'devops' | 'ot' | 'ticketing';
  status: 'connected' | 'disconnected' | 'error' | 'testing';
  lastSync: Date;
  healthScore: number;
  capabilities: ConnectorCapability[];
  authType: 'oauth2' | 'api_key' | 'service_principal' | 'certificate';
  rateLimits: {
    requestsPerMinute: number;
    current: number;
  };
  discoveredAssets: number;
  complianceFrameworks: string[];
  configuration: Record<string, any>;
}

interface ConnectorCapability {
  name: string;
  type: 'discover' | 'read' | 'write' | 'evidence';
  enabled: boolean;
  lastTested: Date;
  successRate: number;
}

interface ConnectorTemplate {
  id: string;
  name: string;
  provider: string;
  category: string;
  description: string;
  authType: string;
  requiredFields: ConnectorField[];
  supportedFrameworks: string[];
  documentation: string;
  isPopular: boolean;
  isDodApproved: boolean;
}

interface ConnectorField {
  name: string;
  label: string;
  type: 'text' | 'password' | 'url' | 'select';
  required: boolean;
  placeholder?: string;
  options?: string[];
  validation?: string;
}

// Awaiting telemetry for real connectors
const pendingConnectors: Connector[] = [];

const connectorTemplates: ConnectorTemplate[] = [
  {
    id: 'azure-template',
    name: 'Microsoft Azure',
    provider: 'Microsoft',
    category: 'cloud',
    description: 'Connect to Azure cloud services for resource discovery and compliance monitoring',
    authType: 'service_principal',
    requiredFields: [
      { name: 'tenantId', label: 'Tenant ID', type: 'text', required: true },
      { name: 'clientId', label: 'Client ID', type: 'text', required: true },
      { name: 'clientSecret', label: 'Client Secret', type: 'password', required: true },
      { name: 'subscriptionId', label: 'Subscription ID', type: 'text', required: true }
    ],
    supportedFrameworks: ['SOC2', 'PCI-DSS', 'ISO27001', 'HIPAA'],
    documentation: 'https://docs.azure.com/compliance-connector',
    isPopular: true,
    isDodApproved: true
  },
  {
    id: 'crowdstrike-template',
    name: 'CrowdStrike Falcon',
    provider: 'CrowdStrike',
    category: 'security',
    description: 'Endpoint detection and response security monitoring',
    authType: 'api_key',
    requiredFields: [
      { name: 'clientId', label: 'Client ID', type: 'text', required: true },
      { name: 'clientSecret', label: 'Client Secret', type: 'password', required: true },
      { name: 'baseUrl', label: 'Base URL', type: 'select', required: true, options: ['https://api.crowdstrike.com', 'https://api.us-2.crowdstrike.com', 'https://api.eu-1.crowdstrike.com'] }
    ],
    supportedFrameworks: ['SOC2', 'NIST-800-171', 'CMMC'],
    documentation: 'https://falcon.crowdstrike.com/api-docs',
    isPopular: true,
    isDodApproved: true
  },
  {
    id: 'splunk-template',
    name: 'Splunk SIEM',
    provider: 'Splunk',
    category: 'security',
    description: 'Security information and event management platform',
    authType: 'api_key',
    requiredFields: [
      { name: 'baseUrl', label: 'Splunk URL', type: 'url', required: true, placeholder: 'https://your-splunk.com:8089' },
      { name: 'username', label: 'Username', type: 'text', required: true },
      { name: 'password', label: 'Password', type: 'password', required: true }
    ],
    supportedFrameworks: ['SOC2', 'PCI-DSS', 'HIPAA'],
    documentation: 'https://docs.splunk.com/Documentation/Splunk/latest/RESTREF',
    isPopular: false,
    isDodApproved: false
  }
];

export const ConnectorSDK: React.FC = () => {
  const [connectors, setConnectors] = useState<Connector[]>(pendingConnectors);
  const [templates, setTemplates] = useState<ConnectorTemplate[]>(connectorTemplates);
  const [selectedConnector, setSelectedConnector] = useState<Connector | null>(null);
  const [showAddConnector, setShowAddConnector] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<ConnectorTemplate | null>(null);
  const [isTestingConnection, setIsTestingConnection] = useState(false);
  // Learning Mode: shown when a test fails for connectors that allow it
  const [learningConnectorId, setLearningConnectorId] = useState<string | null>(null);
  const {
    status: learningStatus,
    analysis: learningAnalysis,
    error: learningError,
    trigger: triggerLearning,
    reset: resetLearning,
  } = useConnectorLearning();
  const { toast } = useToast();

  const calculateHealthScore = (status: string) => {
    if (status === 'connected') return 100;
    if (status === 'error') return 0;
    return 50;
  };

  useEffect(() => {
    const fetchConnectors = async () => {
      try {
        const { data, error } = await supabase
          .from('compliance_connectors')
          .select('*');

        if (error) throw error;

        if (data && data.length > 0) {
          const mappedConnectors: Connector[] = data.map((d: any) => ({
            id: d.id,
            name: d.name,
            provider: d.type,
            category: d.config?.category || 'cloud',
            status: d.status || 'disconnected',
            lastSync: d.last_sync ? new Date(d.last_sync) : new Date(),
            healthScore: calculateHealthScore(d.status || 'disconnected'),
            capabilities: Array.isArray(d.capabilities) && d.capabilities.length > 0 ? d.capabilities : [
              { name: 'Discovery', type: 'discover', enabled: true, lastTested: new Date(), successRate: 100 }
            ],
            authType: d.config?.authType || 'api_key',
            rateLimits: { requestsPerMinute: 100, current: 0 },
            discoveredAssets: 0,
            complianceFrameworks: d.config?.frameworks || ['SOC2'],
            configuration: d.config || {}
          }));
          setConnectors(mappedConnectors);
        }
      } catch (err) {
        console.error('Error fetching connectors:', err);
      }
    };

    fetchConnectors();
  }, []);

  const testConnection = async (connector: Connector) => {
    setIsTestingConnection(true);
    resetLearning();
    setLearningConnectorId(null);

    // Resolve org from auth
    const { data: userData } = await supabase.auth.getUser();
    if (!userData?.user?.id) {
      toast({ title: 'Not authenticated', variant: 'destructive' });
      setIsTestingConnection(false);
      return;
    }
    const orgId = userData.user.id;

    // DAG: record test start
    const testNodeHash = await writeDAGNode({
      action: 'connector.test',
      symbol: 'connector-sdk',
      organizationId: orgId,
      connectorId: connector.id,
      pqcMetadata: { provider: connector.provider, threatLevel: 'green' },
    });

    try {
      // Route through mitochondrial-proxy (PQC-OAuth gateway)
      const { data, error } = await supabase.functions.invoke('mitochondrial-proxy', {
        body: {
          action: 'test',
          connector_id: connector.id,
          organization_id: orgId,
          provider: connector.provider,
          configuration: connector.configuration,
          dag_node_hash: testNodeHash,
        },
      });

      if (error) throw error;
      const success = data?.success === true;
      const httpStatus: number | undefined = data?.http_status;

      // DAG: record outcome
      await writeDAGNode({
        action: success ? 'connector.test.pass' : 'connector.test.fail',
        symbol: 'connector-sdk',
        organizationId: orgId,
        connectorId: connector.id,
        parentHashes: testNodeHash ? [testNodeHash] : [],
        pqcMetadata: {
          provider: connector.provider,
          httpStatus,
          threatLevel: success ? 'green' : 'yellow',
        },
      });

      // Update DB status
      const newStatus = success ? 'connected' : 'error';
      await supabase
        .from('compliance_connectors')
        .update({ status: newStatus, last_sync: new Date().toISOString() })
        .eq('id', connector.id);

      setConnectors(prev => prev.map(c =>
        c.id === connector.id ? {
          ...c,
          status: newStatus,
          healthScore: success ? Math.min(100, c.healthScore + 10) : Math.max(50, c.healthScore - 20),
          lastSync: new Date(),
        } : c
      ));

      if (!success) {
        // Offer Learning Mode for the failed connector
        setLearningConnectorId(connector.id);
      }

      toast({
        title: success ? 'Connection Test Successful' : 'Connection Test Failed',
        description: success
          ? `${connector.name} is working properly.`
          : `${connector.name} failed. Learning Mode available below.`,
        variant: success ? 'default' : 'destructive',
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('Failed to test connection:', err);

      // DAG: record failure
      await writeDAGNode({
        action: 'connector.test.fail',
        symbol: 'connector-sdk',
        organizationId: orgId,
        connectorId: connector.id,
        parentHashes: testNodeHash ? [testNodeHash] : [],
        pqcMetadata: { provider: connector.provider, errorCode: msg, threatLevel: 'yellow' },
      });

      setLearningConnectorId(connector.id);
      toast({ title: 'Test Failed', description: msg, variant: 'destructive' });
    } finally {
      setIsTestingConnection(false);
    }
  };

  const addConnector = async (template: ConnectorTemplate, config: Record<string, any>) => {
    try {
      // Create a sensible config payload
      const combinedConfig = {
        ...config,
        category: template.category,
        authType: template.authType,
        frameworks: template.supportedFrameworks
      };

      const { data: userData } = await supabase.auth.getUser();
      if (!userData?.user?.id) throw new Error('User must be authenticated to add a connector');
      const orgId = userData.user.id;

      const newConnectorData = {
        name: `${template.name} - ${config.name || 'New'}`,
        type: template.provider,
        status: 'testing',
        organization_id: orgId,
        config: combinedConfig,
        capabilities: [
          { name: 'Discovery', type: 'discover', enabled: true, lastTested: new Date().toISOString(), successRate: 100 },
          { name: 'Read', type: 'read', enabled: true, lastTested: new Date().toISOString(), successRate: 100 }
        ] as any
      };

      const { data, error } = await supabase
        .from('compliance_connectors')
        .insert(newConnectorData)
        .select()
        .single();

      if (error) throw error;

      // Refresh map
      if (data) {
        const c: Connector = {
          id: data.id,
          name: data.name,
          provider: data.type,
          category: template.category as any,
          status: 'testing',
          lastSync: new Date(),
          healthScore: 100,
          capabilities: data.capabilities as any,
          authType: template.authType as any,
          rateLimits: { requestsPerMinute: 100, current: 0 },
          discoveredAssets: 0,
          complianceFrameworks: template.supportedFrameworks,
          configuration: combinedConfig
        };

        setConnectors(prev => [...prev, c]);

        // DAG: record connector add
        await writeDAGNode({
          action: 'connector.add',
          symbol: 'connector-sdk',
          organizationId: orgId,
          connectorId: data.id,
          pqcMetadata: { provider: template.provider, tier: 'community', threatLevel: 'green' },
        });

        // Auto-test the new connection
        setTimeout(() => testConnection(c), 1000);
      }

      setShowAddConnector(false);
      setSelectedTemplate(null);

      toast({
        title: "Connector Added",
        description: `${template.name} connector has been added and is being tested`,
      });
    } catch (err) {
      console.error('Error adding connector:', err);
      toast({
        title: "Error",
        description: "Failed to add connector",
        variant: "destructive"
      });
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'error': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'testing': return <Clock className="h-4 w-4 text-blue-500 animate-spin" />;
      default: return <AlertTriangle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected': return 'bg-green-500';
      case 'error': return 'bg-red-500';
      case 'testing': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'cloud': return <Globe className="h-4 w-4" />;
      case 'identity': return <Key className="h-4 w-4" />;
      case 'security': return <Shield className="h-4 w-4" />;
      case 'devops': return <Settings className="h-4 w-4" />;
      case 'ot': return <Database className="h-4 w-4" />;
      default: return <Plug className="h-4 w-4" />;
    }
  };

  const overallStats = {
    total: connectors.length,
    connected: connectors.filter(c => c.status === 'connected').length,
    errors: connectors.filter(c => c.status === 'error').length,
    avgHealth: connectors.length > 0 ? Math.round(connectors.reduce((acc, c) => acc + c.healthScore, 0) / connectors.length) : 0,
    totalAssets: connectors.reduce((acc, c) => acc + c.discoveredAssets, 0)
  };

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold">{overallStats.total}</div>
              <div className="text-sm text-muted-foreground">Total Connectors</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">{overallStats.connected}</div>
              <div className="text-sm text-muted-foreground">Connected</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-500">{overallStats.errors}</div>
              <div className="text-sm text-muted-foreground">Errors</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">{overallStats.avgHealth}%</div>
              <div className="text-sm text-muted-foreground">Avg Health</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-500">{overallStats.totalAssets.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground">Assets</div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="connectors" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="connectors">Active Connectors</TabsTrigger>
          <TabsTrigger value="templates">Available Integrations</TabsTrigger>
          <TabsTrigger value="sdk">Developer SDK</TabsTrigger>
        </TabsList>

        <TabsContent value="connectors" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Plug className="h-5 w-5" />
                    Connector Management
                  </CardTitle>
                  <CardDescription>
                    Manage active connectors for compliance data collection and remediation
                  </CardDescription>
                </div>
                <Button onClick={() => setShowAddConnector(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Connector
                </Button>
              </div>
            </CardHeader>
          </Card>

          <div className="grid gap-4">
            {connectors.map((connector) => (
              <Card key={connector.id}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        {getCategoryIcon(connector.category)}
                        <Badge className={getStatusColor(connector.status)}>
                          {connector.status.toUpperCase()}
                        </Badge>
                        <Badge variant="outline">{connector.provider}</Badge>
                        <Badge variant="secondary">{connector.authType}</Badge>
                      </div>
                      <CardTitle className="flex items-center gap-2">
                        {getStatusIcon(connector.status)}
                        {connector.name}
                      </CardTitle>
                      <CardDescription>
                        Last sync: {connector.lastSync.toLocaleString()} •
                        {connector.discoveredAssets} assets •
                        Health: {connector.healthScore}%
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        onClick={() => testConnection(connector)}
                        disabled={isTestingConnection || connector.status === 'testing'}
                        size="sm"
                        variant="outline"
                      >
                        <TestTube className="h-4 w-4 mr-1" />
                        Test
                      </Button>
                      {learningConnectorId === connector.id && (
                        <Button
                          onClick={async () => {
                            const { data: userData } = await supabase.auth.getUser();
                            if (!userData?.user?.id) return;
                            await triggerLearning({
                              connectorId: connector.id,
                              organizationId: userData.user.id,
                              provider: connector.provider,
                            });
                          }}
                          disabled={learningStatus === 'analyzing' || learningStatus === 'updating_model' || learningStatus === 'checking_cost'}
                          size="sm"
                          variant="outline"
                          className="border-amber-500 text-amber-600 hover:bg-amber-50"
                        >
                          {(learningStatus === 'analyzing' || learningStatus === 'updating_model' || learningStatus === 'checking_cost')
                            ? <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                            : <Brain className="h-4 w-4 mr-1" />}
                          {learningStatus === 'idle' || learningStatus === 'complete' || learningStatus === 'error'
                            ? 'Analyze Failure'
                            : 'Analyzing…'}
                        </Button>
                      )}
                      <Button
                        onClick={() => setSelectedConnector(connector)}
                        size="sm"
                        variant="outline"
                      >
                        <Settings className="h-4 w-4 mr-1" />
                        Configure
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Health Score</span>
                        <span>{connector.healthScore}%</span>
                      </div>
                      <Progress value={connector.healthScore} className="h-2" />
                    </div>

                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Rate Limit Usage</span>
                        <span>{connector.rateLimits.current}/{connector.rateLimits.requestsPerMinute}</span>
                      </div>
                      <Progress
                        value={(connector.rateLimits.current / connector.rateLimits.requestsPerMinute) * 100}
                        className="h-2"
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <h5 className="font-medium mb-2">Capabilities</h5>
                        <div className="space-y-1">
                          {connector.capabilities.map((capability, index) => (
                            <div key={index} className="flex items-center justify-between text-sm">
                              <div className="flex items-center gap-2">
                                {capability.enabled ? (
                                  <CheckCircle className="h-3 w-3 text-green-500" />
                                ) : (
                                  <XCircle className="h-3 w-3 text-red-500" />
                                )}
                                <span>{capability.name}</span>
                              </div>
                              <span className="text-muted-foreground">{capability.successRate}%</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div>
                        <h5 className="font-medium mb-2">Compliance Frameworks</h5>
                        <div className="flex flex-wrap gap-1">
                          {connector.complianceFrameworks.map((framework, index) => (
                            <Badge key={index} variant="outline" className="text-xs">
                              {framework}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Learning Mode panel — shown after analysis completes */}
                    {learningConnectorId === connector.id && learningStatus !== 'idle' && (
                      <div className="border-t pt-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Brain className="h-4 w-4 text-amber-500" />
                          <span className="font-medium text-sm">AI Learning Mode</span>
                          {learningStatus === 'complete' && learningAnalysis && (
                            <Badge variant="outline" className="text-xs">
                              {learningAnalysis.confidencePercent}% confidence
                            </Badge>
                          )}
                          {learningAnalysis?.dagNodeHash && (
                            <Badge variant="outline" className="text-xs font-mono">
                              DAG: {learningAnalysis.dagNodeHash.slice(0, 8)}
                            </Badge>
                          )}
                        </div>

                        {(learningStatus === 'checking_cost' || learningStatus === 'analyzing' || learningStatus === 'updating_model') && (
                          <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <Loader2 className="h-3 w-3 animate-spin" />
                            {learningStatus === 'checking_cost' && 'Checking API budget…'}
                            {learningStatus === 'analyzing' && 'Analyzing failure with Grok AI…'}
                            {learningStatus === 'updating_model' && 'Updating learning model…'}
                          </div>
                        )}

                        {learningStatus === 'error' && learningError && (
                          <Alert variant="destructive" className="py-2">
                            <AlertDescription className="text-xs">{learningError}</AlertDescription>
                          </Alert>
                        )}

                        {learningStatus === 'complete' && learningAnalysis && (
                          <div className="space-y-3">
                            <div>
                              <span className="text-xs font-medium text-muted-foreground">Root Cause</span>
                              <p className="text-sm mt-0.5">{learningAnalysis.rootCause}</p>
                            </div>
                            <div className="bg-muted/50 rounded p-3 text-xs text-muted-foreground whitespace-pre-wrap max-h-40 overflow-y-auto">
                              {learningAnalysis.response}
                            </div>
                            {learningAnalysis.recommendations.length > 0 && (
                              <div>
                                <span className="text-xs font-medium">Recommended Actions (operator approval required)</span>
                                <div className="mt-1 space-y-1">
                                  {learningAnalysis.recommendations.map((rec, i) => (
                                    <div key={i} className="flex items-start gap-2 text-xs">
                                      <Badge variant="outline" className="shrink-0 text-[10px]">{rec.riskLevel}</Badge>
                                      <span>{rec.text}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="templates" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Available Integrations</CardTitle>
              <CardDescription>
                Pre-built connectors for popular compliance and security platforms
              </CardDescription>
            </CardHeader>
          </Card>

          <div className="grid gap-4">
            {templates.map((template) => (
              <Card key={template.id}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        {getCategoryIcon(template.category)}
                        <Badge variant="outline">{template.provider}</Badge>
                        {template.isPopular && (
                          <Badge variant="secondary">Popular</Badge>
                        )}
                        {template.isDodApproved && (
                          <Badge className="bg-blue-500">DoD Approved</Badge>
                        )}
                      </div>
                      <CardTitle>{template.name}</CardTitle>
                      <CardDescription>{template.description}</CardDescription>
                    </div>
                    <Button
                      onClick={() => {
                        setSelectedTemplate(template);
                        setShowAddConnector(true);
                      }}
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Add
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <h5 className="font-medium mb-2">Authentication</h5>
                      <Badge variant="outline">{template.authType}</Badge>
                    </div>
                    <div>
                      <h5 className="font-medium mb-2">Supported Frameworks</h5>
                      <div className="flex flex-wrap gap-1">
                        {template.supportedFrameworks.map((framework, index) => (
                          <Badge key={index} variant="outline" className="text-xs">
                            {framework}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="mt-4">
                    <h5 className="font-medium mb-2">Required Configuration</h5>
                    <div className="text-sm text-muted-foreground">
                      {template.requiredFields.map(field => field.label).join(', ')}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="sdk" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                Connector SDK Documentation
              </CardTitle>
              <CardDescription>
                Build custom connectors for proprietary systems and specialized compliance requirements
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <Alert>
                  <Shield className="h-4 w-4" />
                  <AlertDescription>
                    All custom connectors are automatically sandboxed and require security review before deployment.
                  </AlertDescription>
                </Alert>

                <div>
                  <h3 className="text-lg font-semibold mb-3">TypeScript Connector Interface</h3>
                  <div className="bg-black text-green-400 p-4 rounded font-mono text-sm overflow-x-auto">
                    <pre>{`export interface Connector {
  name: string;
  capabilities: ("discover" | "read" | "write" | "evidence")[];
  auth: OAuth2 | APIKey | ServicePrincipal;
  
  listResources(q: Query): Promise<Resource[]>;
  getConfig(ref: ResourceRef): Promise<ConfigBlob>;
  applyChange(change: ChangeRequest): Promise<ChangeResult>;
  
  // Evidence collection
  collectEvidence(controlId: string): Promise<EvidenceBlob>;
  
  // Health monitoring
  healthCheck(): Promise<HealthStatus>;
}

// Example implementation
export class MyCustomConnector implements Connector {
  name = "Custom System Connector";
  capabilities = ["discover", "read", "evidence"];
  
  async listResources(query: Query): Promise<Resource[]> {
    // Your discovery logic here
    return await this.client.discover(query);
  }
  
  async collectEvidence(controlId: string): Promise<EvidenceBlob> {
    // Compliance evidence collection
    return await this.gatherControlEvidence(controlId);
  }
}`}</pre>
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold mb-3">Security Requirements</h3>
                  <div className="space-y-2 text-sm">
                    <div>• All credentials must be encrypted using KHEPRA key management</div>
                    <div>• Rate limiting and retry logic are mandatory</div>
                    <div>• Evidence must include cryptographic signatures</div>
                    <div>• All API calls must be logged for audit purposes</div>
                    <div>• Connector must support graceful degradation</div>
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold mb-3">Testing Framework</h3>
                  <div className="bg-black text-green-400 p-4 rounded font-mono text-sm">
                    <pre>{`// Automated testing suite
describe('CustomConnector', () => {
  it('should discover resources', async () => {
    const resources = await connector.listResources({});
    expect(resources).toBeDefined();
    expect(resources.length).toBeGreaterThan(0);
  });
  
  it('should collect valid evidence', async () => {
    const evidence = await connector.collectEvidence('SOC2-CC6.1');
    expect(evidence.signature).toBeDefined();
    expect(evidence.timestamp).toBeInstanceOf(Date);
  });
});`}</pre>
                  </div>
                </div>

                <div className="flex gap-4">
                  <Button>
                    <FileText className="h-4 w-4 mr-2" />
                    Full Documentation
                  </Button>
                  <Button variant="outline">
                    <Github className="h-4 w-4 mr-2" />
                    Example Repository
                  </Button>
                  <Button variant="outline">
                    <TestTube className="h-4 w-4 mr-2" />
                    Testing Sandbox
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};