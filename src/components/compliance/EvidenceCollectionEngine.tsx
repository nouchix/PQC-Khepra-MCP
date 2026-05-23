import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useIndustryIntegrations } from '@/hooks/useIndustryIntegrations';
import { InfrastructureDiscovery } from '@/components/InfrastructureDiscovery';
import {
  Database,
  FileCheck,
  Shield,
  Cloud,
  Server,
  CheckCircle,
  Clock,
  AlertTriangle,
  Download,
  Scan,
  Network,
  Key,
  HardDrive,
  Globe,
  Users,
  Lock,
  Bot,
  Link,
  Eye,
  Settings
} from 'lucide-react';

interface EvidenceBundle {
  id: string;
  title: string;
  description: string;
  evidence_type: string;
  collection_date: string;
  status: 'verified' | 'pending' | 'rejected' | 'signed';
  file_path?: string;
  metadata?: any;
  // Security enhancements
  sha256_hash: string;
  digital_signature?: string;
  pqc_signature_stub?: string;
  immutable_storage: boolean;
  verification_chain: VerificationStep[];
  stig_rule_ids: string[];
  nist_control_ids: string[];
  config_state_delta?: ConfigurationDelta;
}

interface VerificationStep {
  timestamp: string;
  verifier: string;
  method: 'sha256' | 'pqc_dilithium' | 'manual_review';
  result: 'valid' | 'invalid' | 'pending';
  signature?: string;
}

interface ConfigurationDelta {
  before_state: any;
  after_state: any;
  change_summary: string;
  affected_controls: string[];
}

interface EvidenceItem {
  id: string;
  controlId: string;
  stigId?: string;
  framework: string;
  evidenceType: 'configuration' | 'log' | 'screenshot' | 'document' | 'scan' | 'infrastructure' | 'stig_rule' | 'config_state';
  source: string;
  collectedAt: Date;
  status: 'collected' | 'processing' | 'verified' | 'failed';
  metadata: {
    hash: string;
    size: number;
    integrity: boolean;
    automationSource?: string;
    assetId?: string;
    integrationSource?: string;
    stigRuleId?: string;
    configStateBefore?: any;
    configStateAfter?: any;
    stigFingerprint?: string;
  };
  description: string;
  path?: string;
}

interface IntegrationStatus {
  source: string;
  status: 'connected' | 'disconnected' | 'error';
  lastSync: Date;
  evidenceCount: number;
  automationLevel: number;
  infrastructureAccess: boolean;
}

export const EvidenceCollectionEngine: React.FC = () => {
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationStatus[]>([]);
  const [isCollecting, setIsCollecting] = useState(false);
  const [collectionProgress, setCollectionProgress] = useState(0);
  const { userIntegrations, library, loading } = useIndustryIntegrations();
  const { toast } = useToast();

  useEffect(() => {
    initializeEvidenceSystem();
    loadIntegrationStatus();
  }, [userIntegrations]);

  const initializeEvidenceSystem = () => {
    // STIG rule ID tracking with configuration state deltas
    // Awaiting telemetry for real evidence
    const pendingEvidence: EvidenceItem[] = [];

    setEvidenceItems(pendingEvidence);
  };

  const loadIntegrationStatus = () => {
    // Awaiting telemetry for real integrations
    const pendingIntegrations: IntegrationStatus[] = [];

    setIntegrations(pendingIntegrations);
  };

  const runEvidenceCollection = async (framework: string = 'CMMC 2.0') => {
    setIsCollecting(true);
    setCollectionProgress(0);

    try {
      // Simulate evidence collection across integrations including infrastructure
      const progressInterval = setInterval(() => {
        setCollectionProgress(prev => {
          if (prev >= 100) {
            clearInterval(progressInterval);
            return 100;
          }
          return prev + 15; // Fixed increment; real progress tracking requires event stream from edge function
        });
      }, 500);

      // Call enhanced evidence collection function
      const { data, error } = await supabase.functions.invoke('grok-ai-agent', {
        body: {
          action: 'collect_evidence',
          framework,
          integrations: integrations.filter(i => i.status === 'connected').map(i => i.source),
          include_infrastructure: true,
          automation_level: 'high'
        }
      });

      if (error) throw error;

      setTimeout(() => {
        clearInterval(progressInterval);
        setCollectionProgress(100);

        toast({
          title: "Enhanced Evidence Collection Complete",
          description: `Collected evidence from ${integrations.filter(i => i.status === 'connected').length} integrated systems including infrastructure discovery`,
        });

        // Refresh evidence items
        initializeEvidenceSystem();
        setIsCollecting(false);
      }, 3000);

    } catch (error) {
      console.error('Evidence collection failed:', error);
      setIsCollecting(false);
      toast({
        title: "Collection Failed",
        description: "Unable to complete evidence collection",
        variant: "destructive"
      });
    }
  };

  const downloadEvidencePackage = (controlId?: string) => {
    const filteredEvidence = controlId
      ? evidenceItems.filter(item => item.controlId === controlId)
      : evidenceItems;

    toast({
      title: "Evidence Package",
      description: `Preparing ${filteredEvidence.length} evidence items for download including infrastructure data`,
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'verified': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'processing': return <Clock className="h-4 w-4 text-yellow-500 animate-spin" />;
      case 'collected': return <FileCheck className="h-4 w-4 text-blue-500" />;
      case 'failed': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getIntegrationIcon = (source: string) => {
    if (source.includes('AWS')) return <Cloud className="h-5 w-5 text-orange-500" />;
    if (source.includes('Splunk')) return <Database className="h-5 w-5 text-green-500" />;
    if (source.includes('Okta')) return <Users className="h-5 w-5 text-blue-500" />;
    if (source.includes('CrowdStrike')) return <Shield className="h-5 w-5 text-red-500" />;
    if (source.includes('Microsoft')) return <Globe className="h-5 w-5 text-blue-600" />;
    if (source.includes('Infrastructure')) return <Server className="h-5 w-5 text-purple-500" />;
    if (source.includes('Wiz')) return <Scan className="h-5 w-5 text-purple-500" />;
    return <HardDrive className="h-5 w-5 text-gray-500" />;
  };

  const evidenceStats = {
    total: evidenceItems.length,
    verified: evidenceItems.filter(e => e.status === 'verified').length,
    processing: evidenceItems.filter(e => e.status === 'processing').length,
    automationRate: Math.round((evidenceItems.filter(e => e.metadata.automationSource).length / evidenceItems.length) * 100),
    infrastructureItems: evidenceItems.filter(e => e.evidenceType === 'infrastructure').length
  };

  return (
    <div className="space-y-6">
      {/* Enhanced Evidence Collection Header */}
      <Card className="bg-gradient-to-r from-green-900/40 to-blue-900/40 border-green-500/30">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-white">
                <Bot className="h-6 w-6 text-green-400" />
                Enhanced Evidence Collection Engine
              </CardTitle>
              <CardDescription className="text-green-200">
                Automated evidence collection with infrastructure discovery and AI-powered analysis
              </CardDescription>
            </div>
            <div className="flex items-center gap-3">
              <Button
                onClick={() => runEvidenceCollection()}
                disabled={isCollecting}
                className="bg-green-600 hover:bg-green-700"
              >
                {isCollecting ? (
                  <>
                    <Clock className="h-4 w-4 animate-spin mr-2" />
                    Collecting...
                  </>
                ) : (
                  <>
                    <Scan className="h-4 w-4 mr-2" />
                    Collect Evidence
                  </>
                )}
              </Button>
              <Button
                onClick={() => downloadEvidencePackage()}
                variant="outline"
                className="border-green-500/30 text-green-400 hover:bg-green-600/20"
              >
                <Download className="h-4 w-4 mr-2" />
                Export Package
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Collection Progress */}
      {isCollecting && (
        <Card className="bg-black/40 border-yellow-500/30">
          <CardContent className="pt-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-white">Collecting evidence from integrated systems and infrastructure...</span>
                <span className="text-yellow-400">{Math.round(collectionProgress)}%</span>
              </div>
              <Progress value={collectionProgress} className="h-2" />
              <div className="text-sm text-gray-400">
                Scanning {integrations.filter(i => i.status === 'connected').length} connected integrations with infrastructure discovery
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Enhanced Evidence Statistics */}
      <div className="grid grid-cols-5 gap-4">
        <Card className="bg-black/40 border-blue-500/30">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-white">{evidenceStats.total}</div>
              <div className="text-sm text-muted-foreground">Total Evidence</div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-black/40 border-green-500/30">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">{evidenceStats.verified}</div>
              <div className="text-sm text-muted-foreground">Verified</div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-black/40 border-yellow-500/30">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-500">{evidenceStats.processing}</div>
              <div className="text-sm text-muted-foreground">Processing</div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-black/40 border-purple-500/30">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-500">{evidenceStats.automationRate}%</div>
              <div className="text-sm text-muted-foreground">Automation</div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-black/40 border-orange-500/30">
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-500">{evidenceStats.infrastructureItems}</div>
              <div className="text-sm text-muted-foreground">Infrastructure</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Enhanced Tabs with Infrastructure Integration */}
      <Tabs defaultValue="evidence" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="evidence">Evidence Items</TabsTrigger>
          <TabsTrigger value="infrastructure">Infrastructure Discovery</TabsTrigger>
          <TabsTrigger value="integrations">Connected Systems</TabsTrigger>
          <TabsTrigger value="mapping">Control Mapping</TabsTrigger>
        </TabsList>

        <TabsContent value="evidence" className="space-y-4">
          <div className="space-y-4">
            {evidenceItems.map((item) => (
              <Card key={item.id} className="bg-black/40 border-slate-600/30">
                <CardContent className="pt-6">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 space-y-3">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(item.status)}
                        <Badge variant="outline" className="text-blue-400 border-blue-400">
                          {item.controlId}
                        </Badge>
                        <Badge className="bg-purple-500/20 text-purple-400">
                          {item.framework}
                        </Badge>
                        <Badge variant="secondary">
                          {item.evidenceType}
                        </Badge>
                        {item.metadata.integrationSource && (
                          <Badge className="bg-green-500/20 text-green-400">
                            <Link className="h-3 w-3 mr-1" />
                            Integrated
                          </Badge>
                        )}
                      </div>
                      <div>
                        <h3 className="font-semibold text-white">{item.description}</h3>
                        <div className="flex items-center gap-2 text-sm text-gray-400 mt-1">
                          {getIntegrationIcon(item.source)}
                          <span>Source: {item.source}</span>
                          <span>•</span>
                          <span>Collected: {item.collectedAt.toLocaleString()}</span>
                          {item.metadata.assetId && (
                            <>
                              <span>•</span>
                              <span>Asset: {item.metadata.assetId}</span>
                            </>
                          )}
                        </div>
                        {item.metadata.integrationSource && (
                          <div className="text-xs text-green-400 mt-1">
                            Integration: {item.metadata.integrationSource}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-gray-400">
                        <span>Hash: {item.metadata.hash}</span>
                        <span>Size: {(item.metadata.size / 1024).toFixed(1)}KB</span>
                        {item.metadata.integrity && (
                          <div className="flex items-center gap-1">
                            <Lock className="h-3 w-3 text-green-500" />
                            <span className="text-green-400">Verified</span>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="ml-4 flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="border-blue-500/30 text-blue-400 hover:bg-blue-600/20"
                      >
                        <Eye className="h-4 w-4 mr-1" />
                        View
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => downloadEvidencePackage(item.controlId)}
                        className="border-green-500/30 text-green-400 hover:bg-green-600/20"
                      >
                        <Download className="h-4 w-4 mr-1" />
                        Download
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="infrastructure" className="space-y-4">
          <InfrastructureDiscovery />
        </TabsContent>

        <TabsContent value="integrations" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {integrations.map((integration) => (
              <Card key={integration.source} className="bg-black/40 border-slate-600/30">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      {getIntegrationIcon(integration.source)}
                      <div>
                        <h3 className="font-semibold text-white">{integration.source}</h3>
                        <div className="text-sm text-gray-400">
                          Last sync: {integration.lastSync.toLocaleString()}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={
                        integration.status === 'connected' ? 'bg-green-500/20 text-green-400' :
                          integration.status === 'error' ? 'bg-red-500/20 text-red-400' :
                            'bg-gray-500/20 text-gray-400'
                      }>
                        {integration.status.toUpperCase()}
                      </Badge>
                      {integration.infrastructureAccess && (
                        <Badge className="bg-purple-500/20 text-purple-400">
                          <Server className="h-3 w-3 mr-1" />
                          Infrastructure
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Evidence Items</span>
                      <span className="text-white">{integration.evidenceCount}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Automation Level</span>
                      <span className="text-blue-400">{integration.automationLevel}%</span>
                    </div>
                    <Progress value={integration.automationLevel} className="h-2" />
                  </div>
                  <div className="mt-4 flex gap-2">
                    <Button size="sm" variant="outline" className="border-blue-500/30 text-blue-400">
                      <Settings className="h-3 w-3 mr-1" />
                      Configure
                    </Button>
                    {integration.infrastructureAccess && (
                      <Button size="sm" variant="outline" className="border-purple-500/30 text-purple-400">
                        <Server className="h-3 w-3 mr-1" />
                        Scan
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="mapping" className="space-y-4">
          <Card className="bg-black/40 border-slate-600/30">
            <CardHeader>
              <CardTitle className="text-white">Evidence to Control Mapping</CardTitle>
              <CardDescription>
                Automated mapping of collected evidence to compliance controls
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8">
                <Network className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-400">
                  Advanced control mapping will be displayed here based on collected evidence
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};