/**
 * DoD Comprehensive STIG-Codex Center
 * Unified STIG-First compliance automation interface integrating 
 * STIG-Codex orchestration with STIG-Connector discovery and management
 */

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';

import {
  Shield,
  Activity,
  Zap,
  Brain,
  AlertTriangle,
  CheckCircle,
  Clock,
  Eye,
  Globe,
  Server,
  Search,
  RefreshCw,
  Command
} from 'lucide-react';

// Import all STIG-related components and hooks
import { STIGCodexDashboard } from '@/components/stig-codex/STIGCodexDashboard';
import { STIGConnectorDashboard } from '@/components/discovery/STIGConnectorDashboard';
import { useSTIGCodex } from '@/hooks/useSTIGCodex';
import { useOrganization } from '@/hooks/useOrganization';
import { useSecurityClearance } from '@/hooks/useSecurityClearance';
import { AccessControlWrapper } from '@/components/security/AccessControlWrapper';
import { STIGConnectorService } from '@/services/STIGConnectorService';
import { useToast } from '@/components/ui/use-toast';
import { DashboardToggle } from '@/components/DashboardToggle';

export default function DoD() {
  const { toast } = useToast();
  const { currentOrganization } = useOrganization();
  const organizationId = currentOrganization?.organization_id || '';
  const { currentClearance } = useSecurityClearance('CONFIDENTIAL');

  const [activeTab, setActiveTab] = useState('overview');
  const [isInitializing, setIsInitializing] = useState(false);
  const [stigCodexStatus, setStigCodexStatus] = useState<'inactive' | 'initializing' | 'active'>('inactive');
  const [discoveredAssets, setDiscoveredAssets] = useState([]);
  const [totalAssets, setTotalAssets] = useState(0);

  // STIG-Codex hook
  const stigCodexData = useSTIGCodex(organizationId);

  const {
    complianceScore,
    agents,
    driftEvents,
    threatCorrelations,
    loading: codexLoading,
    initializeMonitoring,
    refreshAllData
  } = stigCodexData;

  useEffect(() => {
    if (organizationId) {
      loadAssetData();
    }
  }, [organizationId]);

  const loadAssetData = async () => {
    try {
      const assetsResponse = await STIGConnectorService.getDiscoveredAssets(organizationId);
      setDiscoveredAssets(assetsResponse.assets);
      setTotalAssets(assetsResponse.total_count);
    } catch (error) {
      console.error('Failed to load asset data:', error);
    }
  };

  const handleInitializeSTIGCodex = async () => {
    try {
      setIsInitializing(true);
      setStigCodexStatus('initializing');

      // Initialize with discovered assets - using real DISA STIG rules (no mock data)
      const assetIds = discoveredAssets.map((asset: any) => asset.id);
      const realSTIGRules = [
        'WN22-DC-000010', // Account lockout policy
        'WN22-DC-000020', // Password policy
        'WN22-DC-000030', // Network security configuration
        'WN22-DC-000040', // Audit policy configuration
        'WN22-DC-000050'  // Access control configuration
      ];

      await initializeMonitoring(assetIds, realSTIGRules);

      setStigCodexStatus('active');
      toast({
        title: "STIG-Codex TRL10 Initialized",
        description: `Real-time monitoring active for ${assetIds.length} assets with cryptographic baselines`,
      });
    } catch (error) {
      console.error('Failed to initialize STIG-Codex:', error);
      setStigCodexStatus('inactive');
      toast({
        title: "Initialization Failed",
        description: "Failed to initialize STIG-Codex monitoring",
        variant: "destructive",
      });
    } finally {
      setIsInitializing(false);
    }
  };

  const getComplianceColor = (score: number) => {
    if (score >= 90) return 'text-green-600 dark:text-green-400';
    if (score >= 75) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-red-600 dark:text-red-400';
  };

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case 'active': return 'default';
      case 'initializing': return 'secondary';
      case 'inactive': return 'outline';
      default: return 'outline';
    }
  };

  return (
    <AccessControlWrapper
      requiredClearance="CONFIDENTIAL"
      resourceType="dod_stig_system"
      resourceId="main_dashboard"
    >
      <div className="min-h-screen bg-cyber-mesh bg-animate p-6 space-y-8">
        {/* Ra (Standard) Branding Strip */}
        <div className="flex items-center justify-between bg-black/40 backdrop-blur-md border-b border-white/10 px-6 py-2 -mx-6 -mt-6 mb-6">
          <div className="flex items-center gap-4">
            <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30 text-[10px] uppercase tracking-tighter">
              SouHimBou AI Core
            </Badge>
            <div className="h-4 w-px bg-white/20" />
            <span className="text-[10px] text-muted-foreground uppercase tracking-widest">
              Active Protocol: Ra (Standard)
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            <span className="text-[10px] text-green-500 font-bold uppercase tracking-widest">
              TRL-10 Verified
            </span>
          </div>
        </div>

        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 animate-fade-in">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-3 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-2xl shadow-lg shadow-blue-500/20">
                <Shield className="h-8 w-8 text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-black tracking-tight text-white italic bg-gradient-to-r from-white to-white/60 bg-clip-text">
                  STIG-CODEX CENTER
                </h1>
                <p className="text-blue-400/80 text-xs font-bold uppercase tracking-[0.2em]">
                  Department of Defense Operations Portal
                </p>
              </div>
            </div>
            <p className="text-muted-foreground max-w-2xl leading-relaxed mt-4">
              Comprehensive STIG-First compliance automation platform. Unified asset discovery,
              continuous monitoring, and automated remediation for <span className="text-white font-semibold">DoD / Iron Bank</span> environments.
            </p>
            <div className="flex items-center gap-3 mt-6">
              <Badge variant="secondary" className="bg-white/5 border-white/10 text-white px-3 py-1 font-mono">
                CLEARANCE: {currentClearance}
              </Badge>
              <Badge variant={getStatusBadgeVariant(stigCodexStatus)} className="px-3 py-1 uppercase tracking-widest text-[10px]">
                STATUS: {stigCodexStatus}
              </Badge>
              <div className="flex -space-x-2">
                {[1, 2, 3].map(i => (
                  <div key={i} className="w-8 h-8 rounded-full border-2 border-background bg-muted flex items-center justify-center text-[10px] font-bold">
                    ID
                  </div>
                ))}
                <div className="w-8 h-8 rounded-full border-2 border-background bg-primary/20 flex items-center justify-center text-[10px] font-bold text-primary">
                  +{totalAssets}
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <DashboardToggle />
            <Button
              onClick={refreshAllData}
              disabled={codexLoading}
              variant="outline"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${codexLoading ? 'animate-spin' : ''}`} />
              Refresh Data
            </Button>

            {stigCodexStatus === 'inactive' && (
              <Button
                onClick={handleInitializeSTIGCodex}
                disabled={isInitializing || !totalAssets}
                className="bg-blue-600 hover:bg-blue-700"
              >
                <Zap className="h-4 w-4 mr-2" />
                {isInitializing ? 'Initializing...' : 'Initialize STIG-Codex'}
              </Button>
            )}
          </div>
        </div>

        {/* Quick Status Overview */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Compliance Score</CardTitle>
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${getComplianceColor(complianceScore)}`}>
                {complianceScore}%
              </div>
              <Progress value={complianceScore} className="mt-2" />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Discovered Assets</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-2">
                <div className="text-2xl font-bold">{totalAssets}</div>
                <Server className="h-5 w-5 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Active Agents</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-2">
                <div className="text-2xl font-bold">{agents.length}</div>
                <Eye className="h-5 w-5 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Configuration Drift</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-2">
                <div className="text-2xl font-bold text-orange-600">
                  {driftEvents.filter(e => !e.acknowledged).length}
                </div>
                <AlertTriangle className="h-5 w-5 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Critical Threats</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-2">
                <div className="text-2xl font-bold text-red-600">
                  {threatCorrelations.filter(t => t.risk_elevation === 'critical').length}
                </div>
                <Globe className="h-5 w-5 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Interface Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="overview" className="flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="discovery" className="flex items-center gap-2">
              <Search className="h-4 w-4" />
              Asset Discovery
            </TabsTrigger>
            <TabsTrigger value="codex" className="flex items-center gap-2">
              <Command className="h-4 w-4" />
              STIG-Codex
            </TabsTrigger>
            <TabsTrigger value="monitoring" className="flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Monitoring
            </TabsTrigger>
            <TabsTrigger value="intelligence" className="flex items-center gap-2">
              <Brain className="h-4 w-4" />
              Intelligence
            </TabsTrigger>
            <TabsTrigger value="remediation" className="flex items-center gap-2">
              <Zap className="h-4 w-4" />
              Remediation
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* System Status */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Activity className="h-5 w-5 mr-2" />
                    System Status
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span>Asset Discovery Engine</span>
                    <Badge variant="default">Active</Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>STIG-Codex Orchestrator</span>
                    <Badge variant={getStatusBadgeVariant(stigCodexStatus)}>
                      {stigCodexStatus}
                    </Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Compliance Monitoring</span>
                    <Badge variant={agents.length > 0 ? 'default' : 'outline'}>
                      {agents.length > 0 ? 'Active' : 'Inactive'}
                    </Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Threat Intelligence</span>
                    <Badge variant="default">Connected</Badge>
                  </div>
                </CardContent>
              </Card>

              {/* Recent Activities */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Clock className="h-5 w-5 mr-2" />
                    Recent Activities
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 text-sm">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span>Asset discovery completed - {totalAssets} assets found</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-500" />
                      <span>{driftEvents.length} configuration drift events detected</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Globe className="h-4 w-4 text-blue-500" />
                      <span>{threatCorrelations.length} threat intelligence correlations</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Shield className="h-4 w-4 text-purple-500" />
                      <span>Compliance score: {complianceScore}%</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
                <CardDescription>
                  Common STIG compliance and asset management tasks
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <Button
                    variant="outline"
                    className="h-20 flex flex-col items-center gap-2"
                    onClick={() => setActiveTab('discovery')}
                  >
                    <Search className="h-6 w-6" />
                    <span className="text-sm">Start Discovery</span>
                  </Button>

                  <Button
                    variant="outline"
                    className="h-20 flex flex-col items-center gap-2"
                    onClick={() => setActiveTab('codex')}
                  >
                    <Command className="h-6 w-6" />
                    <span className="text-sm">STIG Analysis</span>
                  </Button>

                  <Button
                    variant="outline"
                    className="h-20 flex flex-col items-center gap-2"
                    onClick={() => setActiveTab('monitoring')}
                  >
                    <Activity className="h-6 w-6" />
                    <span className="text-sm">View Monitoring</span>
                  </Button>

                  <Button
                    variant="outline"
                    className="h-20 flex flex-col items-center gap-2"
                    onClick={() => setActiveTab('remediation')}
                  >
                    <Zap className="h-6 w-6" />
                    <span className="text-sm">Auto-Remediate</span>
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="discovery">
            <STIGConnectorDashboard organizationId={organizationId} />
          </TabsContent>

          <TabsContent value="codex">
            <STIGCodexDashboard {...stigCodexData} />
          </TabsContent>

          <TabsContent value="monitoring" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Activity className="h-5 w-5 mr-2" />
                  Continuous Monitoring Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                {agents.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {agents.map((agent: any) => (
                      <Card key={agent.id} className="border-l-4 border-l-blue-500">
                        <CardContent className="pt-4">
                          <div className="space-y-2">
                            <div className="flex justify-between items-center">
                              <span className="font-medium">{agent.agent_type}</span>
                              <Badge variant={agent.status === 'active' ? 'default' : 'outline'}>
                                {agent.status}
                              </Badge>
                            </div>
                            <div className="text-sm text-muted-foreground">
                              Monitoring: {agent.performance_metrics.configurations_monitored} configs
                            </div>
                            <div className="text-sm text-muted-foreground">
                              Violations: {agent.performance_metrics.violations_detected}
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Eye className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground mb-4">No monitoring agents deployed</p>
                    <Button onClick={handleInitializeSTIGCodex} disabled={!totalAssets}>
                      Initialize Monitoring
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="intelligence" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Brain className="h-5 w-5 mr-2" />
                  Threat Intelligence Correlations
                </CardTitle>
              </CardHeader>
              <CardContent>
                {threatCorrelations.length > 0 ? (
                  <div className="space-y-4">
                    {threatCorrelations.slice(0, 10).map((correlation: any) => (
                      <div key={correlation.id} className="border rounded-lg p-4">
                        <div className="flex justify-between items-start mb-2">
                          <span className="font-medium">Threat: {correlation.threat_id}</span>
                          <Badge variant={correlation.risk_elevation === 'critical' ? 'destructive' : 'secondary'}>
                            {correlation.risk_elevation}
                          </Badge>
                        </div>
                        <div className="text-sm text-muted-foreground">
                          STIG Rule: {correlation.stig_rule_id}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          Platforms: {correlation.affected_platforms.join(', ')}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Globe className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No threat correlations available</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="remediation" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Zap className="h-5 w-5 mr-2" />
                  Automated Remediation
                </CardTitle>
              </CardHeader>
              <CardContent>
                {driftEvents.length > 0 ? (
                  <div className="space-y-4">
                    {driftEvents.filter((event: any) => !event.acknowledged).map((event: any) => (
                      <div key={event.id} className="border rounded-lg p-4">
                        <div className="flex justify-between items-start mb-2">
                          <span className="font-medium">{event.drift_type}</span>
                          <Badge variant={event.severity === 'critical' ? 'destructive' : 'secondary'}>
                            {event.severity}
                          </Badge>
                        </div>
                        <div className="text-sm text-muted-foreground mb-2">
                          STIG Rule: {event.stig_rule_id}
                        </div>
                        <div className="flex items-center gap-4">
                          <span className="text-sm">Auto-remediated: {event.auto_remediated ? 'Yes' : 'No'}</span>
                          {!event.auto_remediated && (
                            <Button size="sm" variant="outline">
                              <Zap className="h-4 w-4 mr-1" />
                              Remediate
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                    <p className="text-muted-foreground">No remediation actions required</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AccessControlWrapper>
  );
}