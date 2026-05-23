import { useState, useCallback, useMemo, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Server,
  Database,
  Cloud,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Terminal,
  Settings,
  Network,
  Container,
  Globe,
  Lock,
  Zap,
  PlayCircle,
  PauseCircle,
  RotateCcw,
  Download,
  Upload,
  Eye,
  EyeOff,
  Monitor,
  Code,
  Brain,
  Sparkles,
  Laptop,
  Wifi,
  Router,
  Smartphone,
  Loader2
} from 'lucide-react';
import { ThreatIntelligenceOrchestrator } from '@/components/khepra/ThreatIntelligenceOrchestrator';
import { OSINTConnector } from '@/components/khepra/OSINTConnector';
import { AdinkraSymbolDisplay } from '@/components/khepra/AdinkraSymbolDisplay';
import { DeploymentWizard } from '@/components/khepra/deployment/DeploymentWizard';
import { KipConnectionStatus } from '@/components/khepra/KipConnectionStatus';
import { KipIntegrationSettings } from '@/components/khepra/KipIntegrationSettings';
import { AssetNetworkVisualization } from '@/components/AssetNetworkVisualization';
import { BrowserSecurityContext } from '@/components/BrowserSecurityContext';
import useRealTimeAssetDiscovery from '@/hooks/useRealTimeAssetDiscovery';
import { useKipConnection } from '@/hooks/useKipConnection';
import CacheStatusBadge from '@/components/CacheStatusBadge';


const DeploymentOrchestrationDashboard = () => {
  const {
    discoveredAssets,
    networkInfo,
    isScanning,
    lastScanTime,
    discoverLocalAssets,
    protectAsset
  } = useRealTimeAssetDiscovery();

  const {
    connection,
    recentTransformations,
    isLoading: kipLoading,
    syncCulturalTransformations
  } = useKipConnection();

  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [showOSINT, setShowOSINT] = useState(false);
  const [showConfig, setShowConfig] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([
    '🛡️ KHEPRA Protocol Deployment Orchestration Console',
    '📡 Initializing secure communication channels...',
    '🔍 Scanning for deployment targets...',
    '✅ Ready for commands. Type "help" for available commands.',
    ''
  ]);
  const [showDeploymentWizard, setShowDeploymentWizard] = useState(false);
  const [commandInput, setCommandInput] = useState('');

  // Debug logging for discovered assets and listen for protection changes
  useEffect(() => {
    console.log('Discovered assets updated:', discoveredAssets);
    if (discoveredAssets.length > 0) {
      setTerminalOutput(prev => [
        ...prev,
        `📊 Asset discovery complete: ${discoveredAssets.length} assets found`,
        `🔍 ${discoveredAssets.filter(a => a.protectionLevel === 'none').length} assets need protection`
      ]);
    }
  }, [discoveredAssets]);

  // Listen for protection changes from UI components
  useEffect(() => {
    const handleProtectionChange = () => {
      console.log('Protection changed, refreshing assets...');
      discoverLocalAssets();
    };

    globalThis.addEventListener('khepra-protection-changed', handleProtectionChange);
    return () => globalThis.removeEventListener('khepra-protection-changed', handleProtectionChange);
  }, [discoverLocalAssets]);

  const executeCommand = (command: string) => {
    const timestamp = new Date().toLocaleTimeString();
    const newOutput = [...terminalOutput, `[${timestamp}] $ ${command}`];

    const args = command.toLowerCase().split(' ');
    const cmd = args[0];

    switch (cmd) {
      case 'help':
        newOutput.push('Available commands:');
        newOutput.push('  scan - Rescan environment for assets');
        newOutput.push('  protect [asset-id] - Protect specific asset');
        newOutput.push('  status - Show deployment status');
        newOutput.push('  deploy - Launch deployment wizard');
        newOutput.push('  clear - Clear terminal');
        break;
      case 'scan':
        newOutput.push('🔍 Rescanning environment for assets...');
        discoverLocalAssets();
        setTimeout(() => {
          setTerminalOutput(prev => [
            ...prev,
            `✅ Scan complete. Found ${discoveredAssets.length} assets.`,
            `⚠️  ${discoveredAssets.filter(a => a.protectionLevel === 'none').length} assets need protection`
          ]);
        }, 2000);
        break;
      case 'protect': {
        const assetId = args[1];
        if (assetId) {
          const asset = discoveredAssets.find(a => a.id === assetId);
          if (asset) {
            newOutput.push(`🛡️ Enabling KHEPRA protection for: ${asset.name}`);
            protectAsset(assetId);
            setTimeout(() => {
              setTerminalOutput(prev => [
                ...prev,
                '✅ Protection activated successfully',
                '🔐 Asset is now secured with KHEPRA protocol'
              ]);
            }, 1500);
          } else {
            newOutput.push('❌ Asset not found');
          }
        } else {
          newOutput.push('❌ Please specify an asset ID');
          newOutput.push('Available assets:');
          discoveredAssets.forEach(asset => {
            newOutput.push(`   ${asset.id}: ${asset.name}`);
          });
        }
        break;
      }
      case 'status': {
        const protectedCount = discoveredAssets.filter(a => a.protectionLevel !== 'none').length;
        const vulnerableCount = discoveredAssets.filter(a => a.protectionLevel === 'none' && a.vulnerabilities.length > 0).length;
        const totalCount = discoveredAssets.length;

        newOutput.push('📊 Real-Time Environment Status:');
        newOutput.push(`   Protected Assets: ${protectedCount}`);
        newOutput.push(`   Vulnerable Assets: ${vulnerableCount}`);
        newOutput.push(`   Total Assets: ${totalCount}`);
        newOutput.push(`   Last Scan: ${lastScanTime?.toLocaleTimeString() || 'Never'}`);

        // Trigger a background scan to refresh data
        setTimeout(() => discoverLocalAssets(), 100);
        break;
      }
      case 'deploy':
        newOutput.push('🚀 Launching KHEPRA deployment wizard...');
        setShowDeploymentWizard(true);
        break;
      case 'clear':
        setTerminalOutput(['🛡️ KHEPRA Protocol Console - Terminal Cleared', '']);
        return;
      default:
        newOutput.push(`❌ Unknown command: ${cmd}. Type "help" for available commands.`);
    }

    newOutput.push('');
    setTerminalOutput(newOutput);
  };

  const vulnerabilityData = useMemo(() => {
    const total = discoveredAssets.length;
    const critical = discoveredAssets.filter(a => a.status === 'vulnerable' && a.vulnerabilities.length > 2).length;
    const warning = discoveredAssets.filter(a => a.status === 'vulnerable' && a.vulnerabilities.length <= 2).length;
    const healthy = discoveredAssets.filter(a => a.status === 'monitoring').length;
    const protectedCount = discoveredAssets.filter(a => a.protectionLevel !== 'none').length;

    return { total, critical, warning, healthy, protected: protectedCount };
  }, [discoveredAssets]);

  const handleAssetSelect = useCallback((asset: any) => {
    setSelectedAssetId(asset.id);
  }, []);

  const handleAssetProtect = useCallback(async (assetId: string) => {
    const success = await protectAsset(assetId);
    if (success) {
      setTerminalOutput(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] 🛡️ Asset ${assetId} protected successfully`
      ]);
      // Force refresh of discovered assets to update CLI status
      setTimeout(() => discoverLocalAssets(), 100);
    }
  }, [protectAsset, discoverLocalAssets]);

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && commandInput.trim()) {
      executeCommand(commandInput);
      setCommandInput('');
    }
  };

  return (
    <div className="h-screen flex flex-col bg-background">
      {/* KHEPRA Protocol Header */}
      <div className="relative overflow-hidden border-b border-primary/20 bg-gradient-to-r from-primary/5 via-purple-500/5 to-amber-500/5 p-4">
        <div className="relative z-10 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <AdinkraSymbolDisplay symbolName="Eban" size="small" showMatrix={false} />
            <div>
              <h1 className="text-2xl font-bold text-primary">KHEPRA Deployment Orchestration</h1>
              <p className="text-sm text-muted-foreground">
                Real-time asset discovery with Afrofuturist cryptographic framework
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <CacheStatusBadge />
            <Badge variant="outline" className="bg-primary/10 border-primary/30">
              {isScanning ? 'Scanning...' : 'Protocol Active'}
            </Badge>
            <Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
              {vulnerabilityData.protected} Protected
            </Badge>
            <Badge variant={connection.isConnected ? "default" : "secondary"} className="flex items-center gap-1">
              <div className={`w-2 h-2 rounded-full ${connection.isConnected ? 'bg-emerald-500' : 'bg-muted-foreground'}`} />
              KIP {connection.isConnected ? 'Connected' : 'Disconnected'}
            </Badge>
          </div>
        </div>

        {/* Decorative Adinkra symbols */}
        <div className="absolute top-0 right-0 w-24 h-24 opacity-10">
          <AdinkraSymbolDisplay symbolName="Nkyinkyim" size="large" showMatrix={false} />
        </div>
        <div className="absolute bottom-0 left-1/3 w-16 h-16 opacity-10">
          <AdinkraSymbolDisplay symbolName="Fawohodie" size="medium" showMatrix={false} />
        </div>
      </div>

      <div className="flex-1 flex">
        {/* Main Graph Area */}
        <div className="flex-1 relative">
          <AssetNetworkVisualization
            assets={discoveredAssets}
            onAssetSelect={handleAssetSelect}
            onAssetProtect={handleAssetProtect}
            selectedAssetId={selectedAssetId}
          />

          {/* KHEPRA-Enhanced Floating Action Buttons */}
          <div className="absolute top-4 left-4 flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="bg-primary/10 border-primary/30 hover:bg-primary/20"
              onClick={() => setShowDeploymentWizard(true)}
            >
              <Sparkles className="h-4 w-4 mr-2" />
              One-Click Deploy
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="bg-blue-500/10 border-blue-500/30 hover:bg-blue-500/20"
              onClick={discoverLocalAssets}
              disabled={isScanning}
            >
              {isScanning ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Shield className="h-4 w-4 mr-2" />}
              Rescan Environment
            </Button>
          </div>

          {/* Enhanced Status Overview with Browser Security Context */}
          <div className="absolute top-4 right-4 w-80 space-y-4">
            <BrowserSecurityContext
              vulnerabilities={vulnerabilityData.critical + vulnerabilityData.warning}
              warningCount={vulnerabilityData.warning}
              criticalCount={vulnerabilityData.critical}
              lastScanTime={lastScanTime?.toLocaleTimeString() || '10:37:47'}
              networkType={networkInfo.isPublic ? 'Public WiFi' : 'Private'}
            />

            <div className="bg-card/95 backdrop-blur-sm rounded-lg p-4 border border-primary/20 shadow-lg">
              <div className="space-y-2">
                <div className="flex items-center gap-4 text-sm">
                  <div className="flex items-center gap-1">
                    <Shield className="h-4 w-4 text-emerald-500" />
                    <span>{vulnerabilityData.protected} Protected</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                    <span>{vulnerabilityData.warning} Warning</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <XCircle className="h-4 w-4 text-destructive" />
                    <span>{vulnerabilityData.critical} Critical</span>
                  </div>
                </div>
                <Separator />
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>Total Assets: {vulnerabilityData.total}</div>
                  <div>Network: {networkInfo.isPublic ? 'Public WiFi' : 'Private'}</div>
                  <div>KHEPRA Agents: Active</div>
                  <div>Last Scan: {lastScanTime ? new Date(lastScanTime).toLocaleTimeString() : 'Never'}</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Panel */}
        <div className="w-96 border-l bg-card border-primary/20">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="h-full">
            <TabsList className="grid w-full grid-cols-6">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="terminal">CLI</TabsTrigger>
              <TabsTrigger value="khepra">KHEPRA</TabsTrigger>
              <TabsTrigger value="kip">KIP</TabsTrigger>
              <TabsTrigger value="osint">OSINT</TabsTrigger>
              <TabsTrigger value="config">Config</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="h-full p-4 space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Real-Time Asset Discovery</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="text-center p-4 bg-card rounded-lg">
                        <div className="text-2xl font-bold text-emerald-500">{vulnerabilityData.protected}</div>
                        <div className="text-sm text-muted-foreground">Protected</div>
                      </div>
                      <div className="text-center p-4 bg-card rounded-lg">
                        <div className="text-2xl font-bold text-amber-500">{vulnerabilityData.warning}</div>
                        <div className="text-sm text-muted-foreground">Warning</div>
                      </div>
                      <div className="text-center p-4 bg-card rounded-lg">
                        <div className="text-2xl font-bold text-destructive">{vulnerabilityData.critical}</div>
                        <div className="text-sm text-muted-foreground">Critical</div>
                      </div>
                      <div className="text-center p-4 bg-card rounded-lg">
                        <div className="text-2xl font-bold">{vulnerabilityData.total}</div>
                        <div className="text-sm text-muted-foreground">Total Assets</div>
                      </div>
                    </div>

                    <Separator />

                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium">Real-Time Environment</h4>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={discoverLocalAssets}
                          disabled={isScanning}
                        >
                          {isScanning ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Rescan'}
                        </Button>
                      </div>

                      {lastScanTime && (
                        <div className="text-xs text-muted-foreground">
                          Last scan: {lastScanTime.toLocaleString()}
                        </div>
                      )}

                      <div className="space-y-2 max-h-60 overflow-y-auto">
                        {discoveredAssets.map((asset) => (
                          <div
                            key={asset.id}
                            className="p-3 bg-card rounded border text-sm"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-medium">{asset.name}</span>
                              <Badge variant={asset.protectionLevel !== 'none' ? "default" : "secondary"}>
                                {asset.protectionLevel !== 'none' ? "Protected" : asset.status}
                              </Badge>
                            </div>
                            <div className="text-xs text-muted-foreground mt-1">
                              {asset.type} • {asset.type === 'device' ? 'Local' : 'Network'}
                              {asset.vulnerabilities.length > 0 && asset.protectionLevel === 'none' && (
                                <span className="text-destructive ml-2">
                                  {asset.vulnerabilities.length} vulnerabilities
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="terminal" className="h-full p-4">
              <Card className="h-full flex flex-col">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Terminal className="h-5 w-5" />
                    KHEPRA Command Interface
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex-1 flex flex-col">
                  <ScrollArea className="flex-1 bg-black text-green-400 p-3 rounded text-sm font-mono max-h-80">
                    {terminalOutput.map((line, index) => (
                      <div key={index}>{line}</div>
                    ))}
                  </ScrollArea>
                  <div className="mt-2 flex items-center gap-2">
                    <span className="text-green-400 font-mono">$</span>
                    <Input
                      value={commandInput}
                      onChange={(e) => setCommandInput(e.target.value)}
                      onKeyPress={handleKeyPress}
                      placeholder="Enter command..."
                      className="font-mono"
                    />
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="khepra" className="h-full p-4 overflow-y-auto">
              <ThreatIntelligenceOrchestrator />
            </TabsContent>

            <TabsContent value="kip" className="h-full p-4 space-y-4 overflow-y-auto">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold">KIP Integration Protocol</h3>
                  <div className="flex items-center gap-2">
                    <Badge variant={connection.isConnected ? "default" : "secondary"}>
                      {connection.isConnected ? "Connected" : "Disconnected"}
                    </Badge>
                    {recentTransformations.length > 0 && (
                      <Badge variant="outline" className="bg-primary/10">
                        {recentTransformations.length} Events
                      </Badge>
                    )}
                  </div>
                </div>
                <KipConnectionStatus />
              </div>
            </TabsContent>

            <TabsContent value="osint" className="h-full p-4 overflow-y-auto">
              <OSINTConnector />
            </TabsContent>

            <TabsContent value="config" className="h-full p-4 space-y-4 overflow-y-auto">
              <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center space-x-2">
                    <Settings className="h-5 w-5" />
                    <span>KHEPRA Configuration</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label>Deployment Strategy</Label>
                    <select className="w-full mt-1 p-2 border rounded bg-background">
                      <option>Personal Protection Mode</option>
                      <option>Enterprise Zero Trust</option>
                      <option>Government Enclave Security</option>
                    </select>
                  </div>
                  <div>
                    <Label>Real-Time Scanning</Label>
                    <div className="flex items-center space-x-2 mt-1">
                      <input type="checkbox" id="realtime-scan" defaultChecked />
                      <label htmlFor="realtime-scan">Enable continuous asset discovery</label>
                    </div>
                  </div>
                  <div>
                    <Label>KHEPRA Protocol Features</Label>
                    <div className="space-y-2 mt-1">
                      <div className="flex items-center space-x-2">
                        <input type="checkbox" id="khepra-aae" defaultChecked />
                        <label htmlFor="khepra-aae">Adinkra Algebraic Encoding</label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <input type="checkbox" id="khepra-pq" defaultChecked />
                        <label htmlFor="khepra-pq">Post-Quantum Cryptography</label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <input type="checkbox" id="auto-protect" defaultChecked />
                        <label htmlFor="auto-protect">Auto-protect vulnerable assets</label>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center space-x-2">
                    <Zap className="h-5 w-5" />
                    <span>KIP Integration Settings</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <KipIntegrationSettings />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>

      {/* Deployment Wizard Overlay */}
      {showDeploymentWizard && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-background rounded-lg shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
            <DeploymentWizard
              onComplete={(deploymentData) => {
                // Apply protection to selected assets
                if (deploymentData?.selectedAssets) {
                  deploymentData.selectedAssets.forEach((assetId: string) => {
                    protectAsset(assetId);
                  });
                }
                setShowDeploymentWizard(false);

                // Update terminal with deployment success
                setTerminalOutput(prev => [
                  ...prev,
                  `[${new Date().toLocaleTimeString()}] ✅ Deployment completed successfully`,
                  `🛡️ Protected ${deploymentData?.selectedAssets?.length || 0} assets`,
                  '🔐 KHEPRA protocol is now active',
                  ''
                ]);
              }}
              onCancel={() => setShowDeploymentWizard(false)}
              discoveredAssets={discoveredAssets}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default DeploymentOrchestrationDashboard;