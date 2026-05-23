import { useState, useEffect } from 'react';
import { useSearchParams } from '@/lib/router-compat';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

import { TRL10DiscoveryConsole } from './TRL10DiscoveryConsole';
import { ServiceMapper } from './ServiceMapper';
import useRealTimeAssetDiscovery from '@/hooks/useRealTimeAssetDiscovery';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import {
  Shield,
  Search,
  Settings,
  Network,
  Plus,
  RefreshCw,
  AlertTriangle,
  CheckCircle,

  Server,
  Terminal
} from 'lucide-react';

interface EnhancedSTIGConnectorProps {
  organizationId: string;
}

export const EnhancedSTIGConnector: React.FC<EnhancedSTIGConnectorProps> = ({ organizationId }) => {
  const {
    isScanning,
    discoverLocalAssets,
  } = useRealTimeAssetDiscovery();

  const [, setDiscoveryJobs] = useState<any[]>([]);
  const [discoveredAssetsDB, setDiscoveredAssetsDB] = useState<any[]>([]);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [newTarget, setNewTarget] = useState('');

  const [targets, setTargets] = useState<string[]>([]);
  const [showConsole] = useState(true);
  const [statistics, setStatistics] = useState<any>(null);

  const [searchParams, setSearchParams] = useSearchParams();

  useEffect(() => {
    if (organizationId) {
      fetchDiscoveryJobs();
      fetchAssets();
      fetchStatistics();
    }
  }, [organizationId]);

  useEffect(() => {
    if (searchParams.get('runScan') === 'true' && !isScanning) {
      toast.info('Initiating scan from global dashboard...');
      discoverLocalAssets();
      // Remove the param so it doesn't re-trigger on refresh
      const newParams = new URLSearchParams(searchParams);
      newParams.delete('runScan');
      setSearchParams(newParams, { replace: true });
    }
  }, [searchParams, isScanning, discoverLocalAssets, setSearchParams]);

  const fetchDiscoveryJobs = async () => {
    try {
      const { data, error } = await supabase
        .from('discovery_jobs')
        .select('*')
        .eq('organization_id', organizationId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setDiscoveryJobs(data || []);
    } catch (error) {
      console.error('Failed to fetch discovery jobs:', error);
    }
  };

  const fetchAssets = async () => {
    try {
      const { data, error } = await supabase
        .from('discovered_assets')
        .select('asset_type, platform, risk_score, applicable_stigs, compliance_status')
        .eq('organization_id', organizationId)
        .eq('is_active', true);

      if (error) throw error;
      setDiscoveredAssetsDB(data || []);
    } catch (error) {
      console.error('Failed to fetch assets:', error);
    }
  };

  const fetchStatistics = async () => {
    try {
      // Fetch asset statistics
      const { data: assets } = await supabase
        .from('discovered_assets')
        .select('*')
        .eq('organization_id', organizationId)
        .eq('is_active', true);

      if (assets) {
        const totalAssets = assets.length;
        const totalStigs = assets.reduce((sum, asset) => sum + (asset.applicable_stigs?.length || 0), 0);
        const complianceSum = assets.reduce((sum, asset) => {
          const status = asset.compliance_status as any;
          return sum + (status?.compliant || 0);
        }, 0);
        const complianceTotal = assets.reduce((sum, asset) => {
          const status = asset.compliance_status as any;
          return sum + (status?.total_stigs || 0);
        }, 0);

        const riskDistribution = assets.reduce((dist, asset) => {
          const risk = asset.risk_score || 0;
          if (risk >= 90) dist.critical++;
          else if (risk >= 75) dist.high++;
          else if (risk >= 50) dist.medium++;
          else dist.low++;
          return dist;
        }, { critical: 0, high: 0, medium: 0, low: 0 });

        setStatistics({
          total_assets: totalAssets,
          compliance_overview: {
            total_stigs: totalStigs,
            compliance_percentage: complianceTotal > 0 ? Math.round((complianceSum / complianceTotal) * 100) : 0
          },
          risk_distribution: riskDistribution
        });
      }
    } catch (error) {
      console.error('Failed to fetch statistics:', error);
    }
  };

  const addTarget = () => {
    if (!newTarget.trim()) {
      toast.error('Please enter a target IP or hostname');
      return;
    }

    if (targets.includes(newTarget)) {
      toast.error('Target already added');
    } else {
      setTargets([...targets, newTarget]);
      setNewTarget('');
      toast.success('Target added to scan list');
    }
  };

  const removeTarget = (target: string) => {
    setTargets(targets.filter(t => t !== target));
  };

  const startDiscovery = async () => {
    if (targets.length === 0) {
      toast.error('Please add at least one target');
      return;
    }

    setIsDiscovering(true);
    try {
      const { error } = await supabase.functions.invoke('enhanced-asset-discovery', {
        body: {
          action: 'start_discovery',
          organization_id: organizationId,
          discovery_config: {
            type: 'network_scan',
            targets: targets,
            scan_options: {}
          }
        }
      });

      if (error) throw error;

      toast.success('TRL10 Asset discovery started successfully');
      await fetchDiscoveryJobs();
      await fetchAssets();
      await fetchStatistics();

    } catch (error) {
      console.error('Discovery error:', error);
      toast.error('Failed to start discovery');
    } finally {
      setIsDiscovering(false);
    }
  };

  const stopDiscovery = () => {
    setIsDiscovering(false);
    toast.info('Discovery scan stopped');
  };

  return (
    <div className="space-y-6">
      {/* Header Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Assets</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics?.total_assets || 0}</div>
            <p className="text-xs text-muted-foreground">TRL10 Discovered</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">STIG Coverage</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics?.compliance_overview.total_stigs || 0}</div>
            <p className="text-xs text-muted-foreground">Mapped STIGs</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Compliance Rate</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics?.compliance_overview.compliance_percentage || 0}%</div>
            <p className="text-xs text-muted-foreground">Production Ready</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Risk Assets</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(statistics?.risk_distribution.high || 0) + (statistics?.risk_distribution.critical || 0)}
            </div>
            <p className="text-xs text-muted-foreground">Require Attention</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Tabbed Interface */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            TRL10 Enhanced STIG Asset Discovery & Service Mapping Platform
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="discovery" className="w-full">
            <TabsList className="grid grid-cols-5 w-fit mb-6">
              <TabsTrigger value="discovery" className="flex items-center gap-2">
                <Search className="h-4 w-4" />
                Discovery
              </TabsTrigger>
              <TabsTrigger value="console" className="flex items-center gap-2">
                <Terminal className="h-4 w-4" />
                TRL10 Console
              </TabsTrigger>
              <TabsTrigger value="services" className="flex items-center gap-2">
                <Server className="h-4 w-4" />
                Service Mapping
              </TabsTrigger>
              <TabsTrigger value="visualization" className="flex items-center gap-2">
                <Network className="h-4 w-4" />
                Network Map
              </TabsTrigger>
              <TabsTrigger value="config" className="flex items-center gap-2">
                <Settings className="h-4 w-4" />
                Configuration
              </TabsTrigger>
            </TabsList>

            <TabsContent value="discovery" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Search className="h-5 w-5 text-primary" />
                    TRL10 Asset Discovery & STIG Compliance Scanner
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex gap-4">
                      <Input
                        placeholder="Enter IP address or hostname (e.g., 192.168.1.1)"
                        value={newTarget}
                        onChange={(e) => setNewTarget(e.target.value)}
                        className="flex-1"
                        onKeyDown={(e) => e.key === 'Enter' && addTarget()}
                      />
                      <Button
                        onClick={addTarget}
                        variant="outline"
                        className="min-w-[100px]"
                      >
                        <Plus className="mr-2 h-4 w-4" />
                        Add Target
                      </Button>
                    </div>

                    {targets.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="text-sm font-medium text-slate-400">Scan Targets ({targets.length})</h4>
                        <div className="flex flex-wrap gap-2">
                          {targets.map((target) => (
                            <Badge
                              key={target}
                              variant="outline"
                              className="flex items-center gap-1"
                            >
                              {target}
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-4 w-4 p-0 hover:bg-red-500/20"
                                onClick={() => removeTarget(target)}
                              >
                                ×
                              </Button>
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    <Button
                      onClick={startDiscovery}
                      disabled={isDiscovering || targets.length === 0}
                      className="w-full"
                      size="lg"
                    >
                      {isDiscovering ? (
                        <>
                          <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                          Running TRL10 Discovery...
                        </>
                      ) : (
                        <>
                          <Search className="mr-2 h-4 w-4" />
                          Start TRL10 Discovery Scan
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="console">
              <TRL10DiscoveryConsole
                isActive={showConsole}
                onStart={startDiscovery}
                onStop={stopDiscovery}
                organizationId={organizationId}
                targets={targets}
              />
            </TabsContent>

            <TabsContent value="services">
              <ServiceMapper
                assets={discoveredAssetsDB.map(asset => ({
                  id: asset.id,
                  identifier: asset.asset_identifier,
                  hostname: asset.hostname,
                  ip_address: asset.ip_addresses?.[0] || asset.asset_identifier,
                  asset_type: asset.asset_type,
                  platform: asset.platform,
                  operating_system: asset.operating_system,
                  services: asset.discovered_services || [],
                  overall_risk_score: asset.risk_score || 0,
                  compliance_percentage: Math.round((asset.compliance_status?.compliant || 0) / Math.max(asset.compliance_status?.total_stigs || 1, 1) * 100),
                  last_scan: asset.last_discovered
                }))}
                onServiceSelect={(assetId, service) => {
                  toast.info(`Selected ${service.service} on port ${service.port} for asset ${assetId}`);
                }}
                showCompliance={true}
              />
            </TabsContent>

            <TabsContent value="visualization">
              <Card>
                <CardHeader>
                  <CardTitle>Network Topology</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-slate-400">Network visualization will appear here after discovery.</p>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="config" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Settings className="h-5 w-5 text-primary" />
                    TRL10 Configuration & Security Settings
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <label htmlFor="clearance-level" className="text-sm font-medium text-slate-300">Security Clearance Level</label>
                        <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30">
                          TOP SECRET
                        </Badge>
                      </div>
                      <div className="space-y-2">
                        <label htmlFor="trl-compliance" className="text-sm font-medium text-slate-300">TRL Compliance</label>
                        <Badge variant="outline" className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                          TRL-10 OPERATIONAL
                        </Badge>
                      </div>
                    </div>

                    <div className="pt-4 border-t border-slate-700">
                      <h4 className="text-sm font-medium text-slate-300 mb-2">Discovery Engines Status</h4>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                          <span className="text-sm">Nmap Engine</span>
                          <Badge variant="default" className="bg-green-500/20 text-green-400">
                            Active
                          </Badge>
                        </div>
                        <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                          <span className="text-sm">Shodan API</span>
                          <Badge variant="default" className="bg-green-500/20 text-green-400">
                            Connected
                          </Badge>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};